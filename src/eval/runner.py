"""Run signature + anomaly evaluation and produce a report dict."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Set

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from ..config import Config
from ..detect.frame_features import FeatureExtractor, WindowFeatures, parse_frame
from ..detect.drift import evaluate_drift_detection
from ..detect.fusion import RadioFusionEngine
from ..detect.honeypot import HoneypotEngine, evaluate_honeypot_model
from ..detect.signatures import SignatureEngine
from .dataset import (
    Scenario,
    attack_window_vectors,
    benign_window_vectors,
    build_scenarios,
)
from .explain import FEATURE_NAMES, top_feature_contributions
from .metrics import multilabel_alert_scores, scores_for_label

ALERT_TYPES = [
    "deauth_flood",
    "evil_twin",
    "encryption_downgrade",
    "karma",
    "pmkid_harvest",
    "handshake_harvest",
    "beacon_fingerprint_mismatch",
    "beacon_tsf_anomaly",
    "radio_fingerprint_disagreement",
    "radio_channel_conflict",
    "radio_ssid_split_view",
    "honeypot_recon_burst",
    "honeypot_client_anomaly",
]


def _run_scenario(cfg: Config, scenario: Scenario) -> Set[str]:
    engine = SignatureEngine(cfg)
    fusion = RadioFusionEngine(cfg)
    honeypot = HoneypotEngine(cfg)
    if honeypot.enabled():
        honeypot.fit_default()
    engine.load_baseline_inventory(
        {
            "00:13:37:a9:43:43": {
                "ssid": "Open999",
                "channel": 11,
                "encryption": "WPA2/WPA3",
            }
        }
    )
    extractor = FeatureExtractor(window_seconds=60)
    predicted: Set[str] = set()
    t0 = time.time()
    for i, item in enumerate(scenario.packets):
        radio_id = None
        pkt = item
        if isinstance(item, tuple) and len(item) == 2:
            pkt, radio_id = item
        # Spread probes a bit so burst window sees them as near-simultaneous
        ev = parse_frame(pkt, timestamp=t0 + i * 0.05, radio_id=radio_id)
        if ev is None:
            continue
        extractor.ingest(ev)
        for alert in engine.process(ev, extractor):
            predicted.add(alert.alert_type)
        for alert in fusion.process(ev):
            predicted.add(alert.alert_type)
        for alert in honeypot.process(ev):
            predicted.add(alert.alert_type)
    return predicted


def evaluate_signatures(cfg: Config) -> Dict[str, Any]:
    scenarios = build_scenarios()
    cfg.detectors = dict(cfg.detectors)
    cfg.detectors["deauth"] = {
        **(cfg.detectors.get("deauth") or {}),
        "window_seconds": 10,
        "threshold": 20,
        "ignore_broadcast_source": True,
    }
    cfg.detectors["karma"] = {
        **(cfg.detectors.get("karma") or {}),
        "window_seconds": 60,
        "min_ssids_per_bssid": 5,
    }
    # Fusion scenarios need the engine on
    cfg.fusion = dict(cfg.fusion or {})
    cfg.fusion["enabled"] = True
    cfg.fusion.setdefault("disagreement_window_seconds", 30)
    cfg.honeypot = dict(cfg.honeypot or {})
    cfg.honeypot["enabled"] = True
    cfg.honeypot["ssids"] = list(
        set(cfg.honeypot.get("ssids") or []) | {"Open999"}
    )
    cfg.honeypot.setdefault("burst_probe_threshold", 12)
    cfg.allowlist_ssids = set(cfg.allowlist_ssids) | {"Open999"}

    expected_sets: List[Set[str]] = []
    predicted_sets: List[Set[str]] = []
    rows = []
    for sc in scenarios:
        pred = _run_scenario(cfg, sc)
        expected_sets.append(sc.expected_alerts)
        predicted_sets.append(pred)
        hit = sc.expected_alerts <= pred if sc.expected_alerts else (len(pred) == 0)
        if sc.label == "benign":
            hit = len(pred & set(ALERT_TYPES)) == 0
        rows.append(
            {
                "name": sc.name,
                "label": sc.label,
                "expected": sorted(sc.expected_alerts),
                "predicted": sorted(pred),
                "pass": hit,
            }
        )

    per_type = multilabel_alert_scores(expected_sets, predicted_sets, ALERT_TYPES)
    return {
        "scenarios": rows,
        "per_alert_type": {k: v.to_dict() for k, v in per_type.items()},
        "scenario_pass_rate": (
            sum(1 for r in rows if r["pass"]) / len(rows) if rows else 0.0
        ),
    }


def _score_model(model, X_test, y_true) -> Dict[str, Any]:
    scores = -model.decision_function(X_test)
    preds = (model.predict(X_test) == -1).astype(int)
    auc = float(roc_auc_score(y_true, scores))
    binary = scores_for_label(y_true.tolist(), preds.tolist())
    n_benign = int((y_true == 0).sum())
    return {
        "roc_auc": round(auc, 4),
        "at_default_threshold": binary.to_dict(),
        "mean_anomaly_score_benign": round(float(scores[:n_benign].mean()), 4),
        "mean_anomaly_score_attack": round(float(scores[n_benign:].mean()), 4),
    }


def evaluate_anomaly_models(random_state: int = 42) -> Dict[str, Any]:
    """Compare IsolationForest vs One-Class SVM + feature attributions."""
    X_benign = np.array(benign_window_vectors(80), dtype=float)
    X_attack = np.array(attack_window_vectors(40), dtype=float)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_benign[:50])
    X_test_benign = scaler.transform(X_benign[50:])
    X_test_attack = scaler.transform(X_attack)
    X_test = np.vstack([X_test_benign, X_test_attack])
    y_true = np.array([0] * len(X_test_benign) + [1] * len(X_test_attack))
    train_mean = X_train.mean(axis=0)

    iso = IsolationForest(
        contamination=0.05, random_state=random_state, n_estimators=200
    )
    iso.fit(X_train)

    ocsvm = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05)
    ocsvm.fit(X_train)

    iso_metrics = _score_model(iso, X_test, y_true)
    svm_metrics = _score_model(ocsvm, X_test, y_true)

    # Example attribution on first attack sample
    attack0 = X_test_attack[0]
    contribs = top_feature_contributions(attack0, train_mean, top_k=5)

    return {
        "n_train_benign": int(len(X_train)),
        "n_test_benign": int(len(X_test_benign)),
        "n_test_attack": int(len(X_test_attack)),
        "feature_names": FEATURE_NAMES,
        "isolation_forest": iso_metrics,
        "one_class_svm": svm_metrics,
        "example_attack_attribution": contribs,
        "winner": (
            "isolation_forest"
            if iso_metrics["roc_auc"] >= svm_metrics["roc_auc"]
            else "one_class_svm"
        ),
    }


def deauth_threshold_sweep(cfg: Config) -> Dict[str, Any]:
    """Measure deauth detector TPR/FPR across thresholds on synthetic scenarios."""
    scenarios = build_scenarios()
    rows = []
    for thr in [5, 10, 15, 20, 30, 40]:
        cfg.detectors = dict(cfg.detectors)
        cfg.detectors["deauth"] = {
            "window_seconds": 10,
            "threshold": thr,
            "ignore_broadcast_source": True,
        }
        cfg.detectors["karma"] = {
            "window_seconds": 60,
            "min_ssids_per_bssid": 5,
        }
        y_true = []
        y_pred = []
        for sc in scenarios:
            pred = _run_scenario(cfg, sc)
            truth = 1 if "deauth_flood" in sc.expected_alerts else 0
            guess = 1 if "deauth_flood" in pred else 0
            y_true.append(truth)
            y_pred.append(guess)
        scores = scores_for_label(y_true, y_pred)
        # FPR among negatives
        negatives = sum(1 for t in y_true if t == 0)
        fpr = scores.fp / negatives if negatives else 0.0
        rows.append(
            {
                "threshold": thr,
                "precision": round(scores.precision, 4),
                "recall": round(scores.recall, 4),
                "f1": round(scores.f1, 4),
                "fpr": round(fpr, 4),
                "tp": scores.tp,
                "fp": scores.fp,
                "fn": scores.fn,
            }
        )
    # Prefer high recall with zero FPR, else best F1
    zero_fpr = [r for r in rows if r["fpr"] == 0 and r["recall"] > 0]
    recommended = max(zero_fpr or rows, key=lambda r: (r["f1"], r["recall"]))
    return {"sweep": rows, "recommended_threshold": recommended["threshold"]}


def evaluate_isolation_forest(random_state: int = 42) -> Dict[str, Any]:
    """Back-compat wrapper returning IsolationForest block with dataset sizes."""
    am = evaluate_anomaly_models(random_state=random_state)
    return {
        "n_train_benign": am["n_train_benign"],
        "n_test_benign": am["n_test_benign"],
        "n_test_attack": am["n_test_attack"],
        **am["isolation_forest"],
    }


def run_full_eval(cfg: Config) -> Dict[str, Any]:
    from .autotune import autotune_thresholds
    from .stress import run_stress_suite

    anomaly = evaluate_anomaly_models()
    return {
        "generated_at": time.time(),
        "signatures": evaluate_signatures(cfg),
        "anomaly_models": anomaly,
        "honeypot_client_model": evaluate_honeypot_model(),
        "concept_drift": evaluate_drift_detection(),
        "stress_suite": run_stress_suite(cfg),
        "autotune": autotune_thresholds(cfg, max_fpr=0.0),
        # Back-compat key used by older tests / docs
        "isolation_forest": {
            "n_train_benign": anomaly["n_train_benign"],
            "n_test_benign": anomaly["n_test_benign"],
            "n_test_attack": anomaly["n_test_attack"],
            **anomaly["isolation_forest"],
        },
        "deauth_threshold_sweep": deauth_threshold_sweep(cfg),
    }


def report_markdown(result: Dict[str, Any]) -> str:
    lines = [
        "# WIDS evaluation report",
        "",
        f"Generated (unix): `{result.get('generated_at')}`",
        "",
        "## Signature detectors",
        "",
        f"Scenario pass rate: **"
        f"{result['signatures']['scenario_pass_rate']:.0%}**",
        "",
        "| Scenario | Label | Expected | Predicted | Pass |",
        "|---|---|---|---|---|",
    ]
    for row in result["signatures"]["scenarios"]:
        lines.append(
            f"| {row['name']} | {row['label']} | "
            f"{', '.join(row['expected']) or '—'} | "
            f"{', '.join(row['predicted']) or '—'} | "
            f"{'yes' if row['pass'] else 'NO'} |"
        )
    lines += [
        "",
        "### Per alert-type precision / recall / F1",
        "",
        "| Alert | P | R | F1 | TP | FP | FN | Support |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, m in result["signatures"]["per_alert_type"].items():
        lines.append(
            f"| {name} | {m['precision']:.2f} | {m['recall']:.2f} | "
            f"{m['f1']:.2f} | {m['tp']} | {m['fp']} | {m['fn']} | "
            f"{m['support_positive']} |"
        )

    am = result.get("anomaly_models") or {}
    iso = am.get("isolation_forest") or result.get("isolation_forest") or {}
    svm = am.get("one_class_svm") or {}
    lines += [
        "",
        "## Anomaly models (IsolationForest vs One-Class SVM)",
        "",
        f"| Model | ROC-AUC | P | R | F1 |",
        f"|---|---:|---:|---:|---:|",
        f"| IsolationForest | {iso.get('roc_auc')} | "
        f"{iso.get('at_default_threshold', {}).get('precision')} | "
        f"{iso.get('at_default_threshold', {}).get('recall')} | "
        f"{iso.get('at_default_threshold', {}).get('f1')} |",
        f"| One-Class SVM | {svm.get('roc_auc')} | "
        f"{svm.get('at_default_threshold', {}).get('precision')} | "
        f"{svm.get('at_default_threshold', {}).get('recall')} | "
        f"{svm.get('at_default_threshold', {}).get('f1')} |",
        "",
        f"Winner (ROC-AUC): **{am.get('winner', 'isolation_forest')}**",
        "",
        "### Example attack feature attribution (z-dev from benign mean)",
        "",
    ]
    for c in am.get("example_attack_attribution") or []:
        lines.append(
            f"- `{c['feature']}`: delta={c['delta']} "
            f"(value={c['value']}, baseline={c['baseline_mean']})"
        )

    hp = result.get("honeypot_client_model") or {}
    if hp:
        lines += [
            "",
            "## Honeypot client model (benign phone vs recon STA)",
            "",
            f"ROC-AUC: **{hp.get('roc_auc')}**  "
            f"(train_benign={hp.get('n_train_benign')}, "
            f"test_recon={hp.get('n_test_recon')})",
            "",
        ]

    drift = result.get("concept_drift") or {}
    if drift:
        lines += [
            "",
            "## Concept drift (PSI on window features)",
            "",
            f"PSI same dist: `{drift.get('psi_same_distribution')}`  ·  "
            f"PSI shifted: **{drift.get('psi_shifted_distribution')}**  ·  "
            f"detects_shift={drift.get('detects_shift')}",
            "",
        ]

    stress = result.get("stress_suite") or {}
    if stress:
        lines += [
            "",
            "## Detector stress suite (near-threshold)",
            "",
            f"Pass rate: **{stress.get('pass_rate', 0):.0%}** "
            f"({stress.get('n_pass')}/{stress.get('n_cases')})",
            "",
            "| Case | Expect | Got | Pass | Note |",
            "|---|---|---|---|---|",
        ]
        for row in stress.get("cases") or []:
            lines.append(
                f"| {row['name']} | {row['expect_alert']} | {row['got_alert']} | "
                f"{'yes' if row['pass'] else 'NO'} | {row.get('note', '')} |"
            )

    auto = result.get("autotune") or {}
    if auto:
        rd = auto.get("recommended_deauth") or {}
        rk = auto.get("recommended_karma") or {}
        lines += [
            "",
            "## Threshold autotune (max FPR = "
            f"{auto.get('max_fpr', 0)})",
            "",
            f"Recommended deauth threshold: **{rd.get('threshold')}** "
            f"(F1={rd.get('f1')}, FPR={rd.get('fpr')})",
            "",
            f"Recommended karma min_ssids: **{rk.get('min_ssids_per_bssid')}** "
            f"(F1={rk.get('f1')}, FPR={rk.get('fpr')})",
            "",
        ]

    sweep = result.get("deauth_threshold_sweep") or {}
    lines += [
        "",
        "## Deauth threshold sweep",
        "",
        f"Recommended threshold: **{sweep.get('recommended_threshold')}**",
        "",
        "| Threshold | P | R | F1 | FPR |",
        "|---:|---:|---:|---:|---:|",
    ]
    for r in sweep.get("sweep") or []:
        lines.append(
            f"| {r['threshold']} | {r['precision']:.2f} | {r['recall']:.2f} | "
            f"{r['f1']:.2f} | {r['fpr']:.2f} |"
        )
    lines += [
        "",
        "## Notes",
        "",
        "- Metrics use **synthetic labeled scenarios** (not third-party live RF).",
        "- Feature attribution is centroid z-deviation (lightweight SHAP-style).",
        "",
    ]
    return "\n".join(lines)
