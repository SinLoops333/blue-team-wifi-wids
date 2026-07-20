"""Run signature + anomaly evaluation and produce a report dict."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Set

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from ..config import Config
from ..detect.frame_features import FeatureExtractor, parse_frame
from ..detect.signatures import SignatureEngine
from .dataset import (
    Scenario,
    attack_window_vectors,
    benign_window_vectors,
    build_scenarios,
)
from .metrics import BinaryScores, multilabel_alert_scores, scores_for_label


ALERT_TYPES = [
    "deauth_flood",
    "evil_twin",
    "encryption_downgrade",
    "karma",
    "pmkid_harvest",
    "handshake_harvest",
]


def _run_scenario(cfg: Config, scenario: Scenario) -> Set[str]:
    """Fresh engine per scenario so state does not leak."""
    engine = SignatureEngine(cfg)
    # Seed known-good map for evil-twin / downgrade (owned AP)
    engine.load_baseline_inventory(
        {
            "00:13:37:a9:43:43": {
                "ssid": "Open999",
                "channel": 11,
                "encryption": "WPA2/WPA3",
            }
        }
    )
    # Lower karma / deauth thresholds already set via cfg in tests; use production
    # defaults from config but ensure deauth threshold is reachable (25 frames).
    extractor = FeatureExtractor(window_seconds=60)
    predicted: Set[str] = set()
    t0 = time.time()
    for i, pkt in enumerate(scenario.packets):
        ev = parse_frame(pkt, timestamp=t0 + i * 0.01)
        if ev is None:
            continue
        extractor.ingest(ev)
        for alert in engine.process(ev, extractor):
            predicted.add(alert.alert_type)
    return predicted


def evaluate_signatures(cfg: Config) -> Dict[str, Any]:
    scenarios = build_scenarios()
    # Use a deauth threshold of 20 for eval consistency with production defaults
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

    expected_sets: List[Set[str]] = []
    predicted_sets: List[Set[str]] = []
    rows = []
    for sc in scenarios:
        pred = _run_scenario(cfg, sc)
        expected_sets.append(sc.expected_alerts)
        predicted_sets.append(pred)
        hit = sc.expected_alerts <= pred if sc.expected_alerts else (len(pred) == 0)
        # For benign: success if no attack alerts (ignore anomaly — not run here)
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


def evaluate_isolation_forest(random_state: int = 42) -> Dict[str, Any]:
    """Train on benign windows; score benign vs attack; report ROC-AUC + F1."""
    X_benign = np.array(benign_window_vectors(80), dtype=float)
    X_attack = np.array(attack_window_vectors(40), dtype=float)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_benign[:50])
    model = IsolationForest(
        contamination=0.05, random_state=random_state, n_estimators=200
    )
    model.fit(X_train)

    X_test_benign = scaler.transform(X_benign[50:])
    X_test_attack = scaler.transform(X_attack)
    X_test = np.vstack([X_test_benign, X_test_attack])
    y_true = np.array([0] * len(X_test_benign) + [1] * len(X_test_attack))

    scores = -model.decision_function(X_test)
    preds = (model.predict(X_test) == -1).astype(int)

    auc = float(roc_auc_score(y_true, scores))
    binary = scores_for_label(y_true.tolist(), preds.tolist())

    return {
        "n_train_benign": int(len(X_train)),
        "n_test_benign": int(len(X_test_benign)),
        "n_test_attack": int(len(X_test_attack)),
        "roc_auc": round(auc, 4),
        "at_default_threshold": binary.to_dict(),
        "mean_anomaly_score_benign": round(
            float(scores[: len(X_test_benign)].mean()), 4
        ),
        "mean_anomaly_score_attack": round(
            float(scores[len(X_test_benign) :].mean()), 4
        ),
    }


def run_full_eval(cfg: Config) -> Dict[str, Any]:
    return {
        "generated_at": time.time(),
        "signatures": evaluate_signatures(cfg),
        "isolation_forest": evaluate_isolation_forest(),
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

    iso = result["isolation_forest"]
    lines += [
        "",
        "## IsolationForest anomaly model",
        "",
        f"- Train benign windows: {iso['n_train_benign']}",
        f"- Test benign / attack: {iso['n_test_benign']} / {iso['n_test_attack']}",
        f"- **ROC-AUC:** {iso['roc_auc']}",
        f"- Mean anomaly score (benign): {iso['mean_anomaly_score_benign']}",
        f"- Mean anomaly score (attack): {iso['mean_anomaly_score_attack']}",
        f"- At default threshold — P/R/F1: "
        f"{iso['at_default_threshold']['precision']:.2f} / "
        f"{iso['at_default_threshold']['recall']:.2f} / "
        f"{iso['at_default_threshold']['f1']:.2f}",
        "",
        "## Notes",
        "",
        "- Metrics use **synthetic labeled scenarios** (not third-party live RF).",
        "- Signature eval is scenario-level presence of alert types.",
        "- IsolationForest is trained only on synthetic benign windows.",
        "",
    ]
    return "\n".join(lines)
