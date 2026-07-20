"""Threshold autotune: maximize F1 under a max false-positive rate constraint.

Lab/synthetic only — searches deauth + karma thresholds using labeled
scenarios from the eval harness.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..config import Config
from ..eval.dataset import build_scenarios
from ..eval.metrics import scores_for_label


def _score_detector(
    cfg: Config,
    *,
    alert_type: str,
    positive_labels: Sequence[str],
) -> Dict[str, Any]:
    """Binary scores for one alert type across build_scenarios()."""
    from ..eval.runner import _run_scenario

    y_true: List[int] = []
    y_pred: List[int] = []
    for sc in build_scenarios():
        # Skip fusion/honeypot extras that muddy deauth/karma tuning
        if sc.label in ("fusion", "beacon_clone", "honeypot"):
            continue
        pred = _run_scenario(cfg, sc)
        truth = 1 if alert_type in sc.expected_alerts else 0
        # For benign, truth is 0
        if sc.label == "benign":
            truth = 0
        elif sc.label not in positive_labels and alert_type not in sc.expected_alerts:
            # Other attacks: still a negative for this detector
            truth = 0
        guess = 1 if alert_type in pred else 0
        y_true.append(truth)
        y_pred.append(guess)
    scores = scores_for_label(y_true, y_pred)
    negatives = sum(1 for t in y_true if t == 0)
    fpr = scores.fp / negatives if negatives else 0.0
    return {
        "precision": round(scores.precision, 4),
        "recall": round(scores.recall, 4),
        "f1": round(scores.f1, 4),
        "fpr": round(fpr, 4),
        "tp": scores.tp,
        "fp": scores.fp,
        "fn": scores.fn,
        "tn": scores.tn,
    }


def _base_cfg(cfg: Config) -> Config:
    c = deepcopy(cfg)
    c.detectors = dict(c.detectors or {})
    c.fusion = dict(c.fusion or {})
    c.fusion["enabled"] = False  # faster; fusion not needed for deauth/karma tune
    c.honeypot = dict(c.honeypot or {})
    c.honeypot["enabled"] = False
    c.drift = dict(c.drift or {})
    c.drift["enabled"] = False
    return c


def autotune_thresholds(
    cfg: Config,
    *,
    max_fpr: float = 0.0,
    deauth_candidates: Optional[Sequence[int]] = None,
    karma_candidates: Optional[Sequence[int]] = None,
) -> Dict[str, Any]:
    """Grid-search deauth threshold and karma min_ssids under FPR cap."""
    deauth_candidates = list(deauth_candidates or [5, 10, 15, 20, 25, 30, 40])
    karma_candidates = list(karma_candidates or [3, 4, 5, 6, 7, 8])

    deauth_rows = []
    best_deauth = None
    for thr in deauth_candidates:
        c = _base_cfg(cfg)
        c.detectors["deauth"] = {
            "window_seconds": 10,
            "threshold": int(thr),
            "ignore_broadcast_source": True,
        }
        c.detectors["karma"] = {
            "window_seconds": 60,
            "min_ssids_per_bssid": 5,
        }
        m = _score_detector(c, alert_type="deauth_flood", positive_labels=("deauth",))
        row = {"threshold": thr, **m}
        deauth_rows.append(row)
        if m["fpr"] <= max_fpr:
            if best_deauth is None or (m["f1"], m["recall"]) > (
                best_deauth["f1"],
                best_deauth["recall"],
            ):
                best_deauth = row

    if best_deauth is None and deauth_rows:
        # Fall back to lowest FPR then best F1
        best_deauth = min(deauth_rows, key=lambda r: (r["fpr"], -r["f1"]))

    karma_rows = []
    best_karma = None
    for mn in karma_candidates:
        c = _base_cfg(cfg)
        c.detectors["deauth"] = {
            "window_seconds": 10,
            "threshold": int(best_deauth["threshold"]) if best_deauth else 20,
            "ignore_broadcast_source": True,
        }
        c.detectors["karma"] = {
            "window_seconds": 60,
            "min_ssids_per_bssid": int(mn),
        }
        m = _score_detector(c, alert_type="karma", positive_labels=("karma",))
        row = {"min_ssids_per_bssid": mn, **m}
        karma_rows.append(row)
        if m["fpr"] <= max_fpr:
            if best_karma is None or (m["f1"], m["recall"]) > (
                best_karma["f1"],
                best_karma["recall"],
            ):
                best_karma = row

    if best_karma is None and karma_rows:
        best_karma = min(karma_rows, key=lambda r: (r["fpr"], -r["f1"]))

    recommended = {
        "detectors": {
            "deauth": {
                "window_seconds": 10,
                "threshold": int(best_deauth["threshold"]) if best_deauth else 20,
                "ignore_broadcast_source": True,
            },
            "karma": {
                "window_seconds": 60,
                "min_ssids_per_bssid": int(best_karma["min_ssids_per_bssid"])
                if best_karma
                else 5,
            },
        },
        "constraint": {"max_fpr": max_fpr},
    }

    return {
        "max_fpr": max_fpr,
        "deauth_sweep": deauth_rows,
        "karma_sweep": karma_rows,
        "recommended_deauth": best_deauth,
        "recommended_karma": best_karma,
        "recommended_config": recommended,
    }


def recommended_yaml(result: Dict[str, Any]) -> str:
    """Render a YAML snippet operators can paste into wids.yaml."""
    d = result.get("recommended_config", {}).get("detectors", {})
    deauth = d.get("deauth") or {}
    karma = d.get("karma") or {}
    return (
        "# Autotuned thresholds (lab/synthetic eval)\n"
        "detectors:\n"
        "  deauth:\n"
        f"    window_seconds: {deauth.get('window_seconds', 10)}\n"
        f"    threshold: {deauth.get('threshold', 20)}\n"
        "    ignore_broadcast_source: true\n"
        "  karma:\n"
        f"    window_seconds: {karma.get('window_seconds', 60)}\n"
        f"    min_ssids_per_bssid: {karma.get('min_ssids_per_bssid', 5)}\n"
    )
