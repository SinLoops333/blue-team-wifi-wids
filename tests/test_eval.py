"""Tests for evaluation metrics and harness."""

from __future__ import annotations

from src.config import Config
from src.eval.dataset import build_scenarios
from src.eval.metrics import BinaryScores, scores_for_label
from src.eval.runner import evaluate_isolation_forest, evaluate_signatures, run_full_eval


def test_binary_scores_f1():
    s = scores_for_label([1, 1, 0, 0], [1, 0, 1, 0])
    assert s.tp == 1 and s.fn == 1 and s.fp == 1 and s.tn == 1
    assert 0 < s.f1 < 1


def test_scenarios_include_benign_and_attacks():
    sc = build_scenarios()
    labels = {s.label for s in sc}
    assert "benign" in labels
    assert "evil_twin" in labels
    assert "deauth" in labels


def test_signature_eval_passes(config):
    # Production-like deauth threshold; fixtures lower it — override for this test
    config.detectors["deauth"] = {
        "window_seconds": 10,
        "threshold": 20,
        "ignore_broadcast_source": True,
    }
    config.detectors["karma"] = {
        "window_seconds": 60,
        "min_ssids_per_bssid": 5,
    }
    result = evaluate_signatures(config)
    assert result["scenario_pass_rate"] == 1.0
    for name, m in result["per_alert_type"].items():
        if m["support_positive"] > 0:
            assert m["recall"] == 1.0, name


def test_isolation_forest_auc():
    result = evaluate_isolation_forest()
    assert result["roc_auc"] >= 0.9


def test_full_eval_keys(config):
    config.detectors["deauth"] = {
        "window_seconds": 10,
        "threshold": 20,
        "ignore_broadcast_source": True,
    }
    out = run_full_eval(config)
    assert "signatures" in out and "isolation_forest" in out
