"""Tests for concept-drift / continual baseline."""

from __future__ import annotations

import time

import numpy as np

from src.config import PROJECT_ROOT, Config
from src.detect.drift import (
    DriftMonitor,
    evaluate_drift_detection,
    mean_shift_l2,
    population_stability_index,
)
from src.detect.frame_features import WindowFeatures


def _cfg(**overrides):
    cfg = Config(yaml_path=PROJECT_ROOT / "config" / "wids.example.yaml")
    cfg.drift = {
        "enabled": True,
        "reference_windows": 20,
        "recent_windows": 15,
        "min_recent": 10,
        "psi_threshold": 0.2,
        "mean_shift_threshold": 2.0,
        "adapt": True,
        "adapt_fraction": 0.3,
        "alert_cooldown_seconds": 0,
    }
    cfg.drift.update(overrides)
    return cfg


def _quiet_window(bssid: str = "00:13:37:a9:43:43", deauth: int = 0) -> WindowFeatures:
    return WindowFeatures(
        bssid=bssid,
        window_start=0,
        window_end=1,
        beacon_count=10,
        probe_req_count=1,
        probe_resp_count=2,
        deauth_count=deauth,
        disassoc_count=0,
        auth_count=0,
        assoc_count=0,
        eapol_count=0,
        pmkid_count=0,
        unique_ssids=1,
        unique_clients=1,
        avg_rssi=-50.0,
        ssids=["Open999"],
        encryption="WPA2/WPA3",
        channel=11,
    )


def test_psi_detects_shift():
    out = evaluate_drift_detection()
    assert out["detects_shift"] is True
    assert out["psi_shifted_distribution"] > out["psi_same_distribution"]


def test_drift_monitor_alerts_and_adapts():
    mon = DriftMonitor(_cfg())
    n = len(WindowFeatures.FEATURE_NAMES)
    rng = np.random.default_rng(2)
    ref = rng.normal(loc=5, scale=1, size=(25, n)).tolist()
    mon.seed_reference(ref)
    assert mon._locked

    # Shift quiet features (not filtered as attack bursts)
    now = time.time()
    shifted = []
    for i in range(15):
        w = _quiet_window()
        w.beacon_count = 80
        w.probe_resp_count = 60
        w.unique_clients = 40
        w.avg_rssi = -10.0
        w.unique_ssids = 15
        w.window_end = now + i
        shifted.append(w)

    alerts = mon.observe_windows(shifted, now=now + 20)
    assert any(a.alert_type == "baseline_concept_drift" for a in alerts)
    assert alerts[0].metadata.get("adapted") is True


def test_mean_shift_l2():
    a = np.zeros((10, 3))
    b = np.ones((10, 3)) * 5
    assert mean_shift_l2(a, b) > 1.0


def test_psi_same_lower_than_shifted():
    out = evaluate_drift_detection()
    assert out["psi_same_distribution"] < out["psi_shifted_distribution"]
