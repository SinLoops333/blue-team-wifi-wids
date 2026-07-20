"""Tests for owned-honeypot client behavior detection."""

from __future__ import annotations

import time

from src.config import PROJECT_ROOT, Config
from src.detect.frame_features import parse_frame
from src.detect.honeypot import HoneypotEngine, evaluate_honeypot_model
from tests.frame_builders import make_probe_req


def _cfg():
    cfg = Config(yaml_path=PROJECT_ROOT / "config" / "wids.example.yaml")
    cfg.honeypot = {
        "enabled": True,
        "ssids": ["Open999"],
        "burst_probe_threshold": 12,
        "min_probes_for_ml": 5,
        "window_seconds": 60,
        "contamination": 0.08,
        "model_path": "models/honeypot_client_test.pkl",
    }
    cfg.allowlist_ssids = {"Open999"}
    return cfg


def test_honeypot_recon_burst():
    eng = HoneypotEngine(_cfg())
    eng.fit_default()
    now = time.time()
    client = "aa:aa:aa:11:22:33"
    alerts = []
    for i in range(15):
        ev = parse_frame(
            make_probe_req(client, "Open999", bssid="00:13:37:a9:43:43"),
            timestamp=now + i * 0.05,
        )
        assert ev is not None
        alerts.extend(eng.process(ev))
    assert any(a.alert_type == "honeypot_recon_burst" for a in alerts)


def test_benign_sparse_probes_no_burst():
    eng = HoneypotEngine(_cfg())
    now = time.time()
    client = "aa:aa:aa:44:55:66"
    alerts = []
    for i in range(3):
        ev = parse_frame(
            make_probe_req(client, "Open999"),
            timestamp=now + i * 5.0,
        )
        alerts.extend(eng.process(ev))
    assert not any(a.alert_type == "honeypot_recon_burst" for a in alerts)


def test_honeypot_model_auc():
    m = evaluate_honeypot_model()
    assert m["roc_auc"] >= 0.85
