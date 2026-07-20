"""Tests for metrics, privacy, localization, and ONNX export helpers."""

from __future__ import annotations

import time

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap  # type: ignore

from src.config import PROJECT_ROOT, Config
from src.detect.frame_features import parse_frame
from src.detect.localization import (
    LocalizationEngine,
    SensorPose,
    estimate_distance_m,
    localize_two_sensors,
)
from src.detect.privacy import PrivacyEngine
from src.metrics import MetricsRegistry
from tests.frame_builders import make_probe_req


def test_metrics_prometheus_format():
    m = MetricsRegistry()
    m.inc_frame("beacon")
    m.inc_alert("deauth_flood")
    m.set_drift_psi(0.4)
    text = m.prometheus_text()
    assert "wids_frames_total 1" in text
    assert "wids_alerts_total 1" in text
    assert 'wids_alerts_by_type{type="deauth_flood"} 1' in text
    snap = m.snapshot()
    assert snap["drift_psi"] == 0.4


def test_privacy_exposure_owned_client():
    cfg = Config(yaml_path=PROJECT_ROOT / "config" / "wids.example.yaml")
    cfg.privacy = {
        "enabled": True,
        "owned_clients": ["aa:aa:aa:11:22:33"],
        "window_seconds": 600,
        "unique_ssid_threshold": 5,
    }
    eng = PrivacyEngine(cfg)
    now = time.time()
    alerts = []
    for i in range(6):
        ev = parse_frame(
            make_probe_req("aa:aa:aa:11:22:33", f"Net{i}"),
            timestamp=now + i,
        )
        alerts.extend(eng.process(ev))
    assert any(a.alert_type == "privacy_probe_exposure" for a in alerts)


def test_privacy_ignores_foreign_client():
    cfg = Config(yaml_path=PROJECT_ROOT / "config" / "wids.example.yaml")
    cfg.privacy = {
        "enabled": True,
        "owned_clients": ["aa:aa:aa:11:22:33"],
        "unique_ssid_threshold": 3,
        "window_seconds": 600,
    }
    eng = PrivacyEngine(cfg)
    now = time.time()
    alerts = []
    for i in range(5):
        ev = parse_frame(
            make_probe_req("de:ad:be:ef:00:99", f"Net{i}"),
            timestamp=now + i,
        )
        alerts.extend(eng.process(ev))
    assert alerts == []


def test_localize_two_sensors_closer_to_stronger():
    s1 = SensorPose("primary", 0, 0)
    s2 = SensorPose("secondary", 10, 0)
    # Stronger at primary (-40) than secondary (-70) → nearer x=0
    x, y, d1, d2 = localize_two_sensors(s1, s2, -40, -70)
    assert x < 5
    assert d1 < d2
    assert estimate_distance_m(-40) < estimate_distance_m(-70)


def _beacon_rssi(bssid: str, ssid: str, rssi: int, channel: int = 11):
    return (
        RadioTap(dBm_AntSignal=rssi)
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
        / Dot11Beacon(cap=0x0411)
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / Dot11Elt(ID="DSset", info=bytes([channel]))
    )


def test_localization_engine_alert():
    cfg = Config(yaml_path=PROJECT_ROOT / "config" / "wids.example.yaml")
    cfg.localization = {
        "enabled": True,
        "window_seconds": 30,
        "alert_cooldown_seconds": 0,
        "ref_rssi": -40,
        "path_loss_exp": 2.5,
        "sensors": [
            {"radio_id": "primary", "x": 0, "y": 0},
            {"radio_id": "secondary", "x": 10, "y": 0},
        ],
    }
    eng = LocalizationEngine(cfg)
    now = time.time()
    rogue = "de:ad:be:ef:00:01"
    a = parse_frame(
        _beacon_rssi(rogue, "Open999", -45),
        timestamp=now,
        radio_id="primary",
    )
    b = parse_frame(
        _beacon_rssi(rogue, "Open999", -55),
        timestamp=now + 0.1,
        radio_id="secondary",
    )
    assert a and b
    # Scapy RadioTap RSSI field presence varies — set explicitly for unit test
    a.rssi = -45
    b.rssi = -55
    eng.process(a)
    alerts = eng.process(b)
    assert any(x.alert_type == "rssi_lab_localization" for x in alerts)
    meta = alerts[0].metadata
    assert "x_m" in meta and "y_m" in meta
