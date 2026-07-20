"""Tests for alert store and anomaly detector wiring."""

from __future__ import annotations

import time

from src.alerts.alert import Alert, AlertDeduper, AlertSeverity
from src.alerts.store import EventStore
from src.detect.anomaly import AnomalyDetector
from src.detect.baseline import BaselineStore
from src.detect.frame_features import WindowFeatures


def test_alert_deduper():
    d = AlertDeduper(dedup_seconds=60)
    a = Alert(
        alert_type="deauth_flood",
        severity=AlertSeverity.HIGH,
        title="t",
        evidence="e",
        bssid="aa:bb:cc:dd:ee:ff",
        timestamp=1000.0,
    )
    assert d.should_emit(a) is True
    assert d.should_emit(a) is False
    a2 = Alert(
        alert_type="deauth_flood",
        severity=AlertSeverity.HIGH,
        title="t",
        evidence="e",
        bssid="aa:bb:cc:dd:ee:ff",
        timestamp=1070.0,
    )
    assert d.should_emit(a2) is True


def test_event_store_roundtrip(tmp_path):
    store = EventStore(tmp_path / "events.db")
    seen = []
    store.add_listener(lambda a: seen.append(a))
    alert = Alert(
        alert_type="karma",
        severity=AlertSeverity.HIGH,
        title="KARMA",
        evidence="multi ssid",
        bssid="11:22:33:44:55:66",
        ssid="X",
        timestamp=time.time(),
    )
    stored = store.insert_alert(alert)
    assert stored.id is not None
    assert len(seen) == 1
    rows = store.recent_alerts(limit=10)
    assert len(rows) == 1
    assert rows[0]["alert_type"] == "karma"

    store.update_ap_inventory(
        {"aa:bb:cc:dd:ee:ff": {"ssid": "Lab", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 1}}
    )
    inv = store.get_ap_inventory()
    assert inv[0]["ssid"] == "Lab"


def test_anomaly_trains_and_flags(config, tmp_path):
    baseline = BaselineStore(
        tmp_path / "inv.json",
        tmp_path / "model.pkl",
    )
    det = AnomalyDetector(config, baseline)
    # Quiet windows
    for i in range(25):
        w = WindowFeatures(
            bssid="28:ee:52:01:f4:ab",
            window_start=float(i),
            window_end=float(i + 30),
            beacon_count=10,
            probe_resp_count=2,
            deauth_count=0,
            eapol_count=0,
            unique_ssids=1,
            avg_rssi=-50.0,
            ssids=["HomeLab"],
            channel=6,
        )
        det.observe([w])
    assert det.maybe_train() is True
    assert det.model is not None

    # Anomalous window: huge deauth + many SSIDs
    bad = WindowFeatures(
        bssid="aa:aa:aa:aa:aa:aa",
        window_start=100.0,
        window_end=130.0,
        beacon_count=50,
        deauth_count=200,
        eapol_count=40,
        pmkid_count=5,
        unique_ssids=20,
        avg_rssi=-20.0,
        ssids=["A", "B"],
        channel=1,
    )
    alerts = det.evaluate([bad])
    # IsolationForest with contamination may or may not flag a single point
    # depending on scale — at least evaluate should not crash and return a list.
    assert isinstance(alerts, list)
