"""Tests for rule-based signature detectors."""

from __future__ import annotations

import time

from src.detect.frame_features import FeatureExtractor, parse_frame
from src.detect.signatures import SignatureEngine
from tests.frame_builders import (
    make_beacon,
    make_deauth,
    make_eapol_m1,
    make_eapol_m1_pmkid,
    make_probe_resp,
)


def _ingest(engine, extractor, pkt, ts):
    ev = parse_frame(pkt, timestamp=ts)
    assert ev is not None
    extractor.ingest(ev)
    return engine.process(ev, extractor)


def test_deauth_flood(config):
    engine = SignatureEngine(config)
    ext = FeatureExtractor(window_seconds=30)
    now = time.time()
    bssid = "28:ee:52:01:f4:ab"
    alerts = []
    for i in range(5):
        alerts.extend(_ingest(engine, ext, make_deauth(bssid), now + i * 0.05))
    types = [a.alert_type for a in alerts]
    assert "deauth_flood" in types


def test_evil_twin_new_bssid(config):
    engine = SignatureEngine(config)
    ext = FeatureExtractor(window_seconds=30)
    now = time.time()
    # Seed known-good AP
    engine.load_baseline_inventory(
        {
            "28:ee:52:01:f4:ab": {
                "ssid": "Office_WiFi",
                "channel": 6,
                "encryption": "WPA2/WPA3",
            }
        }
    )
    # Legitimate beacon first (same BSSID) — should not alert
    a1 = _ingest(
        engine,
        ext,
        make_beacon("28:ee:52:01:f4:ab", "Office_WiFi"),
        now,
    )
    assert not any(a.alert_type == "evil_twin" for a in a1)

    # Evil twin: same SSID, different BSSID
    a2 = _ingest(
        engine,
        ext,
        make_beacon("de:ad:be:ef:00:01", "Office_WiFi", open_network=True),
        now + 1,
    )
    assert any(a.alert_type == "evil_twin" for a in a2)


def test_encryption_downgrade(config):
    engine = SignatureEngine(config)
    ext = FeatureExtractor(window_seconds=30)
    now = time.time()
    engine.load_baseline_inventory(
        {
            "28:ee:52:01:f4:ab": {
                "ssid": "HomeLab",
                "channel": 6,
                "encryption": "WPA2/WPA3",
            }
        }
    )
    alerts = _ingest(
        engine,
        ext,
        make_beacon("28:ee:52:01:f4:ab", "HomeLab", open_network=True),
        now,
    )
    assert any(a.alert_type == "encryption_downgrade" for a in alerts)


def test_karma_multi_ssid(config):
    engine = SignatureEngine(config)
    ext = FeatureExtractor(window_seconds=60)
    now = time.time()
    attacker = "aa:bb:cc:11:22:33"
    alerts = []
    for i, ssid in enumerate(["NetA", "NetB", "NetC"]):
        alerts.extend(
            _ingest(
                engine,
                ext,
                make_probe_resp(attacker, ssid),
                now + i,
            )
        )
    assert any(a.alert_type == "karma" for a in alerts)


def test_pmkid_harvest(config):
    engine = SignatureEngine(config)
    ext = FeatureExtractor(window_seconds=30)
    now = time.time()
    alerts = _ingest(
        engine,
        ext,
        make_eapol_m1_pmkid("28:ee:52:01:f4:ab"),
        now,
    )
    assert any(a.alert_type == "pmkid_harvest" for a in alerts)


def test_handshake_harvest_after_deauth(config):
    engine = SignatureEngine(config)
    ext = FeatureExtractor(window_seconds=30)
    now = time.time()
    bssid = "28:ee:52:01:f4:ab"
    # A few deauths (below flood threshold of 5)
    for i in range(2):
        _ingest(engine, ext, make_deauth(bssid), now + i * 0.1)
    alerts = _ingest(engine, ext, make_eapol_m1(bssid), now + 1.0)
    assert any(a.alert_type == "handshake_harvest" for a in alerts)


def test_allowlisted_bssid_skips_evil_twin(config):
    config.allowlist_bssids.add("de:ad:be:ef:00:01")
    engine = SignatureEngine(config)
    ext = FeatureExtractor(window_seconds=30)
    now = time.time()
    engine.load_baseline_inventory(
        {
            "28:ee:52:01:f4:ab": {
                "ssid": "Office_WiFi",
                "channel": 6,
                "encryption": "WPA2/WPA3",
            }
        }
    )
    alerts = _ingest(
        engine,
        ext,
        make_beacon("de:ad:be:ef:00:01", "Office_WiFi"),
        now,
    )
    assert not any(a.alert_type == "evil_twin" for a in alerts)
