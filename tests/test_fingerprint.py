"""Tests for beacon IE fingerprint + TSF clone detection."""

from __future__ import annotations

import time

from src.detect.frame_features import FeatureExtractor, parse_frame
from src.detect.fingerprint import FingerprintBaseline, TsfTracker, extract_beacon_identity
from src.detect.signatures import SignatureEngine
from tests.frame_builders import make_beacon


def _ingest(engine, extractor, pkt, ts):
    ev = parse_frame(pkt, timestamp=ts)
    assert ev is not None
    extractor.ingest(ev)
    return engine.process(ev, extractor)


def test_extract_fingerprint_changes_with_vendor_ie():
    a = make_beacon("28:ee:52:01:f4:ab", "HomeLab")
    b = make_beacon(
        "28:ee:52:01:f4:ab",
        "HomeLab",
        extra_vendor_oui=b"\x00\x13\x37",
    )
    ia = extract_beacon_identity(a)
    ib = extract_beacon_identity(b)
    assert ia is not None and ib is not None
    assert ia.fingerprint != ib.fingerprint
    assert 221 in ib.ie_ids


def test_fingerprint_baseline_locks_then_alerts():
    fp = FingerprintBaseline(stabilize_count=3)
    assert fp.observe("aaa") is None
    assert fp.observe("aaa") is None
    assert fp.observe("aaa") is None
    assert fp.locked
    reason = fp.observe("bbb")
    assert reason is not None and "aaa" in reason and "bbb" in reason


def test_tsf_backward_jump():
    t = TsfTracker(min_samples=2, max_backward_us=1_000_000)
    assert t.observe(1.0, 5_000_000) is None
    assert t.observe(2.0, 6_000_000) is None
    reason = t.observe(3.0, 1000)
    assert reason is not None and "backward" in reason


def test_signature_beacon_fingerprint_mismatch(config):
    engine = SignatureEngine(config)
    ext = FeatureExtractor(window_seconds=30)
    now = time.time()
    bssid = "28:ee:52:01:f4:ab"
    ssid = "HomeLab"
    alerts = []
    for i in range(4):
        alerts.extend(
            _ingest(
                engine,
                ext,
                make_beacon(bssid, ssid, tsf=10_000 * (i + 1)),
                now + i * 1.0,
            )
        )
    assert not any(a.alert_type == "beacon_fingerprint_mismatch" for a in alerts)

    clone = _ingest(
        engine,
        ext,
        make_beacon(bssid, ssid, tsf=50_000, extra_vendor_oui=b"\x00\x13\x37"),
        now + 5.0,
    )
    assert any(a.alert_type == "beacon_fingerprint_mismatch" for a in clone)


def test_signature_beacon_tsf_anomaly(config):
    engine = SignatureEngine(config)
    ext = FeatureExtractor(window_seconds=30)
    now = time.time()
    bssid = "28:ee:52:01:f4:ab"
    ssid = "HomeLab"
    for i in range(5):
        _ingest(
            engine,
            ext,
            make_beacon(bssid, ssid, tsf=1_000_000 * (i + 1)),
            now + i * 1.0,
        )
    alerts = _ingest(
        engine,
        ext,
        make_beacon(bssid, ssid, tsf=500),
        now + 6.0,
    )
    assert any(a.alert_type == "beacon_tsf_anomaly" for a in alerts)
