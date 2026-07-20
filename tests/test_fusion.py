"""Tests for multi-radio fusion detectors."""

from __future__ import annotations

import time

from src.config import Config
from src.detect.frame_features import parse_frame
from src.detect.fusion import RadioFusionEngine
from tests.frame_builders import make_beacon


def _cfg_fusion(tmp_path, monkeypatch=None):
    # Build a minimal config via example + fusion on
    from src.config import PROJECT_ROOT

    cfg = Config(yaml_path=PROJECT_ROOT / "config" / "wids.example.yaml")
    cfg.fusion = {
        "enabled": True,
        "disagreement_window_seconds": 30,
    }
    return cfg


def test_ssid_split_view():
    cfg = _cfg_fusion(None)
    fusion = RadioFusionEngine(cfg)
    now = time.time()
    a = parse_frame(
        make_beacon("00:13:37:a9:43:43", "Open999", channel=11),
        timestamp=now,
        radio_id="primary",
    )
    b = parse_frame(
        make_beacon("de:ad:be:ef:00:01", "Open999", channel=6, open_network=True),
        timestamp=now + 0.1,
        radio_id="secondary",
    )
    assert a and b
    fusion.process(a)
    alerts = fusion.process(b)
    assert any(x.alert_type == "radio_ssid_split_view" for x in alerts)


def test_channel_conflict():
    cfg = _cfg_fusion(None)
    fusion = RadioFusionEngine(cfg)
    now = time.time()
    a = parse_frame(
        make_beacon("00:13:37:a9:43:43", "Open999", channel=11),
        timestamp=now,
        radio_id="primary",
    )
    b = parse_frame(
        make_beacon("00:13:37:a9:43:43", "Open999", channel=1),
        timestamp=now + 0.1,
        radio_id="secondary",
    )
    assert a and b
    fusion.process(a)
    alerts = fusion.process(b)
    assert any(x.alert_type == "radio_channel_conflict" for x in alerts)


def test_fingerprint_disagreement():
    cfg = _cfg_fusion(None)
    fusion = RadioFusionEngine(cfg)
    now = time.time()
    a = parse_frame(
        make_beacon("00:13:37:a9:43:43", "Open999", channel=11),
        timestamp=now,
        radio_id="primary",
    )
    b = parse_frame(
        make_beacon(
            "00:13:37:a9:43:43",
            "Open999",
            channel=11,
            extra_vendor_oui=b"\x00\x13\x37",
        ),
        timestamp=now + 0.1,
        radio_id="secondary",
    )
    assert a and b
    fusion.process(a)
    alerts = fusion.process(b)
    assert any(x.alert_type == "radio_fingerprint_disagreement" for x in alerts)


def test_fusion_disabled_noop():
    cfg = _cfg_fusion(None)
    cfg.fusion["enabled"] = False
    fusion = RadioFusionEngine(cfg)
    ev = parse_frame(
        make_beacon("00:13:37:a9:43:43", "Open999"),
        radio_id="primary",
    )
    assert fusion.process(ev) == []
