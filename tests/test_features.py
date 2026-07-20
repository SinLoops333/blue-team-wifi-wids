"""Tests for frame parsing and feature extraction."""

from __future__ import annotations

import time

from src.detect.frame_features import FeatureExtractor, parse_frame
from tests.frame_builders import make_beacon, make_deauth, make_eapol_m1_pmkid


def test_parse_beacon_ssid_and_encryption():
    pkt = make_beacon("28:ee:52:01:f4:ab", "HomeLab", channel=6)
    ev = parse_frame(pkt, timestamp=time.time())
    assert ev is not None
    assert ev.frame_type == "beacon"
    assert ev.ssid == "HomeLab"
    assert ev.bssid == "28:ee:52:01:f4:ab"
    assert ev.channel == 6
    assert ev.encryption in ("WPA2/WPA3", "WEP/PRIVACY")


def test_parse_open_beacon():
    pkt = make_beacon("aa:bb:cc:dd:ee:ff", "OpenCafe", open_network=True)
    ev = parse_frame(pkt)
    assert ev is not None
    assert ev.encryption == "OPEN"


def test_parse_deauth():
    pkt = make_deauth("28:ee:52:01:f4:ab", client="11:22:33:44:55:66")
    ev = parse_frame(pkt)
    assert ev is not None
    assert ev.frame_type == "deauth"
    assert ev.addr1 == "11:22:33:44:55:66"


def test_parse_pmkid_flag():
    pkt = make_eapol_m1_pmkid("28:ee:52:01:f4:ab")
    ev = parse_frame(pkt)
    assert ev is not None
    assert ev.is_eapol
    assert ev.has_pmkid is True


def test_feature_extractor_window():
    ext = FeatureExtractor(window_seconds=30)
    now = time.time()
    for i in range(3):
        pkt = make_beacon("28:ee:52:01:f4:ab", "HomeLab")
        ev = parse_frame(pkt, timestamp=now + i * 0.1)
        assert ev
        ext.ingest(ev)
    for i in range(2):
        pkt = make_deauth("28:ee:52:01:f4:ab")
        ev = parse_frame(pkt, timestamp=now + 1 + i * 0.1)
        assert ev
        ext.ingest(ev)

    windows = ext.window_features(now=now + 2)
    assert len(windows) >= 1
    w = next(x for x in windows if x.bssid == "28:ee:52:01:f4:ab")
    assert w.beacon_count == 3
    assert w.deauth_count == 2
    assert "HomeLab" in w.ssids
    assert len(w.as_vector()) == len(w.FEATURE_NAMES)
    assert "28:ee:52:01:f4:ab" in ext.ap_inventory
