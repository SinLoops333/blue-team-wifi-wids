"""Pytest fixtures and path setup."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config import Config  # noqa: E402


@pytest.fixture
def config(tmp_path, monkeypatch):
    """Config backed by the example yaml with temp model/db paths."""
    example = ROOT / "config" / "wids.example.yaml"
    cfg = Config(yaml_path=example, env_path=ROOT / ".env.example")
    # Point mutable paths at tmp
    cfg.anomaly = dict(cfg.anomaly)
    cfg.anomaly["model_path"] = str(tmp_path / "baseline.pkl")
    cfg.anomaly["inventory_path"] = str(tmp_path / "ap_inventory.json")
    cfg.store = dict(cfg.store)
    cfg.store["db_path"] = str(tmp_path / "events.db")
    # Lower deauth threshold for faster tests
    cfg.detectors = dict(cfg.detectors)
    cfg.detectors["deauth"] = {"window_seconds": 10, "threshold": 5}
    cfg.detectors["karma"] = {"window_seconds": 60, "min_ssids_per_bssid": 3}
    cfg.detectors["evil_twin"] = {"enabled": True}
    cfg.detectors["pmkid"] = {"enabled": True}
    cfg.detectors["handshake_harvest"] = {"deauth_then_eapol_window": 15}
    return cfg
