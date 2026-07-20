"""Phase 2 lab scope and confirmation tests."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
import yaml

from src.config import Config
from src.lab.confirm import require_confirm
from src.lab.scope import LabScope, ScopeError, load_lab_config


@pytest.fixture
def wids_cfg(tmp_path):
    yml = tmp_path / "wids.yaml"
    yml.write_text(
        """
allowlist:
  bssids:
    - "00:13:37:a9:43:43"
    - "00:13:37:be:ef:00"
  ssids:
    - "Open999"
    - "PineAP_WPA"
capture:
  interface: wlan1
detectors: {}
anomaly: {}
dashboard: {}
store: {}
alerts: {}
""",
        encoding="utf-8",
    )
    env = tmp_path / ".env"
    env.write_text("PINEAPPLE_PASSWORD=test\n", encoding="utf-8")
    return Config(yaml_path=yml, env_path=env)


def _lab_yaml(tmp_path, targets):
    path = tmp_path / "lab.yaml"
    data = {
        "lab": {
            "enabled": True,
            "require_confirm": True,
            "inject_interface": "wlan1",
            "audit_log": str(tmp_path / "audit.jsonl"),
            "targets": targets,
            "deauth": {"count": 10},
            "simulate": {"output_pcap": str(tmp_path / "sim.pcap")},
        }
    }
    path.write_text(yaml.dump(data), encoding="utf-8")
    return path


def test_scope_accepts_allowlisted_target(tmp_path, wids_cfg):
    path = _lab_yaml(
        tmp_path,
        [{"bssid": "00:13:37:a9:43:43", "ssid": "Open999"}],
    )
    lab_cfg, _ = load_lab_config(path, wids_cfg)
    scope = LabScope(lab_cfg, wids_cfg)
    t = scope.assert_attack_bssid("00:13:37:A9:43:43")
    assert t.bssid == "00:13:37:a9:43:43"


def test_scope_rejects_foreign_bssid(tmp_path, wids_cfg):
    path = _lab_yaml(
        tmp_path,
        [{"bssid": "00:13:37:a9:43:43", "ssid": "Open999"}],
    )
    lab_cfg, _ = load_lab_config(path, wids_cfg)
    scope = LabScope(lab_cfg, wids_cfg)
    with pytest.raises(ScopeError, match="not in the WIDS allowlist"):
        scope.assert_attack_bssid("11:22:33:44:55:66")


def test_scope_rejects_allowlisted_but_not_lab_target(tmp_path, wids_cfg):
    path = _lab_yaml(
        tmp_path,
        [{"bssid": "00:13:37:a9:43:43", "ssid": "Open999"}],
    )
    lab_cfg, _ = load_lab_config(path, wids_cfg)
    scope = LabScope(lab_cfg, wids_cfg)
    # be:ef:00 is allowlisted in wids but not a lab target
    with pytest.raises(ScopeError, match="not a configured lab target"):
        scope.assert_attack_bssid("00:13:37:be:ef:00")


def test_config_rejects_target_missing_from_allowlist(tmp_path, wids_cfg):
    path = _lab_yaml(
        tmp_path,
        [{"bssid": "ff:ee:dd:cc:bb:aa", "ssid": "Evil"}],
    )
    lab_cfg, _ = load_lab_config(path, wids_cfg)
    with pytest.raises(ScopeError, match="NOT in wids.yaml allowlist"):
        LabScope(lab_cfg, wids_cfg)


def test_confirm_requires_exact_word():
    assert require_confirm("test", require=True, assume_yes=False,
                           stdin=io.StringIO("CONFIRM\n"),
                           stdout=io.StringIO()) is True
    assert require_confirm("test", require=True, assume_yes=False,
                           stdin=io.StringIO("confirm\n"),
                           stdout=io.StringIO()) is False
    assert require_confirm("test", require=True, assume_yes=False,
                           stdin=io.StringIO("yes\n"),
                           stdout=io.StringIO()) is False


def test_simulate_evil_twin_writes_pcap(tmp_path, wids_cfg):
    path = _lab_yaml(
        tmp_path,
        [{"bssid": "00:13:37:a9:43:43", "ssid": "Open999"}],
    )
    lab_cfg, _ = load_lab_config(path, wids_cfg)
    scope = LabScope(lab_cfg, wids_cfg)
    from src.lab.attacks.simulate import write_simulation

    out = write_simulation(scope, "evil_twin", path=tmp_path / "et.pcap")
    assert out.exists()
    assert out.stat().st_size > 0
