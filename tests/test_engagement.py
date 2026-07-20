"""Tests for engagement RoE and export helpers."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
import yaml

from src.config import Config
from src.engagement.session import (
    acknowledge_roe,
    load_engagement_config,
    start_session,
)
from src.reporting.export import export_alerts_csv, write_html_report


def test_roe_requires_yes(tmp_path):
    yml = tmp_path / "eng.yaml"
    yml.write_text(
        yaml.dump(
            {
                "engagement": {
                    "name": "T",
                    "operator": "op",
                    "authorization": "lab",
                    "report_dir": str(tmp_path / "reports"),
                    "session_file": str(tmp_path / "sess.json"),
                    "roe": ["Rule one", "Rule two"],
                    "allowed_actions": ["monitor"],
                }
            }
        ),
        encoding="utf-8",
    )
    cfg = load_engagement_config(yml)
    with pytest.raises(RuntimeError):
        acknowledge_roe(
            cfg,
            assume_yes=False,
            stdin=io.StringIO("YES\nno\n"),
            stdout=io.StringIO(),
        )
    ack = acknowledge_roe(
        cfg,
        assume_yes=False,
        stdin=io.StringIO("YES\nYES\n"),
        stdout=io.StringIO(),
    )
    assert len(ack) == 2


def test_start_session_yes(tmp_path):
    yml = tmp_path / "eng.yaml"
    sess = tmp_path / "sess.json"
    yml.write_text(
        yaml.dump(
            {
                "engagement": {
                    "name": "T",
                    "operator": "op",
                    "authorization": "lab",
                    "report_dir": str(tmp_path / "reports"),
                    "session_file": str(sess),
                    "roe": ["Only owned gear"],
                    "allowed_actions": ["monitor"],
                }
            }
        ),
        encoding="utf-8",
    )
    cfg = load_engagement_config(yml)
    session = start_session(cfg, assume_yes=True)
    assert session.active
    assert sess.exists()


def test_export_helpers(tmp_path):
    alerts = [
        {
            "id": 1,
            "timestamp": 1.0,
            "alert_type": "deauth_flood",
            "severity": "high",
            "title": "t",
            "evidence": "e",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "X",
            "channel": 11,
            "source_mac": "aa:bb:cc:dd:ee:ff",
        }
    ]
    csv_path = export_alerts_csv(alerts, tmp_path / "a.csv")
    assert csv_path.exists()
    html = write_html_report(
        tmp_path / "r.html",
        title="Test",
        engagement={"name": "T"},
        alerts=alerts,
        audit=[{"timestamp": 1, "event": "deauth"}],
        inventory=[],
    )
    assert "deauth_flood" in html.read_text(encoding="utf-8")
