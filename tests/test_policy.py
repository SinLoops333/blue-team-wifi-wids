"""Tests for alert suppressions and severity scoring."""

from __future__ import annotations

from src.alerts.alert import Alert, AlertSeverity
from src.alerts.policy import AlertPolicy


def test_suppress_bssid():
    policy = AlertPolicy(suppress_bssids={"aa:bb:cc:dd:ee:ff"})
    alert = Alert(
        alert_type="deauth_flood",
        severity=AlertSeverity.HIGH,
        title="Deauth",
        evidence="x",
        bssid="AA:BB:CC:DD:EE:FF",
    )
    assert policy.filter(alert) is None


def test_severity_score_applied():
    policy = AlertPolicy()
    alert = Alert(
        alert_type="evil_twin",
        severity=AlertSeverity.LOW,
        title="Evil twin",
        evidence="x",
        bssid="11:22:33:44:55:66",
    )
    out = policy.filter(alert)
    assert out is not None
    assert out.severity == AlertSeverity.CRITICAL
    assert out.metadata["severity_score"] == 4


def test_severity_override():
    policy = AlertPolicy(severity_overrides={"anomaly": "low"})
    alert = Alert(
        alert_type="anomaly",
        severity=AlertSeverity.MEDIUM,
        title="Anomaly",
        evidence="x",
    )
    out = policy.filter(alert)
    assert out is not None
    assert out.severity == AlertSeverity.LOW
