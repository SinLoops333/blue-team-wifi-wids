"""Alert suppressions and severity scoring."""

from __future__ import annotations

from typing import Optional, Set

from .alert import Alert, AlertSeverity


# Default relative severity ranks (higher = worse)
SEVERITY_RANK = {
    AlertSeverity.LOW: 1,
    AlertSeverity.MEDIUM: 2,
    AlertSeverity.HIGH: 3,
    AlertSeverity.CRITICAL: 4,
}

DEFAULT_TYPE_SEVERITY = {
    "anomaly": AlertSeverity.MEDIUM,
    "deauth_flood": AlertSeverity.HIGH,
    "karma": AlertSeverity.HIGH,
    "pmkid_harvest": AlertSeverity.HIGH,
    "handshake_harvest": AlertSeverity.HIGH,
    "beacon_tsf_anomaly": AlertSeverity.HIGH,
    "evil_twin": AlertSeverity.CRITICAL,
    "encryption_downgrade": AlertSeverity.CRITICAL,
    "beacon_fingerprint_mismatch": AlertSeverity.CRITICAL,
    "radio_fingerprint_disagreement": AlertSeverity.CRITICAL,
    "radio_ssid_split_view": AlertSeverity.CRITICAL,
    "radio_channel_conflict": AlertSeverity.HIGH,
}


class AlertPolicy:
    """Apply suppressions and optional severity overrides from config."""

    def __init__(
        self,
        suppress_bssids: Optional[Set[str]] = None,
        suppress_ssids: Optional[Set[str]] = None,
        suppress_types: Optional[Set[str]] = None,
        severity_overrides: Optional[dict] = None,
    ):
        self.suppress_bssids = {b.lower() for b in (suppress_bssids or set())}
        self.suppress_ssids = set(suppress_ssids or set())
        self.suppress_types = set(suppress_types or set())
        self.severity_overrides = severity_overrides or {}

    @classmethod
    def from_config(cls, alerts_cfg: dict) -> "AlertPolicy":
        return cls(
            suppress_bssids=set(alerts_cfg.get("suppress_bssids") or []),
            suppress_ssids=set(alerts_cfg.get("suppress_ssids") or []),
            suppress_types=set(alerts_cfg.get("suppress_types") or []),
            severity_overrides=dict(alerts_cfg.get("severity_overrides") or {}),
        )

    def is_suppressed(self, alert: Alert) -> bool:
        if alert.alert_type in self.suppress_types:
            return True
        if alert.bssid and alert.bssid.lower() in self.suppress_bssids:
            return True
        if alert.ssid and alert.ssid in self.suppress_ssids:
            return True
        return False

    def apply_severity(self, alert: Alert) -> Alert:
        override = self.severity_overrides.get(alert.alert_type)
        if override:
            try:
                alert.severity = AlertSeverity(str(override).lower())
            except ValueError:
                pass
        elif alert.alert_type in DEFAULT_TYPE_SEVERITY:
            # Keep explicit constructor severity if already higher
            default = DEFAULT_TYPE_SEVERITY[alert.alert_type]
            if SEVERITY_RANK.get(alert.severity, 0) < SEVERITY_RANK.get(default, 0):
                alert.severity = default
        # Numeric score for SOC sorting / dashboards
        alert.metadata = dict(alert.metadata or {})
        alert.metadata["severity_score"] = SEVERITY_RANK.get(alert.severity, 0)
        return alert

    def filter(self, alert: Alert) -> Optional[Alert]:
        if self.is_suppressed(alert):
            return None
        return self.apply_severity(alert)
