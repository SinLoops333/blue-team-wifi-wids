"""Alert types for the WIDS."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    alert_type: str
    severity: AlertSeverity
    title: str
    evidence: str
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    channel: Optional[int] = None
    source_mac: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    id: Optional[int] = None

    def dedup_key(self) -> str:
        return "|".join(
            [
                self.alert_type,
                self.bssid or "",
                self.ssid or "",
                self.source_mac or "",
                self.title,
            ]
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = (
            self.severity.value
            if isinstance(self.severity, AlertSeverity)
            else str(self.severity)
        )
        return d


class AlertDeduper:
    """Suppress identical alerts within a time window."""

    def __init__(self, dedup_seconds: float = 60.0):
        self.dedup_seconds = dedup_seconds
        self._last: Dict[str, float] = {}

    def should_emit(self, alert: Alert) -> bool:
        key = alert.dedup_key()
        last = self._last.get(key)
        if last is not None and (alert.timestamp - last) < self.dedup_seconds:
            return False
        self._last[key] = alert.timestamp
        cutoff = alert.timestamp - self.dedup_seconds * 2
        stale = [k for k, t in self._last.items() if t < cutoff]
        for k in stale:
            del self._last[k]
        return True
