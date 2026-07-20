"""Owned-device probe privacy / exposure scoring.

Scores how much SSID history *your* stations leak via probe requests.
Not for tracking third parties — only MACs listed under privacy.owned_clients
(or allowlisted client MACs).
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set

from ..alerts.alert import Alert, AlertSeverity
from ..config import Config
from .frame_features import FrameEvent


@dataclass
class PrivacyEngine:
    config: Config
    _probes: Dict[str, Deque[tuple]] = field(
        default_factory=lambda: defaultdict(deque)
    )  # client -> (ts, ssid)
    _alerted: Set[str] = field(default_factory=set)

    def enabled(self) -> bool:
        return bool(self.config.privacy.get("enabled", False))

    def owned_clients(self) -> Set[str]:
        raw = self.config.privacy.get("owned_clients") or []
        return {c.lower() for c in raw if c}

    @property
    def window(self) -> float:
        return float(self.config.privacy.get("window_seconds", 600))

    @property
    def unique_ssid_threshold(self) -> int:
        return int(self.config.privacy.get("unique_ssid_threshold", 8))

    def process(self, event: FrameEvent) -> List[Alert]:
        if not self.enabled():
            return []
        if event.frame_type != "probe_req":
            return []
        client = (event.addr2 or "").lower()
        if not client:
            return []
        owned = self.owned_clients()
        if owned and client not in owned:
            return []
        # If no owned_clients list, only score when privacy.score_all_unicast is set
        if not owned and not bool(self.config.privacy.get("score_all_unicast", False)):
            return []
        try:
            if (int(client.split(":")[0], 16) & 1) == 1:
                return []
        except (ValueError, IndexError):
            return []

        ssid = event.ssid or ""
        buf = self._probes[client]
        buf.append((event.timestamp, ssid))
        cutoff = event.timestamp - self.window
        while buf and buf[0][0] < cutoff:
            buf.popleft()

        ssids = {s for _, s in buf if s}
        # Exposure score: unique SSIDs (simple, explainable)
        score = len(ssids)
        if score < self.unique_ssid_threshold:
            return []
        key = f"{client}|{score // 5}"  # bucket to reduce spam
        if key in self._alerted:
            return []
        self._alerted.add(key)
        sample = sorted(ssids)[:10]
        return [
            Alert(
                alert_type="privacy_probe_exposure",
                severity=AlertSeverity.LOW,
                title="Owned device probe privacy exposure",
                evidence=(
                    f"STA {client} probed {score} distinct SSIDs in "
                    f"{self.window:.0f}s (threshold {self.unique_ssid_threshold}); "
                    f"sample={sample}"
                ),
                source_mac=client,
                ssid=event.ssid,
                channel=event.channel,
                timestamp=event.timestamp,
                metadata={
                    "unique_ssids": score,
                    "sample_ssids": sample,
                    "exposure_score": score,
                },
            )
        ]
