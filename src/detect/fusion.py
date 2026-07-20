"""Multi-radio / multi-channel fusion detectors.

Compares beacon views from primary vs secondary Pineapple radios.
Disagreement (fingerprint, channel, or SSID→BSSID split) raises confidence
that something is spoofing or channel-hopping in a hostile way.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set, Tuple

from ..alerts.alert import Alert, AlertSeverity
from ..config import Config
from .frame_features import FrameEvent


@dataclass
class _Sighting:
    radio_id: str
    bssid: str
    ssid: str
    channel: Optional[int]
    fingerprint: Optional[str]
    timestamp: float


@dataclass
class RadioFusionEngine:
    """Correlate beacon observations across capture radios."""

    config: Config
    _by_bssid: Dict[str, Deque[_Sighting]] = field(default_factory=lambda: defaultdict(deque))
    _by_ssid: Dict[str, Deque[_Sighting]] = field(default_factory=lambda: defaultdict(deque))
    _alerted: Set[str] = field(default_factory=set)

    def enabled(self) -> bool:
        return bool(self.config.fusion.get("enabled", False))

    @property
    def window(self) -> float:
        return float(self.config.fusion.get("disagreement_window_seconds", 30))

    def process(self, event: FrameEvent) -> List[Alert]:
        if not self.enabled():
            return []
        if event.frame_type not in ("beacon", "probe_resp"):
            return []
        if not event.bssid or not event.ssid:
            return []
        radio = (event.radio_id or "primary").lower()
        sight = _Sighting(
            radio_id=radio,
            bssid=event.bssid.lower(),
            ssid=event.ssid,
            channel=event.channel,
            fingerprint=event.ie_fingerprint,
            timestamp=event.timestamp,
        )
        self._by_bssid[sight.bssid].append(sight)
        self._by_ssid[sight.ssid].append(sight)
        self._expire(event.timestamp)

        alerts: List[Alert] = []
        alerts.extend(self._check_fingerprint_disagreement(sight, event))
        alerts.extend(self._check_channel_conflict(sight, event))
        alerts.extend(self._check_ssid_split(sight, event))
        return alerts

    def _expire(self, now: float) -> None:
        cutoff = now - self.window
        for store in (self._by_bssid, self._by_ssid):
            for key, buf in list(store.items()):
                while buf and buf[0].timestamp < cutoff:
                    buf.popleft()
                if not buf:
                    del store[key]
        # Drop stale alert keys periodically
        if len(self._alerted) > 500:
            self._alerted.clear()

    def _once(self, key: str) -> bool:
        if key in self._alerted:
            return False
        self._alerted.add(key)
        return True

    def _check_fingerprint_disagreement(
        self, sight: _Sighting, event: FrameEvent
    ) -> List[Alert]:
        if not sight.fingerprint:
            return []
        others = [
            s
            for s in self._by_bssid.get(sight.bssid, ())
            if s.radio_id != sight.radio_id
            and s.fingerprint
            and s.fingerprint != sight.fingerprint
        ]
        if not others:
            return []
        other = others[-1]
        key = f"fp|{sight.bssid}|{sight.fingerprint}|{other.fingerprint}"
        if not self._once(key):
            return []
        return [
            Alert(
                alert_type="radio_fingerprint_disagreement",
                severity=AlertSeverity.CRITICAL,
                title="Multi-radio IE fingerprint disagreement",
                evidence=(
                    f"BSSID {sight.bssid} SSID '{sight.ssid}': "
                    f"radio '{sight.radio_id}' fp={sight.fingerprint} vs "
                    f"radio '{other.radio_id}' fp={other.fingerprint} "
                    f"within {self.window:.0f}s"
                ),
                bssid=sight.bssid,
                ssid=sight.ssid,
                channel=sight.channel,
                timestamp=event.timestamp,
                metadata={
                    "radio_a": sight.radio_id,
                    "radio_b": other.radio_id,
                    "fp_a": sight.fingerprint,
                    "fp_b": other.fingerprint,
                },
            )
        ]

    def _check_channel_conflict(
        self, sight: _Sighting, event: FrameEvent
    ) -> List[Alert]:
        if sight.channel is None:
            return []
        others = [
            s
            for s in self._by_bssid.get(sight.bssid, ())
            if s.radio_id != sight.radio_id
            and s.channel is not None
            and s.channel != sight.channel
        ]
        if not others:
            return []
        other = others[-1]
        key = f"ch|{sight.bssid}|{sight.channel}|{other.channel}"
        if not self._once(key):
            return []
        return [
            Alert(
                alert_type="radio_channel_conflict",
                severity=AlertSeverity.HIGH,
                title="Multi-radio channel conflict",
                evidence=(
                    f"BSSID {sight.bssid} seen on ch{sight.channel} "
                    f"({sight.radio_id}) and ch{other.channel} ({other.radio_id})"
                ),
                bssid=sight.bssid,
                ssid=sight.ssid,
                channel=sight.channel,
                timestamp=event.timestamp,
                metadata={
                    "channel_a": sight.channel,
                    "channel_b": other.channel,
                    "radio_a": sight.radio_id,
                    "radio_b": other.radio_id,
                },
            )
        ]

    def _check_ssid_split(self, sight: _Sighting, event: FrameEvent) -> List[Alert]:
        """Same SSID, different BSSIDs, each primarily on a different radio."""
        if self.config.is_allowlisted_bssid(sight.bssid):
            # Still useful, but skip if the *other* BSSID is also owned
            pass
        peers = [
            s
            for s in self._by_ssid.get(sight.ssid, ())
            if s.bssid != sight.bssid and s.radio_id != sight.radio_id
        ]
        if not peers:
            return []
        other = peers[-1]
        if self.config.is_allowlisted_bssid(sight.bssid) and self.config.is_allowlisted_bssid(
            other.bssid
        ):
            return []
        key = f"split|{sight.ssid}|{sight.bssid}|{other.bssid}"
        if not self._once(key):
            return []
        return [
            Alert(
                alert_type="radio_ssid_split_view",
                severity=AlertSeverity.CRITICAL,
                title="Multi-radio SSID split view",
                evidence=(
                    f"SSID '{sight.ssid}' on BSSID {sight.bssid} ({sight.radio_id}"
                    f"/ch{sight.channel}) vs {other.bssid} ({other.radio_id}"
                    f"/ch{other.channel}) — likely evil twin across channels"
                ),
                bssid=sight.bssid,
                ssid=sight.ssid,
                channel=sight.channel,
                timestamp=event.timestamp,
                metadata={
                    "bssid_a": sight.bssid,
                    "bssid_b": other.bssid,
                    "radio_a": sight.radio_id,
                    "radio_b": other.radio_id,
                },
            )
        ]
