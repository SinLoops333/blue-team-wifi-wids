"""Two-sensor RSSI localization for lab floorplans (owned space only)."""

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple

from ..alerts.alert import Alert, AlertSeverity
from ..config import Config
from .frame_features import FrameEvent


@dataclass
class SensorPose:
    radio_id: str
    x: float
    y: float


def estimate_distance_m(
    rssi: float,
    *,
    ref_rssi: float = -40.0,
    ref_dist_m: float = 1.0,
    path_loss_exp: float = 2.5,
) -> float:
    """Log-distance path loss → meters (rough lab estimate)."""
    return float(ref_dist_m * (10 ** ((ref_rssi - rssi) / (10.0 * path_loss_exp))))


def localize_two_sensors(
    s1: SensorPose,
    s2: SensorPose,
    rssi1: float,
    rssi2: float,
    *,
    ref_rssi: float = -40.0,
    ref_dist_m: float = 1.0,
    path_loss_exp: float = 2.5,
) -> Tuple[float, float, float, float]:
    """Return (x, y, d1, d2) along the segment between sensors."""
    d1 = estimate_distance_m(
        rssi1, ref_rssi=ref_rssi, ref_dist_m=ref_dist_m, path_loss_exp=path_loss_exp
    )
    d2 = estimate_distance_m(
        rssi2, ref_rssi=ref_rssi, ref_dist_m=ref_dist_m, path_loss_exp=path_loss_exp
    )
    total = d1 + d2
    if total <= 0:
        t = 0.5
    else:
        # Stronger at s1 (small d1) → closer to s1
        t = d1 / total
    x = s1.x + t * (s2.x - s1.x)
    y = s1.y + t * (s2.y - s1.y)
    return x, y, d1, d2


@dataclass
class LocalizationEngine:
    """Fuse RSSI from primary/secondary radios for the same BSSID."""

    config: Config
    _rssi: Dict[str, Dict[str, Deque[Tuple[float, float]]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(deque))
    )  # bssid -> radio_id -> (ts, rssi)
    _last_alert: Dict[str, float] = field(default_factory=dict)

    def enabled(self) -> bool:
        return bool(self.config.localization.get("enabled", False))

    def sensors(self) -> List[SensorPose]:
        raw = self.config.localization.get("sensors") or []
        out = []
        for s in raw:
            out.append(
                SensorPose(
                    radio_id=str(s.get("radio_id", "primary")),
                    x=float(s.get("x", 0)),
                    y=float(s.get("y", 0)),
                )
            )
        if len(out) < 2:
            # Defaults: 10m apart on X axis
            return [
                SensorPose("primary", 0.0, 0.0),
                SensorPose("secondary", 10.0, 0.0),
            ]
        return out[:2]

    @property
    def window(self) -> float:
        return float(self.config.localization.get("window_seconds", 15))

    @property
    def cooldown(self) -> float:
        return float(self.config.localization.get("alert_cooldown_seconds", 60))

    def process(self, event: FrameEvent) -> List[Alert]:
        if not self.enabled():
            return []
        if event.frame_type not in ("beacon", "probe_resp"):
            return []
        if event.rssi is None or not event.bssid:
            return []
        radio = (event.radio_id or "primary").lower()
        bssid = event.bssid.lower()
        buf = self._rssi[bssid][radio]
        buf.append((event.timestamp, float(event.rssi)))
        cutoff = event.timestamp - self.window
        while buf and buf[0][0] < cutoff:
            buf.popleft()

        sensors = self.sensors()
        r0, r1 = sensors[0].radio_id.lower(), sensors[1].radio_id.lower()
        if r0 not in self._rssi[bssid] or r1 not in self._rssi[bssid]:
            return []
        if not self._rssi[bssid][r0] or not self._rssi[bssid][r1]:
            return []

        rssi1 = sum(r for _, r in self._rssi[bssid][r0]) / len(self._rssi[bssid][r0])
        rssi2 = sum(r for _, r in self._rssi[bssid][r1]) / len(self._rssi[bssid][r1])
        ref_rssi = float(self.config.localization.get("ref_rssi", -40))
        path_loss = float(self.config.localization.get("path_loss_exp", 2.5))
        x, y, d1, d2 = localize_two_sensors(
            sensors[0],
            sensors[1],
            rssi1,
            rssi2,
            ref_rssi=ref_rssi,
            path_loss_exp=path_loss,
        )

        # Only alert for non-allowlisted BSSIDs (lab rogues / twins)
        if self.config.is_allowlisted_bssid(bssid):
            return []
        last = self._last_alert.get(bssid, 0.0)
        if event.timestamp - last < self.cooldown:
            return []
        self._last_alert[bssid] = event.timestamp

        return [
            Alert(
                alert_type="rssi_lab_localization",
                severity=AlertSeverity.MEDIUM,
                title="Lab RSSI localization estimate",
                evidence=(
                    f"BSSID {bssid} SSID '{event.ssid or '?'}' approx "
                    f"({x:.1f}m, {y:.1f}m) on lab floorplan; "
                    f"RSSI {r0}={rssi1:.0f}dBm (d≈{d1:.1f}m), "
                    f"{r1}={rssi2:.0f}dBm (d≈{d2:.1f}m)"
                ),
                bssid=bssid,
                ssid=event.ssid,
                channel=event.channel,
                timestamp=event.timestamp,
                metadata={
                    "x_m": round(x, 2),
                    "y_m": round(y, 2),
                    "rssi": {r0: round(rssi1, 1), r1: round(rssi2, 1)},
                    "distance_m": {r0: round(d1, 2), r1: round(d2, 2)},
                },
            )
        ]
