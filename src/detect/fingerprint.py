"""AP beacon fingerprinting and TSF clock-skew helpers.

Catches clones that reuse a known BSSID/SSID but advertise different IEs
or an inconsistent 802.11 TSF clock — cases classic evil-twin (new BSSID)
detection misses.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Sequence, Tuple
from collections import deque

from scapy.all import Dot11Beacon, Dot11Elt, Dot11ProbeResp, Packet  # type: ignore


@dataclass
class BeaconIdentity:
    """Stable-ish identity extracted from a beacon / probe response."""

    ie_ids: Tuple[int, ...]
    vendor_ouis: Tuple[str, ...]
    beacon_interval: Optional[int] = None
    capability: Optional[int] = None
    tsf: Optional[int] = None
    fingerprint: str = ""

    def compute_fingerprint(self) -> str:
        parts = [
            str(self.beacon_interval or ""),
            str(self.capability if self.capability is not None else ""),
            ",".join(str(i) for i in self.ie_ids),
            ",".join(self.vendor_ouis),
        ]
        digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
        self.fingerprint = digest
        return digest


def extract_beacon_identity(pkt: Packet) -> Optional[BeaconIdentity]:
    """Pull IE sequence, vendor OUIs, beacon interval, capability, TSF."""
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return None

    beacon_interval = None
    capability = None
    tsf = None
    if pkt.haslayer(Dot11Beacon):
        b = pkt[Dot11Beacon]
        try:
            beacon_interval = int(b.beacon_interval)
        except Exception:  # noqa: BLE001
            pass
        try:
            capability = int(b.cap)
        except Exception:  # noqa: BLE001
            pass
        try:
            tsf = int(b.timestamp)
        except Exception:  # noqa: BLE001
            pass
    elif pkt.haslayer(Dot11ProbeResp):
        pr = pkt[Dot11ProbeResp]
        try:
            beacon_interval = int(pr.beacon_interval)
        except Exception:  # noqa: BLE001
            pass
        try:
            capability = int(pr.cap)
        except Exception:  # noqa: BLE001
            pass
        try:
            tsf = int(pr.timestamp)
        except Exception:  # noqa: BLE001
            pass

    ie_ids: List[int] = []
    vendor_ouis: List[str] = []
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        try:
            eid = int(elt.ID)
        except Exception:  # noqa: BLE001
            break
        ie_ids.append(eid)
        if eid == 221 and elt.info and len(elt.info) >= 3:
            oui = elt.info[:3]
            if isinstance(oui, bytes):
                vendor_ouis.append(oui.hex())
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

    ident = BeaconIdentity(
        ie_ids=tuple(ie_ids),
        vendor_ouis=tuple(vendor_ouis),
        beacon_interval=beacon_interval,
        capability=capability,
        tsf=tsf,
    )
    ident.compute_fingerprint()
    return ident


@dataclass
class TsfTracker:
    """Track TSF vs wall-clock; flag backwards jumps and impossible rates."""

    max_samples: int = 32
    min_samples: int = 4
    # 802.11 TSF is microseconds; allow wide slack for capture jitter
    max_rate_ppm: float = 50_000.0  # 5% — lab-tolerant
    max_backward_us: int = 1_000_000  # 1s reverse = suspicious
    _samples: Deque[Tuple[float, int]] = field(default_factory=deque)

    def observe(self, wall_ts: float, tsf: int) -> Optional[str]:
        """Return anomaly reason string or None."""
        if self._samples:
            prev_wall, prev_tsf = self._samples[-1]
            dt = wall_ts - prev_wall
            d_tsf = tsf - prev_tsf
            # Synthetic / truncated frames often leave TSF at 0 — don't rate-alert
            if prev_tsf == 0 and tsf == 0:
                self._samples.append((wall_ts, tsf))
                self._trim()
                return None
            if d_tsf < -self.max_backward_us and prev_tsf > self.max_backward_us:
                self._samples.append((wall_ts, tsf))
                self._trim()
                return (
                    f"TSF jumped backward by {-d_tsf} µs "
                    f"(wall Δ={dt:.3f}s)"
                )
            if (
                dt > 0.05
                and d_tsf > 0
                and len(self._samples) >= self.min_samples - 1
            ):
                # Expected ~1e6 TSF ticks per wall second
                rate = d_tsf / dt
                expected = 1_000_000.0
                err = abs(rate - expected) / expected
                if err > (self.max_rate_ppm / 1_000_000.0):
                    self._samples.append((wall_ts, tsf))
                    self._trim()
                    return (
                        f"TSF rate {rate:.0f} ticks/s "
                        f"(expected ~1e6, err={err:.1%})"
                    )
        self._samples.append((wall_ts, tsf))
        self._trim()
        return None

    def _trim(self) -> None:
        while len(self._samples) > self.max_samples:
            self._samples.popleft()


@dataclass
class FingerprintBaseline:
    """Lock a fingerprint after stable observations, then detect changes."""

    stabilize_count: int = 3
    fingerprint: Optional[str] = None
    locked: bool = False
    _recent: Deque[str] = field(default_factory=deque)
    seen: int = 0

    def observe(self, fingerprint: str) -> Optional[str]:
        """Return mismatch reason if locked fingerprint changed, else None."""
        self.seen += 1
        self._recent.append(fingerprint)
        while len(self._recent) > self.stabilize_count:
            self._recent.popleft()

        if not self.locked:
            if (
                len(self._recent) >= self.stabilize_count
                and len(set(self._recent)) == 1
            ):
                self.fingerprint = fingerprint
                self.locked = True
            return None

        if fingerprint != self.fingerprint:
            return (
                f"IE fingerprint changed {self.fingerprint} → {fingerprint}"
            )
        return None
