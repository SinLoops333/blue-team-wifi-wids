"""Rule-based Wi-Fi attack signature detectors (defensive / passive)."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Set

from ..alerts.alert import Alert, AlertSeverity
from ..config import Config
from .fingerprint import FingerprintBaseline, TsfTracker
from .frame_features import FeatureExtractor, FrameEvent


class SignatureEngine:
    """Explainable detectors for common Wi-Fi attacks."""

    def __init__(self, config: Config):
        self.config = config
        self._deauth_times: Dict[str, Deque[float]] = defaultdict(deque)
        # Known good SSID -> set of BSSIDs / encryption / channel from baseline
        self._ssid_map: Dict[str, Dict[str, dict]] = defaultdict(dict)
        # BSSID -> set of SSIDs advertised via probe resp / beacon (KARMA)
        self._karma_ssids: Dict[str, Dict[str, float]] = defaultdict(dict)
        # Recent deauth timestamps keyed by (src, dest) for handshake harvest
        self._recent_deauths: Deque[tuple] = deque()
        self._seen_pmkid: Set[str] = set()
        # Per-BSSID IE fingerprint + TSF trackers (clone / impersonation)
        self._fp_baselines: Dict[str, FingerprintBaseline] = {}
        self._tsf_trackers: Dict[str, TsfTracker] = {}

    def load_baseline_inventory(self, inventory: Dict[str, dict]) -> None:
        """Seed SSID map from a known-good AP inventory."""
        for bssid, info in inventory.items():
            ssid = info.get("ssid")
            if not ssid:
                continue
            self._ssid_map[ssid][bssid.lower()] = {
                "channel": info.get("channel"),
                "encryption": info.get("encryption"),
                "bssid": bssid.lower(),
            }

    def process(
        self, event: FrameEvent, extractor: FeatureExtractor
    ) -> List[Alert]:
        alerts: List[Alert] = []
        alerts.extend(self._check_deauth(event))
        alerts.extend(self._check_evil_twin(event))
        alerts.extend(self._check_beacon_clone(event))
        alerts.extend(self._check_karma(event))
        alerts.extend(self._check_pmkid(event))
        alerts.extend(self._check_handshake_harvest(event))
        # Update learned inventory for future evil-twin checks (non-alerting path)
        self._learn_ap(event)
        return alerts

    # --- Deauth / disassoc flood ---

    def _check_deauth(self, event: FrameEvent) -> List[Alert]:
        if event.frame_type not in ("deauth", "disassoc"):
            return []
        window = float(self.config.detector("deauth", "window_seconds", 10))
        threshold = int(self.config.detector("deauth", "threshold", 20))
        ignore_bcast = bool(
            self.config.detector("deauth", "ignore_broadcast_source", True)
        )
        src = event.addr2 or event.bssid or "unknown"
        if ignore_bcast and self._is_broadcast_or_multicast(src):
            # Attribute to BSS instead of counting a duplicate flood under ff:ff:…
            src = event.bssid or event.addr3 or src
        buf = self._deauth_times[src]
        buf.append(event.timestamp)
        cutoff = event.timestamp - window
        while buf and buf[0] < cutoff:
            buf.popleft()
        self._recent_deauths.append(
            (event.timestamp, src, event.addr1, event.bssid)
        )
        while (
            self._recent_deauths
            and self._recent_deauths[0][0]
            < event.timestamp
            - float(self.config.detector("handshake_harvest", "deauth_then_eapol_window", 15))
        ):
            self._recent_deauths.popleft()

        if len(buf) >= threshold:
            return [
                Alert(
                    alert_type="deauth_flood",
                    severity=AlertSeverity.HIGH,
                    title="Deauth/disassoc flood detected",
                    evidence=(
                        f"{len(buf)} {event.frame_type} frames from {src} "
                        f"in {window:.0f}s (threshold {threshold})"
                    ),
                    bssid=event.bssid,
                    ssid=event.ssid,
                    channel=event.channel,
                    source_mac=src,
                    timestamp=event.timestamp,
                    metadata={"count": len(buf), "window": window},
                )
            ]
        return []

    @staticmethod
    def _is_broadcast_or_multicast(mac: str | None) -> bool:
        if not mac:
            return False
        m = mac.lower()
        if m in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return True
        try:
            return (int(m.split(":")[0], 16) & 1) == 1
        except (ValueError, IndexError):
            return False

    # --- Evil twin / rogue AP ---

    def _check_evil_twin(self, event: FrameEvent) -> List[Alert]:
        if not self.config.detector("evil_twin", "enabled", True):
            return []
        if event.frame_type not in ("beacon", "probe_resp"):
            return []
        if not event.ssid or not event.bssid:
            return []

        known = self._ssid_map.get(event.ssid)
        if not known:
            return []

        bssid_l = event.bssid.lower()
        if bssid_l in known:
            # Same BSSID — encryption downgrade (still alert on allowlisted APs)
            prev = known[bssid_l]
            prev_enc = prev.get("encryption")
            if (
                prev_enc
                and event.encryption
                and prev_enc != "OPEN"
                and event.encryption == "OPEN"
            ):
                return [
                    Alert(
                        alert_type="encryption_downgrade",
                        severity=AlertSeverity.CRITICAL,
                        title="Encryption downgrade on known AP",
                        evidence=(
                            f"SSID '{event.ssid}' BSSID {event.bssid} changed "
                            f"from {prev_enc} to OPEN"
                        ),
                        bssid=event.bssid,
                        ssid=event.ssid,
                        channel=event.channel,
                        timestamp=event.timestamp,
                        metadata={"previous_encryption": prev_enc},
                    )
                ]
            return []

        # New BSSID for a known SSID — skip if that BSSID is an owned radio
        if self.config.is_allowlisted_bssid(event.bssid):
            return []

        known_bssids = ", ".join(sorted(known.keys()))
        return [
            Alert(
                alert_type="evil_twin",
                severity=AlertSeverity.CRITICAL,
                title="Possible evil twin / rogue AP",
                evidence=(
                    f"SSID '{event.ssid}' seen on new BSSID {event.bssid} "
                    f"(known BSSID(s): {known_bssids}); "
                    f"enc={event.encryption} ch={event.channel}"
                ),
                bssid=event.bssid,
                ssid=event.ssid,
                channel=event.channel,
                timestamp=event.timestamp,
                metadata={"known_bssids": list(known.keys())},
            )
        ]

    # --- Beacon IE fingerprint + TSF skew (same-BSSID clone) ---

    def _check_beacon_clone(self, event: FrameEvent) -> List[Alert]:
        if not self.config.detector("beacon_clone", "enabled", True):
            return []
        if event.frame_type not in ("beacon", "probe_resp"):
            return []
        if not event.bssid or not event.ie_fingerprint:
            return []

        bssid_l = event.bssid.lower()
        stabilize = int(self.config.detector("beacon_clone", "stabilize_count", 3))
        alerts: List[Alert] = []

        fp = self._fp_baselines.get(bssid_l)
        if fp is None:
            fp = FingerprintBaseline(stabilize_count=stabilize)
            self._fp_baselines[bssid_l] = fp
        reason = fp.observe(event.ie_fingerprint)
        if reason:
            alerts.append(
                Alert(
                    alert_type="beacon_fingerprint_mismatch",
                    severity=AlertSeverity.CRITICAL,
                    title="AP beacon fingerprint changed",
                    evidence=(
                        f"BSSID {event.bssid} SSID '{event.ssid or '?'}': {reason}; "
                        f"ie_ids={list(event.ie_ids)[:12]} "
                        f"interval={event.beacon_interval}"
                    ),
                    bssid=event.bssid,
                    ssid=event.ssid,
                    channel=event.channel,
                    timestamp=event.timestamp,
                    metadata={
                        "baseline_fp": fp.fingerprint,
                        "observed_fp": event.ie_fingerprint,
                        "ie_ids": list(event.ie_ids),
                        "vendor_ouis": list(event.vendor_ouis),
                    },
                )
            )

        if event.tsf is not None and event.frame_type == "beacon":
            tracker = self._tsf_trackers.get(bssid_l)
            if tracker is None:
                tracker = TsfTracker(
                    min_samples=int(
                        self.config.detector("beacon_clone", "tsf_min_samples", 4)
                    ),
                    max_backward_us=int(
                        self.config.detector(
                            "beacon_clone", "tsf_max_backward_us", 1_000_000
                        )
                    ),
                )
                self._tsf_trackers[bssid_l] = tracker
            tsf_reason = tracker.observe(event.timestamp, int(event.tsf))
            if tsf_reason:
                alerts.append(
                    Alert(
                        alert_type="beacon_tsf_anomaly",
                        severity=AlertSeverity.HIGH,
                        title="AP TSF clock anomaly",
                        evidence=(
                            f"BSSID {event.bssid} SSID '{event.ssid or '?'}': "
                            f"{tsf_reason}"
                        ),
                        bssid=event.bssid,
                        ssid=event.ssid,
                        channel=event.channel,
                        timestamp=event.timestamp,
                        metadata={"tsf": event.tsf, "reason": tsf_reason},
                    )
                )

        return alerts

    def _learn_ap(self, event: FrameEvent) -> None:
        if event.frame_type not in ("beacon", "probe_resp"):
            return
        if not event.ssid or not event.bssid:
            return
        # Only auto-learn allowlisted or already-known SSIDs' first BSSID
        # For bootstrapping: first observation of an SSID becomes "known"
        # unless it's a brand-new SSID on a non-allowlisted BSSID after we
        # already have inventory — signatures rely on baseline.load.
        entry = self._ssid_map[event.ssid]
        bssid_l = event.bssid.lower()
        if bssid_l not in entry and not entry:
            # First time we see this SSID — record as baseline candidate
            entry[bssid_l] = {
                "channel": event.channel,
                "encryption": event.encryption,
                "bssid": bssid_l,
            }
        elif bssid_l in entry:
            entry[bssid_l]["channel"] = event.channel or entry[bssid_l].get("channel")
            entry[bssid_l]["encryption"] = (
                event.encryption or entry[bssid_l].get("encryption")
            )

    # --- KARMA ---

    def _check_karma(self, event: FrameEvent) -> List[Alert]:
        if event.frame_type not in ("probe_resp", "beacon"):
            return []
        if not event.bssid or not event.ssid:
            return []
        if self.config.is_allowlisted_bssid(event.bssid):
            return []

        window = float(self.config.detector("karma", "window_seconds", 60))
        min_ssids = int(self.config.detector("karma", "min_ssids_per_bssid", 5))
        store = self._karma_ssids[event.bssid.lower()]
        store[event.ssid] = event.timestamp
        # Expire old SSIDs
        cutoff = event.timestamp - window
        expired = [s for s, t in store.items() if t < cutoff]
        for s in expired:
            del store[s]

        if len(store) >= min_ssids:
            return [
                Alert(
                    alert_type="karma",
                    severity=AlertSeverity.HIGH,
                    title="Possible KARMA / multi-SSID responder",
                    evidence=(
                        f"BSSID {event.bssid} advertised {len(store)} distinct "
                        f"SSIDs in {window:.0f}s: {', '.join(sorted(store)[:8])}"
                        f"{'...' if len(store) > 8 else ''}"
                    ),
                    bssid=event.bssid,
                    ssid=event.ssid,
                    channel=event.channel,
                    timestamp=event.timestamp,
                    metadata={"ssid_count": len(store), "ssids": sorted(store)},
                )
            ]
        return []

    # --- PMKID ---

    def _check_pmkid(self, event: FrameEvent) -> List[Alert]:
        if not self.config.detector("pmkid", "enabled", True):
            return []
        if not event.has_pmkid and not (
            event.is_eapol and event.eapol_msg == 1 and event.has_pmkid
        ):
            if not event.has_pmkid:
                return []
        if not event.has_pmkid:
            return []
        key = f"{event.bssid}:{event.addr1}:{event.addr2}"
        if key in self._seen_pmkid:
            return []
        self._seen_pmkid.add(key)
        return [
            Alert(
                alert_type="pmkid_harvest",
                severity=AlertSeverity.HIGH,
                title="PMKID observed in EAPOL frame",
                evidence=(
                    f"EAPOL frame with RSN PMKID involving BSSID {event.bssid} "
                    f"(src={event.addr2} dst={event.addr1})"
                ),
                bssid=event.bssid,
                ssid=event.ssid,
                channel=event.channel,
                source_mac=event.addr2,
                timestamp=event.timestamp,
            )
        ]

    # --- Handshake harvesting (deauth then EAPOL) ---

    def _check_handshake_harvest(self, event: FrameEvent) -> List[Alert]:
        if not event.is_eapol:
            return []
        window = float(
            self.config.detector("handshake_harvest", "deauth_then_eapol_window", 15)
        )
        # Look for recent deauth involving same BSSID / clients
        matches = []
        for ts, src, dest, bssid in self._recent_deauths:
            if event.timestamp - ts > window:
                continue
            if bssid and event.bssid and bssid != event.bssid:
                continue
            matches.append((ts, src, dest))
        if not matches:
            return []
        return [
            Alert(
                alert_type="handshake_harvest",
                severity=AlertSeverity.HIGH,
                title="Possible forced handshake capture",
                evidence=(
                    f"EAPOL observed {event.timestamp - matches[-1][0]:.1f}s after "
                    f"deauth (src={matches[-1][1]}) on BSSID {event.bssid}"
                ),
                bssid=event.bssid,
                ssid=event.ssid,
                channel=event.channel,
                source_mac=matches[-1][1],
                timestamp=event.timestamp,
                metadata={"prior_deauths": len(matches)},
            )
        ]
