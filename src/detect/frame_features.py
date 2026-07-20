"""Parse 802.11 frames into structured events and windowed feature vectors."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple

from scapy.all import (  # type: ignore
    Dot11,
    Dot11Beacon,
    Dot11ProbeResp,
    Dot11Elt,
    EAPOL,
    Packet,
    RadioTap,
)

SUBTYPE_ASSOC_REQ = 0
SUBTYPE_REASSOC_REQ = 2
SUBTYPE_PROBE_REQ = 4
SUBTYPE_PROBE_RESP = 5
SUBTYPE_BEACON = 8
SUBTYPE_DISASSOC = 10
SUBTYPE_AUTH = 11
SUBTYPE_DEAUTH = 12

FRAME_TYPE_NAMES = {
    (0, SUBTYPE_BEACON): "beacon",
    (0, SUBTYPE_PROBE_REQ): "probe_req",
    (0, SUBTYPE_PROBE_RESP): "probe_resp",
    (0, SUBTYPE_AUTH): "auth",
    (0, SUBTYPE_DEAUTH): "deauth",
    (0, SUBTYPE_DISASSOC): "disassoc",
    (0, SUBTYPE_ASSOC_REQ): "assoc_req",
    (0, SUBTYPE_REASSOC_REQ): "reassoc_req",
}


@dataclass
class FrameEvent:
    """Normalized view of a single 802.11 frame."""

    timestamp: float
    frame_type: str
    subtype: int
    addr1: Optional[str] = None
    addr2: Optional[str] = None
    addr3: Optional[str] = None
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    channel: Optional[int] = None
    rssi: Optional[int] = None
    encryption: Optional[str] = None
    has_pmkid: bool = False
    is_eapol: bool = False
    eapol_msg: Optional[int] = None
    raw_len: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class WindowFeatures:
    """Aggregated features for one BSSID over a time window."""

    bssid: str
    window_start: float
    window_end: float
    beacon_count: int = 0
    probe_req_count: int = 0
    probe_resp_count: int = 0
    deauth_count: int = 0
    disassoc_count: int = 0
    auth_count: int = 0
    assoc_count: int = 0
    eapol_count: int = 0
    pmkid_count: int = 0
    unique_ssids: int = 0
    unique_clients: int = 0
    avg_rssi: float = 0.0
    ssids: List[str] = field(default_factory=list)
    encryption: Optional[str] = None
    channel: Optional[int] = None

    FEATURE_NAMES = [
        "beacon_count",
        "probe_req_count",
        "probe_resp_count",
        "deauth_count",
        "disassoc_count",
        "auth_count",
        "assoc_count",
        "eapol_count",
        "pmkid_count",
        "unique_ssids",
        "unique_clients",
        "avg_rssi",
    ]

    def as_vector(self) -> List[float]:
        return [
            float(self.beacon_count),
            float(self.probe_req_count),
            float(self.probe_resp_count),
            float(self.deauth_count),
            float(self.disassoc_count),
            float(self.auth_count),
            float(self.assoc_count),
            float(self.eapol_count),
            float(self.pmkid_count),
            float(self.unique_ssids),
            float(self.unique_clients),
            float(self.avg_rssi),
        ]


def is_real_bssid(bssid: str | None) -> bool:
    """True for unicast AP BSSIDs (skip broadcast / multicast / empty)."""
    if not bssid:
        return False
    b = bssid.lower()
    if b in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "unknown"):
        return False
    # Multicast/broadcast: least-significant bit of first octet
    try:
        first = int(b.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return (first & 1) == 0


def _mac(addr: Any) -> Optional[str]:
    if addr is None:
        return None
    s = str(addr).lower()
    if s in ("", "00:00:00:00:00:00"):
        return None
    return s


def _extract_ssid(pkt: Packet) -> Optional[str]:
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 0:
            try:
                raw = elt.info
                if isinstance(raw, bytes):
                    if len(raw) == 0:
                        return ""
                    return raw.decode("utf-8", errors="replace")
                return str(raw)
            except Exception:  # noqa: BLE001
                return None
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return None


def _extract_channel(pkt: Packet) -> Optional[int]:
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 3 and elt.info:
            try:
                return elt.info[0] if isinstance(elt.info, bytes) else int(elt.info)
            except Exception:  # noqa: BLE001
                return None
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return None


def _extract_encryption(pkt: Packet) -> Optional[str]:
    has_rsn = False
    has_wpa = False
    privacy = False
    if pkt.haslayer(Dot11Beacon):
        try:
            privacy = bool(int(pkt[Dot11Beacon].cap) & 0x10)
        except Exception:  # noqa: BLE001
            pass
    elif pkt.haslayer(Dot11ProbeResp):
        try:
            privacy = bool(int(pkt[Dot11ProbeResp].cap) & 0x10)
        except Exception:  # noqa: BLE001
            pass

    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 48:
            has_rsn = True
        elif elt.ID == 221 and elt.info and len(elt.info) >= 4:
            if elt.info[:4] == b"\x00\x50\xf2\x01":
                has_wpa = True
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

    if has_rsn:
        return "WPA2/WPA3"
    if has_wpa:
        return "WPA"
    if privacy:
        return "WEP/PRIVACY"
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        return "OPEN"
    return None


def _rssi(pkt: Packet) -> Optional[int]:
    if pkt.haslayer(RadioTap):
        rt = pkt[RadioTap]
        for attr in ("dBm_AntSignal", "dbm_antsignal"):
            if hasattr(rt, attr):
                val = getattr(rt, attr)
                if val is not None:
                    try:
                        return int(val)
                    except (TypeError, ValueError):
                        pass
    return None


def _eapol_message(pkt: Packet) -> Tuple[bool, Optional[int], bool]:
    if not pkt.haslayer(EAPOL):
        return False, None, False
    eapol = pkt[EAPOL]
    raw = bytes(eapol)
    has_pmkid = False
    msg = None
    try:
        if len(raw) >= 7:
            key_info = (raw[5] << 8) | raw[6]
            install = bool(key_info & (1 << 6))
            ack = bool(key_info & (1 << 7))
            mic = bool(key_info & (1 << 8))
            secure = bool(key_info & (1 << 9))
            if ack and not mic:
                msg = 1
            elif mic and not ack and not install and not secure:
                msg = 2
            elif ack and mic and install:
                msg = 3
            elif mic and not ack:
                msg = 4
        if b"\x00\x0f\xac\x04" in raw or b"\xdd\x16\x00\x0f\xac\x04" in raw:
            has_pmkid = True
    except Exception:  # noqa: BLE001
        pass
    return True, msg, has_pmkid


def parse_frame(pkt: Packet, timestamp: Optional[float] = None) -> Optional[FrameEvent]:
    """Convert a Scapy packet into a FrameEvent, or None if not relevant 802.11."""
    if not pkt.haslayer(Dot11):
        return None

    dot11 = pkt[Dot11]
    ftype = int(dot11.type)
    subtype = int(dot11.subtype)
    ts = timestamp if timestamp is not None else time.time()
    if hasattr(pkt, "time") and pkt.time:
        try:
            ts = float(pkt.time)
        except (TypeError, ValueError):
            pass

    name = FRAME_TYPE_NAMES.get((ftype, subtype))
    is_eapol, eapol_msg, has_pmkid = _eapol_message(pkt)
    if is_eapol:
        name = "eapol"

    if name is None and not is_eapol:
        if ftype == 0 and subtype in (SUBTYPE_DEAUTH, SUBTYPE_DISASSOC):
            name = "deauth" if subtype == SUBTYPE_DEAUTH else "disassoc"
        else:
            return None

    addr1 = _mac(getattr(dot11, "addr1", None))
    addr2 = _mac(getattr(dot11, "addr2", None))
    addr3 = _mac(getattr(dot11, "addr3", None))
    bssid = addr3 or addr2

    ssid = None
    channel = None
    encryption = None
    if name in ("beacon", "probe_resp", "probe_req"):
        ssid = _extract_ssid(pkt)
        channel = _extract_channel(pkt)
        if name in ("beacon", "probe_resp"):
            encryption = _extract_encryption(pkt)

    return FrameEvent(
        timestamp=ts,
        frame_type=name or "unknown",
        subtype=subtype,
        addr1=addr1,
        addr2=addr2,
        addr3=addr3,
        bssid=bssid,
        ssid=ssid,
        channel=channel,
        rssi=_rssi(pkt),
        encryption=encryption,
        has_pmkid=has_pmkid,
        is_eapol=is_eapol,
        eapol_msg=eapol_msg,
        raw_len=len(pkt),
    )


class FeatureExtractor:
    """Roll FrameEvents into per-BSSID windowed feature vectors."""

    def __init__(self, window_seconds: float = 30.0):
        self.window_seconds = window_seconds
        self._buffers: Dict[str, Deque[FrameEvent]] = defaultdict(deque)
        self._global: Deque[FrameEvent] = deque()
        self.ap_inventory: Dict[str, dict] = {}
        self.frame_counts: Dict[str, int] = defaultdict(int)
        self.total_frames = 0

    def ingest(self, event: FrameEvent) -> None:
        self.total_frames += 1
        self.frame_counts[event.frame_type] += 1
        self._global.append(event)
        self._trim(self._global, event.timestamp)

        key = event.bssid or event.addr2 or "unknown"
        self._buffers[key].append(event)
        self._trim(self._buffers[key], event.timestamp)

        if event.frame_type in ("beacon", "probe_resp") and event.bssid:
            inv = self.ap_inventory.setdefault(event.bssid, {})
            if event.ssid is not None:
                inv["ssid"] = event.ssid
            if event.channel is not None:
                inv["channel"] = event.channel
            if event.encryption is not None:
                inv["encryption"] = event.encryption
            if event.rssi is not None:
                inv["rssi"] = event.rssi
            inv["last_seen"] = event.timestamp
            inv["bssid"] = event.bssid

    def _trim(self, buf: Deque[FrameEvent], now: float) -> None:
        cutoff = now - self.window_seconds
        while buf and buf[0].timestamp < cutoff:
            buf.popleft()

    def window_features(self, now: Optional[float] = None) -> List[WindowFeatures]:
        now = now if now is not None else time.time()
        results: List[WindowFeatures] = []
        for bssid, buf in list(self._buffers.items()):
            self._trim(buf, now)
            if not buf:
                continue
            results.append(self._aggregate(bssid, buf, now))
        return results

    def _aggregate(
        self, bssid: str, buf: Deque[FrameEvent], now: float
    ) -> WindowFeatures:
        ssids: set[str] = set()
        clients: set[str] = set()
        rssi_vals: list[int] = []
        counts: Dict[str, int] = defaultdict(int)
        encryption = None
        channel = None
        for e in buf:
            counts[e.frame_type] += 1
            if e.ssid:
                ssids.add(e.ssid)
            if e.rssi is not None:
                rssi_vals.append(e.rssi)
            if e.encryption:
                encryption = e.encryption
            if e.channel is not None:
                channel = e.channel
            if e.addr2 and e.addr2 != bssid and e.addr2 != "ff:ff:ff:ff:ff:ff":
                clients.add(e.addr2)
            if e.has_pmkid:
                counts["pmkid"] += 1

        return WindowFeatures(
            bssid=bssid,
            window_start=now - self.window_seconds,
            window_end=now,
            beacon_count=counts["beacon"],
            probe_req_count=counts["probe_req"],
            probe_resp_count=counts["probe_resp"],
            deauth_count=counts["deauth"],
            disassoc_count=counts["disassoc"],
            auth_count=counts["auth"],
            assoc_count=counts["assoc_req"] + counts["reassoc_req"],
            eapol_count=counts["eapol"],
            pmkid_count=counts["pmkid"],
            unique_ssids=len(ssids),
            unique_clients=len(clients),
            avg_rssi=sum(rssi_vals) / len(rssi_vals) if rssi_vals else 0.0,
            ssids=sorted(ssids),
            encryption=encryption,
            channel=channel,
        )

    def recent_events(self, frame_type: Optional[str] = None) -> List[FrameEvent]:
        if frame_type is None:
            return list(self._global)
        return [e for e in self._global if e.frame_type == frame_type]
