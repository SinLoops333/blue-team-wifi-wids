"""Simulate attack patterns as pcaps (no foreign RF targets)."""

from __future__ import annotations

from pathlib import Path
from typing import List

from scapy.all import (  # type: ignore
    LLC,
    SNAP,
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    Dot11ProbeResp,
    EAPOL,
    RadioTap,
    wrpcap,
)

from ..scope import LabScope, ScopeError

LAB_EVIL_TWIN_BSSID = "de:ad:be:ef:00:01"
LAB_KARMA_BSSID = "aa:bb:cc:11:22:33"

SIMULATE_CHOICES = (
    "evil_twin",
    "karma",
    "deauth",
    "encryption_downgrade",
    "pmkid",
    "handshake_harvest",
    "all",
)


def _beacon(bssid: str, ssid: str, channel: int = 6, open_network: bool = False):
    cap = 0x0000 if open_network else 0x0411
    pkt = (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
        / Dot11Beacon(cap=cap)
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / Dot11Elt(ID="DSset", info=bytes([channel]))
    )
    if not open_network:
        pkt = pkt / Dot11Elt(
            ID=48, info=bytes.fromhex("0100000fac040100000fac040100000fac020000")
        )
    return pkt


def _probe_resp(bssid: str, ssid: str, channel: int = 6):
    return (
        RadioTap()
        / Dot11(
            type=0,
            subtype=5,
            addr1="aa:aa:aa:aa:aa:01",
            addr2=bssid,
            addr3=bssid,
        )
        / Dot11ProbeResp(cap=0x0411)
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / Dot11Elt(ID="DSset", info=bytes([channel]))
    )


def _deauth(bssid: str, count: int = 25):
    return [
        RadioTap()
        / Dot11(
            type=0,
            subtype=12,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=bssid,
            addr3=bssid,
        )
        / Dot11Deauth(reason=7)
        for _ in range(count)
    ]


def _eapol_m1(bssid: str, client: str = "aa:aa:aa:aa:aa:02", with_pmkid: bool = False):
    key_info = (0x008A).to_bytes(2, "big")
    body = b"\x02" + key_info + b"\x00" * 90
    if with_pmkid:
        body += b"\xdd\x16\x00\x0f\xac\x04" + (b"\x11" * 16)
    return (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=client, addr2=bssid, addr3=bssid)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0, code=0x888E)
        / EAPOL(version=1, type=3, len=len(body))
        / body
    )


def build_evil_twin_pcap(scope: LabScope) -> List:
    if not scope.lab.targets:
        raise ScopeError("No lab targets")
    real = scope.lab.targets[0]
    if not real.ssid:
        raise ScopeError("Lab target needs an ssid for evil-twin simulation")
    ch = real.channel or 6
    return [
        _beacon(real.bssid, real.ssid, channel=ch, open_network=False),
        _beacon(LAB_EVIL_TWIN_BSSID, real.ssid, channel=ch, open_network=True),
    ]


def build_encryption_downgrade_pcap(scope: LabScope) -> List:
    real = scope.lab.targets[0]
    if not real.ssid:
        raise ScopeError("Lab target needs an ssid")
    ch = real.channel or 6
    # First encrypted observation is learned as baseline in the same pcap replay
    # if inventory already has encryption — seed via two frames: secured then open
    return [
        _beacon(real.bssid, real.ssid, channel=ch, open_network=False),
        _beacon(real.bssid, real.ssid, channel=ch, open_network=True),
    ]


def build_karma_pcap(scope: LabScope) -> List:
    _ = scope
    return [
        _probe_resp(LAB_KARMA_BSSID, s)
        for s in ["LabSimA", "LabSimB", "LabSimC", "LabSimD", "LabSimE"]
    ]


def build_deauth_flood_pcap(scope: LabScope, count: int = 25) -> List:
    return _deauth(scope.lab.targets[0].bssid, count=count)


def build_pmkid_pcap(scope: LabScope) -> List:
    return [_eapol_m1(scope.lab.targets[0].bssid, with_pmkid=True)]


def build_handshake_harvest_pcap(scope: LabScope) -> List:
    bssid = scope.lab.targets[0].bssid
    return _deauth(bssid, count=3) + [_eapol_m1(bssid, with_pmkid=False)]


def build_all(scope: LabScope) -> List:
    pkts: List = []
    pkts.extend(build_evil_twin_pcap(scope))
    pkts.extend(build_karma_pcap(scope))
    pkts.extend(build_deauth_flood_pcap(scope, count=max(25, scope.lab.deauth_count)))
    pkts.extend(build_pmkid_pcap(scope))
    pkts.extend(build_handshake_harvest_pcap(scope))
    return pkts


def write_simulation(
    scope: LabScope, attack: str, path: Path | None = None
) -> Path:
    attack = attack.lower().replace("-", "_")
    builders = {
        "evil_twin": build_evil_twin_pcap,
        "eviltwin": build_evil_twin_pcap,
        "karma": build_karma_pcap,
        "deauth": lambda s: build_deauth_flood_pcap(
            s, count=max(25, s.lab.deauth_count)
        ),
        "encryption_downgrade": build_encryption_downgrade_pcap,
        "pmkid": build_pmkid_pcap,
        "handshake_harvest": build_handshake_harvest_pcap,
        "all": build_all,
    }
    if attack not in builders:
        raise ScopeError(
            f"Unknown simulation {attack!r}. Use: {', '.join(SIMULATE_CHOICES)}"
        )
    pkts = builders[attack](scope)
    out = Path(path or scope.lab.simulate_pcap)
    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), pkts)
    return out
