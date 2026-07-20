"""Synthetic 802.11 frame builders for tests."""

from __future__ import annotations

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
)


def make_beacon(bssid: str, ssid: str, channel: int = 6, open_network: bool = False):
    cap = 0x0000 if open_network else 0x0411
    pkt = (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
        / Dot11Beacon(cap=cap)
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / Dot11Elt(ID="DSset", info=bytes([channel]))
    )
    if not open_network:
        rsn = bytes.fromhex("0100000fac040100000fac040100000fac020000")
        pkt = pkt / Dot11Elt(ID=48, info=rsn)
    return pkt


def make_probe_resp(
    bssid: str, ssid: str, channel: int = 6, dest: str = "aa:aa:aa:aa:aa:01"
):
    return (
        RadioTap()
        / Dot11(type=0, subtype=5, addr1=dest, addr2=bssid, addr3=bssid)
        / Dot11ProbeResp(cap=0x0411)
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / Dot11Elt(ID="DSset", info=bytes([channel]))
        / Dot11Elt(
            ID=48, info=bytes.fromhex("0100000fac040100000fac040100000fac020000")
        )
    )


def make_deauth(
    bssid: str, client: str = "aa:aa:aa:aa:aa:02", src: str | None = None
):
    src = src or bssid
    return (
        RadioTap()
        / Dot11(type=0, subtype=12, addr1=client, addr2=src, addr3=bssid)
        / Dot11Deauth(reason=7)
    )


def make_eapol_m1_pmkid(bssid: str, client: str = "aa:aa:aa:aa:aa:02"):
    pmkid_kde = b"\xdd\x16\x00\x0f\xac\x04" + (b"\x11" * 16)
    key_info = (0x008A).to_bytes(2, "big")
    body = b"\x02" + key_info + b"\x00" * 90 + pmkid_kde
    return (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=client, addr2=bssid, addr3=bssid)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0, code=0x888E)
        / EAPOL(version=1, type=3, len=len(body))
        / body
    )


def make_eapol_m1(bssid: str, client: str = "aa:aa:aa:aa:aa:02"):
    key_info = (0x008A).to_bytes(2, "big")
    body = b"\x02" + key_info + b"\x00" * 90
    return (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=client, addr2=bssid, addr3=bssid)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0, code=0x888E)
        / EAPOL(version=1, type=3, len=len(body))
        / body
    )
