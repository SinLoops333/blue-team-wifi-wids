"""Labeled synthetic scenarios for detector evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Set

from scapy.all import Packet  # type: ignore

from ..lab.attacks import simulate as sim


@dataclass
class Scenario:
    name: str
    label: str  # "benign" or attack family
    expected_alerts: Set[str]
    packets: List[Packet] = field(default_factory=list)


def _benign_beacons(n: int = 20) -> List[Packet]:
    bssid = "00:13:37:a9:43:43"
    ssid = "Open999"
    return [sim._beacon(bssid, ssid, channel=11, open_network=False) for _ in range(n)]


def build_scenarios() -> List[Scenario]:
    """Ground-truth scenarios (synthetic only — no live RF)."""
    real_bssid = "00:13:37:a9:43:43"
    real_ssid = "Open999"

    return [
        Scenario(
            name="benign_beacons",
            label="benign",
            expected_alerts=set(),
            packets=_benign_beacons(30),
        ),
        Scenario(
            name="evil_twin",
            label="evil_twin",
            expected_alerts={"evil_twin"},
            packets=[
                sim._beacon(real_bssid, real_ssid, channel=11, open_network=False),
                sim._beacon(
                    sim.LAB_EVIL_TWIN_BSSID, real_ssid, channel=11, open_network=True
                ),
            ],
        ),
        Scenario(
            name="encryption_downgrade",
            label="encryption_downgrade",
            expected_alerts={"encryption_downgrade"},
            packets=[
                sim._beacon(real_bssid, real_ssid, channel=11, open_network=False),
                sim._beacon(real_bssid, real_ssid, channel=11, open_network=True),
            ],
        ),
        Scenario(
            name="karma",
            label="karma",
            expected_alerts={"karma"},
            packets=[
                sim._probe_resp(sim.LAB_KARMA_BSSID, s)
                for s in ["LabSimA", "LabSimB", "LabSimC", "LabSimD", "LabSimE"]
            ],
        ),
        Scenario(
            name="deauth_flood",
            label="deauth",
            expected_alerts={"deauth_flood"},
            packets=sim._deauth(real_bssid, count=25),
        ),
        Scenario(
            name="pmkid",
            label="pmkid",
            expected_alerts={"pmkid_harvest"},
            packets=[sim._eapol_m1(real_bssid, with_pmkid=True)],
        ),
        Scenario(
            name="handshake_harvest",
            label="handshake_harvest",
            expected_alerts={"handshake_harvest"},
            packets=sim._deauth(real_bssid, count=3)
            + [sim._eapol_m1(real_bssid, with_pmkid=False)],
        ),
        Scenario(
            name="benign_sparse_beacons",
            label="benign",
            expected_alerts=set(),
            packets=_benign_beacons(5),
        ),
    ]


def benign_window_vectors(n: int = 40) -> List[List[float]]:
    from ..detect.frame_features import WindowFeatures

    rng = __import__("random").Random(0)
    out = []
    for i in range(n):
        w = WindowFeatures(
            bssid="00:13:37:a9:43:43",
            window_start=float(i),
            window_end=float(i + 30),
            beacon_count=8 + rng.randint(0, 4),
            probe_resp_count=rng.randint(0, 2),
            probe_req_count=rng.randint(0, 1),
            deauth_count=0,
            disassoc_count=0,
            auth_count=rng.randint(0, 1),
            assoc_count=0,
            eapol_count=0,
            pmkid_count=0,
            unique_ssids=1,
            unique_clients=1 + rng.randint(0, 3),
            avg_rssi=-50.0 - rng.random() * 10,
            ssids=["Open999"],
            channel=11,
            encryption="WPA2/WPA3",
        )
        out.append(w.as_vector())
    return out


def attack_window_vectors(n: int = 20) -> List[List[float]]:
    from ..detect.frame_features import WindowFeatures

    rng = __import__("random").Random(1)
    out = []
    for i in range(n):
        w = WindowFeatures(
            bssid="aa:bb:cc:dd:ee:ff",
            window_start=float(i),
            window_end=float(i + 30),
            beacon_count=rng.randint(1, 5),
            probe_resp_count=rng.randint(20, 50),
            deauth_count=rng.randint(50, 120),
            disassoc_count=rng.randint(10, 40),
            eapol_count=rng.randint(15, 40),
            pmkid_count=rng.randint(1, 8),
            unique_ssids=rng.randint(6, 15),
            unique_clients=rng.randint(10, 40),
            avg_rssi=-20.0 - rng.random() * 5,
            ssids=["A", "B", "C", "D"],
            channel=1,
        )
        out.append(w.as_vector())
    return out
