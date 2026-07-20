"""Adversarial / near-threshold stress suite for signature detectors.

Generates lab-only synthetic traffic that sits just below or just above
detector thresholds to measure robustness (not offensive tooling).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from ..config import Config
from ..lab.attacks import simulate as sim
from .dataset import Scenario


@dataclass
class StressCase:
    name: str
    alert_type: str
    expect_alert: bool
    packets: list = field(default_factory=list)
    note: str = ""


def build_stress_cases(
    *,
    deauth_threshold: int = 20,
    karma_min_ssids: int = 5,
    honeypot_burst: int = 12,
) -> List[StressCase]:
    """Near-miss and just-over cases for key detectors."""
    bssid = "00:13:37:a9:43:43"
    ssid = "Open999"
    client = sim.LAB_SCANNER_CLIENT

    cases: List[StressCase] = [
        StressCase(
            name="deauth_just_below",
            alert_type="deauth_flood",
            expect_alert=False,
            packets=sim._deauth(bssid, count=max(1, deauth_threshold - 1)),
            note=f"deauth count={deauth_threshold - 1} < threshold {deauth_threshold}",
        ),
        StressCase(
            name="deauth_just_above",
            alert_type="deauth_flood",
            expect_alert=True,
            packets=sim._deauth(bssid, count=deauth_threshold),
            note=f"deauth count={deauth_threshold} == threshold",
        ),
        StressCase(
            name="deauth_sparse_benign",
            alert_type="deauth_flood",
            expect_alert=False,
            packets=sim._deauth(bssid, count=3),
            note="sparse deauth should not flood-alert",
        ),
        StressCase(
            name="karma_just_below",
            alert_type="karma",
            expect_alert=False,
            packets=[
                sim._probe_resp(sim.LAB_KARMA_BSSID, f"LabSim{i}")
                for i in range(max(1, karma_min_ssids - 1))
            ],
            note=f"{karma_min_ssids - 1} SSIDs < min {karma_min_ssids}",
        ),
        StressCase(
            name="karma_just_above",
            alert_type="karma",
            expect_alert=True,
            packets=[
                sim._probe_resp(sim.LAB_KARMA_BSSID, f"LabSim{i}")
                for i in range(karma_min_ssids)
            ],
            note=f"{karma_min_ssids} SSIDs == min",
        ),
        StressCase(
            name="honeypot_just_below",
            alert_type="honeypot_recon_burst",
            expect_alert=False,
            packets=[
                sim._probe_req(client, ssid, bssid=bssid)
                for _ in range(max(1, honeypot_burst - 1))
            ],
            note=f"{honeypot_burst - 1} probes < burst {honeypot_burst}",
        ),
        StressCase(
            name="honeypot_just_above",
            alert_type="honeypot_recon_burst",
            expect_alert=True,
            packets=[
                sim._probe_req(client, ssid, bssid=bssid)
                for _ in range(honeypot_burst)
            ],
            note=f"{honeypot_burst} probes == burst threshold",
        ),
        StressCase(
            name="evil_twin_positive",
            alert_type="evil_twin",
            expect_alert=True,
            packets=[
                sim._beacon(bssid, ssid, channel=11, open_network=False),
                sim._beacon(
                    sim.LAB_EVIL_TWIN_BSSID, ssid, channel=11, open_network=True
                ),
            ],
            note="classic twin — must still fire under stress config",
        ),
    ]
    return cases


def _prep_cfg(cfg: Config) -> Config:
    cfg.detectors = dict(cfg.detectors)
    deauth_thr = int((cfg.detectors.get("deauth") or {}).get("threshold", 20))
    cfg.detectors["deauth"] = {
        **(cfg.detectors.get("deauth") or {}),
        "window_seconds": 10,
        "threshold": deauth_thr,
        "ignore_broadcast_source": True,
    }
    karma_min = int((cfg.detectors.get("karma") or {}).get("min_ssids_per_bssid", 5))
    cfg.detectors["karma"] = {
        **(cfg.detectors.get("karma") or {}),
        "window_seconds": 60,
        "min_ssids_per_bssid": karma_min,
    }
    cfg.fusion = dict(cfg.fusion or {})
    cfg.fusion["enabled"] = True
    cfg.honeypot = dict(cfg.honeypot or {})
    cfg.honeypot["enabled"] = True
    cfg.honeypot["ssids"] = list(set(cfg.honeypot.get("ssids") or []) | {"Open999"})
    cfg.honeypot.setdefault(
        "burst_probe_threshold",
        int(cfg.honeypot.get("burst_probe_threshold", 12)),
    )
    cfg.allowlist_ssids = set(cfg.allowlist_ssids) | {"Open999"}
    return cfg


def run_stress_suite(cfg: Config) -> Dict[str, Any]:
    """Run near-threshold cases; return pass rate + per-case rows."""
    from .runner import _run_scenario

    cfg = _prep_cfg(cfg)
    deauth_thr = int(cfg.detectors["deauth"]["threshold"])
    karma_min = int(cfg.detectors["karma"]["min_ssids_per_bssid"])
    hp_burst = int(cfg.honeypot.get("burst_probe_threshold", 12))

    cases = build_stress_cases(
        deauth_threshold=deauth_thr,
        karma_min_ssids=karma_min,
        honeypot_burst=hp_burst,
    )
    rows = []
    for case in cases:
        sc = Scenario(
            name=case.name,
            label="stress",
            expected_alerts={case.alert_type} if case.expect_alert else set(),
            packets=case.packets,
        )
        pred = _run_scenario(cfg, sc)
        hit = case.alert_type in pred
        ok = hit == case.expect_alert
        rows.append(
            {
                "name": case.name,
                "alert_type": case.alert_type,
                "expect_alert": case.expect_alert,
                "got_alert": hit,
                "pass": ok,
                "predicted": sorted(pred),
                "note": case.note,
            }
        )

    n_pass = sum(1 for r in rows if r["pass"])
    # Robustness: fraction of boundary cases correct
    return {
        "n_cases": len(rows),
        "n_pass": n_pass,
        "pass_rate": n_pass / len(rows) if rows else 0.0,
        "cases": rows,
        "thresholds_under_test": {
            "deauth": deauth_thr,
            "karma_min_ssids": karma_min,
            "honeypot_burst": hp_burst,
        },
    }
