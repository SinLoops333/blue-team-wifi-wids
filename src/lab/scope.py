"""Hard allowlist / lab-target enforcement. Non-bypassable scope checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..config import PROJECT_ROOT, Config


class ScopeError(RuntimeError):
    """Raised when an action would leave the authorized lab scope."""


@dataclass(frozen=True)
class LabTarget:
    bssid: str
    ssid: str | None = None
    notes: str = ""
    channel: int | None = None


@dataclass
class LabConfig:
    enabled: bool
    require_confirm: bool
    inject_interface: str
    audit_log: Path
    targets: list[LabTarget]
    deauth_count: int
    deauth_client: str | None
    simulate_pcap: Path
    raw: dict


def load_lab_config(
    path: Path | None = None, wids_config: Config | None = None
) -> tuple[LabConfig, Config]:
    from ..config import get_config

    wids = wids_config or get_config()
    lab_path = path or (PROJECT_ROOT / "config" / "lab.yaml")
    if not lab_path.exists():
        example = PROJECT_ROOT / "config" / "lab.example.yaml"
        if example.exists():
            lab_path = example
        else:
            raise FileNotFoundError(f"Missing lab config at {lab_path}")

    with open(lab_path, encoding="utf-8") as f:
        raw_root = yaml.safe_load(f) or {}
    raw = raw_root.get("lab") or raw_root

    targets: list[LabTarget] = []
    for t in raw.get("targets") or []:
        bssid = (t.get("bssid") or "").strip().lower()
        if not bssid:
            continue
        targets.append(
            LabTarget(
                bssid=bssid,
                ssid=t.get("ssid"),
                notes=t.get("notes") or "",
                channel=int(t["channel"]) if t.get("channel") is not None else None,
            )
        )

    deauth = raw.get("deauth") or {}
    client = deauth.get("client")
    if client:
        client = str(client).strip().lower()
    else:
        client = None

    sim = raw.get("simulate") or {}
    audit = Path(raw.get("audit_log") or "data/logs/lab_audit.jsonl")
    if not audit.is_absolute():
        audit = PROJECT_ROOT / audit
    sim_pcap = Path(sim.get("output_pcap") or "data/captures/lab_simulated.pcap")
    if not sim_pcap.is_absolute():
        sim_pcap = PROJECT_ROOT / sim_pcap

    cfg = LabConfig(
        enabled=bool(raw.get("enabled", True)),
        require_confirm=bool(raw.get("require_confirm", True)),
        inject_interface=str(raw.get("inject_interface") or "wlan1"),
        audit_log=audit,
        targets=targets,
        deauth_count=int(deauth.get("count", 30)),
        deauth_client=client,
        simulate_pcap=sim_pcap,
        raw=raw,
    )
    return cfg, wids


class LabScope:
    """Enforces: lab enabled, non-empty targets, targets ⊆ WIDS allowlist."""

    def __init__(self, lab: LabConfig, wids: Config):
        self.lab = lab
        self.wids = wids
        self._validate_config()

    def _validate_config(self) -> None:
        if not self.lab.enabled:
            raise ScopeError(
                "Lab is disabled in config/lab.yaml (lab.enabled: false)."
            )
        if not self.lab.targets:
            raise ScopeError(
                "No lab targets configured. Add owned BSSIDs under lab.targets "
                "in config/lab.yaml (must also be in wids allowlist)."
            )
        for t in self.lab.targets:
            if not self.wids.is_allowlisted_bssid(t.bssid):
                raise ScopeError(
                    f"Lab target {t.bssid} is NOT in wids.yaml allowlist.bssids. "
                    "Add it to the allowlist first, or remove it from lab.targets."
                )
            if t.ssid and self.wids.allowlist_ssids and t.ssid not in self.wids.allowlist_ssids:
                # Soft warning path: still require SSID in allowlist if allowlist_ssids non-empty
                raise ScopeError(
                    f"Lab target SSID {t.ssid!r} is not in wids.yaml allowlist.ssids."
                )

    def target_bssids(self) -> set[str]:
        return {t.bssid for t in self.lab.targets}

    def get_target(self, bssid: str) -> LabTarget:
        b = bssid.strip().lower()
        for t in self.lab.targets:
            if t.bssid == b:
                return t
        raise ScopeError(
            f"BSSID {b} is not a configured lab target. "
            f"Allowed lab targets: {sorted(self.target_bssids())}"
        )

    def assert_attack_bssid(self, bssid: str) -> LabTarget:
        """Hard gate: BSSID must be a lab target (hence allowlisted)."""
        if not bssid:
            raise ScopeError("Empty BSSID refused.")
        b = bssid.strip().lower()
        # Defense in depth: must be allowlisted AND a lab target
        if not self.wids.is_allowlisted_bssid(b):
            raise ScopeError(
                f"REFUSED: {b} is not in the WIDS allowlist. "
                "Lab attacks cannot target foreign networks."
            )
        return self.get_target(b)

    def assert_client_mac(self, client: str | None) -> str:
        """Client MAC for deauth: broadcast or any MAC (client of own AP)."""
        if not client:
            return "ff:ff:ff:ff:ff:ff"
        c = client.strip().lower()
        # Never treat a non-allowlisted AP BSSID as "client" confusion —
        # if someone passes a foreign AP as client, still OK for deauth toward own AP.
        # Block obviously invalid.
        if len(c.split(":")) != 6:
            raise ScopeError(f"Invalid client MAC: {client}")
        return c

    def describe(self) -> str:
        lines = [
            "Lab scope (owned targets only):",
            f"  inject_interface: {self.lab.inject_interface}",
            f"  require_confirm: {self.lab.require_confirm}",
            "  targets:",
        ]
        for t in self.lab.targets:
            lines.append(
                f"    - {t.bssid}  ssid={t.ssid!r}  ch={t.channel}  {t.notes}".rstrip()
            )
        return "\n".join(lines)
