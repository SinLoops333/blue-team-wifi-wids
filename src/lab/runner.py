"""Orchestrate scoped lab attacks with confirmation + audit."""

from __future__ import annotations

import logging
from typing import Optional

from ..capture.pineapple_ssh import PineappleSSH
from ..config import Config
from .attacks.deauth import run_deauth
from .attacks.simulate import write_simulation
from .audit import AuditLog
from .confirm import require_confirm
from .scope import LabScope, ScopeError, load_lab_config

logger = logging.getLogger(__name__)


class LabRunner:
    def __init__(
        self,
        scope: LabScope,
        wids: Config,
        audit: AuditLog | None = None,
    ):
        self.scope = scope
        self.wids = wids
        self.audit = audit or AuditLog(scope.lab.audit_log)

    @classmethod
    def from_config(cls, lab_yaml=None) -> "LabRunner":
        lab_cfg, wids = load_lab_config(lab_yaml)
        scope = LabScope(lab_cfg, wids)
        return cls(scope, wids)

    def _confirm(self, summary: str, assume_yes: bool) -> bool:
        ok = require_confirm(
            summary,
            require=self.scope.lab.require_confirm,
            assume_yes=assume_yes,
        )
        self.audit.record(
            "confirmation",
            approved=ok,
            assume_yes=assume_yes,
            require_confirm=self.scope.lab.require_confirm,
            summary=summary,
        )
        return ok

    def run_live_deauth(
        self,
        target_bssid: Optional[str] = None,
        *,
        count: Optional[int] = None,
        dry_run: bool = False,
        assume_yes: bool = False,
    ) -> int:
        target = self.scope.get_target(
            target_bssid or self.scope.lab.targets[0].bssid
        )
        # Pre-check scope (will raise if illegal)
        self.scope.assert_attack_bssid(target.bssid)

        summary = (
            f"LIVE RF ACTION: deauth\n"
            f"  target BSSID : {target.bssid}\n"
            f"  target SSID  : {target.ssid}\n"
            f"  channel      : {target.channel if target.channel is not None else '(auto-detect)'}\n"
            f"  notes        : {target.notes}\n"
            f"  count        : {count or self.scope.lab.deauth_count}\n"
            f"  interface    : {self.scope.lab.inject_interface}\n"
            f"  pineapple    : {self.wids.pineapple_ip}\n"
            f"  dry_run      : {dry_run}\n"
            f"\n{self.scope.describe()}"
        )
        if not self._confirm(summary, assume_yes=assume_yes):
            return 2

        if not self.wids.pineapple_password:
            raise ScopeError("PINEAPPLE_PASSWORD not set in .env")

        ssh = PineappleSSH(
            host=self.wids.pineapple_ip,
            username=self.wids.pineapple_user,
            password=self.wids.pineapple_password,
            port=self.wids.pineapple_ssh_port,
            timeout=self.wids.ssh_timeout,
        )
        try:
            result = run_deauth(
                ssh,
                self.scope,
                target.bssid,
                count=count,
                dry_run=dry_run,
            )
            self.audit.record(
                "deauth",
                dry_run=dry_run,
                success=result.success,
                command=result.command,
                exit_code=result.exit_code,
                target_bssid=result.target_bssid,
                client=result.client,
                count=result.count,
                channel=result.channel,
                stdout=result.stdout[-2000:],
                stderr=result.stderr[-2000:],
            )
            if result.success:
                logger.info("Deauth completed (exit %s)", result.exit_code)
                if result.stdout:
                    logger.info("stdout: %s", result.stdout[:500])
                if result.stderr:
                    logger.info("stderr: %s", result.stderr[:500])
                return 0
            logger.error(
                "Deauth failed (exit %s): %s %s",
                result.exit_code,
                result.stdout,
                result.stderr,
            )
            return 1
        finally:
            ssh.close()

    def run_simulate(
        self,
        attack: str,
        *,
        assume_yes: bool = False,
    ) -> int:
        summary = (
            f"SIMULATION (pcap only — no live RF injection)\n"
            f"  attack : {attack}\n"
            f"  output : {self.scope.lab.simulate_pcap}\n"
            f"\n{self.scope.describe()}\n"
            f"\nReplay with:\n"
            f"  python -m src.main --offline {self.scope.lab.simulate_pcap}"
        )
        if not self._confirm(summary, assume_yes=assume_yes):
            return 2

        path = write_simulation(self.scope, attack)
        self.audit.record(
            "simulate",
            attack=attack,
            pcap=str(path),
            success=True,
        )
        logger.info("Wrote simulation pcap: %s", path)
        logger.info(
            "Validate detectors: python -m src.main --offline %s", path
        )
        return 0
