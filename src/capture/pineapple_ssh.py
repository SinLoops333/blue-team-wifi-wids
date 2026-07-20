"""SSH helpers for the WiFi Pineapple Mark VII (passive capture only)."""

from __future__ import annotations

import logging
import shlex
from typing import BinaryIO, Optional

import paramiko

logger = logging.getLogger(__name__)


class PineappleSSH:
    """SSH session to the Pineapple for monitor-mode capture.

    This class is strictly passive: it only runs read-only / interface setup
    commands needed for sniffing. It never injects frames.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        timeout: int = 30,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None
        self._capture_channel = None

    def connect(self) -> None:
        if self._client is not None:
            return
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logger.info("Connecting SSH to %s:%s", self.host, self.port)
        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        self._client = client

    def close(self) -> None:
        self.stop_capture()
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "PineappleSSH":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def run(self, command: str, timeout: Optional[int] = None) -> tuple[int, str, str]:
        """Run a command and return (exit_code, stdout, stderr)."""
        self.connect()
        assert self._client is not None
        logger.debug("SSH run: %s", command)
        _stdin, stdout, stderr = self._client.exec_command(
            command, timeout=timeout or self.timeout
        )
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        code = stdout.channel.recv_exit_status()
        return code, out, err

    def list_interfaces(self) -> list[str]:
        code, out, _err = self.run("ls /sys/class/net/ 2>/dev/null")
        if code == 0 and out.strip():
            return [n.strip() for n in out.split() if n.strip() and n.strip() != "lo"]
        code, out, _err = self.run("ip -o link show")
        names: list[str] = []
        for line in out.splitlines():
            line = line.strip()
            if not line or not line[0].isdigit():
                continue
            parts = line.split(":", 2)
            if len(parts) >= 2:
                name = parts[1].strip().split("@")[0]
                if name and name != "lo":
                    names.append(name)
        return names

    def list_monitor_interfaces(self) -> list[str]:
        """Return wireless ifaces already in monitor mode (e.g. Mark VII ``wlan1``)."""
        code, out, err = self.run("iwconfig 2>&1 || true")
        text = out + err
        monitors: list[str] = []
        current: str | None = None
        for line in text.splitlines():
            if line and not line.startswith(" ") and not line.startswith("\t"):
                tok = line.split()[0] if line.split() else ""
                current = tok if tok and "no wireless" not in line.lower() else None
            if current and ("Mode:Monitor" in line or "Mode: Monitor" in line):
                if current not in monitors:
                    monitors.append(current)
        # Fallback: iw dev
        if not monitors:
            code, out, _err = self.run("iw dev 2>&1 || true")
            current = None
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Interface "):
                    current = line.split()[1]
                elif current and "type monitor" in line:
                    if current not in monitors:
                        monitors.append(current)
        return monitors

    def interface_exists(self, interface: str) -> bool:
        return interface in self.list_interfaces()

    def resolve_capture_interface(self, interface: str) -> str:
        """Resolve config interface name to a real capture iface.

        ``auto`` (or a missing name like ``wlan1mon``) picks an existing
        monitor-mode radio. On Mark VII that is typically ``wlan1``.
        """
        requested = (interface or "auto").strip()
        monitors = self.list_monitor_interfaces()
        ifaces = self.list_interfaces()
        logger.info("Wireless/net ifaces: %s", ", ".join(ifaces) or "(none)")
        logger.info("Monitor-mode ifaces: %s", ", ".join(monitors) or "(none)")

        if requested.lower() == "auto":
            if monitors:
                logger.info("Auto-selected monitor iface: %s", monitors[0])
                return monitors[0]
            raise RuntimeError(
                "No monitor-mode interface found. In the Pineapple UI, put a "
                "radio into Recon/monitor mode (often wlan1), then retry."
            )

        if requested in monitors:
            logger.info("%s already in monitor mode", requested)
            return requested

        if not self.interface_exists(requested):
            if monitors:
                logger.warning(
                    "Interface %s does not exist; using monitor iface %s instead",
                    requested,
                    monitors[0],
                )
                return monitors[0]
            raise RuntimeError(
                f"Interface {requested!r} not found on Pineapple. "
                f"Available: {ifaces}. Put a radio in monitor mode and set "
                f"capture.interface (usually wlan1 on Mark VII)."
            )

        # Exists but not monitor yet — try to enable (best-effort)
        return self.ensure_monitor_mode(requested)

    def ensure_monitor_mode(self, interface: str) -> str:
        """Best-effort: put *interface* into monitor mode."""
        if not self.interface_exists(interface):
            raise RuntimeError(f"Interface {interface!r} does not exist")

        code, out, err = self.run(f"iwconfig {shlex.quote(interface)} 2>&1 || true")
        combined = (out + err).lower()
        if "mode:monitor" in combined or "mode: monitor" in combined:
            logger.info("%s already in monitor mode", interface)
            return interface

        for cmd in (
            f"iw dev {shlex.quote(interface)} set type monitor && "
            f"ip link set {shlex.quote(interface)} up",
            f"airmon-ng start {shlex.quote(interface)}",
        ):
            code, out, err = self.run(cmd)
            logger.info(
                "monitor setup (%s) -> %s out=%s err=%s",
                cmd,
                code,
                out[:200],
                err[:200],
            )
            monitors = self.list_monitor_interfaces()
            if interface in monitors:
                return interface
            mon = f"{interface}mon"
            if mon in monitors or mon in self.list_interfaces():
                return mon

        monitors = self.list_monitor_interfaces()
        if monitors:
            logger.warning(
                "Could not put %s in monitor mode; falling back to %s",
                interface,
                monitors[0],
            )
            return monitors[0]

        raise RuntimeError(
            f"Could not enable monitor mode on {interface}. "
            "Enable Recon/monitor in the Pineapple UI first."
        )

    def start_tcpdump_stream(
        self, interface: str, snaplen: int = 256
    ) -> BinaryIO:
        """Start ``tcpdump -w -`` and return a binary file-like stdout stream."""
        self.connect()
        assert self._client is not None
        self.stop_capture()

        if not self.interface_exists(interface):
            raise RuntimeError(
                f"Cannot capture: interface {interface!r} does not exist"
            )

        # Keep stderr so failures are visible if stdout is empty
        cmd = (
            f"tcpdump -i {shlex.quote(interface)} -U -s {int(snaplen)} "
            f"-n -w -"
        )
        logger.info("Starting remote capture: %s", cmd)
        transport = self._client.get_transport()
        if transport is None:
            raise RuntimeError("SSH transport not available")
        channel = transport.open_session()
        channel.set_combine_stderr(False)
        channel.exec_command(cmd)
        self._capture_channel = channel
        return channel.makefile("rb")

    def set_channel(self, interface: str, channel: int) -> None:
        """Tune a wireless iface to a fixed channel (monitor-friendly)."""
        if channel < 1 or channel > 196:
            raise RuntimeError(f"Invalid channel {channel}")
        cmd = (
            f"iw dev {shlex.quote(interface)} set channel {int(channel)} || "
            f"iwconfig {shlex.quote(interface)} channel {int(channel)}"
        )
        code, out, err = self.run(cmd)
        if code != 0:
            raise RuntimeError(
                f"Failed to set {interface} to channel {channel}: {out} {err}"
            )
        logger.info("Pinned %s to channel %s", interface, channel)

    def stop_capture(self) -> None:
        if self._capture_channel is not None:
            try:
                self._capture_channel.close()
            except Exception:  # noqa: BLE001
                pass
            self._capture_channel = None
