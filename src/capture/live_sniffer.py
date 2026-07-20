"""Live and offline 802.11 frame sniffers (Scapy)."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Callable, Iterator, Optional, Union

from scapy.all import Packet  # type: ignore
from scapy.utils import PcapReader  # type: ignore

from .pineapple_ssh import PineappleSSH

logger = logging.getLogger(__name__)

FrameCallback = Callable[[Packet], None]


class LiveSniffer:
    """Yield Scapy packets from a live SSH tcpdump stream or a local pcap."""

    def __init__(
        self,
        ssh: Optional[PineappleSSH] = None,
        interface: str = "wlan1mon",
        snaplen: int = 256,
        ensure_monitor: bool = True,
        channel: Optional[int] = None,
    ):
        self.ssh = ssh
        self.interface = interface
        self.snaplen = snaplen
        self.ensure_monitor = ensure_monitor
        self.channel = channel
        self._stop = threading.Event()
        self._stream = None
        self._reader: Optional[PcapReader] = None

    def stop(self) -> None:
        self._stop.set()
        if self.ssh is not None:
            self.ssh.stop_capture()
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:  # noqa: BLE001
                pass
            self._reader = None

    def frames_from_pcap(self, path: Union[str, Path]) -> Iterator[Packet]:
        """Iterate frames from a local pcap file (offline / test mode)."""
        path = Path(path)
        logger.info("Reading offline pcap: %s", path)
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                if self._stop.is_set():
                    break
                yield pkt

    def frames_live(self) -> Iterator[Packet]:
        """Iterate frames from a remote tcpdump over SSH."""
        if self.ssh is None:
            raise RuntimeError("LiveSniffer requires a PineappleSSH instance for live capture")

        if self.ensure_monitor:
            iface = self.ssh.resolve_capture_interface(self.interface)
        else:
            iface = self.interface
        self.interface = iface

        if self.channel is not None:
            self.ssh.set_channel(iface, int(self.channel))

        stream = self.ssh.start_tcpdump_stream(iface, snaplen=self.snaplen)
        self._stream = stream
        try:
            reader = PcapReader(stream)
        except Exception as exc:  # noqa: BLE001
            # tcpdump often exits immediately if the iface is wrong; surface stderr
            err = ""
            if self.ssh._capture_channel is not None:
                try:
                    err = (
                        self.ssh._capture_channel.recv_stderr(4096)
                        .decode("utf-8", errors="replace")
                        .strip()
                    )
                except Exception:  # noqa: BLE001
                    pass
            self.stop()
            raise RuntimeError(
                f"Failed to read pcap stream from {iface}: {exc}. "
                f"tcpdump stderr: {err or '(empty)'}"
            ) from exc

        self._reader = reader
        logger.info("Live capture started on %s", iface)
        try:
            for pkt in reader:
                if self._stop.is_set():
                    break
                yield pkt
        except (EOFError, OSError, ValueError) as exc:
            if not self._stop.is_set():
                logger.warning("Capture stream ended: %s", exc)
        finally:
            self.stop()

    def iter_frames(
        self, offline_pcap: Optional[Union[str, Path]] = None
    ) -> Iterator[Packet]:
        if offline_pcap:
            yield from self.frames_from_pcap(offline_pcap)
        else:
            yield from self.frames_live()

    def run(
        self,
        on_frame: FrameCallback,
        offline_pcap: Optional[Union[str, Path]] = None,
    ) -> None:
        """Blocking loop: call *on_frame* for every packet until stopped."""
        self._stop.clear()
        for pkt in self.iter_frames(offline_pcap=offline_pcap):
            if self._stop.is_set():
                break
            try:
                on_frame(pkt)
            except Exception:  # noqa: BLE001
                logger.exception("Error in frame callback")
