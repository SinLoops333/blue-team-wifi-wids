"""Dual-radio live capture for Mark VII sensor fusion."""

from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass
from typing import Callable, List, Optional

from scapy.all import Packet  # type: ignore

from .live_sniffer import LiveSniffer
from .pineapple_ssh import PineappleSSH

logger = logging.getLogger(__name__)

TaggedCallback = Callable[[Packet, str], None]


@dataclass
class RadioSpec:
    radio_id: str
    interface: str
    channel: Optional[int] = None
    hop_channels: Optional[List[int]] = None
    hop_seconds: float = 2.0


class DualRadioSniffer:
    """Run two LiveSniffer streams; invoke callback(pkt, radio_id)."""

    def __init__(
        self,
        primary_ssh: PineappleSSH,
        secondary_ssh: PineappleSSH,
        primary: RadioSpec,
        secondary: RadioSpec,
        snaplen: int = 512,
    ):
        self.primary_ssh = primary_ssh
        self.secondary_ssh = secondary_ssh
        self.primary = primary
        self.secondary = secondary
        self.snaplen = snaplen
        self._stop = threading.Event()
        self._sniffers: list[LiveSniffer] = []
        self._threads: list[threading.Thread] = []

    def stop(self) -> None:
        self._stop.set()
        for s in self._sniffers:
            s.stop()

    def run(self, on_frame: TaggedCallback) -> None:
        self._stop.clear()
        q: queue.Queue = queue.Queue(maxsize=2000)

        def _pump(spec: RadioSpec, ssh: PineappleSSH) -> None:
            sniffer = LiveSniffer(
                ssh=ssh,
                interface=spec.interface,
                snaplen=self.snaplen,
                ensure_monitor=True,
                channel=spec.channel if not spec.hop_channels else None,
            )
            self._sniffers.append(sniffer)
            try:
                for pkt in sniffer.iter_frames():
                    if self._stop.is_set():
                        break
                    try:
                        q.put((spec.radio_id, pkt), timeout=1)
                    except queue.Full:
                        pass
            except Exception:  # noqa: BLE001
                logger.exception("Radio %s capture failed", spec.radio_id)
            finally:
                try:
                    q.put((spec.radio_id, None), timeout=1)
                except queue.Full:
                    pass

        def _hopper(spec: RadioSpec, ssh: PineappleSSH) -> None:
            if not spec.hop_channels:
                return
            # Wait until iface is resolved by sniffer
            iface = spec.interface
            idx = 0
            while not self._stop.wait(spec.hop_seconds):
                ch = spec.hop_channels[idx % len(spec.hop_channels)]
                idx += 1
                try:
                    # Prefer resolved monitor iface from sniffers if available
                    for s in self._sniffers:
                        if s.ssh is ssh and s.interface:
                            iface = s.interface
                            break
                    ssh.set_channel(iface, ch)
                    logger.info(
                        "Fusion hop: %s (%s) → channel %s",
                        spec.radio_id,
                        iface,
                        ch,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Channel hop failed: %s", exc)

        t1 = threading.Thread(
            target=_pump,
            args=(self.primary, self.primary_ssh),
            name="wids-radio-primary",
            daemon=True,
        )
        t2 = threading.Thread(
            target=_pump,
            args=(self.secondary, self.secondary_ssh),
            name="wids-radio-secondary",
            daemon=True,
        )
        self._threads = [t1, t2]
        t1.start()
        t2.start()

        hop = None
        if self.secondary.hop_channels:
            hop = threading.Thread(
                target=_hopper,
                args=(self.secondary, self.secondary_ssh),
                name="wids-radio-hop",
                daemon=True,
            )
            hop.start()
            self._threads.append(hop)

        finished = 0
        while finished < 2 and not self._stop.is_set():
            try:
                radio_id, pkt = q.get(timeout=0.5)
            except queue.Empty:
                if not t1.is_alive() and not t2.is_alive():
                    break
                continue
            if pkt is None:
                finished += 1
                continue
            try:
                on_frame(pkt, radio_id)
            except Exception:  # noqa: BLE001
                logger.exception("Error in fusion frame callback")

        self.stop()
        for t in self._threads:
            t.join(timeout=2)
