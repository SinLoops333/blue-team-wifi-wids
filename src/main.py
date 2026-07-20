#!/usr/bin/env python3
"""WIDS entry point — passive Wi-Fi intrusion detection.

Usage examples:
  python -m src.main --offline data/captures/sample.pcap
  python -m src.main --train-baseline
  python -m src.main                 # live capture from Pineapple
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time
from pathlib import Path

# Allow `python -m src.main` and `python src/main.py` from wids/
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.alerts.alert import AlertDeduper
from src.alerts.policy import AlertPolicy
from src.alerts.store import EventStore
from src.capture.live_sniffer import LiveSniffer
from src.capture.multi_radio import DualRadioSniffer, RadioSpec
from src.capture.pineapple_ssh import PineappleSSH
from src.config import Config, get_config
from src.dashboard.app import create_app
from src.detect.anomaly import AnomalyDetector
from src.detect.baseline import BaselineStore
from src.detect.frame_features import FeatureExtractor, parse_frame
from src.detect.fusion import RadioFusionEngine
from src.detect.honeypot import HoneypotEngine
from src.detect.signatures import SignatureEngine
from src.logging_setup import configure_logging, log_alert

logger = logging.getLogger("wids")


class WIDSEngine:
    """Wire capture → features → signatures/anomaly → alerts → store."""

    def __init__(
        self,
        config: Config,
        train_baseline: bool = False,
        channel: int | None = None,
    ):
        self.config = config
        self.train_baseline = train_baseline
        # CLI --channel overrides config capture.channel
        self.channel = (
            channel if channel is not None else config.capture_channel
        )
        self.running = False

        db_path = config.path(config.store.get("db_path", "data/events.db"))
        self.store = EventStore(db_path)

        inv_path = config.path(
            config.anomaly.get("inventory_path", "models/ap_inventory.json")
        )
        model_path = config.path(
            config.anomaly.get("model_path", "models/baseline.pkl")
        )
        self.baseline = BaselineStore(inv_path, model_path)
        self.baseline.load()

        window = float(config.anomaly.get("window_seconds", 30))
        self.extractor = FeatureExtractor(window_seconds=window)
        self.signatures = SignatureEngine(config)
        if self.baseline.inventory:
            self.signatures.load_baseline_inventory(self.baseline.inventory)

        self.anomaly = AnomalyDetector(config, self.baseline)
        self.anomaly.load()

        self.fusion = RadioFusionEngine(config)
        self.honeypot = HoneypotEngine(config)
        if self.honeypot.enabled():
            self.honeypot.load_or_train_default()

        dedup_s = float(config.alerts.get("dedup_seconds", 60))
        self.deduper = AlertDeduper(dedup_seconds=dedup_s)
        self.policy = AlertPolicy.from_config(config.alerts)

        self._ssh: PineappleSSH | None = None
        self._ssh_secondary: PineappleSSH | None = None
        self._sniffer: LiveSniffer | None = None
        self._dual: DualRadioSniffer | None = None
        self._last_window_eval = 0.0
        self._frames_since_stats = 0
        self._replay_wallclock = False

    def _emit(self, alerts) -> None:
        for alert in alerts:
            filtered = self.policy.filter(alert)
            if filtered is None:
                continue
            if not self.deduper.should_emit(filtered):
                continue
            self.store.insert_alert(filtered)
            log_alert(logger, filtered.to_dict())

    def on_frame(self, pkt, radio_id: str | None = None) -> None:
        ts = time.time() if self._replay_wallclock else None
        event = parse_frame(pkt, timestamp=ts, radio_id=radio_id)
        if event is None:
            return
        self.extractor.ingest(event)
        self._frames_since_stats += 1

        alerts = self.signatures.process(event, self.extractor)
        alerts.extend(self.fusion.process(event))
        alerts.extend(self.honeypot.process(event))
        self._emit(alerts)

        now = event.timestamp
        # Periodic window evaluation for anomaly + inventory sync
        if now - self._last_window_eval >= 5.0:
            self._last_window_eval = now
            windows = self.extractor.window_features(now=now)
            if self.train_baseline or self.anomaly.model is None:
                self.anomaly.observe(windows)
                self.anomaly.maybe_train()
            else:
                self._emit(self.anomaly.evaluate(windows))

            self.baseline.update_from_inventory(self.extractor.ap_inventory)
            self.store.update_ap_inventory(self.extractor.ap_inventory)
            self.store.update_frame_stats(
                self.extractor.total_frames, dict(self.extractor.frame_counts)
            )

            if self.train_baseline and self.extractor.total_frames % 500 == 0:
                self.baseline.save_inventory()

    def start_dashboard(self) -> threading.Thread:
        host = self.config.dashboard.get("host", "127.0.0.1")
        port = int(self.config.dashboard.get("port", 8080))
        app = create_app(self.store)

        def _run():
            logger.info("Dashboard at http://%s:%s", host, port)
            app.run(host=host, port=port, threaded=True, use_reloader=False)

        t = threading.Thread(target=_run, name="wids-dashboard", daemon=True)
        t.start()
        return t

    def run(
        self,
        offline_pcap: str | None = None,
        no_dashboard: bool = False,
        *,
        replay_loop: bool = False,
        replay_delay: float = 0.0,
    ) -> None:
        self.running = True
        if not no_dashboard:
            self.start_dashboard()

        if offline_pcap:
            self._sniffer = LiveSniffer()
            if replay_loop:
                # Re-emit alerts each pass so the terminal/dashboard stay lively
                self.deduper = AlertDeduper(dedup_seconds=2.0)
                self._replay_wallclock = True
                logger.info(
                    "Replay loop: %s (delay=%.2fs between frames, Ctrl+C to stop)",
                    offline_pcap,
                    replay_delay,
                )
            else:
                logger.info("Offline mode: %s", offline_pcap)
            try:
                self._sniffer.run(
                    self.on_frame,
                    offline_pcap=offline_pcap,
                    replay_loop=replay_loop,
                    replay_delay=replay_delay,
                )
            finally:
                self._finalize()
            return

        if not self.config.pineapple_password:
            raise SystemExit(
                "PINEAPPLE_PASSWORD not set. Copy wids/.env.example to wids/.env"
            )

        fusion_on = bool(self.config.fusion.get("enabled", False))
        self._ssh = PineappleSSH(
            host=self.config.pineapple_ip,
            username=self.config.pineapple_user,
            password=self.config.pineapple_password,
            port=self.config.pineapple_ssh_port,
            timeout=self.config.ssh_timeout,
        )

        if fusion_on:
            self._run_dual_radio()
            return

        self._sniffer = LiveSniffer(
            ssh=self._ssh,
            interface=self.config.capture_interface,
            snaplen=self.config.capture_snaplen,
            ensure_monitor=True,
            channel=self.channel,
        )
        logger.info(
            "Live capture from %s iface=%s channel=%s",
            self.config.pineapple_ip,
            self.config.capture_interface,
            self.channel if self.channel is not None else "(unchanged)",
        )
        try:
            self._sniffer.run(self.on_frame)
        except RuntimeError as exc:
            logger.error("%s", exc)
            raise SystemExit(1) from exc
        finally:
            self._finalize()

    def _run_dual_radio(self) -> None:
        assert self._ssh is not None
        primary_iface = self.config.capture_interface
        # Resolve primary first so we know which monitor to avoid for secondary
        try:
            primary_iface = self._ssh.resolve_capture_interface(primary_iface)
        except RuntimeError as exc:
            logger.error("%s", exc)
            raise SystemExit(1) from exc

        secondary_req = str(
            self.config.fusion.get("secondary_interface") or "auto"
        )
        monitors = self._ssh.list_monitor_interfaces()
        if secondary_req.lower() == "auto":
            secondary_iface = next(
                (m for m in monitors if m != primary_iface), None
            )
            if not secondary_iface:
                raise SystemExit(
                    "Fusion enabled but no second monitor-mode radio found. "
                    "Put another Mark VII radio in monitor/Recon mode, or set "
                    "fusion.secondary_interface explicitly."
                )
        else:
            secondary_iface = secondary_req

        hop = self.config.fusion.get("hop_channels") or [1, 6, 11]
        hop_channels = [int(c) for c in hop] if hop else None
        hop_s = float(self.config.fusion.get("hop_seconds", 2.0))
        sec_ch = self.config.fusion.get("secondary_channel")
        if sec_ch is not None:
            hop_channels = None
            secondary_channel = int(sec_ch)
        else:
            secondary_channel = None

        self._ssh_secondary = PineappleSSH(
            host=self.config.pineapple_ip,
            username=self.config.pineapple_user,
            password=self.config.pineapple_password,
            port=self.config.pineapple_ssh_port,
            timeout=self.config.ssh_timeout,
        )

        primary = RadioSpec(
            radio_id="primary",
            interface=primary_iface,
            channel=self.channel,
        )
        secondary = RadioSpec(
            radio_id="secondary",
            interface=secondary_iface,
            channel=secondary_channel,
            hop_channels=hop_channels,
            hop_seconds=hop_s,
        )
        self._dual = DualRadioSniffer(
            primary_ssh=self._ssh,
            secondary_ssh=self._ssh_secondary,
            primary=primary,
            secondary=secondary,
            snaplen=self.config.capture_snaplen,
        )
        logger.info(
            "Dual-radio fusion: primary=%s ch=%s | secondary=%s hop=%s",
            primary_iface,
            self.channel,
            secondary_iface,
            hop_channels or secondary_channel,
        )
        try:
            self._dual.run(self.on_frame)
        except RuntimeError as exc:
            logger.error("%s", exc)
            raise SystemExit(1) from exc
        finally:
            self._finalize()

    def stop(self) -> None:
        self.running = False
        if self._dual:
            self._dual.stop()
        if self._sniffer:
            self._sniffer.stop()
        if self._ssh:
            self._ssh.close()
        if self._ssh_secondary:
            self._ssh_secondary.close()

    def _finalize(self) -> None:
        self.store.update_ap_inventory(self.extractor.ap_inventory)
        self.store.update_frame_stats(
            self.extractor.total_frames, dict(self.extractor.frame_counts)
        )
        if self.train_baseline:
            self.baseline.save_inventory()
            self.anomaly.maybe_train()
            if self.anomaly.model is not None:
                self.anomaly.save()
            logger.info(
                "Baseline saved (%d APs, %d frames)",
                len(self.baseline.inventory),
                self.extractor.total_frames,
            )
        if self._dual:
            self._dual.stop()
        if self._ssh:
            self._ssh.close()
        if self._ssh_secondary:
            self._ssh_secondary.close()
        logger.info("WIDS stopped. Processed %d frames.", self.extractor.total_frames)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Blue-team Wi-Fi WIDS (passive only)")
    p.add_argument(
        "--offline",
        metavar="PCAP",
        help="Analyze a local pcap instead of live Pineapple capture",
    )
    p.add_argument(
        "--train-baseline",
        action="store_true",
        help="Treat capture as quiet baseline; fit IsolationForest + save AP inventory",
    )
    p.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Do not start the Flask dashboard",
    )
    p.add_argument(
        "--config",
        metavar="YAML",
        help="Path to wids.yaml (default: config/wids.yaml)",
    )
    p.add_argument(
        "--channel",
        type=int,
        metavar="N",
        help="Pin monitor radio to channel N (e.g. 11 for Open999 lab tests)",
    )
    p.add_argument(
        "--keep-dashboard",
        action="store_true",
        help="After offline pcap finishes, keep dashboard up until Ctrl+C",
    )
    p.add_argument(
        "--replay-loop",
        action="store_true",
        help="With --offline: loop the pcap forever (demo / recording)",
    )
    p.add_argument(
        "--replay-delay",
        type=float,
        default=0.15,
        metavar="SEC",
        help="Seconds between frames when --replay-loop (default 0.15)",
    )
    p.add_argument(
        "--fusion",
        action="store_true",
        help="Enable dual-radio fusion (overrides config fusion.enabled)",
    )
    p.add_argument(
        "--json-logs",
        action="store_true",
        help="Emit structured JSON logs (SOC / pipeline friendly)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(json_logs=args.json_logs)
    if args.config:
        config = Config(yaml_path=Path(args.config))
    else:
        config = get_config()

    if args.replay_loop and not args.offline:
        raise SystemExit("--replay-loop requires --offline PCAP")
    if args.fusion:
        config.fusion = dict(config.fusion or {})
        config.fusion["enabled"] = True

    engine = WIDSEngine(
        config,
        train_baseline=args.train_baseline,
        channel=args.channel,
    )

    def _sig(_signum, _frame):
        logger.info("Signal received, shutting down…")
        engine.stop()

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    try:
        engine.run(
            offline_pcap=args.offline,
            no_dashboard=args.no_dashboard,
            replay_loop=args.replay_loop,
            replay_delay=args.replay_delay,
        )
        if (
            args.offline
            and args.keep_dashboard
            and not args.no_dashboard
            and not args.replay_loop
        ):
            logger.info(
                "Offline analysis done — dashboard still at http://%s:%s (Ctrl+C to quit)",
                config.dashboard.get("host", "127.0.0.1"),
                config.dashboard.get("port", 8080),
            )
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
    except KeyboardInterrupt:
        engine.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
