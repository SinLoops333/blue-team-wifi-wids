#!/usr/bin/env python3
"""Phase 2 isolated lab CLI — attacks only against owned / allowlisted targets.

Examples:
  python -m src.lab_main --list
  python -m src.lab_main --attack deauth --dry-run
  python -m src.lab_main --attack deauth
  python -m src.lab_main --simulate all --yes
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.lab.attacks.simulate import SIMULATE_CHOICES
from src.lab.runner import LabRunner
from src.lab.scope import ScopeError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wids.lab")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Isolated Wi-Fi lab. Live attacks only hit BSSIDs in lab.targets "
            "AND wids allowlist."
        )
    )
    p.add_argument("--list", action="store_true", help="Show lab scope / targets")
    p.add_argument(
        "--attack",
        choices=["deauth"],
        help="Live RF attack (deauth via aireplay-ng)",
    )
    p.add_argument(
        "--simulate",
        choices=list(SIMULATE_CHOICES),
        help="Write scoped pcap(s) to validate WIDS (no live RF)",
    )
    p.add_argument("--target", help="Target BSSID (must be a lab target)")
    p.add_argument("--count", type=int, help="Deauth frame count")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--yes", action="store_true", help="Skip CONFIRM (still audited)")
    p.add_argument("--lab-config", type=Path)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        runner = LabRunner.from_config(args.lab_config)
    except ScopeError as exc:
        logger.error("Scope error: %s", exc)
        return 1

    if args.list or (not args.attack and not args.simulate):
        print(runner.scope.describe())
        if not args.attack and not args.simulate:
            print(
                "\nLive:\n"
                "  python -m src.lab_main --attack deauth --dry-run\n"
                "  python -m src.lab_main --attack deauth\n"
                "\nSimulate:\n"
                f"  python -m src.lab_main --simulate all --yes\n"
                f"  choices: {', '.join(SIMULATE_CHOICES)}\n"
                "\nMonitor (pin ch 11 for Open999 lab):\n"
                "  python -m src.main --channel 11\n"
            )
        return 0

    try:
        if args.simulate:
            return runner.run_simulate(args.simulate, assume_yes=args.yes)
        if args.attack == "deauth":
            return runner.run_live_deauth(
                args.target,
                count=args.count,
                dry_run=args.dry_run,
                assume_yes=args.yes,
            )
    except ScopeError as exc:
        logger.error("REFUSED by scope guard: %s", exc)
        runner.audit.record(
            "scope_refusal", error=str(exc), attack=args.attack or args.simulate
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
