#!/usr/bin/env python3
"""Authorized engagement CLI — RoE checklist, session lifecycle, reports.

Examples:
  python -m src.engagement_main start
  python -m src.engagement_main status
  python -m src.engagement_main export
  python -m src.engagement_main end
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.alerts.store import EventStore
from src.config import get_config
from src.engagement.session import (
    end_session,
    load_engagement_config,
    load_session,
    start_session,
)
from src.lab.scope import load_lab_config
from src.reporting.export import (
    export_alerts_csv,
    export_alerts_json,
    read_jsonl,
    write_html_report,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wids.engagement")


def cmd_start(args) -> int:
    cfg = load_engagement_config(args.config)
    existing = load_session(cfg)
    if existing and existing.active and not args.force:
        logger.error(
            "Session %s already active. Use --force to replace, or: end",
            existing.session_id,
        )
        return 1
    try:
        session = start_session(cfg, assume_yes=args.yes)
    except RuntimeError as exc:
        logger.error("%s", exc)
        return 1
    logger.info(
        "Engagement session %s started (%s)", session.session_id, session.name
    )
    print(f"\nSession ID: {session.session_id}")
    print("Next:")
    print("  python -m src.main --channel 11")
    print("  python -m src.lab_main --attack deauth")
    print("  python -m src.engagement_main export")
    print("  python -m src.engagement_main end")
    return 0


def cmd_status(args) -> int:
    cfg = load_engagement_config(args.config)
    session = load_session(cfg)
    print(f"Engagement: {cfg.name}")
    print(f"Operator:   {cfg.operator}")
    print(f"Authz:      {cfg.authorization}")
    print(f"Allowed:    {', '.join(cfg.allowed_actions)}")
    if session is None:
        print("Session:    (none)")
        return 0
    print(f"Session:    {session.session_id}  active={session.active}")
    print(f"Started:    {time.ctime(session.started_at)}")
    if session.ended_at:
        print(f"Ended:      {time.ctime(session.ended_at)}")
    print(f"RoE items:  {len(session.roe_acknowledged)}")
    return 0


def cmd_export(args) -> int:
    cfg = load_engagement_config(args.config)
    session = load_session(cfg)
    wids = get_config()
    store = EventStore(wids.path(wids.store.get("db_path", "data/events.db")))
    alerts = store.recent_alerts(limit=args.limit)
    try:
        lab_cfg, _ = load_lab_config()
        audit = read_jsonl(lab_cfg.audit_log)
    except Exception:  # noqa: BLE001
        audit = []

    stamp = time.strftime("%Y%m%d_%H%M%S")
    out_dir = cfg.report_dir / (session.session_id if session else "ad_hoc")
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = export_alerts_json(alerts, out_dir / f"alerts_{stamp}.json")
    csv_path = export_alerts_csv(alerts, out_dir / f"alerts_{stamp}.csv")
    html_path = write_html_report(
        out_dir / f"report_{stamp}.html",
        title=f"{cfg.name} — engagement report",
        engagement={
            "config": {
                "name": cfg.name,
                "operator": cfg.operator,
                "authorization": cfg.authorization,
            },
            "session": session.to_dict() if session else None,
        },
        alerts=alerts,
        audit=audit,
        inventory=store.get_ap_inventory(),
    )
    logger.info("Wrote %s", json_path)
    logger.info("Wrote %s", csv_path)
    logger.info("Wrote %s", html_path)
    print(f"Report directory: {out_dir}")
    return 0


def cmd_end(args) -> int:
    cfg = load_engagement_config(args.config)
    session = end_session(cfg)
    if session is None:
        logger.error("No session to end")
        return 1
    logger.info("Session %s ended", session.session_id)
    if not args.no_export:
        args.limit = getattr(args, "limit", 500)
        return cmd_export(args)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Authorized WIDS engagement CLI")
    p.add_argument("--config", type=Path, help="Path to engagement.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("start", help="Start session after RoE checklist")
    s.add_argument("--force", action="store_true", help="Replace active session")
    s.add_argument(
        "--yes",
        action="store_true",
        help="Auto-acknowledge all RoE items (logged in session file)",
    )
    s.set_defaults(func=cmd_start)

    s = sub.add_parser("status", help="Show engagement / session status")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("export", help="Export alerts + audit HTML/JSON/CSV report")
    s.add_argument("--limit", type=int, default=500, help="Max alerts to include")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("end", help="End session and export report")
    s.add_argument("--no-export", action="store_true")
    s.add_argument("--limit", type=int, default=500)
    s.set_defaults(func=cmd_end)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
