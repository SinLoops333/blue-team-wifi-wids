#!/usr/bin/env python3
"""Health / status check for WIDS + Pineapple connectivity."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.alerts.store import EventStore
from src.capture.pineapple_ssh import PineappleSSH
from src.config import get_config
from src.engagement.session import load_engagement_config, load_session
from src.lab.scope import LabScope, ScopeError, load_lab_config

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("wids.status")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="WIDS health check")
    p.add_argument("--no-ssh", action="store_true", help="Skip Pineapple SSH checks")
    args = p.parse_args(argv)

    cfg = get_config()
    ok = True
    print("=== WIDS status ===")
    print(f"Pineapple: {cfg.pineapple_ip}:{cfg.pineapple_ssh_port}")
    print(f"Capture:   iface={cfg.capture_interface} channel={cfg.capture_channel}")
    print(f"Allowlist: {len(cfg.allowlist_bssids)} BSSIDs, {len(cfg.allowlist_ssids)} SSIDs")
    print(f"Password:  {'set' if cfg.pineapple_password else 'MISSING'}")
    if not cfg.pineapple_password:
        ok = False

    model = cfg.path(cfg.anomaly.get("model_path", "models/baseline.pkl"))
    inv = cfg.path(cfg.anomaly.get("inventory_path", "models/ap_inventory.json"))
    print(f"Model:     {'yes' if model.exists() else 'no'} ({model})")
    print(f"Inventory: {'yes' if inv.exists() else 'no'} ({inv})")

    db = cfg.path(cfg.store.get("db_path", "data/events.db"))
    store = EventStore(db)
    alerts = store.recent_alerts(limit=5)
    stats = store.get_stats()
    print(f"DB:        {db}  recent_alerts={len(alerts)} frames_total={stats.get('frames_total')}")

    try:
        lab_cfg, _ = load_lab_config(wids_config=cfg)
        scope = LabScope(lab_cfg, cfg)
        print(f"Lab:       OK — {len(scope.lab.targets)} target(s)")
        for t in scope.lab.targets:
            print(f"           - {t.bssid} ssid={t.ssid!r} ch={t.channel}")
    except ScopeError as exc:
        print(f"Lab:       FAIL — {exc}")
        ok = False

    try:
        eng = load_engagement_config()
        sess = load_session(eng)
        print(f"Engagement:{eng.name}")
        if sess:
            print(f"           session={sess.session_id} active={sess.active}")
        else:
            print("           session=(none)")
    except Exception as exc:  # noqa: BLE001
        print(f"Engagement: {exc}")

    if not args.no_ssh and cfg.pineapple_password:
        try:
            ssh = PineappleSSH(
                cfg.pineapple_ip,
                cfg.pineapple_user,
                cfg.pineapple_password,
                cfg.pineapple_ssh_port,
                timeout=cfg.ssh_timeout,
            )
            ssh.connect()
            monitors = ssh.list_monitor_interfaces()
            ifaces = ssh.list_interfaces()
            print(f"SSH:       OK")
            print(f"Ifaces:    {', '.join(ifaces)}")
            print(f"Monitor:   {', '.join(monitors) or '(none)'}")
            ssh.close()
            if not monitors:
                ok = False
        except Exception as exc:  # noqa: BLE001
            print(f"SSH:       FAIL — {exc}")
            ok = False
    elif args.no_ssh:
        print("SSH:       skipped")

    print("===", "READY" if ok else "ISSUES FOUND", "===")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
