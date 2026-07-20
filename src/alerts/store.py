"""SQLite storage for alerts, AP inventory snapshots, and frame counters."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .alert import Alert, AlertSeverity


class EventStore:
    """Thread-safe sqlite-backed store with optional live listeners."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._listeners: List[Callable[[Alert], None]] = []
        self._stats = {
            "frames_total": 0,
            "frame_counts": {},
            "started_at": time.time(),
        }
        self._ap_inventory: Dict[str, dict] = {}
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        alert_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        evidence TEXT NOT NULL,
                        bssid TEXT,
                        ssid TEXT,
                        channel INTEGER,
                        source_mac TEXT,
                        metadata TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp DESC);
                    CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);

                    CREATE TABLE IF NOT EXISTS frame_stats (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        frames_total INTEGER NOT NULL DEFAULT 0,
                        frame_counts TEXT NOT NULL DEFAULT '{}',
                        updated_at REAL
                    );
                    INSERT OR IGNORE INTO frame_stats (id, frames_total, frame_counts)
                    VALUES (1, 0, '{}');
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def add_listener(self, callback: Callable[[Alert], None]) -> None:
        self._listeners.append(callback)

    def insert_alert(self, alert: Alert) -> Alert:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    """
                    INSERT INTO alerts
                    (timestamp, alert_type, severity, title, evidence,
                     bssid, ssid, channel, source_mac, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.timestamp,
                        alert.alert_type,
                        alert.severity.value
                        if isinstance(alert.severity, AlertSeverity)
                        else str(alert.severity),
                        alert.title,
                        alert.evidence,
                        alert.bssid,
                        alert.ssid,
                        alert.channel,
                        alert.source_mac,
                        json.dumps(alert.metadata or {}),
                    ),
                )
                conn.commit()
                alert.id = int(cur.lastrowid)
            finally:
                conn.close()
        for cb in list(self._listeners):
            try:
                cb(alert)
            except Exception:  # noqa: BLE001
                pass
        return alert

    def recent_alerts(self, limit: int = 100) -> List[dict]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
                return [self._row_to_alert_dict(r) for r in rows]
            finally:
                conn.close()

    def alerts_since(self, since_ts: float, limit: int = 200) -> List[dict]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM alerts
                    WHERE timestamp > ?
                    ORDER BY timestamp ASC
                    LIMIT ?
                    """,
                    (since_ts, limit),
                ).fetchall()
                return [self._row_to_alert_dict(r) for r in rows]
            finally:
                conn.close()

    @staticmethod
    def _row_to_alert_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        meta = d.get("metadata")
        if isinstance(meta, str):
            try:
                d["metadata"] = json.loads(meta)
            except json.JSONDecodeError:
                d["metadata"] = {}
        return d

    def update_frame_stats(
        self, total: int, frame_counts: Dict[str, int]
    ) -> None:
        with self._lock:
            self._stats["frames_total"] = total
            self._stats["frame_counts"] = dict(frame_counts)
            conn = self._connect()
            try:
                conn.execute(
                    """
                    UPDATE frame_stats
                    SET frames_total = ?, frame_counts = ?, updated_at = ?
                    WHERE id = 1
                    """,
                    (total, json.dumps(frame_counts), time.time()),
                )
                conn.commit()
            finally:
                conn.close()

    def update_ap_inventory(self, inventory: Dict[str, dict]) -> None:
        with self._lock:
            self._ap_inventory = {k: dict(v) for k, v in inventory.items()}

    def get_ap_inventory(self) -> List[dict]:
        with self._lock:
            return sorted(
                self._ap_inventory.values(),
                key=lambda x: x.get("ssid") or x.get("bssid") or "",
            )

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "frames_total": self._stats["frames_total"],
                "frame_counts": dict(self._stats["frame_counts"]),
                "started_at": self._stats["started_at"],
                "uptime_seconds": time.time() - self._stats["started_at"],
                "ap_count": len(self._ap_inventory),
            }
