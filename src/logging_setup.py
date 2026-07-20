"""Structured JSON logging for SOC-friendly pipelines."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if hasattr(record, "event"):
            payload["event"] = record.event
        if hasattr(record, "extra_fields"):
            payload.update(record.extra_fields)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(json_logs: bool = False, level: int = logging.INFO) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    if json_logs:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
    root.addHandler(handler)
    root.setLevel(level)


def log_alert(logger: logging.Logger, alert_dict: dict) -> None:
    """Emit a structured alert event (works with both text and JSON formatters)."""
    logger.warning(
        "ALERT [%s] %s — %s",
        alert_dict.get("severity"),
        alert_dict.get("title"),
        alert_dict.get("evidence"),
        extra={
            "event": "wids_alert",
            "extra_fields": {
                "alert_type": alert_dict.get("alert_type"),
                "severity": alert_dict.get("severity"),
                "bssid": alert_dict.get("bssid"),
                "ssid": alert_dict.get("ssid"),
                "severity_score": (alert_dict.get("metadata") or {}).get(
                    "severity_score"
                ),
            },
        },
    )
