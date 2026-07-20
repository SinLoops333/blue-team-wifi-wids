"""Alert / audit export helpers (JSON, CSV, HTML)."""

from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from typing import Any, Iterable


def export_alerts_json(alerts: list[dict], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2, default=str)
    return path


def export_alerts_csv(alerts: list[dict], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "id",
        "timestamp",
        "alert_type",
        "severity",
        "title",
        "evidence",
        "bssid",
        "ssid",
        "channel",
        "source_mac",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for a in alerts:
            w.writerow(a)
    return path


def export_jsonl(entries: Iterable[dict], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, default=str) + "\n")
    return path


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_html_report(
    path: Path,
    *,
    title: str,
    engagement: dict[str, Any] | None,
    alerts: list[dict],
    audit: list[dict],
    inventory: list[dict] | None = None,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    eng = engagement or {}
    inv = inventory or []

    def esc(s: Any) -> str:
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    alert_rows = "".join(
        f"<tr><td>{esc(a.get('timestamp'))}</td>"
        f"<td>{esc(a.get('severity'))}</td>"
        f"<td>{esc(a.get('alert_type'))}</td>"
        f"<td>{esc(a.get('title'))}</td>"
        f"<td>{esc(a.get('evidence'))}</td></tr>"
        for a in alerts
    )
    audit_rows = "".join(
        "<tr><td>"
        + esc(e.get("timestamp"))
        + "</td><td>"
        + esc(e.get("event"))
        + "</td><td><code>"
        + esc(
            json.dumps(
                {k: v for k, v in e.items() if k not in ("timestamp", "event")},
                default=str,
            )[:240]
        )
        + "</code></td></tr>"
        for e in audit
    )
    inv_rows = "".join(
        f"<tr><td>{esc(a.get('ssid'))}</td><td>{esc(a.get('bssid'))}</td>"
        f"<td>{esc(a.get('channel'))}</td><td>{esc(a.get('encryption'))}</td></tr>"
        for a in inv
    )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{esc(title)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #0b1220; color: #e8eefc; }}
h1,h2 {{ color: #8b9bb8; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }}
th, td {{ border: 1px solid #243049; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.9rem; }}
th {{ background: #121a2b; }}
code {{ font-size: 0.75rem; }}
.meta {{ color: #8b9bb8; }}
</style></head><body>
<h1>{esc(title)}</h1>
<p class="meta">Generated {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<h2>Engagement</h2>
<pre>{esc(json.dumps(eng, indent=2, default=str))}</pre>
<h2>Alerts ({len(alerts)})</h2>
<table><tr><th>Time</th><th>Severity</th><th>Type</th><th>Title</th><th>Evidence</th></tr>
{alert_rows or '<tr><td colspan="5">None</td></tr>'}
</table>
<h2>Lab audit ({len(audit)})</h2>
<table><tr><th>Time</th><th>Event</th><th>Details</th></tr>
{audit_rows or '<tr><td colspan="3">None</td></tr>'}
</table>
<h2>AP inventory snapshot ({len(inv)})</h2>
<table><tr><th>SSID</th><th>BSSID</th><th>Ch</th><th>Enc</th></tr>
{inv_rows or '<tr><td colspan="4">None</td></tr>'}
</table>
</body></html>"""
    path.write_text(html, encoding="utf-8")
    return path
