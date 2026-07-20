"""In-process metrics for Prometheus scrape + JSON API."""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any, Dict


class MetricsRegistry:
    """Minimal counters/gauges — no prometheus_client dependency required."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started_at = time.time()
        self.frames_total = 0
        self.alerts_total = 0
        self.alerts_by_type: Dict[str, int] = defaultdict(int)
        self.frames_by_type: Dict[str, int] = defaultdict(int)
        self.drift_psi: float = 0.0
        self.drift_events = 0
        self.fusion_disagreements = 0
        self.honeypot_recon = 0
        self.privacy_alerts = 0
        self.localization_updates = 0

    def inc_frame(self, frame_type: str | None = None) -> None:
        with self._lock:
            self.frames_total += 1
            if frame_type:
                self.frames_by_type[frame_type] += 1

    def inc_alert(self, alert_type: str) -> None:
        with self._lock:
            self.alerts_total += 1
            self.alerts_by_type[alert_type] += 1
            if alert_type == "baseline_concept_drift":
                self.drift_events += 1
            if alert_type.startswith("radio_"):
                self.fusion_disagreements += 1
            if alert_type.startswith("honeypot_"):
                self.honeypot_recon += 1
            if alert_type.startswith("privacy_"):
                self.privacy_alerts += 1
            if alert_type.startswith("rssi_"):
                self.localization_updates += 1

    def set_drift_psi(self, psi: float) -> None:
        with self._lock:
            self.drift_psi = float(psi)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "uptime_seconds": round(time.time() - self.started_at, 1),
                "frames_total": self.frames_total,
                "frames_by_type": dict(self.frames_by_type),
                "alerts_total": self.alerts_total,
                "alerts_by_type": dict(self.alerts_by_type),
                "drift_psi": self.drift_psi,
                "drift_events": self.drift_events,
                "fusion_disagreements": self.fusion_disagreements,
                "honeypot_recon": self.honeypot_recon,
                "privacy_alerts": self.privacy_alerts,
                "localization_updates": self.localization_updates,
            }

    def prometheus_text(self) -> str:
        s = self.snapshot()
        lines = [
            "# HELP wids_uptime_seconds Process uptime",
            "# TYPE wids_uptime_seconds gauge",
            f"wids_uptime_seconds {s['uptime_seconds']}",
            "# HELP wids_frames_total Frames processed",
            "# TYPE wids_frames_total counter",
            f"wids_frames_total {s['frames_total']}",
            "# HELP wids_alerts_total Alerts emitted",
            "# TYPE wids_alerts_total counter",
            f"wids_alerts_total {s['alerts_total']}",
            "# HELP wids_drift_psi Latest PSI from drift monitor",
            "# TYPE wids_drift_psi gauge",
            f"wids_drift_psi {s['drift_psi']}",
            "# HELP wids_drift_events_total Concept-drift alerts",
            "# TYPE wids_drift_events_total counter",
            f"wids_drift_events_total {s['drift_events']}",
            "# HELP wids_fusion_disagreements_total Multi-radio disagreements",
            "# TYPE wids_fusion_disagreements_total counter",
            f"wids_fusion_disagreements_total {s['fusion_disagreements']}",
            "# HELP wids_honeypot_recon_total Honeypot recon-style alerts",
            "# TYPE wids_honeypot_recon_total counter",
            f"wids_honeypot_recon_total {s['honeypot_recon']}",
            "# HELP wids_privacy_alerts_total Owned-device privacy alerts",
            "# TYPE wids_privacy_alerts_total counter",
            f"wids_privacy_alerts_total {s['privacy_alerts']}",
            "# HELP wids_localization_updates_total RSSI localization updates",
            "# TYPE wids_localization_updates_total counter",
            f"wids_localization_updates_total {s['localization_updates']}",
            "# HELP wids_alerts_by_type Alerts by type",
            "# TYPE wids_alerts_by_type counter",
        ]
        for t, n in sorted(s["alerts_by_type"].items()):
            safe = t.replace('"', "")
            lines.append(f'wids_alerts_by_type{{type="{safe}"}} {n}')
        lines.append("# HELP wids_frames_by_type Frames by 802.11 type")
        lines.append("# TYPE wids_frames_by_type counter")
        for t, n in sorted(s["frames_by_type"].items()):
            safe = t.replace('"', "")
            lines.append(f'wids_frames_by_type{{type="{safe}"}} {n}')
        lines.append("")
        return "\n".join(lines)


# Process-wide registry (dashboard + engine share this)
METRICS = MetricsRegistry()
