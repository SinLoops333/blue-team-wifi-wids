"""Owned-honeypot client behavior tracking + classifier.

Defensive only: watch stations that probe / auth / assoc toward SSIDs or
BSSIDs you own (allowlisted honeypot). Classifies bursty automated recon
vs sparse phone-like behavior. Does not enable KARMA or spoof foreign SSIDs.
"""

from __future__ import annotations

import logging
import math
import pickle
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, List, Optional, Sequence, Set, Tuple

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from ..alerts.alert import Alert, AlertSeverity
from ..config import Config
from .frame_features import FrameEvent

logger = logging.getLogger(__name__)

CLIENT_FEATURE_NAMES = [
    "probe_count",
    "honeypot_probe_count",
    "unique_ssids",
    "auth_count",
    "assoc_count",
    "honeypot_auth_assoc",
    "probes_per_sec",
    "honeypot_probe_ratio",
    "ssid_entropy",
    "burst_max",
]


@dataclass
class ClientWindow:
    client: str
    window_start: float
    window_end: float
    probe_count: int = 0
    honeypot_probe_count: int = 0
    unique_ssids: int = 0
    auth_count: int = 0
    assoc_count: int = 0
    honeypot_auth_assoc: int = 0
    probes_per_sec: float = 0.0
    honeypot_probe_ratio: float = 0.0
    ssid_entropy: float = 0.0
    burst_max: int = 0
    ssids: List[str] = field(default_factory=list)

    def as_vector(self) -> List[float]:
        return [
            float(self.probe_count),
            float(self.honeypot_probe_count),
            float(self.unique_ssids),
            float(self.auth_count),
            float(self.assoc_count),
            float(self.honeypot_auth_assoc),
            float(self.probes_per_sec),
            float(self.honeypot_probe_ratio),
            float(self.ssid_entropy),
            float(self.burst_max),
        ]


def _entropy(counts: Dict[str, int]) -> float:
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            h -= p * math.log(p + 1e-12, 2)
    return h


@dataclass
class HoneypotEngine:
    """Track per-STA behavior toward owned honeypot SSIDs/BSSIDs."""

    config: Config
    model: Optional[RandomForestClassifier] = None
    scaler: Optional[StandardScaler] = None
    _events: Dict[str, Deque[FrameEvent]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    _last_eval: Dict[str, float] = field(default_factory=dict)
    _train_mean: Optional[np.ndarray] = None
    recon_proba_threshold: float = 0.65

    def __post_init__(self) -> None:
        self._hp_ssids: Set[str] = set(self.config.honeypot.get("ssids") or [])
        self._hp_bssids: Set[str] = {
            b.lower() for b in (self.config.honeypot.get("bssids") or []) if b
        }
        # Fall back to allowlisted SSIDs if honeypot.ssids empty but enabled
        if not self._hp_ssids and self.enabled():
            self._hp_ssids = set(self.config.allowlist_ssids)
        self.window = float(self.config.honeypot.get("window_seconds", 60))
        self.min_probes = int(self.config.honeypot.get("min_probes_for_ml", 5))
        self.burst_threshold = int(self.config.honeypot.get("burst_probe_threshold", 12))
        self.model_path = self.config.path(
            self.config.honeypot.get("model_path", "models/honeypot_client.pkl")
        )
        self.recon_proba_threshold = float(
            self.config.honeypot.get("recon_proba_threshold", 0.65)
        )

    def enabled(self) -> bool:
        return bool(self.config.honeypot.get("enabled", False))

    def is_honeypot_ssid(self, ssid: Optional[str]) -> bool:
        return bool(ssid) and ssid in self._hp_ssids

    def is_honeypot_bssid(self, bssid: Optional[str]) -> bool:
        return bool(bssid) and bssid.lower() in self._hp_bssids

    def load_or_train_default(self) -> None:
        if self.model_path.exists():
            self.load()
            return
        self.fit_default()
        self.save()

    def load(self) -> None:
        with open(self.model_path, "rb") as f:
            blob = pickle.load(f)
        self.model = blob.get("model")
        self.scaler = blob.get("scaler")
        mean = blob.get("train_mean")
        self._train_mean = np.asarray(mean, dtype=float) if mean is not None else None
        logger.info("Loaded honeypot client model from %s", self.model_path)

    def save(self) -> None:
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        blob = {
            "model": self.model,
            "scaler": self.scaler,
            "train_mean": (
                self._train_mean.tolist() if self._train_mean is not None else None
            ),
            "feature_names": CLIENT_FEATURE_NAMES,
        }
        with open(self.model_path, "wb") as f:
            pickle.dump(blob, f)
        logger.info("Saved honeypot client model to %s", self.model_path)

    def fit_default(self, random_state: int = 42) -> None:
        """Train RandomForest on synthetic benign vs recon client windows."""
        X_b = np.array(synthetic_benign_client_vectors(80), dtype=float)
        X_a = np.array(synthetic_recon_client_vectors(80), dtype=float)
        X = np.vstack([X_b, X_a])
        y = np.array([0] * len(X_b) + [1] * len(X_a))
        self.scaler = StandardScaler()
        Xs = self.scaler.fit_transform(X)
        self._train_mean = Xs[y == 0].mean(axis=0)
        self.model = RandomForestClassifier(
            n_estimators=100, random_state=random_state, max_depth=6
        )
        self.model.fit(Xs, y)
        logger.info(
            "Trained honeypot client RandomForest on %d vectors", len(X)
        )

    def process(self, event: FrameEvent) -> List[Alert]:
        if not self.enabled():
            return []
        client = self._client_mac(event)
        if not client:
            return []
        try:
            if (int(client.split(":")[0], 16) & 1) == 1:
                return []
        except (ValueError, IndexError):
            return []

        if event.frame_type not in (
            "probe_req",
            "auth",
            "assoc_req",
            "reassoc_req",
        ):
            return []

        buf = self._events[client]
        buf.append(event)
        self._trim(buf, event.timestamp)

        alerts: List[Alert] = []
        # Rule: burst of probes toward honeypot SSID
        alerts.extend(self._check_burst(client, event))

        # Periodic ML eval per client
        last = self._last_eval.get(client, 0.0)
        if event.timestamp - last >= 5.0:
            self._last_eval[client] = event.timestamp
            win = self._window_for(client, event.timestamp)
            if win and win.probe_count + win.auth_count + win.assoc_count >= self.min_probes:
                alerts.extend(self._ml_alert(win, event))
        return alerts

    def _client_mac(self, event: FrameEvent) -> Optional[str]:
        if event.frame_type == "probe_req":
            return (event.addr2 or "").lower() or None
        # auth / assoc: STA is typically addr2 when talking to AP
        return (event.addr2 or "").lower() or None

    def _trim(self, buf: Deque[FrameEvent], now: float) -> None:
        cutoff = now - self.window
        while buf and buf[0].timestamp < cutoff:
            buf.popleft()

    def _targets_honeypot(self, event: FrameEvent) -> bool:
        if self.is_honeypot_ssid(event.ssid):
            return True
        if self.is_honeypot_bssid(event.bssid):
            return True
        if self.is_honeypot_bssid(event.addr1):
            return True
        if self.is_honeypot_bssid(event.addr3):
            return True
        return False

    def _window_for(self, client: str, now: float) -> Optional[ClientWindow]:
        buf = self._events.get(client)
        if not buf:
            return None
        ssid_counts: Dict[str, int] = defaultdict(int)
        probe = hp_probe = auth = assoc = hp_aa = 0
        # Burst: max probes in any 2s slice
        times = []
        for e in buf:
            if e.frame_type == "probe_req":
                probe += 1
                times.append(e.timestamp)
                if e.ssid:
                    ssid_counts[e.ssid] += 1
                if self._targets_honeypot(e):
                    hp_probe += 1
            elif e.frame_type == "auth":
                auth += 1
                if self._targets_honeypot(e):
                    hp_aa += 1
            elif e.frame_type in ("assoc_req", "reassoc_req"):
                assoc += 1
                if self._targets_honeypot(e):
                    hp_aa += 1
        duration = max(now - buf[0].timestamp, 0.1)
        burst_max = 0
        if times:
            t0 = times[0]
            i = 0
            for j, t in enumerate(times):
                while times[i] < t - 2.0:
                    i += 1
                burst_max = max(burst_max, j - i + 1)
        return ClientWindow(
            client=client,
            window_start=buf[0].timestamp,
            window_end=now,
            probe_count=probe,
            honeypot_probe_count=hp_probe,
            unique_ssids=len(ssid_counts),
            auth_count=auth,
            assoc_count=assoc,
            honeypot_auth_assoc=hp_aa,
            probes_per_sec=probe / duration,
            honeypot_probe_ratio=(hp_probe / probe) if probe else 0.0,
            ssid_entropy=_entropy(ssid_counts),
            burst_max=burst_max,
            ssids=sorted(ssid_counts.keys())[:12],
        )

    def _check_burst(self, client: str, event: FrameEvent) -> List[Alert]:
        if event.frame_type != "probe_req" or not self._targets_honeypot(event):
            return []
        # Count honeypot probes in last 10s
        cutoff = event.timestamp - 10.0
        n = sum(
            1
            for e in self._events[client]
            if e.timestamp >= cutoff
            and e.frame_type == "probe_req"
            and self._targets_honeypot(e)
        )
        if n < self.burst_threshold:
            return []
        return [
            Alert(
                alert_type="honeypot_recon_burst",
                severity=AlertSeverity.HIGH,
                title="Honeypot probe burst (possible recon)",
                evidence=(
                    f"STA {client} sent {n} probes toward honeypot "
                    f"SSID/BSSID in 10s (threshold {self.burst_threshold}); "
                    f"last_ssid='{event.ssid}'"
                ),
                bssid=event.bssid or event.addr1,
                ssid=event.ssid,
                source_mac=client,
                channel=event.channel,
                timestamp=event.timestamp,
                metadata={"honeypot_probes_10s": n, "client": client},
            )
        ]

    def _ml_alert(self, win: ClientWindow, event: FrameEvent) -> List[Alert]:
        if self.model is None or self.scaler is None:
            return []
        # Only score if client touched honeypot or looked like multi-SSID scanner
        if win.honeypot_probe_count == 0 and win.unique_ssids < 4:
            return []
        vec = np.array(win.as_vector(), dtype=float).reshape(1, -1)
        scaled = self.scaler.transform(vec)
        proba = float(self.model.predict_proba(scaled)[0][1])
        if proba < self.recon_proba_threshold:
            return []
        return [
            Alert(
                alert_type="honeypot_client_anomaly",
                severity=AlertSeverity.MEDIUM,
                title="Honeypot client behavior anomaly",
                evidence=(
                    f"STA {win.client} classified as recon-like "
                    f"(p={proba:.2f}); probes={win.probe_count} "
                    f"hp_probes={win.honeypot_probe_count} "
                    f"unique_ssids={win.unique_ssids} "
                    f"burst_max={win.burst_max}"
                ),
                bssid=event.bssid,
                ssid=event.ssid,
                source_mac=win.client,
                channel=event.channel,
                timestamp=event.timestamp,
                metadata={
                    "recon_proba": proba,
                    "vector": win.as_vector(),
                    "features": CLIENT_FEATURE_NAMES,
                    "ssids": win.ssids,
                },
            )
        ]


def synthetic_benign_client_vectors(n: int = 40) -> List[List[float]]:
    rng = np.random.default_rng(0)
    out = []
    for _ in range(n):
        probes = int(rng.integers(1, 4))
        hp = int(rng.integers(0, min(2, probes) + 1))
        uniq = int(rng.integers(1, 3))
        out.append(
            [
                float(probes),
                float(hp),
                float(uniq),
                float(rng.integers(0, 2)),
                float(rng.integers(0, 2)),
                float(rng.integers(0, 2)),
                float(probes / 60.0),
                float(hp / probes) if probes else 0.0,
                float(rng.uniform(0.0, 1.0)),
                float(rng.integers(1, 3)),
            ]
        )
    return out


def synthetic_recon_client_vectors(n: int = 40) -> List[List[float]]:
    rng = np.random.default_rng(1)
    out = []
    for _ in range(n):
        probes = int(rng.integers(15, 40))
        hp = int(rng.integers(10, probes + 1))
        uniq = int(rng.integers(1, 8))
        out.append(
            [
                float(probes),
                float(hp),
                float(uniq),
                float(rng.integers(0, 5)),
                float(rng.integers(0, 5)),
                float(rng.integers(2, 8)),
                float(probes / 10.0),
                float(hp / probes),
                float(rng.uniform(1.5, 3.0)),
                float(rng.integers(8, 20)),
            ]
        )
    return out


def evaluate_honeypot_model(random_state: int = 42) -> dict:
    """Supervised metrics for RandomForest on synthetic client windows."""
    from sklearn.metrics import roc_auc_score

    from ..eval.metrics import scores_for_label

    X_b = np.array(synthetic_benign_client_vectors(80), dtype=float)
    X_a = np.array(synthetic_recon_client_vectors(40), dtype=float)
    scaler = StandardScaler()
    X_train = scaler.fit_transform(
        np.vstack([X_b[:50], X_a[:20]])
    )
    y_train = np.array([0] * 50 + [1] * 20)
    X_test = np.vstack(
        [scaler.transform(X_b[50:]), scaler.transform(X_a[20:])]
    )
    y = np.array([0] * len(X_b[50:]) + [1] * len(X_a[20:]))
    model = RandomForestClassifier(
        n_estimators=100, random_state=random_state, max_depth=6
    )
    model.fit(X_train, y_train)
    proba = model.predict_proba(X_test)[:, 1]
    preds = (proba >= 0.65).astype(int)
    binary = scores_for_label(y.tolist(), preds.tolist())
    return {
        "roc_auc": round(float(roc_auc_score(y, proba)), 4),
        "at_default_threshold": binary.to_dict(),
        "n_train_benign": 50,
        "n_train_recon": 20,
        "n_test_benign": int(len(X_b[50:])),
        "n_test_recon": int(len(X_a[20:])),
        "feature_names": CLIENT_FEATURE_NAMES,
        "model": "RandomForestClassifier",
    }
