"""Concept-drift detection for the RF feature baseline.

Maintains a locked reference distribution of quiet window vectors, compares
a recent sliding window via Population Stability Index (PSI), and optionally
adapts the reference after a confirmed shift (continual baseline).
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Sequence, Tuple

import numpy as np

from ..alerts.alert import Alert, AlertSeverity
from ..config import Config
from .frame_features import WindowFeatures, is_real_bssid

logger = logging.getLogger(__name__)

# Align with WindowFeatures.FEATURE_NAMES
DRIFT_FEATURE_NAMES = list(WindowFeatures.FEATURE_NAMES)


def population_stability_index(
    reference: np.ndarray,
    recent: np.ndarray,
    n_bins: int = 10,
    eps: float = 1e-4,
) -> Tuple[float, Dict[str, float]]:
    """Mean PSI across columns; also per-feature PSI.

    reference/recent: shape (n_samples, n_features)
    """
    if reference.size == 0 or recent.size == 0:
        return 0.0, {}
    ref = np.asarray(reference, dtype=float)
    cur = np.asarray(recent, dtype=float)
    if ref.ndim == 1:
        ref = ref.reshape(-1, 1)
    if cur.ndim == 1:
        cur = cur.reshape(-1, 1)
    n_feat = min(ref.shape[1], cur.shape[1], len(DRIFT_FEATURE_NAMES))
    per: Dict[str, float] = {}
    scores = []
    for j in range(n_feat):
        col_r = ref[:, j]
        col_c = cur[:, j]
        lo = float(min(col_r.min(), col_c.min()))
        hi = float(max(col_r.max(), col_c.max()))
        if hi - lo < eps:
            per[DRIFT_FEATURE_NAMES[j]] = 0.0
            scores.append(0.0)
            continue
        bins = np.linspace(lo, hi, n_bins + 1)
        hist_r, _ = np.histogram(col_r, bins=bins)
        hist_c, _ = np.histogram(col_c, bins=bins)
        p = hist_r.astype(float) / max(hist_r.sum(), 1)
        q = hist_c.astype(float) / max(hist_c.sum(), 1)
        p = np.clip(p, eps, None)
        q = np.clip(q, eps, None)
        # Renormalize after clip
        p = p / p.sum()
        q = q / q.sum()
        psi = float(np.sum((q - p) * np.log(q / p)))
        name = DRIFT_FEATURE_NAMES[j] if j < len(DRIFT_FEATURE_NAMES) else f"f{j}"
        per[name] = round(psi, 4)
        scores.append(psi)
    mean_psi = float(np.mean(scores)) if scores else 0.0
    return mean_psi, per


def mean_shift_l2(reference: np.ndarray, recent: np.ndarray) -> float:
    """L2 distance between feature means (scaled by ref std)."""
    ref = np.asarray(reference, dtype=float)
    cur = np.asarray(recent, dtype=float)
    mu_r = ref.mean(axis=0)
    mu_c = cur.mean(axis=0)
    std = ref.std(axis=0)
    std = np.where(std < 1e-6, 1.0, std)
    return float(np.linalg.norm((mu_c - mu_r) / std))


@dataclass
class DriftMonitor:
    """Lock a reference baseline, then watch for distribution shift."""

    config: Config
    _reference: List[List[float]] = field(default_factory=list)
    _recent: Deque[List[float]] = field(default_factory=deque)
    _locked: bool = False
    _last_alert_ts: float = 0.0
    _adapt_count: int = 0

    def enabled(self) -> bool:
        return bool(self.config.drift.get("enabled", True))

    @property
    def reference_size(self) -> int:
        return int(self.config.drift.get("reference_windows", 40))

    @property
    def recent_size(self) -> int:
        return int(self.config.drift.get("recent_windows", 20))

    @property
    def min_recent(self) -> int:
        return int(self.config.drift.get("min_recent", 15))

    @property
    def psi_threshold(self) -> float:
        return float(self.config.drift.get("psi_threshold", 0.25))

    @property
    def mean_shift_threshold(self) -> float:
        return float(self.config.drift.get("mean_shift_threshold", 2.5))

    @property
    def adapt(self) -> bool:
        return bool(self.config.drift.get("adapt", True))

    @property
    def cooldown(self) -> float:
        return float(self.config.drift.get("alert_cooldown_seconds", 120))

    def observe_windows(
        self, windows: Sequence[WindowFeatures], now: float
    ) -> List[Alert]:
        if not self.enabled():
            return []
        alerts: List[Alert] = []
        for w in windows:
            if not is_real_bssid(w.bssid):
                continue
            # Prefer quiet-ish windows for baseline (low attack signatures)
            if w.deauth_count > 5 or w.pmkid_count > 0:
                continue
            vec = w.as_vector()
            if not self._locked:
                self._reference.append(vec)
                if len(self._reference) >= self.reference_size:
                    self._locked = True
                    logger.info(
                        "Drift reference locked (%d windows)",
                        len(self._reference),
                    )
                continue

            self._recent.append(vec)
            while len(self._recent) > self.recent_size:
                self._recent.popleft()

        if not self._locked or len(self._recent) < self.min_recent:
            return alerts

        ref = np.array(self._reference, dtype=float)
        cur = np.array(list(self._recent), dtype=float)
        psi, per = population_stability_index(ref, cur)
        shift = mean_shift_l2(ref, cur)

        drifted = psi >= self.psi_threshold or shift >= self.mean_shift_threshold
        if not drifted:
            return alerts
        if now - self._last_alert_ts < self.cooldown:
            return alerts

        self._last_alert_ts = now
        top = sorted(per.items(), key=lambda kv: -kv[1])[:5]
        top_s = ", ".join(f"{k}={v:.2f}" for k, v in top)
        adapted = False
        if self.adapt:
            adapted = self._adapt_reference(cur)
            self._adapt_count += 1

        alerts.append(
            Alert(
                alert_type="baseline_concept_drift",
                severity=AlertSeverity.MEDIUM,
                title="RF baseline concept drift",
                evidence=(
                    f"Feature distribution shifted vs locked baseline "
                    f"(PSI={psi:.3f} thr={self.psi_threshold}, "
                    f"mean_shift={shift:.2f} thr={self.mean_shift_threshold}); "
                    f"top_features=[{top_s}]"
                    + ("; reference adapted" if adapted else "")
                ),
                timestamp=now,
                metadata={
                    "psi": round(psi, 4),
                    "mean_shift_l2": round(shift, 4),
                    "per_feature_psi": per,
                    "reference_n": len(self._reference),
                    "recent_n": len(self._recent),
                    "adapted": adapted,
                    "adapt_count": self._adapt_count,
                },
            )
        )
        return alerts

    def _adapt_reference(self, recent: np.ndarray) -> bool:
        """Blend recent samples into reference (continual baseline)."""
        frac = float(self.config.drift.get("adapt_fraction", 0.25))
        frac = min(max(frac, 0.05), 0.5)
        n_take = max(1, int(len(recent) * frac))
        # Replace oldest reference rows with a sample of recent
        take = recent[-n_take:].tolist()
        drop = min(n_take, len(self._reference))
        self._reference = self._reference[drop:] + take
        # Keep reference size bounded
        max_ref = self.reference_size * 2
        if len(self._reference) > max_ref:
            self._reference = self._reference[-max_ref:]
        self._recent.clear()
        logger.info(
            "Adapted drift reference (replaced %d rows, size=%d)",
            drop,
            len(self._reference),
        )
        return True

    # --- Test / eval helpers ---

    def seed_reference(self, vectors: Sequence[Sequence[float]]) -> None:
        self._reference = [list(map(float, v)) for v in vectors]
        self._locked = len(self._reference) >= min(5, self.reference_size)
        if len(self._reference) >= self.reference_size:
            self._locked = True

    def feed_recent(self, vectors: Sequence[Sequence[float]]) -> None:
        for v in vectors:
            self._recent.append(list(map(float, v)))
            while len(self._recent) > self.recent_size:
                self._recent.popleft()


def evaluate_drift_detection() -> dict:
    """Synthetic: lock benign, shift distribution, expect PSI above threshold."""
    rng = np.random.default_rng(0)
    n_feat = len(DRIFT_FEATURE_NAMES)
    benign = rng.normal(0, 1, size=(60, n_feat))
    # Shift several attack-relevant features
    shifted = rng.normal(0, 1, size=(30, n_feat))
    shifted[:, 3] += 8  # deauth_count
    shifted[:, 7] += 5  # eapol_count
    shifted[:, 9] += 4  # unique_ssids

    psi_same, _ = population_stability_index(benign[:40], benign[40:60])
    psi_shift, per = population_stability_index(benign[:40], shifted)
    shift_l2 = mean_shift_l2(benign[:40], shifted)
    return {
        "psi_same_distribution": round(float(psi_same), 4),
        "psi_shifted_distribution": round(float(psi_shift), 4),
        "mean_shift_l2_shifted": round(float(shift_l2), 4),
        "detects_shift": bool(psi_shift > psi_same and psi_shift >= 0.2),
        "top_shifted_features": sorted(per.items(), key=lambda kv: -kv[1])[:5],
    }
