"""IsolationForest anomaly detection over windowed RF features."""

from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import List, Optional

import numpy as np
from sklearn.ensemble import IsolationForest

from ..alerts.alert import Alert, AlertSeverity
from ..config import Config
from ..eval.explain import format_contributions, top_feature_contributions
from .baseline import BaselineStore
from .frame_features import WindowFeatures, is_real_bssid

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Flag novel deviations that rule signatures may miss."""

    def __init__(self, config: Config, baseline: BaselineStore):
        self.config = config
        self.baseline = baseline
        self.model: Optional[IsolationForest] = None
        self.enabled = bool(config.anomaly.get("enabled", True))
        self.contamination = float(config.anomaly.get("contamination", 0.05))
        self.min_train = int(config.anomaly.get("min_train_windows", 20))
        self.model_path = config.path(
            config.anomaly.get("model_path", "models/baseline.pkl")
        )
        self._windows_seen = 0
        self._train_mean_scaled: Optional[np.ndarray] = None

    def load(self) -> None:
        if not self.model_path.exists():
            return
        with open(self.model_path, "rb") as f:
            blob = pickle.load(f)
        self.model = blob.get("isolation_forest")
        if blob.get("scaler") is not None:
            self.baseline.scaler = blob["scaler"]
        mean = blob.get("train_mean_scaled")
        if mean is not None:
            self._train_mean_scaled = np.asarray(mean, dtype=float)
        logger.info("Loaded IsolationForest from %s", self.model_path)

    def save(self) -> None:
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        blob = {
            "isolation_forest": self.model,
            "scaler": self.baseline.scaler,
            "train_mean_scaled": (
                self._train_mean_scaled.tolist()
                if self._train_mean_scaled is not None
                else None
            ),
        }
        with open(self.model_path, "wb") as f:
            pickle.dump(blob, f)
        logger.info("Saved anomaly model to %s", self.model_path)

    def observe(self, windows: List[WindowFeatures]) -> None:
        """Accumulate quiet windows for training."""
        for w in windows:
            if not is_real_bssid(w.bssid):
                continue
            self.baseline.add_training_window(w)
            self._windows_seen += 1

    def maybe_train(self) -> bool:
        if self.model is not None:
            return False
        matrix = self.baseline.training_matrix
        if matrix is None or len(matrix) < self.min_train:
            return False
        self.baseline.fit_scaler(min_samples=self.min_train)
        assert self.baseline.scaler is not None
        X = self.baseline.scaler.transform(matrix)
        self._train_mean_scaled = X.mean(axis=0)
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )
        self.model.fit(X)
        self.save()
        logger.info("Trained IsolationForest on %d windows", len(X))
        return True

    def evaluate(self, windows: List[WindowFeatures]) -> List[Alert]:
        if not self.enabled or self.model is None or self.baseline.scaler is None:
            return []
        alerts: List[Alert] = []
        for w in windows:
            if not is_real_bssid(w.bssid):
                continue
            if self.config.is_allowlisted_bssid(w.bssid):
                continue
            vec = np.array(w.as_vector(), dtype=float).reshape(1, -1)
            scaled = self.baseline.scaler.transform(vec)
            pred = self.model.predict(scaled)[0]  # -1 = anomaly
            score = float(self.model.decision_function(scaled)[0])
            if pred == -1:
                contribs = []
                if self._train_mean_scaled is not None:
                    contribs = top_feature_contributions(
                        scaled.ravel(), self._train_mean_scaled, top_k=5
                    )
                why = (
                    f" top_features={format_contributions(contribs)}"
                    if contribs
                    else ""
                )
                alerts.append(
                    Alert(
                        alert_type="anomaly",
                        severity=AlertSeverity.MEDIUM,
                        title="RF behavior anomaly",
                        evidence=(
                            f"BSSID {w.bssid} window looks anomalous "
                            f"(score={score:.3f}); "
                            f"deauth={w.deauth_count} eapol={w.eapol_count} "
                            f"ssids={w.unique_ssids}{why}"
                        ),
                        bssid=w.bssid,
                        ssid=w.ssids[0] if w.ssids else None,
                        channel=w.channel,
                        timestamp=w.window_end,
                        metadata={
                            "score": score,
                            "vector": w.as_vector(),
                            "feature_contributions": contribs,
                        },
                    )
                )
        return alerts
