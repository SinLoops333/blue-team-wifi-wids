"""Known-good AP inventory and feature scaler persistence."""

from __future__ import annotations

import json
import logging
import pickle
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
from sklearn.preprocessing import StandardScaler

from .frame_features import WindowFeatures

logger = logging.getLogger(__name__)


class BaselineStore:
    """Persist AP inventory + StandardScaler for anomaly detection."""

    def __init__(self, inventory_path: Path, model_path: Path):
        self.inventory_path = Path(inventory_path)
        self.model_path = Path(model_path)
        self.inventory: Dict[str, dict] = {}
        self.scaler: Optional[StandardScaler] = None
        self._train_vectors: List[List[float]] = []

    def load(self) -> None:
        if self.inventory_path.exists():
            with open(self.inventory_path, encoding="utf-8") as f:
                self.inventory = json.load(f)
            logger.info(
                "Loaded AP inventory (%d APs) from %s",
                len(self.inventory),
                self.inventory_path,
            )
        if self.model_path.exists():
            with open(self.model_path, "rb") as f:
                blob = pickle.load(f)
            self.scaler = blob.get("scaler")
            # IsolationForest lives in AnomalyDetector; we only keep scaler here
            # if bundled — AnomalyDetector loads the full blob.
            logger.info("Found model blob at %s", self.model_path)

    def save_inventory(self) -> None:
        self.inventory_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.inventory_path, "w", encoding="utf-8") as f:
            json.dump(self.inventory, f, indent=2, sort_keys=True)
        logger.info("Wrote AP inventory to %s", self.inventory_path)

    def update_from_inventory(self, ap_inventory: Dict[str, dict]) -> None:
        for bssid, info in ap_inventory.items():
            cur = self.inventory.setdefault(bssid.lower(), {})
            cur.update({k: v for k, v in info.items() if v is not None})
            cur["bssid"] = bssid.lower()

    def add_training_window(self, features: WindowFeatures) -> None:
        self._train_vectors.append(features.as_vector())

    def fit_scaler(self, min_samples: int = 20) -> Optional[StandardScaler]:
        if len(self._train_vectors) < min_samples:
            logger.info(
                "Not enough windows to fit scaler (%d < %d)",
                len(self._train_vectors),
                min_samples,
            )
            return None
        X = np.array(self._train_vectors, dtype=float)
        self.scaler = StandardScaler()
        self.scaler.fit(X)
        logger.info("Fitted StandardScaler on %d windows", len(X))
        return self.scaler

    def transform(self, features: WindowFeatures) -> Optional[np.ndarray]:
        if self.scaler is None:
            return None
        vec = np.array(features.as_vector(), dtype=float).reshape(1, -1)
        return self.scaler.transform(vec)

    @property
    def training_matrix(self) -> Optional[np.ndarray]:
        if not self._train_vectors:
            return None
        return np.array(self._train_vectors, dtype=float)
