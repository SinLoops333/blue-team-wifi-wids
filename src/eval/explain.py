"""Simple SHAP-style feature attribution without heavy SHAP dependency.

Compares a scaled sample to the training centroid and reports the largest
absolute z-deviations — enough for interview demos and SOC evidence text.
"""

from __future__ import annotations

from typing import List, Sequence

import numpy as np

from ..detect.frame_features import WindowFeatures


FEATURE_NAMES = list(WindowFeatures.FEATURE_NAMES)


def top_feature_contributions(
    scaled_vector: Sequence[float],
    train_scaled_mean: Sequence[float],
    top_k: int = 5,
    feature_names: Sequence[str] | None = None,
) -> List[dict]:
    """Return top-k features by |z - mean| on scaled space."""
    names = list(feature_names or FEATURE_NAMES)
    v = np.asarray(scaled_vector, dtype=float).ravel()
    m = np.asarray(train_scaled_mean, dtype=float).ravel()
    if v.shape != m.shape:
        raise ValueError("vector/mean shape mismatch")
    delta = v - m
    order = np.argsort(-np.abs(delta))
    out = []
    for idx in order[:top_k]:
        out.append(
            {
                "feature": names[int(idx)] if int(idx) < len(names) else f"f{idx}",
                "delta": round(float(delta[idx]), 4),
                "value": round(float(v[idx]), 4),
                "baseline_mean": round(float(m[idx]), 4),
            }
        )
    return out


def format_contributions(contribs: List[dict]) -> str:
    parts = [f"{c['feature']}({c['delta']:+.2f})" for c in contribs]
    return ", ".join(parts)
