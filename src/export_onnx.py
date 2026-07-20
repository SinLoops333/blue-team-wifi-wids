#!/usr/bin/env python3
"""Export honeypot client model (and optional scaler) to ONNX for edge inference.

  python -m src.export_onnx
  python -m src.export_onnx --out models/honeypot_client.onnx

Requires optional deps: pip install skl2onnx onnx onnxruntime
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.config import PROJECT_ROOT, get_config
from src.detect.honeypot import CLIENT_FEATURE_NAMES, HoneypotEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wids.export_onnx")


def export_honeypot_onnx(out_path: Path) -> dict:
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
    except ImportError as exc:
        raise SystemExit(
            "ONNX export requires: pip install skl2onnx onnx onnxruntime\n"
            f"Import error: {exc}"
        ) from exc

    cfg = get_config()
    eng = HoneypotEngine(cfg)
    eng.fit_default()
    assert eng.model is not None and eng.scaler is not None

    # Pipeline: scaler then RandomForest
    from sklearn.pipeline import Pipeline

    pipe = Pipeline([("scaler", eng.scaler), ("clf", eng.model)])
    n = len(CLIENT_FEATURE_NAMES)
    initial = [("input", FloatTensorType([None, n]))]
    onnx_model = convert_sklearn(pipe, initial_types=initial, target_opset=12)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    meta = {
        "path": str(out_path),
        "features": CLIENT_FEATURE_NAMES,
        "n_features": n,
        "model": "Pipeline(StandardScaler, RandomForestClassifier)",
        "input_name": "input",
        "note": "Scores P(recon); threshold typically 0.65",
    }
    meta_path = out_path.with_suffix(".json")
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    logger.info("Wrote %s", out_path)
    logger.info("Wrote %s", meta_path)

    # Smoke-test with onnxruntime if available
    try:
        import numpy as np
        import onnxruntime as ort

        from src.detect.honeypot import synthetic_recon_client_vectors

        sess = ort.InferenceSession(str(out_path), providers=["CPUExecutionProvider"])
        x = np.array(synthetic_recon_client_vectors(1), dtype=np.float32)
        outs = sess.run(None, {"input": x})
        meta["smoke_output_shapes"] = [getattr(o, "shape", None) for o in outs]
        logger.info("ONNXRuntime smoke OK: %s", meta["smoke_output_shapes"])
    except Exception as exc:  # noqa: BLE001
        logger.warning("ONNXRuntime smoke skipped/failed: %s", exc)

    return meta


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Export WIDS models to ONNX")
    p.add_argument(
        "--out",
        type=Path,
        default=PROJECT_ROOT / "models" / "honeypot_client.onnx",
    )
    args = p.parse_args(argv)
    meta = export_honeypot_onnx(args.out)
    print(json.dumps(meta, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
