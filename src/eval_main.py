#!/usr/bin/env python3
"""Run WIDS evaluation harness and write JSON + Markdown reports.

  python -m src.eval_main
  python -m src.eval_main --out-dir data/reports/eval
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
from src.eval.runner import report_markdown, run_full_eval

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wids.eval")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="WIDS detector evaluation harness")
    p.add_argument(
        "--out-dir",
        type=Path,
        default=PROJECT_ROOT / "data" / "reports" / "eval",
        help="Directory for metrics.json and report.md",
    )
    args = p.parse_args(argv)

    cfg = get_config()
    # Ensure allowlist does not suppress lab synthetic evil twin BSSID
    result = run_full_eval(cfg)
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "metrics.json"
    md_path = out_dir / "report.md"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    md = report_markdown(result)
    md_path.write_text(md, encoding="utf-8")

    logger.info("Wrote %s", json_path)
    logger.info("Wrote %s", md_path)
    print(md)
    sig = result["signatures"]
    iso = result["isolation_forest"]
    am = result.get("anomaly_models") or {}
    svm = am.get("one_class_svm") or {}
    print(
        f"\nSummary: scenario_pass={sig['scenario_pass_rate']:.0%}  "
        f"IF_ROC_AUC={iso['roc_auc']}  "
        f"OCSVM_ROC_AUC={svm.get('roc_auc')}  "
        f"winner={am.get('winner')}"
    )
    # Non-zero exit if any scenario failed (CI gate)
    if sig["scenario_pass_rate"] < 1.0:
        logger.error("One or more signature scenarios failed")
        return 1
    if iso["roc_auc"] < 0.8:
        logger.error("IsolationForest ROC-AUC below 0.8")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
