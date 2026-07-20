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
from src.eval.autotune import recommended_yaml
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
    result = run_full_eval(cfg)
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "metrics.json"
    md_path = out_dir / "report.md"
    yaml_path = out_dir / "recommended_thresholds.yaml"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    md_path.write_text(report_markdown(result), encoding="utf-8")
    if result.get("autotune"):
        yaml_path.write_text(recommended_yaml(result["autotune"]), encoding="utf-8")

    logger.info("Wrote %s", json_path)
    logger.info("Wrote %s", md_path)
    if yaml_path.exists():
        logger.info("Wrote %s", yaml_path)
    print(report_markdown(result))

    sig = result["signatures"]
    iso = result["isolation_forest"]
    am = result.get("anomaly_models") or {}
    svm = am.get("one_class_svm") or {}
    stress = result.get("stress_suite") or {}
    auto = result.get("autotune") or {}
    rd = auto.get("recommended_deauth") or {}
    print(
        f"\nSummary: scenario_pass={sig['scenario_pass_rate']:.0%}  "
        f"IF_ROC_AUC={iso['roc_auc']}  "
        f"OCSVM_ROC_AUC={svm.get('roc_auc')}  "
        f"winner={am.get('winner')}  "
        f"stress={stress.get('pass_rate', 0):.0%}  "
        f"autotune_deauth={rd.get('threshold')}"
    )
    if sig["scenario_pass_rate"] < 1.0:
        logger.error("One or more signature scenarios failed")
        return 1
    if iso["roc_auc"] < 0.8:
        logger.error("IsolationForest ROC-AUC below 0.8")
        return 1
    if stress and stress.get("pass_rate", 1.0) < 1.0:
        logger.error("Detector stress suite failed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
