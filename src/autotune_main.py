#!/usr/bin/env python3
"""Autotune detector thresholds and optionally write a YAML snippet.

  python -m src.autotune_main
  python -m src.autotune_main --max-fpr 0.0 --write data/reports/eval/recommended_thresholds.yaml
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
from src.eval.autotune import autotune_thresholds, recommended_yaml
from src.eval.stress import run_stress_suite

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wids.autotune")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="WIDS threshold autotune + stress suite")
    p.add_argument("--max-fpr", type=float, default=0.0)
    p.add_argument(
        "--write",
        type=Path,
        default=PROJECT_ROOT / "data" / "reports" / "eval" / "recommended_thresholds.yaml",
        help="Write recommended YAML snippet here",
    )
    p.add_argument(
        "--json-out",
        type=Path,
        default=PROJECT_ROOT / "data" / "reports" / "eval" / "autotune.json",
    )
    p.add_argument("--skip-stress", action="store_true")
    args = p.parse_args(argv)

    cfg = get_config()
    result = autotune_thresholds(cfg, max_fpr=args.max_fpr)
    stress = None if args.skip_stress else run_stress_suite(cfg)

    args.write.parent.mkdir(parents=True, exist_ok=True)
    yaml_text = recommended_yaml(result)
    args.write.write_text(yaml_text, encoding="utf-8")
    payload = {"autotune": result, "stress_suite": stress}
    args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(yaml_text)
    rd = result.get("recommended_deauth") or {}
    rk = result.get("recommended_karma") or {}
    print(
        f"deauth thr={rd.get('threshold')} F1={rd.get('f1')} FPR={rd.get('fpr')}  |  "
        f"karma min_ssids={rk.get('min_ssids_per_bssid')} F1={rk.get('f1')} FPR={rk.get('fpr')}"
    )
    if stress:
        print(
            f"stress suite pass_rate={stress['pass_rate']:.0%} "
            f"({stress['n_pass']}/{stress['n_cases']})"
        )
        if stress["pass_rate"] < 1.0:
            logger.error("Stress suite failures:")
            for row in stress["cases"]:
                if not row["pass"]:
                    logger.error("  %s expect=%s got=%s", row["name"], row["expect_alert"], row["got_alert"])
            return 1
    logger.info("Wrote %s", args.write)
    logger.info("Wrote %s", args.json_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
