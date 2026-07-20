#!/usr/bin/env python3
"""One-command portfolio demo: eval harness + offline simulate-all.

Does not require a live Pineapple.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wids.demo")


def _run(cmd: list[str]) -> int:
    logger.info("$ %s", " ".join(cmd))
    return subprocess.call(cmd, cwd=str(_ROOT))


def main() -> int:
    py = sys.executable
    steps = [
        [py, "-m", "pytest", "-q"],
        [py, "-m", "src.eval_main"],
        [py, "-m", "src.lab_main", "--simulate", "all", "--yes"],
        [
            py,
            "-m",
            "src.main",
            "--offline",
            "data/captures/lab_simulated.pcap",
            "--no-dashboard",
        ],
    ]
    for cmd in steps:
        code = _run(cmd)
        if code != 0:
            logger.error("Step failed with exit %s: %s", code, cmd)
            return code
    logger.info("Demo complete. See data/reports/eval/report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
