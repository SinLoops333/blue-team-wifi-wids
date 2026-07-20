"""Human confirmation gate before any lab attack."""

from __future__ import annotations

import sys
from typing import TextIO


def require_confirm(
    action_summary: str,
    *,
    require: bool = True,
    assume_yes: bool = False,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> bool:
    """Prompt the operator to type CONFIRM.

    If *require* is False, returns True immediately (config override).
    If *assume_yes* is True, still prints the summary but skips the prompt
    (for scripted lab use — audit log should record skipped_prompt=True).
    """
    out = stdout or sys.stdout
    inp = stdin or sys.stdin

    out.write("\n")
    out.write("=" * 60 + "\n")
    out.write("LAB ATTACK CONFIRMATION\n")
    out.write("=" * 60 + "\n")
    out.write(action_summary.rstrip() + "\n")
    out.write("-" * 60 + "\n")
    out.write(
        "This will transmit frames. Only proceed against equipment YOU own.\n"
    )
    out.write("=" * 60 + "\n")

    if not require:
        out.write("Confirmation disabled in config — proceeding.\n")
        return True

    if assume_yes:
        out.write("--yes set: skipping interactive prompt.\n")
        return True

    out.write('Type CONFIRM to proceed, or anything else to abort: ')
    out.flush()
    try:
        answer = inp.readline()
    except KeyboardInterrupt:
        out.write("\nAborted.\n")
        return False
    if answer is None:
        return False
    ok = answer.strip() == "CONFIRM"
    if not ok:
        out.write("Aborted (did not receive exact CONFIRM).\n")
    return ok
