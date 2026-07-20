"""Authorized engagement session: RoE checklist + lifecycle."""

from __future__ import annotations

import json
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TextIO

import yaml

from ..config import PROJECT_ROOT


@dataclass
class EngagementConfig:
    name: str
    operator: str
    authorization: str
    report_dir: Path
    session_file: Path
    roe: list[str]
    allowed_actions: list[str]
    raw: dict = field(default_factory=dict)


@dataclass
class EngagementSession:
    session_id: str
    started_at: float
    name: str
    operator: str
    roe_acknowledged: list[str]
    active: bool = True
    ended_at: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def load_engagement_config(path: Path | None = None) -> EngagementConfig:
    p = path or (PROJECT_ROOT / "config" / "engagement.yaml")
    if not p.exists():
        p = PROJECT_ROOT / "config" / "engagement.example.yaml"
    with open(p, encoding="utf-8") as f:
        root = yaml.safe_load(f) or {}
    raw = root.get("engagement") or root
    report_dir = Path(raw.get("report_dir") or "data/reports")
    if not report_dir.is_absolute():
        report_dir = PROJECT_ROOT / report_dir
    session_file = Path(
        raw.get("session_file") or "data/logs/engagement_session.json"
    )
    if not session_file.is_absolute():
        session_file = PROJECT_ROOT / session_file
    return EngagementConfig(
        name=str(raw.get("name") or "Engagement"),
        operator=str(raw.get("operator") or ""),
        authorization=str(raw.get("authorization") or ""),
        report_dir=report_dir,
        session_file=session_file,
        roe=list(raw.get("roe") or []),
        allowed_actions=list(raw.get("allowed_actions") or []),
        raw=raw,
    )


def acknowledge_roe(
    cfg: EngagementConfig,
    *,
    assume_yes: bool = False,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> list[str]:
    """Interactive RoE checklist. Returns acknowledged rule strings."""
    out = stdout or sys.stdout
    inp = stdin or sys.stdin
    out.write("\n" + "=" * 60 + "\n")
    out.write(f"ENGAGEMENT: {cfg.name}\n")
    out.write(f"Operator: {cfg.operator}\n")
    out.write(f"Authorization: {cfg.authorization}\n")
    out.write("=" * 60 + "\n")
    out.write("Rules of Engagement — acknowledge each item:\n\n")

    ack: list[str] = []
    for i, rule in enumerate(cfg.roe, 1):
        out.write(f"  [{i}/{len(cfg.roe)}] {rule}\n")
        if assume_yes:
            out.write("      (--yes) acknowledged\n")
            ack.append(rule)
            continue
        out.write("      Type YES to acknowledge: ")
        out.flush()
        answer = inp.readline()
        if answer is None or answer.strip() != "YES":
            out.write("RoE not fully acknowledged — aborting.\n")
            raise RuntimeError("RoE acknowledgement incomplete")
        ack.append(rule)
    out.write("\nAll RoE items acknowledged.\n")
    return ack


def start_session(
    cfg: EngagementConfig, *, assume_yes: bool = False
) -> EngagementSession:
    ack = acknowledge_roe(cfg, assume_yes=assume_yes)
    session = EngagementSession(
        session_id=str(uuid.uuid4())[:8],
        started_at=time.time(),
        name=cfg.name,
        operator=cfg.operator,
        roe_acknowledged=ack,
        active=True,
    )
    cfg.session_file.parent.mkdir(parents=True, exist_ok=True)
    cfg.session_file.write_text(
        json.dumps(session.to_dict(), indent=2), encoding="utf-8"
    )
    return session


def load_session(cfg: EngagementConfig) -> EngagementSession | None:
    if not cfg.session_file.exists():
        return None
    data = json.loads(cfg.session_file.read_text(encoding="utf-8"))
    return EngagementSession(**data)


def end_session(cfg: EngagementConfig) -> EngagementSession | None:
    session = load_session(cfg)
    if session is None:
        return None
    session.active = False
    session.ended_at = time.time()
    cfg.session_file.write_text(
        json.dumps(session.to_dict(), indent=2), encoding="utf-8"
    )
    return session


def require_active_session(cfg: EngagementConfig) -> EngagementSession:
    session = load_session(cfg)
    if session is None or not session.active:
        raise RuntimeError(
            "No active engagement session. Run: python -m src.engagement_main start"
        )
    return session
