"""Load configuration from .env and config/wids.yaml."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

# wids/ is the project root (parent of src/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _deep_get(d: dict, *keys: str, default: Any = None) -> Any:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


class Config:
    """Runtime configuration for WIDS."""

    def __init__(self, yaml_path: Path | None = None, env_path: Path | None = None):
        env_file = env_path or (PROJECT_ROOT / ".env")
        if env_file.exists():
            load_dotenv(env_file)
        else:
            # Still allow env vars set in the shell
            load_dotenv()

        cfg_path = yaml_path or (PROJECT_ROOT / "config" / "wids.yaml")
        if not cfg_path.exists():
            example = PROJECT_ROOT / "config" / "wids.example.yaml"
            if example.exists():
                cfg_path = example
            else:
                raise FileNotFoundError(
                    f"No config found at {cfg_path} or {example}. "
                    "Copy config/wids.example.yaml to config/wids.yaml."
                )

        with open(cfg_path, encoding="utf-8") as f:
            self._raw: dict = yaml.safe_load(f) or {}

        self.pineapple_ip = os.getenv("PINEAPPLE_IP", "192.168.1.72")
        self.pineapple_user = os.getenv("PINEAPPLE_USER", "root")
        self.pineapple_password = os.getenv("PINEAPPLE_PASSWORD", "")
        self.pineapple_ssh_port = int(os.getenv("PINEAPPLE_SSH_PORT", "22"))
        self.pineapple_api_port = int(os.getenv("PINEAPPLE_API_PORT", "1471"))

        self.capture_interface = _deep_get(
            self._raw, "capture", "interface", default="wlan1mon"
        )
        self.capture_snaplen = int(
            _deep_get(self._raw, "capture", "snaplen", default=256)
        )
        self.ssh_timeout = int(
            _deep_get(self._raw, "capture", "ssh_timeout", default=30)
        )
        # Optional fixed channel for live capture (null = leave radio as-is)
        ch = _deep_get(self._raw, "capture", "channel", default=None)
        self.capture_channel = int(ch) if ch is not None else None

        allow = self._raw.get("allowlist") or {}
        self.allowlist_bssids = {
            b.lower() for b in (allow.get("bssids") or []) if b
        }
        self.allowlist_ssids = set(allow.get("ssids") or [])

        self.detectors = self._raw.get("detectors") or {}
        self.anomaly = self._raw.get("anomaly") or {}
        self.dashboard = self._raw.get("dashboard") or {}
        self.store = self._raw.get("store") or {}
        self.alerts = self._raw.get("alerts") or {}
        self.fusion = self._raw.get("fusion") or {}
        # Back-compat: allow fusion under capture.fusion
        if not self.fusion and isinstance(self._raw.get("capture"), dict):
            self.fusion = (self._raw["capture"].get("fusion") or {})

    def path(self, relative: str) -> Path:
        """Resolve a path relative to the project root."""
        p = Path(relative)
        return p if p.is_absolute() else PROJECT_ROOT / p

    def detector(self, name: str, key: str, default: Any = None) -> Any:
        return _deep_get(self.detectors, name, key, default=default)

    def is_allowlisted_bssid(self, bssid: str | None) -> bool:
        if not bssid:
            return False
        return bssid.lower() in self.allowlist_bssids

    def is_allowlisted_ssid(self, ssid: str | None) -> bool:
        if not ssid:
            return False
        return ssid in self.allowlist_ssids


_config: Config | None = None


def get_config(reload: bool = False) -> Config:
    global _config
    if _config is None or reload:
        _config = Config()
    return _config
