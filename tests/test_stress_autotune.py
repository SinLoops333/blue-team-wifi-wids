"""Tests for stress suite and threshold autotune."""

from __future__ import annotations

from src.config import PROJECT_ROOT, Config
from src.eval.autotune import autotune_thresholds, recommended_yaml
from src.eval.stress import build_stress_cases, run_stress_suite


def _cfg():
    return Config(yaml_path=PROJECT_ROOT / "config" / "wids.example.yaml")


def test_stress_cases_cover_boundaries():
    cases = build_stress_cases(deauth_threshold=20, karma_min_ssids=5, honeypot_burst=12)
    names = {c.name for c in cases}
    assert "deauth_just_below" in names
    assert "deauth_just_above" in names
    assert "karma_just_below" in names
    assert "honeypot_just_above" in names


def test_stress_suite_passes():
    result = run_stress_suite(_cfg())
    assert result["pass_rate"] == 1.0, result["cases"]


def test_autotune_recommends_under_fpr():
    result = autotune_thresholds(_cfg(), max_fpr=0.0)
    assert result["recommended_deauth"] is not None
    assert result["recommended_deauth"]["fpr"] <= 0.0
    assert result["recommended_karma"] is not None
    yaml_text = recommended_yaml(result)
    assert "threshold:" in yaml_text
    assert "min_ssids_per_bssid:" in yaml_text
