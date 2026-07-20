# Interview brief — Blue-team Wi-Fi WIDS

One page for recruiters / hiring managers. Repo:
https://github.com/SinLoops333/blue-team-wifi-wids

## Elevator (30 seconds)

Passive 802.11 intrusion detection on a WiFi Pineapple Mark VII: signature
detectors + IsolationForest, with a labeled eval harness (P/R/F1, ROC-AUC,
threshold FPR sweeps), scoped lab validation, and engagement reports. Default
path is receive-only; live RF only hits allowlisted gear I own with CONFIRM.

## What I built (proof)

| Signal | Where to look |
|---|---|
| Measured detectors | `python -m src.eval_main` → [sample_metrics.json](sample_metrics.json) |
| Model comparison | IsolationForest vs One-Class SVM in eval report |
| “Why anomalous” | Feature attribution (z-dev) on anomaly alerts |
| Ship like a team | GitHub Actions: pytest + eval on every push |
| Security maturity | [MODEL_CARD.md](MODEL_CARD.md), [THREAT_MODEL.md](THREAT_MODEL.md) |
| Architecture | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Sample SOC report | [sample_report.html](sample_report.html) |

## Interview lines (use as-is)

1. “I tuned the deauth threshold with a measured false-positive rate on my lab RF, not a guessed constant.”
2. “Eval compares IsolationForest to One-Class SVM and prints feature attribution for why a window looked anomalous.”
3. “Live RF is gated by allowlist ∩ human CONFIRM and an audit log; the public default is passive monitor only.”
4. “CI fails the build if signature scenarios drop below 100% pass or IsolationForest ROC-AUC falls under 0.8.”
5. “Dual-radio fusion on the Mark VII compares pinned vs hopping monitors for SSID split views and IE disagreements.”
6. “An owned honeypot SSID plus a client IsolationForest separates phone-like probes from automated recon bursts.”

## Stack

Python, Scapy, scikit-learn, Flask/SSE dashboard, Paramiko/SSH capture,
pytest, GitHub Actions, Pineapple Mark VII (monitor `wlan1`).

## Scope / ethics (say this early)

- Authorized monitoring only.
- Lab attacks only against owned BSSIDs listed in config.
- No stealth, no autonomous offense, no third-party targeting.
- Ambient third-party MACs are not published in portfolio artifacts.

## Suggested resume bullets

- Built a passive Wi-Fi WIDS (signatures + IsolationForest) with precision/recall
  eval, model comparison, and CI gates on ROC-AUC.
- Designed scoped lab + engagement workflow (RoE, CONFIRM, audit JSONL, HTML/JSON/CSV reports).
- Documented model card / threat model and alert policy (suppressions, severity scores).
