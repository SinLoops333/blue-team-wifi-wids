# Model card — Blue-team Wi-Fi WIDS

**Model/system name:** WASP-WIDS (Wi-Fi Intrusion Detection)  
**Version:** 0.1.0  
**Date:** 2026-07-20  
**Intended users:** Blue-team engineers, lab students, portfolio reviewers  

## Overview

A **passive** 802.11 monitoring pipeline plus rule-based detectors and an
`IsolationForest` anomaly model. Optional **scoped lab** tools generate
controlled traffic **only** against allowlisted BSSIDs the operator owns.

This is **not** an autonomous offensive agent.

## Model details

| Component | Type | Role |
|---|---|---|
| Signature engine | Deterministic rules | deauth flood, evil twin, encryption downgrade, KARMA, PMKID, handshake harvest |
| Feature vectors | Hand-crafted per-BSSID windows | beacon/probe/deauth/EAPOL counts, SSID diversity, RSSI |
| Anomaly model | `sklearn.ensemble.IsolationForest` | Flags unusual window vectors vs quiet baseline |
| Scaler | `StandardScaler` | Fit on quiet training windows |

**Inputs:** Parsed 802.11 management/EAPOL features (not full payloads beyond IE/EAPOL heuristics).  
**Outputs:** Structured alerts (`alert_type`, severity, evidence) stored in SQLite and shown on a Flask dashboard.

## Training data

- **Baseline / IsolationForest:** Quiet live capture windows from the operator’s RF environment and/or synthetic benign beacon windows in `src/eval/dataset.py`.
- **Evaluation labels:** Synthetic scenarios only (see `python -m src.eval_main`). No third-party production network labels are claimed.

## Evaluation (reproducible)

```bash
python -m src.eval_main
# → data/reports/eval/metrics.json
# → data/reports/eval/report.md
```

Reported metrics include:

- Per-scenario pass/fail for each signature
- Per-alert-type precision / recall / F1
- IsolationForest ROC-AUC on synthetic benign vs attack windows

Run `make eval` or CI to regenerate.

## Intended use

- Detect common Wi-Fi attacks in a **lab or authorized** environment
- Validate detectors with allowlisted lab actions + offline simulations
- Portfolio / educational demonstration of ML + security engineering

## Out of scope / misuse

- Attacking networks without authorization
- Stealth, evasion, user tracking, or credential theft
- Claiming production SOC accuracy without site-specific labeled data

## Ethical / legal constraints

- Live RF actions require `lab.targets ⊆ allowlist` and interactive `CONFIRM`
- Engagement workflow records Rules of Engagement acknowledgements
- Passive monitoring of others’ networks may still be restricted by law — operate only where authorized

## Limitations & failure modes

- **Channel blindness:** Monitor radio must be on the victim/AP channel to see frames
- **PMKID heuristics:** Byte-pattern detection can false-positive on unusual EAPOL layouts
- **Handshake harvest:** Correlates deauth→EAPOL; legitimate roaming can look similar
- **IsolationForest:** Sensitive to contamination and baseline drift; broadcast/multicast BSSIDs are filtered
- **Synthetic eval ≠ live RF:** High lab metrics do not guarantee field performance

## Fairness / privacy

- No intentional biometric or person tracking
- Reports may include BSSIDs/SSIDs observed passively — sanitize before publishing

## Maintenance

- Retrain baseline after environment changes: `python -m src.main --train-baseline`
- Thresholds: `config/wids.yaml` → `detectors.*`
- Contact: repository maintainer

## Citation / demo

```bash
make demo   # pytest + eval + simulate all + offline WIDS
```

See also: [THREAT_MODEL.md](THREAT_MODEL.md), [attacks/README.md](attacks/README.md).
