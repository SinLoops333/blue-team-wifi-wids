# Case study: blue-team Wi-Fi WIDS

**Demo video (2–3 min):** _add link after recording_ — [recording script](DEMO_SCRIPT.md).

## Problem

Home / lab Wi-Fi environments need early warning for classic RF attacks
(deauth floods, evil twins, KARMA, PMKID/handshake harvest) without
turning the operator into an offensive toolkit user. Hiring managers for
ML + security roles want **measured detectors**, not a longer attack list.

## Design

1. **Passive first** — Mark VII streams monitor-mode frames over SSH; no
   injection in the default path.
2. **Signatures + ML** — Rule detectors catch known patterns; IsolationForest
   flags novel window behavior with feature attribution (z-deviation from
   benign centroid). Eval compares One-Class SVM as a second model.
3. **Scoped lab** — Live validation only against owned BSSIDs with RoE /
   CONFIRM / audit JSONL.
4. **Ship like a team** — pytest + eval CI, `make demo`, model card + threat
   model, suppressions and severity scores for SOC-style polish.

## Metrics (lab-sanitized)

Run `python -m src.eval_main` (or see [`sample_metrics.json`](sample_metrics.json)):

| Signal | Typical lab result |
|---|---|
| Signature scenario pass rate | 100% on synthetic labeled scenarios |
| IsolationForest ROC-AUC | ≥ 0.9 on noisy benign vs attack windows |
| One-Class SVM ROC-AUC | Competitive; winner reported in eval report |
| Deauth threshold | Tuned via FPR sweep (interview line: measured FPR on lab RF) |

Third-party MACs from ambient RF are **not** published; reports sanitize or
omit foreign BSSIDs.

## Ethics / scope

- Monitor only networks you are authorized to observe.
- Lab attacks only on equipment you own, listed in allowlist + lab targets.
- Model card documents false-positive modes and what the system does **not** claim.

## Interview one-liners

- “I tuned the deauth threshold with a measured FPR on my lab RF.”
- “Eval compares IsolationForest vs One-Class SVM and prints feature
  attribution for why a window looked anomalous.”
- “Live RF is gated by allowlist ∩ CONFIRM; the public path is passive WIDS.”
