# Detector stress suite + threshold autotune

## Idea

Close the loop on eval:

1. **Stress suite** — synthetic near-miss traffic (just below / just above
   thresholds) to prove detectors are sharp, not lucky.
2. **Autotune** — grid-search `deauth.threshold` and `karma.min_ssids_per_bssid`
   maximizing F1 under a max FPR constraint on labeled scenarios.

Lab/synthetic only. Not an attack toolkit.

## Stress cases

| Case | Expect |
|---|---|
| `deauth_just_below` / `just_above` | no / yes `deauth_flood` |
| `karma_just_below` / `just_above` | no / yes `karma` |
| `honeypot_just_below` / `just_above` | no / yes `honeypot_recon_burst` |
| `deauth_sparse_benign` | no flood |
| `evil_twin_positive` | still detects twin |

## Commands

```bash
# Full eval includes stress + autotune → recommended_thresholds.yaml
python -m src.eval_main

# Autotune + stress only
python -m src.autotune_main --max-fpr 0.0
# → data/reports/eval/recommended_thresholds.yaml
# → data/reports/eval/autotune.json

make autotune
```

Paste the YAML snippet into `config/wids.yaml` under `detectors:`.

## Interview line

“I stress-test detectors at the decision boundary and autotune deauth/karma
thresholds for max F1 under a measured FPR cap — not vibes.”
