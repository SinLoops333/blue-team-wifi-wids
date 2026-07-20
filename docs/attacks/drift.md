# Concept drift / continual baseline

## Idea

Signature detectors and IsolationForest assume a **stable quiet RF baseline**.
Real environments drift (new neighbors, channel plan changes, firmware IE
updates). Before (or alongside) per-window anomaly scores, watch whether the
**distribution** of window features has shifted.

## How it works

1. Collect `reference_windows` quiet-ish feature vectors → **lock** reference.
2. Keep a sliding `recent_windows` buffer.
3. Compare recent vs reference with:
   - **PSI** (Population Stability Index) per feature + mean
   - **Mean-shift L2** (standardized distance between means)
4. If over threshold → alert `baseline_concept_drift`.
5. If `adapt: true` → blend recent samples into the reference (continual baseline)
   and clear the recent buffer so we do not alert-spam.

Quiet filter: skips windows with high `deauth_count` or any PMKID so attack
bursts do not poison the reference.

## Config

```yaml
drift:
  enabled: true
  reference_windows: 40
  recent_windows: 20
  min_recent: 15
  psi_threshold: 0.25
  mean_shift_threshold: 2.5
  adapt: true
  adapt_fraction: 0.25
  alert_cooldown_seconds: 120
```

## Alert

| Alert | Meaning |
|---|---|
| `baseline_concept_drift` | Recent RF feature stats diverge from locked baseline |

## Eval

`make eval` reports PSI on same vs shifted synthetic distributions
(`concept_drift` block in metrics).

## Interview line

“I don’t only score outliers — I monitor PSI on the window-feature baseline and
adapt the reference when the RF environment legitimately drifts.”
