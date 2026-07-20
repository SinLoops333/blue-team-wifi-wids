# Wi-Fi attack vectors and WIDS detection

Educational notes for the **blue-team WIDS** in this repo. These describe how common 802.11 attacks work at the protocol level, how this project detects them, and how to defend. They are **not** attack tutorials for use against networks you do not own.

## Lab vs live

| Mode | Command | RF? |
|---|---|---|
| Live monitor | `python -m src.main` | Passive (passive) |
| Live lab deauth (owned AP only) | `python -m src.lab_main --attack deauth` | Yes (scoped) |
| Offline simulation | `python -m src.lab_main --simulate …` then `--offline` | No |

Scope rules: lab targets ⊆ `config/wids.yaml` allowlist. Foreign BSSIDs are refused.

## Detector map

| Attack | Alert type | Doc |
|---|---|---|
| Deauth / disassoc flood | `deauth_flood` | [deauth.md](deauth.md) |
| Evil twin / rogue AP | `evil_twin` | [evil_twin_and_karma.md](evil_twin_and_karma.md) |
| Encryption downgrade | `encryption_downgrade` | [evil_twin_and_karma.md](evil_twin_and_karma.md) |
| KARMA / multi-SSID responder | `karma` | [evil_twin_and_karma.md](evil_twin_and_karma.md) |
| PMKID in EAPOL | `pmkid_harvest` | [pmkid_and_handshake.md](pmkid_and_handshake.md) |
| Deauth then EAPOL | `handshake_harvest` | [pmkid_and_handshake.md](pmkid_and_handshake.md) |
| Same-BSSID IE / TSF clone | `beacon_fingerprint_mismatch`, `beacon_tsf_anomaly` | [beacon_clone.md](beacon_clone.md) |
| Multi-radio fusion | `radio_ssid_split_view`, `radio_channel_conflict`, `radio_fingerprint_disagreement` | [fusion.md](fusion.md) |
| Owned honeypot recon | `honeypot_recon_burst`, `honeypot_client_anomaly` | [honeypot.md](honeypot.md) |
| Concept drift | `baseline_concept_drift` | [drift.md](drift.md) |
| Stress + autotune | near-threshold suite / recommended thresholds | [stress_autotune.md](stress_autotune.md) |
| Metrics / privacy / RSSI / ONNX | SOC metrics + owned privacy + lab localize + edge export | [followons.md](followons.md) |
| IsolationForest outlier | `anomaly` | (ML baseline; see README) |

## Code entry points

- Frame parse / windows: `src/detect/frame_features.py`
- Signatures: `src/detect/signatures.py`
- Lab attacks: `src/lab/`
- Config thresholds: `config/wids.yaml` → `detectors`

## Validated in your lab (Phase 2)

You have already confirmed:

1. **Live deauth** against Pineapple `Open999` → `deauth_flood`
2. **Simulated evil twin** → `evil_twin` (SSID `Open999` on `de:ad:be:ef:00:01`)
3. **Simulated KARMA** → `karma` (5 SSIDs from `aa:bb:cc:11:22:33`)
