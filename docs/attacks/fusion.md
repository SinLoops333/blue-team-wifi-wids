# Dual-radio / multi-channel fusion

## Idea

Use **two Mark VII radios** at once:

| Radio | Role |
|---|---|
| **Primary** (`capture.interface`, often `wlan1`) | Pinned to lab channel (e.g. 11) |
| **Secondary** (`fusion.secondary_interface`) | Fixed channel **or** hops `[1,6,11]` |

Compare beacon views. Attackers / evil twins often disagree across radios or channels.

## Alerts

| Alert | Meaning |
|---|---|
| `radio_ssid_split_view` | Same SSID, different BSSIDs, each seen on a different radio |
| `radio_channel_conflict` | Same BSSID advertised on two different channels |
| `radio_fingerprint_disagreement` | Same BSSID, different IE fingerprints across radios |

## Enable

```yaml
# config/wids.yaml
fusion:
  enabled: true
  secondary_interface: auto   # or wlan2
  hop_channels: [1, 6, 11]
  hop_seconds: 2.0
```

```bash
# Put a second radio in monitor/Recon mode in the Pineapple UI, then:
python -m src.main --fusion --channel 11
```

## Hardware note

Mark VII must expose **two** monitor-mode interfaces. If `auto` cannot find a
second radio, set `fusion.secondary_interface` explicitly after checking
`python -m src.status_main`.

## Eval (no hardware)

Synthetic multi-radio scenarios are in `src/eval/dataset.py` (tagged
`(packet, radio_id)` tuples). `make eval` exercises them with fusion forced on.
