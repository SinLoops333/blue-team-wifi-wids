# Beacon fingerprint & TSF clone detection

## Problem

Classic evil-twin detection looks for a **new BSSID** advertising a known SSID.
A sophisticated clone can spoof the **same BSSID** (and SSID) but still differ in:

- Information Element (IE) order / vendor IEs
- Beacon interval / capability bits
- 802.11 TSF clock (timestamp field)

## What we detect

| Alert | Signal |
|---|---|
| `beacon_fingerprint_mismatch` | Locked IE fingerprint for a BSSID changed |
| `beacon_tsf_anomaly` | TSF jumped backward (or wildly wrong rate vs wall clock) |

## How it works

1. Parse beacon/probe-resp → IE ID sequence, vendor OUIs, interval, capability, TSF.
2. Hash into a 16-hex fingerprint; after `stabilize_count` identical samples, **lock**.
3. Track `(wall_time, TSF)` per BSSID; flag large backward jumps.

## Lab simulation

```bash
python -m src.lab_main --simulate beacon_clone --yes
python -m src.main --offline data/captures/lab_simulated.pcap
```

Uses your allowlisted lab AP MAC with a synthetic vendor IE + TSF rewind — no foreign targets.

## Config

```yaml
detectors:
  beacon_clone:
    enabled: true
    stabilize_count: 3
    tsf_min_samples: 4
    tsf_max_backward_us: 1000000
```

Prefer `capture.snaplen: 512` (or higher) so vendor IEs are not truncated.

## Limits

- Soft APs / firmware updates legitimately change IEs → expect rare FPs; suppress BSSID if needed.
- Truncated captures (tiny snaplen) collapse fingerprints.
- TSF rate checks are lab-tolerant; primary high-confidence signal is **backward jump**.
