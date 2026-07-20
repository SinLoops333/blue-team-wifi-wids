# Owned honeypot + client-behavior classifier

## Idea

Flip the Pineapple’s role: run an **AP SSID you own** as a honeypot and
**classify clients** that probe / authenticate to it.

| Benign phone | Automated recon |
|---|---|
| Sparse probes, few SSIDs | Burst probes, high rate, optional multi-SSID scan |

This does **not** enable KARMA or advertise foreign SSIDs. You only watch
traffic toward networks listed under `honeypot.ssids` / `bssids` (your gear).

## Alerts

| Alert | Signal |
|---|---|
| `honeypot_recon_burst` | ≥ N probes to honeypot SSID from one STA in 10s |
| `honeypot_client_anomaly` | RandomForest P(recon) on per-STA feature vector |

Features: probe counts, honeypot ratio, unique SSIDs, auth/assoc, entropy,
burst max, probes/sec.

## Enable

```yaml
honeypot:
  enabled: true
  ssids: ["Open999"]          # owned only
  burst_probe_threshold: 12
  model_path: models/honeypot_client.pkl
```

```bash
# Terminal A — WIDS (honeypot on)
python -m src.main --channel 11

# Optional lab sim (no foreign RF)
python -m src.lab_main --simulate honeypot_recon --yes
python -m src.main --offline data/captures/lab_simulated.pcap
```

On the Mark VII UI, advertise only **your** honeypot SSID (e.g. Open999).
Do not use PineAP to answer probes for networks you do not own.

## Eval

`make eval` includes a honeypot client ROC-AUC block and a
`honeypot_recon_burst` signature scenario.
