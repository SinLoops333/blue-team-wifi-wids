# Prometheus metrics, privacy, RSSI localization, ONNX

## Metrics

Dashboard exposes:

| Endpoint | Format |
|---|---|
| `GET /metrics` | Prometheus text |
| `GET /api/metrics` | JSON snapshot |

Counters include frames, alerts-by-type, drift PSI, fusion disagreements,
honeypot/privacy/localization events.

## Privacy (owned devices only)

```yaml
privacy:
  enabled: true
  owned_clients:
    - "aa:bb:cc:dd:ee:ff"   # YOUR phone/laptop MAC
  unique_ssid_threshold: 8
  window_seconds: 600
```

Alert: `privacy_probe_exposure` — how many distinct SSIDs your STA probes.

## RSSI lab localization

Requires dual-radio capture (`--fusion`) so the same BSSID is seen on
`primary` and `secondary` with RSSI:

```yaml
localization:
  enabled: true
  sensors:
    - {radio_id: primary, x: 0, y: 0}
    - {radio_id: secondary, x: 10, y: 0}
```

Alert: `rssi_lab_localization` with `(x_m, y_m)` on your lab floorplan.
Allowlisted BSSIDs are skipped (focus on rogues / twins).

## ONNX export

```bash
pip install -r requirements-onnx.txt
python -m src.export_onnx
# → models/honeypot_client.onnx (+ .json feature metadata)
```

Exports `StandardScaler + RandomForest` honeypot recon classifier for edge inference.
