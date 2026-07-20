# Blue-team Wi-Fi WIDS

Passive **Wi-Fi Intrusion Detection** on a WiFi Pineapple Mark VII, plus an
**isolated lab** and **authorized engagement** workflow. Live RF actions only
hit allowlisted gear you own, with RoE + CONFIRM gates and full audit logs.

**For hiring managers:** [Interview brief](docs/INTERVIEW_BRIEF.md) ·
[Case study](docs/CASE_STUDY.md) · [Sample report](docs/sample_report.html) ·
[Sample metrics](docs/sample_metrics.json)

## Capabilities matrix

| Capability | Command |
|---|---|
| Live monitor + dashboard | `python -m src.main` |
| Dual-radio fusion | `python -m src.main --fusion --channel 11` |
| Pin monitor channel (lab) | `python -m src.main --channel 11` |
| Offline pcap analysis | `python -m src.main --offline file.pcap` |
| Keep dashboard after offline | `… --offline file.pcap --keep-dashboard` |
| Train anomaly baseline | `python -m src.main --train-baseline` |
| Eval harness (P/R/F1, ROC-AUC) | `python -m src.eval_main` / `make eval` |
| One-command demo | `make demo` |
| Health check | `python -m src.status_main` |
| Lab scope list | `python -m src.lab_main --list` |
| Live deauth (owned AP) | `python -m src.lab_main --attack deauth` |
| Simulate detectors (pcap) | `python -m src.lab_main --simulate all --yes` |
| Engagement RoE session | `python -m src.engagement_main start` |
| Export HTML/JSON/CSV report | `python -m src.engagement_main export` |
| End session + report | `python -m src.engagement_main end` |

**Detectors:** deauth flood, evil twin, encryption downgrade, KARMA, PMKID,
handshake harvest, IsolationForest anomaly (eval also compares One-Class SVM),
beacon IE fingerprint / TSF clone detection.

**Simulations:** `evil_twin`, `karma`, `deauth`, `encryption_downgrade`,
`pmkid`, `handshake_harvest`, `all`.

## What it detects

| Detector | Signal |
|---|---|
| **Deauth / disassoc flood** | Burst of subtype 12/10 frames from one source |
| **Evil twin / rogue AP** | Known SSID appears on a new BSSID |
| **Encryption downgrade** | Known AP suddenly advertises OPEN |
| **KARMA** | One BSSID answers / beacons many distinct SSIDs |
| **PMKID harvest** | EAPOL frame carrying an RSN PMKID KDE |
| **Handshake harvest** | Deauth shortly followed by EAPOL |
| **Beacon clone** | Same BSSID but IE fingerprint change or TSF clock anomaly |
| **Radio fusion** | Multi-radio SSID split / channel conflict / IE disagreement |
| **Anomaly (ML)** | IsolationForest + feature attribution; OCSVM compared in eval |

## Layout

```
wids/
├── config/*.example.yaml
├── src/
│   ├── capture/          # SSH + live/offline sniffer
│   ├── detect/           # features, signatures, baseline, anomaly
│   ├── alerts/           # Alert model, policy, sqlite store
│   ├── eval/             # labeled scenarios, metrics, model compare
│   ├── dashboard/        # Flask + SSE UI + lab-validation badge
│   ├── lab/              # scoped RF + simulations
│   ├── engagement/       # RoE sessions + reports
│   └── main.py
├── docs/                 # model card, threat model, architecture, case study
├── tests/
└── .github/workflows/ci.yml
```

## Setup

```bash
cd ~/Documents/cursor/cybersecurity/wids
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
cp config/wids.example.yaml config/wids.yaml
# Edit .env with your Pineapple IP / SSH password
# Edit config/wids.yaml allowlist with your own AP BSSIDs and the Pineapple's MACs
```

### Monitor interface on the Pineapple

1. In the Mark VII UI, ensure a radio is in **monitor** / recon mode (often `wlan1` or `wlan1mon`).
2. Or let WIDS try: on start it runs a best-effort `airmon-ng` / `iw` monitor setup over SSH.
3. Set `capture.interface` in `config/wids.yaml` to that interface name.
4. Confirm `tcpdump` is available on the Pineapple (it usually is).

SSH must be enabled on the Pineapple (Management → SSH). Credentials go in `.env` only — never commit them.

### Allowlist (important)

Add every BSSID you own — including the Pineapple’s radios — under `allowlist.bssids` so PineAP / your lab APs are not flagged as evil twins:

```yaml
allowlist:
  bssids:
    - "28:ee:52:01:f4:ab"   # your AP
    - "00:13:37:xx:xx:xx"   # pineapple wlan MAC(s)
  ssids:
    - "HomeLab"
```

## Usage

```bash
cd ~/Documents/cursor/cybersecurity/wids
source .venv/bin/activate

# Live capture + dashboard (http://127.0.0.1:8080)
python -m src.main

# Structured JSON logs (SOC / pipeline friendly)
python -m src.main --json-logs

# Offline analysis of a pcap (no Pineapple needed)
python -m src.main --offline data/captures/sample.pcap

# Quiet period: build AP inventory + train IsolationForest
python -m src.main --train-baseline

# Headless
python -m src.main --offline foo.pcap --no-dashboard
```

Dashboard: **http://127.0.0.1:8080** — live SSE alerts, AP inventory, frame-rate charts.

## Tests

No hardware required — detectors are exercised with synthetic Scapy frames:

```bash
cd ~/Documents/cursor/cybersecurity/wids
pytest -q
```

## Security notes

- Credentials live in `.env` (git-ignored). The old `test_pineapple.py` in the parent folder was updated to load them the same way.
- Capture is **receive-only** over `tcpdump -w -` streamed via SSH.
- Do not point this at networks you are not authorized to monitor. In most jurisdictions, monitoring networks you do not own or operate still requires authorization.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — pipeline diagram
- [Roadmap](docs/ROADMAP.md) — A→E feature build order
- [Interview brief](docs/INTERVIEW_BRIEF.md) — elevator + resume bullets + talking points
- [Case study](docs/CASE_STUDY.md) — problem → design → metrics → ethics
- [Sample report](docs/sample_report.html) — sanitized lab validation HTML
- [Model card](docs/MODEL_CARD.md) — training, metrics, limitations, ethics
- [Threat model](docs/THREAT_MODEL.md) — assets, adversaries, controls
- [Sample eval metrics](docs/sample_metrics.json) — sanitized lab numbers
- [Wi-Fi attack vectors ↔ WIDS detectors](docs/attacks/README.md)

## Evaluation & CI (portfolio)

```bash
# Signatures P/R/F1 + IsolationForest vs One-Class SVM + deauth threshold sweep
python -m src.eval_main
# → data/reports/eval/report.md  and  metrics.json

make demo    # pytest + eval + simulate all + offline WIDS
make test
```

Dashboard shows a **lab validation** badge from the latest eval (or
`docs/sample_metrics.json` fallback). Alert policy supports `suppress_bssids` /
`suppress_types` and `severity_score` in `config/wids.yaml`.

GitHub Actions: [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs
`pytest` and the eval harness on every push/PR.

## Phase 2 — Isolated lab (owned targets only)

Validate WIDS detectors by generating **controlled** attack traffic against
equipment listed in both `config/lab.yaml` → `targets` **and**
`config/wids.yaml` → `allowlist`. Foreign BSSIDs are refused.

```bash
# Show what you are allowed to hit
python -m src.lab_main --list

# Dry-run (no RF)
python -m src.lab_main --attack deauth --dry-run --yes

# Live deauth against your lab target (type CONFIRM when prompted)
# Terminal A: python -m src.main
# Terminal B:
python -m src.lab_main --attack deauth

# Pcap simulations (no live RF) — evil twin / KARMA / deauth flood
python -m src.lab_main --simulate evil_twin --yes
python -m src.main --offline data/captures/lab_simulated.pcap
```

Safety rails:
- Target must be in `lab.targets` **and** WIDS allowlist
- Interactive `CONFIRM` prompt (or audited `--yes`)
- Append-only audit log: `data/logs/lab_audit.jsonl`
- Default target is your Pineapple `Open999` AP (`00:13:37:a9:43:43`)

To attack your own home/lab router instead, add its BSSID/SSID to **both**
`wids.yaml` allowlist and `lab.yaml` targets.

## Authorized engagement (RoE + reports)

```bash
python -m src.engagement_main start --yes    # auto-ack RoE (still logged)
python -m src.main --channel 11              # monitor pinned to lab AP channel
python -m src.lab_main --attack deauth       # scoped live test
python -m src.engagement_main export         # HTML + JSON + CSV under data/reports/
python -m src.engagement_main end            # close session + export

python -m src.status_main                    # health / SSH / scope check
```

Config: `config/engagement.yaml`.
