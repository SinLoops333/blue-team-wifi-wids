# Demo video script (2–3 minutes)

Record this for portfolio / LinkedIn / GitHub README. **No third-party MACs on
screen** — use lab Open999 / synthetic pcaps only.

**Suggested title:** `Blue-team Wi-Fi WIDS — measured detectors on a Pineapple lab`

**Target length:** 2:30–3:00  
**Tone:** calm, precise, blue-team (ship / explain / measure)

---

## Before you hit record

```bash
cd ~/Documents/cursor/cybersecurity/wids
source .venv/bin/activate

# One-shot: eval → simulate all → offline WIDS + dashboard
make prep-demo
# Browser → http://127.0.0.1:8080
# Follow the shot list below while recording
```

Optional live RF (only if Pineapple + Open999 are up): have a **second** terminal
ready for `python -m src.lab_main --attack deauth` after CONFIRM. Skip live RF
if you want a fully offline video — the script below works either way.

---

## Shot list + voiceover

| Time | On screen | Say (approx) |
|---:|---|---|
| **0:00–0:20** | README hero + repo URL, then `docs/ARCHITECTURE.md` mermaid (or zoomed diagram) | “This is a passive Wi-Fi intrusion detection system on a WiFi Pineapple Mark VII. Blue-team only — receive RF, detect classic attacks, measure false positives. Not an autonomous offensive agent.” |
| **0:20–0:45** | Terminal: `make eval` (or scroll `data/reports/eval/report.md`) | “Employers care about metrics. The eval harness scores every signature with precision, recall, and F1 on labeled benign vs attack windows, compares IsolationForest to One-Class SVM, and sweeps the deauth threshold for FPR.” |
| **0:45–0:55** | Highlight: scenario pass 100%, IF AUC, recommended threshold | “Interview line: I tuned deauth with measured FPR on my lab RF — here’s that sweep.” |
| **0:55–1:25** | Terminal A: `python -m src.lab_main --simulate all --yes` then `python -m src.main --offline data/captures/lab_simulated.pcap --keep-dashboard` | “One-command lab path: simulate the attack signatures into a pcap, then run offline WIDS. Dashboard stays up so you can see alerts fire.” |
| **1:25–1:55** | Browser dashboard: alert feed filling (evil twin, deauth, karma, PMKID, …) + **lab validation** badge in the header | “SOC-style surface: severity, evidence text, and a lab-validation badge from the last eval run — not a script dump.” |
| **1:55–2:20** | Optional live: Terminal B `python -m src.main --channel 11`, Terminal C live deauth with CONFIRM; show `deauth_flood` on Open999 **only** | “Live RF is gated: allowlisted owned target, human CONFIRM, audit log. Default path is still passive.” *(Skip this block if offline-only; jump to ethics.)* |
| **2:20–2:40** | Flash `docs/MODEL_CARD.md` + `docs/THREAT_MODEL.md` headings | “Security maturity: model card and threat model document what we collect, false-positive modes, and ethics — not just detectors.” |
| **2:40–3:00** | Back to GitHub repo + CI badge / Actions green | “CI runs pytest and eval on every push. Repo, architecture, case study, and sample metrics are public. Thanks for watching.” |

---

## Exact commands (copy/paste during recording)

**Segment A — metrics (offline)**

```bash
cd ~/Documents/cursor/cybersecurity/wids
source .venv/bin/activate
make eval
# optional: open data/reports/eval/report.md in the editor
```

**Segment B — simulate + dashboard (live-looking replay)**

```bash
python -m src.lab_main --simulate all --yes
# Loops the pcap so the terminal keeps printing ALERTs (not a frozen idle)
python -m src.main --offline data/captures/lab_simulated.pcap --replay-loop --replay-delay 0.2
# Browser: http://127.0.0.1:8080
```

Or one shot: `make prep-demo`

**Segment C — live lab (optional)**

```bash
# Terminal 1
python -m src.main --channel 11

# Terminal 2 (owned Open999 only)
python -m src.lab_main --attack deauth
# type CONFIRM when prompted
```

Stop dashboard with Ctrl+C when the clip is done.

---

## Full voiceover (read-aloud, ~450 words)

> This is a passive Wi-Fi intrusion detection system built around a WiFi Pineapple Mark VII. The goal is blue-team: ingest 802.11 frames, detect classic RF attacks, and **measure** detector quality — not ship a longer attack list.
>
> First, evaluation. The harness labels benign versus attack windows, reports precision, recall, and F1 per signature, compares IsolationForest against One-Class SVM, and sweeps the deauth threshold so I can talk about false-positive rate on my lab RF — not vibes.
>
> Next, the product path. I simulate the attack signatures into a pcap, run offline WIDS, and keep the dashboard up. You see alerts for deauth flood, evil twin, KARMA, PMKID, handshake harvest, and friends — with evidence text and a lab-validation badge from the last eval run.
>
> Live RF is optional and gated: only allowlisted gear I own, a human CONFIRM, and an audit log. The default path stays receive-only.
>
> Finally, maturity docs: model card and threat model cover scope, data collected, and ethics. GitHub Actions runs pytest and eval on every push. Links to architecture and a short case study are in the README. Thanks for watching.

---

## Recording tips

1. **1080p**, terminal font ≥ 16pt, dark theme, no transparency.
2. Crop browser to dashboard header + alert feed (hide clutter).
3. If a foreign BSSID appears in ambient RF, **cut that shot** or blur the MAC.
4. Prefer **OBS** (Display Capture + window audio off) or SimpleScreenRecorder.
5. Export H.264 MP4 ≤ ~50 MB for easy uploads.
6. Upload to YouTube (unlisted) or Loom; paste URL into README under **Demo video**.

---

## After upload — update README

Replace the placeholder in [README.md](../README.md):

```markdown
**Demo video (2–3 min):** https://youtu.be/YOUR_ID
```

Also drop the same link at the top of [CASE_STUDY.md](CASE_STUDY.md).
