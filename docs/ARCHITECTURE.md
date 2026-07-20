# Architecture

Passive Wi-Fi intrusion detection: Pineapple (or pcap) → features → signatures + ML → alerts → dashboard / reports.

```mermaid
flowchart LR
  subgraph Capture
    P[Pineapple Mark VII<br/>tcpdump -w - via SSH]
    O[Offline pcap]
  end

  subgraph Pipeline
    F[Frame parse + window features]
    S[Signature detectors]
    M[IsolationForest + attribution]
    Pol[Alert policy<br/>suppress / severity]
  end

  subgraph Outputs
    DB[(SQLite events)]
    UI[Flask dashboard + SSE]
    Eval[Eval harness<br/>P/R/F1 · ROC · threshold sweep]
    Rpt[Engagement HTML/JSON/CSV]
  end

  P --> F
  O --> F
  F --> S
  F --> M
  S --> Pol
  M --> Pol
  Pol --> DB
  DB --> UI
  F -.-> Eval
  S -.-> Eval
  DB --> Rpt
```

## Layers

| Layer | Role |
|---|---|
| **Capture** | Receive-only RF over SSH `tcpdump`, or local pcap |
| **Features** | Per-BSSID windows: deauth/EAPOL counts, SSID diversity, encryption flags |
| **Signatures** | Rule detectors with tunable thresholds (deauth FPR measured in eval) |
| **ML** | IsolationForest (runtime) vs One-Class SVM (eval compare); z-deviation “why” text |
| **Policy** | Dedup, BSSID/type suppressions, severity scores |
| **Product** | Dashboard badge from last `make eval`, engagement reports, audit JSONL |

## Safety boundary

Live RF **actions** (lab deauth) require: target ∈ lab allowlist ∩ WIDS allowlist + human `CONFIRM` + audit log. Default path is **passive monitor only**.
