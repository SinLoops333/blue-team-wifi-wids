# Threat model — Blue-team WIDS

## Assets we protect (lab / owner context)

- Integrity of wireless client connectivity on **owned** APs
- Visibility into hostile RF behavior on channels we are authorized to monitor
- Auditability of any lab RF actions the operator performs

## Adversaries (assumed)

| Adversary | Capability |
|---|---|
| Opportunistic RF attacker | Deauth floods, evil twin, KARMA, handshake/PMKID capture nearby |
| Misconfiguration | Open twin / downgrade of a known SSID |
| Noisy environment | High management-frame rates, many SSIDs (raises FP risk) |

We **do not** model nation-state RF or sophisticated 802.11w-aware adversaries in v0.1.

## Trust boundaries

```
[Pineapple monitor iface] --SSH/tcpdump--> [WIDS host]
        ^                                      |
        | (lab only, allowlisted)              v
[aireplay deauth]                    [SQLite + dashboard]
```

- **Pineapple / SSH credentials** are secrets (`.env`, never committed)
- **Allowlist + lab.targets** are the hard authorization boundary for transmit
- Dashboard binds to `127.0.0.1` by default (localhost only)

## Controls

1. Passive path is receive-only (`tcpdump -w -`)
2. Lab attacks: target ∈ `lab.targets` ∧ allowlist; RoE session; `CONFIRM`
3. Append-only lab audit JSONL + engagement reports
4. No stealth/evasion features in codebase goals

## Residual risks

- Operator error (wrong BSSID in allowlist)
- Legal risk if monitoring without authorization
- Detection gaps when radio is on the wrong channel
- Third-party BSSIDs appearing in passive alerts (expected on shared channels)

## Abuse cases we refuse

- Autonomous attacks on discovered (non-allowlisted) networks
- User tracking / “attack when high-value target present”
- IDS evasion as a product goal
