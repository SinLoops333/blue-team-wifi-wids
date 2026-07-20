# Deauthentication / disassociation floods

## What it is

802.11 management frames can tear down a client’s association without needing the network password:

- **Deauth** (subtype 12) — “leave this BSS”
- **Disassoc** (subtype 10) — similar disconnect signal

They are normally **unauthenticated** on older WPA2 networks (management frame protection / 802.11w fixes this when enabled). An attacker on the same channel can spoof the AP’s or client’s MAC and spam these frames so clients drop and reconnect — useful as Denial of Service, or as a prelude to capturing a fresh WPA handshake.

## What you see on the air

- Burst of deauth/disassoc frames
- Often `addr2` = spoofed AP or client
- Destination often broadcast `ff:ff:ff:ff:ff:ff` (hit everyone) or a specific client MAC
- Volume is the tell: a few frames can be normal; dozens in a few seconds is not

## How WIDS detects it

`src/detect/signatures.py` → `_check_deauth`:

- Sliding window (default **10s**)
- Count deauth+disassoc from each source MAC
- Alert `deauth_flood` when count ≥ threshold (default **20**)

Config:

```yaml
detectors:
  deauth:
    window_seconds: 10
    threshold: 20
```

## How to defend

- Enable **Protected Management Frames (PMF / 802.11w)** — required on WPA3; optional on WPA2
- Prefer WPA3-Personal / Enterprise where clients support it
- WIDS / WIPS that alert on deauth rate (this project)
- Reduce idle roaming flapping (some clients deauth themselves — tune thresholds to limit false positives)

## Lab validation (your setup)

**Live (owned Open999 AP only):**

```bash
# Terminal A
python -m src.main

# Terminal B
python -m src.lab_main --attack deauth   # type CONFIRM
```

Expected: `ALERT [high] Deauth/disassoc flood detected`.

Notes from your run:

- Inject radio must be on the **same channel** as the AP (Open999 = **ch 11**). Lab code tunes `wlan1` then restores the previous channel.
- You may see two alerts (source AP MAC and broadcast) — both indicate the same flood.

**Offline simulation:**

```bash
python -m src.lab_main --simulate deauth --yes
python -m src.main --offline data/captures/lab_simulated.pcap --no-dashboard
```
