# Evil twin / rogue AP and KARMA

## Evil twin / rogue AP

### What it is

An attacker advertises the **same SSID** as a network users trust, but from a **different BSSID** (MAC). Victims connect to the impostor — often an open or captive-portal AP — and traffic can be intercepted or credentials phished.

Related signal: **encryption downgrade** — the real AP is WPA2/3, but a twin suddenly beacons as OPEN.

### What you see on the air

- Beacons / probe responses for a known SSID on a **new** BSSID
- Sometimes stronger RSSI than the real AP
- Capability / RSN IEs that do not match the baseline (e.g. OPEN vs WPA2)

### How WIDS detects it

`signatures.py` → `_check_evil_twin`:

1. Builds a map: SSID → known BSSID(s), channel, encryption (from baseline inventory + first observations)
2. If the same SSID appears on a **new** BSSID → `evil_twin` (critical)
3. If the same BSSID drops from encrypted → OPEN → `encryption_downgrade` (critical)

Allowlisted BSSIDs (your Pineapple / home AP) are skipped so you do not self-alert.

### How to defend

- Educate users: verify captive portals; prefer 802.1X / WPA3-Enterprise
- Certificate-backed enterprise Wi-Fi (users notice cert failures)
- Continuous rogue-AP detection (this WIDS)
- Disable auto-join for open networks on clients

### Lab validation

```bash
python -m src.lab_main --simulate evil_twin --yes
python -m src.main --offline data/captures/lab_simulated.pcap --no-dashboard
```

Expected (your run):

```text
ALERT [critical] Possible evil twin / rogue AP — SSID 'Open999' seen on new BSSID de:ad:be:ef:00:01
```

The pcap contains a legitimate beacon for `Open999` on `00:13:37:a9:43:43`, then a twin on synthetic `de:ad:be:ef:00:01`. No live RF injection.

---

## KARMA / multi-SSID responder

### What it is

Clients probe for networks they remember (`Probe Request` with SSID). A **KARMA**-style attacker answers many of those probes (or beacons many SSIDs) from **one** radio — pretending to be whichever network the victim is looking for.

### What you see on the air

- One BSSID emitting probe responses / beacons for **many distinct SSIDs** in a short window
- Often correlates with nearby probe requests for those names

### How WIDS detects it

`signatures.py` → `_check_karma`:

- Per BSSID, track distinct SSIDs in probe_resp/beacon within `window_seconds` (default 60)
- Alert `karma` when unique SSIDs ≥ `min_ssids_per_bssid` (default 5)

### How to defend

- Disable or limit Wi-Fi Preferred Network List probing where possible (OS-dependent)
- Prefer networks that use randomized MACs + avoid open auto-join
- Detect multi-SSID responders (this WIDS)
- Enterprise: do not rely on open/PSK SSIDs that users roam into blindly

### Lab validation

```bash
python -m src.lab_main --simulate karma --yes
python -m src.main --offline data/captures/lab_simulated.pcap --no-dashboard
```

Expected (your run):

```text
ALERT [high] Possible KARMA / multi-SSID responder — BSSID aa:bb:cc:11:22:33 advertised 5 distinct SSIDs
```
