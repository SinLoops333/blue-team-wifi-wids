# PMKID harvesting and forced handshake capture

## WPA handshake (quick background)

WPA2-Personal uses a **4-way handshake** (EAPOL-Key messages M1–M4) after association to prove knowledge of the PSK and derive session keys. Capturing that handshake (plus the SSID) enables **offline** PSK cracking.

Attackers often **deauth** a client first so it reconnects and produces a fresh handshake.

## PMKID

### What it is

Some APs include an **RSN PMKID** in the first EAPOL-Key message (M1) or related RSN IE. Tools can extract that PMKID and attempt offline cracking **without** waiting for a full 4-way exchange.

### What you see on the air

- EAPOL frames (EtherType 0x888E over LLC/SNAP)
- M1-like key info flags
- RSN PMKID KDE marker (`00:0f:ac:04` / `dd 16 00 0f ac 04…` in frame bytes)

### How WIDS detects it

`frame_features.py` flags `has_pmkid` when those byte patterns appear in EAPOL payloads.

`signatures.py` → `_check_pmkid` → alert `pmkid_harvest`.

### How to defend

- Strong, unique passphrases (or better: WPA3 / SAE, which changes the game)
- Prefer WPA3-Personal or Enterprise
- Keep AP firmware current (vendor behavior around PMKID varies)
- Detect PMKID-bearing EAPOL (this WIDS) as an early warning of targeting

---

## Forced handshake harvest (deauth → EAPOL)

### What it is

Pattern: **burst of deauth**, then shortly afterward **EAPOL** involving the same BSS — classic “kick then capture handshake” workflow.

### How WIDS detects it

`signatures.py` → `_check_handshake_harvest`:

- Remembers recent deauth events
- If EAPOL arrives within `deauth_then_eapol_window` seconds (default **15**) for the same BSSID → `handshake_harvest`

Config:

```yaml
detectors:
  handshake_harvest:
    deauth_then_eapol_window: 15
```

### How to defend

- PMF (802.11w) to reduce spoofed deauth effectiveness
- WPA3 where possible
- Monitor for deauth floods **and** deauth→EAPOL sequences (this WIDS)
- Client-side: avoid sticky auto-reconnect on hostile RF (hard in practice)

### Lab / test notes

Full live PMKID/handshake validation needs a client associating to **your** lab AP while you generate traffic. Safer first steps already in-repo:

```bash
# Synthetic frames (unit tests / sample pcap)
pytest -q tests/test_signatures.py -k "pmkid or handshake"

# Combined sample
python -m src.main --offline data/captures/sample_attacks.pcap --no-dashboard
```

Live path (owned gear only): run WIDS, associate a test phone to `Open999`, then scoped deauth — you may see `deauth_flood` and, if EAPOL follows, `handshake_harvest`.
