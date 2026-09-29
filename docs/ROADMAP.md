# CleanDesk — Roadmap

Based on the definition sheet (§30 MVP, §31 later). Status as of the project's
start date.

## Milestone 0 — Foundations ✅ (done)

- [x] Cargo workspace with 13 crates and release profiles.
- [x] `proto`: CleanDesk ID, permissions, quality profiles,
      signaling/session/media messages, length-delimited framing. **Tests green.**
- [x] `crypto`: Ed25519 identity, Argon2id, tokens, challenge-response. **Tests green.**
- [x] `signal-server`: registration, ID resolution, signaling relay. Compiles.
- [x] Documentation: README, ARCHITECTURE, SECURITY, SPEC.

## Milestone 1 — Core MVP ✅ (done)

Goal: two Windows machines connect and there is real remote control.

- [x] `transport`: WebRTC transport (control/video/input data channels) +
      WS signaling client. NAT traversal (STUN) and relay (TURN) fallback.
- [x] `capture`: DXGI Desktop Duplication, monitor enumeration, BGRA frames,
      dirty-tile detection.
- [x] `codec`: `VideoEncoder`/`VideoDecoder` trait + tiles+zstd+JPEG impl
      (keyframe/delta).
- [x] `input`: SendInput; `InputEvent` mapping (normalized absolute mouse,
      keyboard by virtual-key, scroll) and permission enforcement.
- [x] `core`: persistence of identity, config, address book, history, trusted
      devices; session state machine; permission manager.
- [x] `host` + `client`: assemble the capture/encoding/input pipelines.
- [x] `gui`: main window (own ID, copy ID, connect, recents) + viewer with
      toolbar.
- [x] `app`: wire up GUI / `--host` / `--connect` modes.
- [x] `relay-server`: TURN server (RFC 5766) with long-term credentials.
- [x] E2E: request → accept → video + control → disconnect → history.

Covers §30: Windows app, ID, signaling, 2-machine connection, capture,
streaming, keyboard/mouse control, accept/reject request, encryption, relay,
password-based unattended access, basic clipboard, file transfer, basic
history.

## Milestone 2 — Robustness and UX

- [x] Multi-monitor (select/switch, §15), full screen/scaling (§16).
- [x] Text clipboard sync (§17), in-session chat, file transfer with
      progress/cancellation (§13).
- [ ] Clipboard images; host-initiated file transfer.
- [x] `Auto` adaptive quality by measured RTT (§8); bandwidth as the next signal.
- [x] Session info panel (RTT/FPS/resolution/codec/bandwidth, §26).
- [x] Windows service (§24): start with Windows, pre-login access.
- [x] Remote reboot, lock session, lock local input, Ctrl+Alt+Del substitute
      (§24). Real secure-attention needs the Windows service (pending).
- [x] Automatic updates with integrity verification (§25): GitHub Releases +
      SHA256SUMS, installed through the MSI.

## Milestone 2b — Community mode ✅ (done)

- [x] `discovery`: mDNS on the LAN, BitTorrent DHT (BEP 44) with a signed record
      under key and under ID, direct TCP signaling with mutual
      challenge-response, NIP-44 encrypted Nostr signaling, UPnP/IGD, relay
      directory via `announce_peer`.
- [x] `host` / `client`: `serve_community` / `connect_community` on top of the
      same session core (`SignalOut`); trust-on-first-use for keys.
- [x] `relay-server --community`: public credentials and DHT announcement.
- [x] GUI: network mode selector, path used shown in the viewer, identity-change
      alarm.
- [x] `platform`: start with Windows, SCM service with a helper in the console
      session, presence lock.
- [x] MSI installer (WiX) with shortcuts and firewall rules.

## Milestone 3 — Post-MVP (§31)

- [ ] Accounts, cloud address book, teams and roles (§21–23).
- [ ] MFA; PAKE for unattended access (see SECURITY.md).
- [x] Wake-on-LAN.
- [ ] Session recording, remote printing, TCP tunnels, remote terminal, API,
      webhooks.
- [ ] Hardware H.264/HEVC codec (NVENC) behind the `codec` trait.
- [ ] macOS / Linux support (per-platform capture/input layers).
- [ ] Web client and mobile app.
