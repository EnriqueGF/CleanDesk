# CleanDesk — Architecture

## Design goal

A **low-latency**, **secure** and **lightweight** remote desktop, with a
**P2P-by-default** connection and a **relay** only as a last resort. All in
Rust, with a clear contract boundary (`cleandesk-proto`) shared by client, host,
server and relay.

## Communication planes

CleanDesk separates three planes, each with its optimal serialization:

| Plane | Channel | Serialization | Content |
|---|---|---|---|
| **Signaling** | WebSocket client↔server | JSON (`SignalMessage`) | registration, ID resolution, requests, SDP/ICE relay |
| **Control** | Reliable P2P data channel | postcard (`SessionMessage`) | permissions, chat, clipboard, files, stats |
| **Media** | P2P data channels | postcard (`VideoFrame`) / (`InputEvent`) | video (host→viewer), input (viewer→host) |

> `SignalMessage` uses serde's internal tagging (readable in JSON). Messages
> that travel over **postcard** (binary, not self-describing) use **external**
> tagging — it is a postcard requirement, verified by tests in `frame.rs`.

## Workspace crates

```
proto      ← contract: IDs, permissions, messages, framing, version           (no heavy deps)
crypto     ← Ed25519 identity, Argon2id, tokens, challenge-response proof
transport  ← WebRTC (ICE/STUN/TURN/DTLS) + WS signaling client
capture    ← DXGI Desktop Duplication (Windows), monitor enumeration
codec      ← VideoEncoder/Decoder trait + tiles+zstd+JPEG impl (MVP)
input      ← SendInput (Windows), InputEvent mapping and key codes
core       ← config, storage, address book, history, session state machine
host       ← host role: capture→encode→send; receive→inject input
client     ← viewer role: receive→decode; capture→send input
gui        ← eframe/egui: main window + session viewer
app        ← binary: GUI / --host / --connect modes
signal-server ← binary: CleanDesk Server (signaling)
relay-server  ← binary: CleanDesk Relay (TURN fallback; --community announces itself in the DHT)
platform   ← OS integration: start with Windows, SCM service, presence lock
discovery  ← serverless rendezvous: mDNS, BitTorrent DHT (BEP 44), Nostr, UPnP
```

Dependency graph (simplified):

```
app ─► gui ─► core ─► crypto ─► proto
        │      │
        ├─► host ─► capture, codec, input, transport
        └─► client ─► codec, transport
transport ─► proto     signal-server ─► proto, crypto
```

## Community mode (serverless)

`cleandesk-discovery` replaces the CleanDesk Server with public infrastructure:

| Need | Mechanism |
|---|---|
| Find a machine on the LAN | mDNS `_cleandesk._tcp` with ID, key and port in the TXT record |
| Find a machine by ID on the Internet | BitTorrent mainline DHT: BEP 44 mutable item signed with the host's key, published under its key and under a key derived from the ID |
| Exchange SDP/ICE when the host is reachable | direct TCP link (port 7423) with mutual Ed25519 challenge-response |
| Exchange SDP/ICE when it is not | ephemeral events (kind 27420) on public Nostr relays, NIP-44 encrypted and with an Ed25519↔Nostr binding signature |
| Be reachable behind the router | UPnP/IGD: mapping of 7423/TCP and 7424/UDP; the external IP is announced as a 1:1 ICE candidate |
| Plan B with no direct route | community TURN relays (`cleandesk-relay-server --community`) announced with `announce_peer` on a well-known infohash |

Every 10 min the host publishes a signed `Record` {key, Nostr key, endpoints,
time}. The viewer resolves LAN → DHT by pinned key → DHT by ID, verifies the
signature and that the key derives to the ID, and tries direct → Nostr. `host`
and `client` do not distinguish the path: both work on top of `SignalOut` + an
inbound channel, and the host turns `ConnectRequest` into `IncomingRequest` by
minting the session.

## Connection flow (summary)

1. Both clients register with the **CleanDesk Server** (WS): they send their
   Ed25519 public key and the ID derived from it, sign the server's nonce
   (`RegisterChallenge` → `RegisterProof`) and receive `Registered`. The server
   rejects IDs that do not derive from the key, and invalid signatures.
2. The viewer sends `ConnectRequest{target}`. The server opens a session and
   delivers `IncomingRequest` to the host.
3. The host shows the request (or validates unattended access) and replies
   `Accept{granted}` / `Reject`.
4. The peers exchange **SDP + ICE** via `Signal` (the server only forwards; it
   cannot read anything). ICE tries direct routes (host, srflx via STUN, and
   TURN relay as fallback).
5. Data channels are opened: `control`, `video`, `input` (+ `files` on demand).
   `video` is unreliable/unordered (a late frame is worthless); `control`,
   `input` and `files` are reliable and ordered (losing a *key-up* would leave
   a key stuck).
   Encryption is end-to-end **DTLS**, negotiated between the peers.
   The first message each peer sends on `control` is an `IdentityProof`: an
   Ed25519 signature over the session id and both DTLS certificate
   fingerprints (session channel binding, protocol 2.2). Nothing else is
   sent or honoured until both proofs verify; for unattended sessions the
   host does not even introduce itself (`Hello`/`Monitors`) before the
   password challenge succeeds.
6. The host captures → encodes → sends `VideoFrame`; the viewer decodes and
   paints; the viewer sends `InputEvent`; the host injects them according to
   permissions.
7. Either side presses **Disconnect** (or the host **End session**) → orderly
   shutdown, release of pressed keys and a history entry.

## Performance

- **Capture:** DXGI Desktop Duplication delivers only frames with changes; a
  dirty-tile grid (64×64) is also computed so that what did not change is not
  re-encoded.
- **Codec:** MVP = JPEG tiles + zstd (keyframe / delta). The `VideoEncoder`
  trait allows replacing it with H.264/HEVC (NVENC) without touching
  host/client.
- **Adaptation:** `QualityProfile::Auto` adjusts FPS/quality according to the
  RTT measured by `Ping`/`Pong` on the control channel
  (`host::media::auto_params`). The host limits the capture rate to the target
  FPS and, if the send queue fills up, drops the frame and forces a keyframe (a
  lost delta would corrupt the canvas).
- **Loss recovery:** the viewer detects sequence gaps, deltas without a
  preceding keyframe or decoding errors and requests `RequestKeyframe` (limited
  to one every 500 ms).
- **Release profile:** thin LTO, `codegen-units=1`, `panic=abort`, symbols
  stripped.
