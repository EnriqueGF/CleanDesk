# CleanDesk — Security and threat model

CleanDesk is a **consent-based remote access** tool. Every design decision
assumes that remote control of a machine is a sensitive capability and must
always be authorized, visible and revocable.

## Principles

1. **Explicit consent.** Every interactive connection requires the host to
   press *Accept*. Unattended access requires a password deliberately
   configured by the machine's owner.
2. **Visibility.** The host shows visual confirmation of an active session
   (spec §18) and who is connected. No hidden connections.
3. **Revocability.** Permissions can be reduced, or the session cut, at any
   time (spec §6, §28).
4. **End-to-end encryption.** Media and control go over DTLS between the peers;
   the signaling server never sees the keys or the content.
5. **Least privilege.** The viewer receives only the permissions the host
   grants (`Permissions` is a negotiated bitset; the host is the authority).

> CleanDesk is **not** covert surveillance software. The design deliberately
> prevents silent access without the knowledge of the machine's user.

## Cryptographic controls (`cleandesk-crypto`)

| Threat | Control |
|---|---|
| Device impersonation | **Ed25519** identity per device. The CleanDesk ID is **derived** from the public key and, at registration, the server demands a **signature over a nonce** (`RegisterChallenge`/`RegisterProof`): nobody can register an ID without the private key. Fingerprint verifiable out of band. |
| Theft of the unattended password | Stored only as **Argon2id** (PHC). Never in plain text (spec §18). |
| Password over the network | **HMAC challenge-response**: the password never crosses the wire; the host verifies. |
| Credential reuse | Random **tokens** with expiry; constant-time comparison. |
| Brute force | Host: 3 free failures, then a lockout of 30 s doubling up to 15 min, keyed by the caller's **verified** public key (not the self-declared ID); plus a global breaker — 10 failures from any callers within 10 min close unattended access for everyone for 5 min, doubling up to 1 h (`host::AuthThrottle`); 30 s timeout to answer the challenge. Server: token bucket of 5 `ConnectRequest` per 30 s per connection, budget of 10 malformed messages, WebSocket messages ≤ 64 KiB, handshake/registration/idle deadlines. |
| Rendezvous in the middle of the DTLS session | **Session channel binding** (below): both peers sign the session id and both DTLS fingerprints with their Ed25519 keys before anything else is exchanged. |
| Disk exhaustion via file transfer | The host refuses offers above `HostConfig::max_file_size` (8 GiB default), more than 4 incoming transfers at once, or when the volume would keep less than 512 MiB free; the viewer is told why (`FileTransferMsg::Refused`). |
| ID impersonation in community mode | Without a server there is no "first come, first served" registration: an attacker can generate a key whose derived ID collides with yours (~2^30 attempts). The viewer **pins the key** after the first session (`Settings::pinned_keys`) and rejects another key under the same ID; the fingerprint is shown under Security so it can be verified over another channel. DHT/mDNS records are only hints: nothing is accepted without a valid signature and without the key deriving to the ID. |
| Caller impersonation | The server overwrites `from.id` with the ID registered on the connection; `Accept`/`Reject` are accepted only from the callee and `Signal` only from session members. |
| Hostile input from the network | Strict `postcard` (no trailing bytes), `Reassembler` validates chunk headers/indices, rejects chunk payloads over 16 KiB and caps the bytes buffered for a frame at 64 MiB (a frame that grows past it is dropped), the decoder bounds dimensions (8192) and zstd decompression (64 MiB) to prevent memory bombs. |
| Stuck keys | The host releases every key/button the viewer left pressed when the session ends, however it ends. |
| Media/control interception | End-to-end **DTLS** (WebRTC layer in `transport`). |

## Session channel binding

WebRTC's DTLS handshake only checks the peer certificate against the
fingerprint carried in the SDP — and the SDP travels through the rendezvous
(CleanDesk Server, a LAN link, the DHT, Nostr). A rendezvous that rewrote both
fingerprints could terminate two DTLS sessions and read everything. Since
protocol 2.2 the **first message on the control channel, in both
directions, is `SessionMessage::IdentityProof`**:

```text
msg  = "cleandesk-session-v1:" ‖ role ‖ session_id ‖ len(local_fp) ‖ local_fp ‖ len(remote_fp) ‖ remote_fp
proof = { public_key, Ed25519-sign(device_key, msg) }
```

`local_fp` / `remote_fp` are the SHA-256 fingerprints of the signer's own DTLS
certificate and of the certificate it actually authenticated against
(`transport::PeerConnection::dtls_fingerprints`, read from the DTLS layer,
not from the relayed SDP). The receiver rebuilds the message from *its* view
of the fingerprints (swapped) and the opposite role, verifies the signature,
and checks that the key derives to the CleanDesk ID it dialed / that
requested the session. A relay in the middle would have to forge a signature
over fingerprints it does not control. Both sides wait at most 10 s for the
peer's proof; any other message before it, a bad signature or a wrong key
closes the session.

The viewer returns the proven host key in `ClientSession::peer_public_key`
in **every** mode (the GUI pins it — trust on first use) and refuses with
`ClientError::IdentityMismatch` when `ClientConfig::expected_host_key` (the
pinned key, or the key from a community record) differs. The host keys its
brute-force throttle by the viewer's proven key and does not send `Hello` /
`Monitors` to an unattended viewer until the password challenge succeeds.

## Known MVP limitation and plan

The current challenge-response proof (`crypto::proof`) uses
`HMAC(Argon2id(pw), challenge)`. Since the **server forwards** the challenge
and the response, a malicious server could attempt an **offline** dictionary
attack. In the MVP this is accepted because the server is first-party
infrastructure and the password goes through Argon2id.

**Post-MVP plan:** replace it with a **PAKE** (e.g. SPAKE2 / OPAQUE) so that
not even a compromised server can derive the password. Tracking: this document.

## Local storage

- The identity private key is stored as PKCS#8 PEM, protected by OS ACLs (and
  DPAPI on Windows as additional hardening). Excluded from git.
- Tokens and password hashes are stored in the user profile, never in the
  repository (`.gitignore` covers `/data`, `*.identity`, `*.token`).
- Next to the Argon2id hash, the **derived HMAC key** is stored (Argon2id of the
  password with a salt bound to the host ID): the host needs it to verify the
  challenge-response. It is not the password, but whoever obtains it can
  authenticate as an unattended viewer of that host; that is why the file is
  written with restricted permissions and atomically (`core::storage`). The
  post-MVP PAKE removes this exposure as well.
- Files are written atomically (temporary + rename) and a corrupt
  `appdata.json` is set aside as a backup instead of preventing startup; a
  corrupt `identity.pem` is a hard error (regenerating it would change the ID).

## Community mode and infrastructure hardening (rendezvous v2)

Findings from the September 2026 audit of the serverless path
(`cleandesk-discovery`), the community host loop (`host::community`), the
signaling server and the relay, with what was done about each.

### Direct-link proof is no longer a registration proof (H1)

The direct TCP handshake (`discovery::direct`) used to have the host sign the
same `cleandesk-register-v1:` + nonce message that the CleanDesk Server
demands at registration. Anyone who could reach a host's direct port could
therefore start a registration on the server, hand the server's nonce to the
host as "its" challenge, and forward the host's signature: the server would
register the attacker's socket under the host's ID and the real host would be
kicked with `IdConflict`.

Now each side signs [`direct_proof_message`](../crates/discovery/src/direct.rs):
prefix `cleandesk-direct-v1:`, the rendezvous version, the signer's **role**
(`host`/`viewer`), **both** public keys and the peer's nonce. A direct-link
signature cannot verify as a registration proof (different prefix), cannot be
replayed as the other role's proof, and is bound to the exact viewer key it
was issued for, so it cannot be relayed to a third party either. The host only
signs after the viewer's own proof verified. `RENDEZVOUS_VERSION` is 2 and the
DHT/mDNS namespace is `cleandesk-v2`; v1 peers are not interoperable
(tests: `direct_proof_and_registration_proof_are_not_interchangeable`,
`direct_proof_is_bound_to_role_and_both_keys`, `legacy_handshake_is_refused`).
The server's registration message format is unchanged.

### Colliding keys for a 9-digit ID (H3)

An ID carries ~30 bits, so a key that derives to a target ID can be ground in
minutes. Pinning (above) is the primary defence; the discovery layer now also:

* rejects records dated more than 5 minutes in the future
  (`MAX_FUTURE_SKEW_SECS`), so a far-future `ts` can no longer be the
  "newest valid record" forever;
* on a by-ID lookup, when **valid records signed by different keys** claim the
  same ID, prefers the record matching the pinned key and otherwise returns
  `DiscoveryError::AmbiguousIdentity { keys }` instead of silently picking
  the newest (the client must refuse or ask the user to verify a fingerprint);
* on a by-key lookup, checks that the record's embedded `pk` is the key the
  slot was looked up under.

### Squatting the ID-index slot (M1)

The BEP 44 slot for an ID is derived from the ID alone, so anyone can write it,
and the DHT keeps the item with the highest `seq`. A squatter can park a huge
`seq` there so the host's later puts are refused. `DhtNode::publish` now reads
the slot back after a sequence conflict and republishes with
`max(current + 1, ts)` (logged at `warn`). **Residual risk:** a squatter that
keeps bumping the slot between republishes (every 10 minutes) can still cause
misses on the by-ID path; the by-key path, which only the host can write, is
unaffected, which is another reason the viewer pins the key.

### LAN announcements are hints only (M2)

mDNS TXT records are unsigned. The resolver now checks that the announced key
derives to the requested ID **before** the pin comparison, so a stray
announcement with an unrelated key is ignored rather than raised as "the
device's identity changed". A key learned from the LAN alone must never be
pinned; pin only after the direct handshake proved it. (The discovery crate
never pins; the GUI is being adjusted separately.)

### Community host: bounded tables and request rate (M4)

`host::community` now detects when a link's driver ended (direct) or drops it
after 10 minutes without traffic (both kinds) unless it owns a session, caps
the number of links at 256 (evicting the longest-idle session-less link),
forgets pending sessions after 5 minutes and sessions whose link is gone, and
rate-limits `ConnectRequest` to 5 per minute per sender key and 30 per minute
overall, answering `RateLimited` and logging at `warn`.

### Nostr signaling: time window and replay set (L2)

Events with `created_at` more than 10 minutes from local time (either way)
are dropped, and the seen-id set is a bounded ring (4096) that evicts the
oldest id one at a time instead of being cleared wholesale, so a burst of
junk events cannot reopen the window for replaying a recent one.

### Relay: peer-address filter, quotas, signed directory records (L3)

The community TURN credential (`cleandesk` / `cleandesk-community`) is public
**by design**: an open community relay has nobody to hand out secrets, the
relayed traffic is DTLS end to end, and the credential exists only because
TURN requires one. The trade-off is that the relay is a UDP proxy for anyone.
Mitigations in `cleandesk-relay-server`:

* **Peer filter.** Relaying towards loopback, link-local, private
  (RFC 1918 / ULA), shared address space (RFC 6598) and multicast peers is
  refused by default (datagrams from such sources are dropped too), so the
  relay cannot be used to reach its operator's host or network. A relay that
  serves one private LAN opts in with `CLEANDESK_RELAY_ALLOW_PRIVATE_PEERS=1`.
  The `turn` crate has no permission hook, so the filter wraps every relay
  socket (`relay_server::guard`), which covers `Send`, `ChannelData` and
  inbound traffic alike.
* **Quotas.** Per allocation: lifetime (`CLEANDESK_RELAY_ALLOCATION_MAX_SECS`,
  default 24 h) and bytes in both directions
  (`CLEANDESK_RELAY_ALLOCATION_MAX_BYTES`, default 16 GiB in community mode,
  unlimited otherwise). Exceeding either tears the allocation down.
* **Signed directory.** A community relay keeps an Ed25519 identity
  (`CLEANDESK_RELAY_IDENTITY`) and publishes a signed `RelayRecord`
  (its key, `host:port`, timestamp; `RELAY_RECORD_VERSION` 1) under a DHT slot
  derived from the address, next to the `announce_peer` it always made.
  Clients only hand ICE the addresses whose record verifies and names that
  exact address. This gives each relay a stable identity to pin or block and
  stops address injection by bare `announce_peer`; it does **not** prove the
  key's owner controls the address, and a hostile operator can still run a
  relay (harmless to confidentiality, relevant to availability and metadata).
  Backward compatibility: relays running the previous code are ignored by
  current clients until updated; the namespace change already separates the
  two generations.

### Signaling server: per-IP limits (L4)

Alongside the per-connection budgets, one source IP may hold at most 20
concurrent sockets (refused before the WebSocket upgrade) and start at most 30
registrations per minute (`state::IpLimits`); the table of tracked addresses
is pruned once it exceeds 10 000 entries.

## Responsible disclosure

Security flaws must be reported privately to the maintainers before public
disclosure.
