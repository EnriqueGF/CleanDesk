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
| Brute force | Host: 3 free failures, then a per-ID lockout of 30 s doubling up to 15 min (`host::AuthThrottle`); 30 s timeout to answer the challenge. Server: token bucket of 5 `ConnectRequest` per 30 s per connection, budget of 10 malformed messages, WebSocket messages ≤ 64 KiB, handshake/registration/idle deadlines. |
| ID impersonation in community mode | Without a server there is no "first come, first served" registration: an attacker can generate a key whose derived ID collides with yours (~2^30 attempts). The viewer **pins the key** after the first session (`Settings::pinned_keys`) and rejects another key under the same ID; the fingerprint is shown under Security so it can be verified over another channel. DHT/mDNS records are only hints: nothing is accepted without a valid signature and without the key deriving to the ID. |
| Caller impersonation | The server overwrites `from.id` with the ID registered on the connection; `Accept`/`Reject` are accepted only from the callee and `Signal` only from session members. |
| Hostile input from the network | Strict `postcard` (no trailing bytes), `Reassembler` validates chunk headers/indices, the decoder bounds dimensions (8192) and zstd decompression (64 MiB) to prevent memory bombs. |
| Stuck keys | The host releases every key/button the viewer left pressed when the session ends, however it ends. |
| Media/control interception | End-to-end **DTLS** (WebRTC layer in `transport`). |

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

## Responsible disclosure

Security flaws must be reported privately to the maintainers before public
disclosure.
