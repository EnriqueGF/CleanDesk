# Trying CleanDesk locally

Requirements: stable Rust (1.85+) and Visual Studio Build Tools (MSVC). To use
CleanDesk without building it, install the MSI from the GitHub release. The
installer asks whether to **start CleanDesk with Windows** and whether to
**create a desktop shortcut**; for silent deployments pass the same choices on
the command line:

```
msiexec /i CleanDesk-0.1.3-x64.msi /qn STARTWITHWINDOWS=1 INSTALLDESKTOPSHORTCUT=0
```

## 0. Community mode (default): no server

When CleanDesk opens, the machine announces itself on its own:

- on the **local network** via mDNS (`_cleandesk._tcp`), instantly;
- in the **BitTorrent DHT** with a signed record (under its key and under its
  ID), so that any viewer on the Internet can find it by the number;
- on **public Nostr relays**, where it receives encrypted signaling (NIP-44)
  when it is not directly reachable;
- and if the router has **UPnP**, it opens ports 7423/TCP (direct signaling)
  and 7424/UDP (WebRTC) so that the connection is direct.

The viewer types the ID and CleanDesk tries, in order: LAN → direct → Nostr,
and uses STUN/community relays to get through NAT. The viewer's bar shows the
path used. After the first connection the machine's key is pinned
(trust-on-first-use); if someone showed up with the same ID and a different
key, the connection is rejected and you can check the fingerprint under
**Security**.

To try it on a single machine, open two instances with different `--data-dir`
values (see §2) and connect by ID: they will find each other via mDNS.

Sections 1 to 3 describe the **private server mode** (Settings → Network).

## 1. Start the CleanDesk Server (signaling)

```powershell
# Terminal 1
cargo run -p cleandesk-signal-server
# Listens on 0.0.0.0:7420 (change with CLEANDESK_SIGNAL_PORT)
# ID ownership is persisted in ./data/owners.json (CLEANDESK_SIGNAL_STATE_DIR)
```

Plain `ws://` is only accepted towards loopback / private addresses; an
Internet-facing server must be reached over `wss://` (terminate TLS in front
of it), or set `CLEANDESK_ALLOW_INSECURE_SIGNALING=1` on a network you trust.

## 2. Start two instances of the app

Each instance registers with the server and shows its **CleanDesk ID**. To run
two instances on the same machine, give them different data folders (each will
have its own identity and therefore its own ID):

```powershell
# Terminal 2 (machine A)
cargo run -p cleandesk-app -- --signal-url ws://127.0.0.1:7420 --data-dir C:\tmp\cd-a

# Terminal 3 (machine B) — on another machine on the LAN use the server's IP
cargo run -p cleandesk-app -- --signal-url ws://127.0.0.1:7420 --data-dir C:\tmp\cd-b
```

On A, type B's **CleanDesk ID** under "Remote connection" and press
**Connect**. On B the request will appear with the requested permissions: tick
the ones you grant and press **Accept**. A will see B's desktop and will be
able to control it according to the permissions. B shows an amber notice while
someone is connected, with an **End session** button.

> Direct connection: `cargo run -p cleandesk-app -- --connect <ID>` opens the
> GUI and connects directly to that ID. `--help` lists all the options.

## 3. Unattended access (without anyone accepting)

On the machine that will act as host, open the GUI → ⚙ **Settings** →
**Unattended access**: type a password (at least 10 characters) and tick *Allow
unattended connections*. The derived key (Argon2id) is stored, never the
password in the clear. Restart the app so the host loads the key, or run it
headless:

```powershell
cargo run -p cleandesk-app -- --host --signal-url ws://127.0.0.1:7420
```

From the viewer, tick **Unattended access (with password)** below the ID field,
type the password and connect. The host verifies it by challenge-response (HMAC
over the derived key) through the encrypted channel. After 3 failed attempts
the host blocks that ID for 30 s, doubling the time on each subsequent failure.

## 4. Windows service and starting with the session

Under ⚙ **Settings → System**:

- **Start with Windows** adds CleanDesk to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`: the GUI opens at
  logon (no administrator permissions required).
- **Install as a service** asks for elevation (UAC) and registers the
  `CleanDesk` service (automatic start, restart on failure). The service runs
  in session 0, where there is no desktop, so it acts as a supervisor: it
  launches `cleandesk.exe --host` inside the active console session (logon
  screen or the user's desktop) with `CreateProcessAsUser`, and relaunches it
  when it dies or the session changes (logon/logoff).
- The service's host only accepts **unattended access**. While the GUI is
  open, the service's host steps aside (`gui.lock` file in the data folder)
  and the GUI handles the connections, including interactive ones; when the
  GUI closes the service resumes registration within seconds.
- Changing the unattended password in the GUI is applied to the service's host
  automatically (it watches `appdata.json`).
- Logs: `gui.log` in the data folder (`%APPDATA%\CleanDesk\CleanDesk\data`
  or `--data-dir`); `service.log` and `host.log` in the *LocalSystem* profile
  (`C:\Windows\System32\config\systemprofile\AppData\Roaming\CleanDesk\CleanDesk\data`)
  and `service-install.log` in the administrator's own data folder. A SYSTEM
  process never writes into a directory another account controls.
- The service can only be registered from an executable under *Program
  Files* (the MSI install); the portable binary refuses, because a service
  pointing at a user-writable file would hand SYSTEM to whoever can replace
  it. `CLEANDESK_SERVICE_ALLOW_ANY_PATH=1` overrides this for development.
- Unattended callers get the interactive permission set (screen, keyboard,
  mouse, clipboard) whether the GUI or the service answers; file transfer,
  restart and local-input lock need `CLEANDESK_UNATTENDED_FULL=1`.
- Manual: `cleandesk --install-service` / `cleandesk --uninstall-service` from
  an administrator console.

## 5. Remember password

When connecting with an unattended password you can tick **Remember**: the
machine is saved to Favorites together with the **derived key** (Argon2id of
the password and the host ID), never the password in the clear. Cards with 🔑
connect directly in unattended mode; press the key to forget it.

## 5b. In-session features

Once connected, the viewer toolbar offers:

- **Clipboard**: toggles two-way text clipboard sync (needs the *Clipboard*
  permission; the host polls every 500 ms and echoes are suppressed).
- **Files**: drop a file on the remote screen or use *Send file…*; the host
  stores it under `Downloads\CleanDesk` with a sanitised, de-duplicated name.
  Files offered by the host appear in the same panel and must be accepted.
- **Actions**: Ctrl+Alt+Del substitute, Ctrl+Shift+Esc, Win+D, lock the remote
  session, lock/unlock the remote keyboard and mouse, restart the remote
  device. Each entry is enabled only when the host granted the matching
  permission; the host re-checks before acting.
- **Wake up (Wake-on-LAN)** in the ⋮ menu of a saved device sends a magic
  packet to the MAC the host announced (LAN broadcast plus directed
  broadcast).

## 5b2. Privileged control (administrator windows and UAC)

Windows silently drops input sent from an ordinary process to an elevated
(administrator) window, and UAC prompts live on a separate *secure desktop*.
Settings → System → **Privileged control** enables the two ways CleanDesk gets
around that:

- **Service installed (recommended).** The CleanDesk service hosts as
  LocalSystem. Its capture and input threads follow the input desktop, so the
  viewer sees and can answer UAC prompts and the lock screen. While the GUI
  is open it does *not* take over hosting in this mode, so only unattended
  (password) connections are accepted.
- **No service.** CleanDesk relaunches itself elevated at startup (one UAC
  prompt). Administrator windows on the normal desktop become controllable;
  the UAC secure desktop still needs the service.

Both paths only decide *who may be driven*; who may connect is still governed
by the approval dialog, the unattended password and the granted permissions.

## 5c. Automatic updates

CleanDesk checks GitHub Releases at startup and every six hours (Settings →
Updates, on by default; *Check now* forces it). When a newer version exists a
banner offers **Update now**: the MSI is downloaded to `<data dir>\updates`,
its SHA-256 is verified against the `SHA256SUMS` file published with the
release (a release without checksums, or a mismatching file, is never
installed; only an asset named exactly `CleanDesk-<version>-x64.msi` served
by GitHub is considered), and *Install and restart* hands it to `msiexec /passive`, closes
CleanDesk and reopens it once the upgrade finishes. `installer/build-msi.ps1`
writes `SHA256SUMS` next to the MSI; upload both to the release.

## 6. Community relay

Anyone can contribute a relay to the community. All it takes is a machine with
a public IP and open UDP:

```powershell
:CLEANDESK_RELAY_COMMUNITY = "1"      # public credentials + DHT announcement
cargo run -p cleandesk-relay-server      # or cleandesk-relay-server.exe from the MSI
# UDP 7421 (TURN) and 7422 (DHT node). CLEANDESK_RELAY_PUBLIC_IP if
# autodetection via the DHT gets it wrong.
```

Clients in community mode query the DHT when connecting and add the relays
found as last-resort TURN.

The relay caps what one client can do with the public credential:
`CLEANDESK_RELAY_MAX_ALLOCATIONS` (1000 live allocations in total),
`CLEANDESK_RELAY_MAX_ALLOCATIONS_PER_IP` (8 per source address),
`CLEANDESK_RELAY_ALLOCATION_MAX_KBPS` (25 000 kbit/s per allocation in
community mode), plus the lifetime and byte quotas below. Unauthenticated
STUN requests and `Allocate`s are rate-limited per source. Only globally
routable relay addresses are announced or used.

## 7. Private TURN relay (when there is no direct route)

When both machines are behind symmetric NATs, ICE finds no direct route and the
connection times out. Deploy the relay on a machine with a public IP:

```powershell
$env:CLEANDESK_RELAY_PUBLIC_IP = "203.0.113.7"       # public IP of the relay
$env:CLEANDESK_RELAY_USERS     = "cleandesk:una-clave-larga"
cargo run -p cleandesk-relay-server
# UDP 7421 (CLEANDESK_RELAY_PORT); realm "cleandesk" (CLEANDESK_RELAY_REALM)
```

And in **each** app (host and viewer) point to the relay:

```powershell
$env:CLEANDESK_TURN_URLS = "turn:203.0.113.7:7421?transport=udp"
$env:CLEANDESK_TURN_USER = "cleandesk"
$env:CLEANDESK_TURN_PASS = "una-clave-larga"
# Optional: your own STUN instead of the public default
$env:CLEANDESK_STUN_URLS = "stun:203.0.113.7:7421"
```

## Network notes

- On the same LAN the connection will be **direct P2P** (host ICE candidates).
- Across the Internet you will need to deploy the **CleanDesk Server** on a
  public IP (port **7420/TCP**) and, for restrictive NATs, the **CleanDesk
  Relay** (port **7421/UDP**).
- The transport uses a public STUN by default only to discover the reflexive
  IP; no session data passes through it.

## Build times

- `cargo build --profile quick -p cleandesk-app` is a release-speed build
  without LTO (about half the time of `--release`); use it for local runs.
- Dependencies are built without debuginfo and our crates with line tables
  only, which keeps the dev target directory around 5 GB instead of 40 GB.
- Point `target-dir` at a fast NTFS disk with free space, and set
  `linker = "rust-lld.exe"` under `[target.x86_64-pc-windows-msvc]` in the
  local `.cargo/config.toml` (rust-lld ships with the toolchain).

## Running the tests

```powershell
cargo test --workspace                              # everything (~200 tests)
cargo test -p cleandesk-signal-server --test e2e    # end-to-end smoke (server+host+viewer)
cargo test -p cleandesk-signal-server --test protocol  # server security rules
cargo test -p cleandesk-codec --test hostile        # hostile frames against the decoder
cargo clippy --workspace --all-targets -- -D warnings
```
