# RotoDesk — Software Definition Sheet

> Source of truth for the product (definition provided by the project owner).
> The code in `crates/proto` implements these concepts.

## 1. Product
Application for remote access and control of machines over the Internet or a
local network: view the remote screen, control keyboard/mouse, transfer files
and provide support without being physically present. Initially **Windows**,
with an architecture ready for macOS and Linux.

## 2. Goal
Fast, lightweight, secure, easy, low latency, no complex network configuration.
Suitable for technical support and personal access. Download, run and receive
a connection within seconds.

## 3. Identification
Each installation has a unique **RotoDesk ID** (e.g. `548 291 743`) and,
optionally, an alias (e.g. `pc-oficina.roto`).

## 4. Main screen
- Recent devices and contacts display the last authenticated desktop-wallpaper
  preview (protocol 2.5), retained locally without capturing open windows.
- Optional automatic reconnection: after connection loss, a modal retries
  indefinitely with a five-second delay between attempts and a Cancel button.
  Intentional closure stops the session; password rejection pauses retries
  for user input, and identity changes stop retries for verification.
- *This device:* ID, alias, connection status, copy-ID button, service status.
- *Connect to device:* "Enter RotoDesk ID" field + "Connect" button; list of
  recent connections and saved devices.

## 5. Connection request
The remote machine receives: requester's name, ID, user, requested
permissions. Options: **Accept** / **Reject**.

## 6. Session permissions (changeable live)
View screen · control keyboard · control mouse · clipboard · transfer files ·
remote audio · reboot machine · restart RotoDesk · administrative actions ·
lock local keyboard/mouse.

## 7. Remote control
Transmits: screen image, mouse, keyboard, cursor state, resolution, session
info. Optimizes quality according to the connection.

## 8. Quality modes
Automatic · Maximum quality · Balanced · Maximum performance.

## 9. Unattended access
Configurable with a password; whoever connects authenticates with it.

## 10. Trusted devices
Always allow, remember permissions, do not ask for confirmation, allow
unattended.

## 11. Device book
Name, ID, alias, description, group, last connection, online/offline status.

## 12. Connection history
Device, user, start, end, duration, connection type, status.

## 13. File transfer
Send/download, drag&drop, folders, progress, cancel. Encrypted channel.
The host bounds incoming files (per-file size cap, at most 4 in flight,
free disk space kept) and refuses with a reason.

## 14. Shared clipboard
Text and URLs (MVP); images/files optional. Can be disabled via permissions.

## 15. Multiple monitors
Select/switch/view all; adapt resolution and scale.

## 16. Full screen
Window, full screen, automatic scaling, original resolution, "fit to window".

## 17. In-session chat
Messages between the remote and local user during the session.

## 18. Security
Encrypted communications, device authentication, unique IDs, protection
against unauthorized connections, session validation, token expiry,
brute-force protection, access logging, visual confirmation of an active
session. Unattended credentials never in plain text.
Each P2P session is bound to the devices' identities: both peers sign the
session id and the DTLS fingerprints (`IdentityProof`) before anything else
travels on the control channel, so no rendezvous can sit in the middle.
Brute-force protection is per verified caller key and global (a rotating
attacker locks unattended access for everyone for a doubling window).

## 19. Connection architecture
- **RotoDesk Client:** capture, inputs, encoding, sessions, files.
- **RotoDesk Server:** authentication, registration, ID resolution, users,
  coordination, signaling.
- **RotoDesk Relay:** intermediary when there is no direct connection.
Flow: `A → P2P → B`; if not possible, `A → Relay → B`.

## 20. NAT Traversal
UDP hole punching, STUN, ICE, TURN/Relay as fallback. Minimize traffic through
the servers.

## 21–23. Users, teams, roles
Use without an account for simple connections; accounts for a synchronized
address book, favorites, history, teams, centralized unattended access.
Professional teams. Roles: Administrator, Technician, User.

## 24. Background service (Windows)
Start with Windows, pre-login access, unattended, remote reboot, connection
after logging off.

## 25. Updates
Check, download, verify integrity, install; "Check for updates".

## 26. Session information
Duration, latency, FPS, resolution, codec, bandwidth, connection type.

## 27. Toolbar
Screens, quality, full screen, transfer, chat, permissions, reboot, connection
info, disconnect.

## 28. Ending a session
"Disconnect" closes video, inputs, transfers and authentication; it is recorded
in the history.

## 29. Device states
Online · Offline · In session · Unavailable.

## 30. MVP
Windows app, ID, signaling server, 2-machine connection, capture, streaming,
keyboard/mouse control, accept/reject request, encrypted connection, relay,
password-based unattended access, basic clipboard, file transfer, basic
history.

## 31. Later
Accounts, cloud address book, teams, MFA, recording, Wake-on-LAN, remote
printing, TCP tunnels, remote terminal, API, webhooks, mobile, web, macOS,
Linux, enterprise policies, advanced auditing.

## 32. Summary
Remote desktop platform for connecting quickly and securely to other machines
through a unique identifier, with screen viewing, remote control, file
transfer and unattended access, using P2P whenever possible and a relay when
not.
