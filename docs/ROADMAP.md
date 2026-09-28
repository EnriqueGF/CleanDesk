# CleanDesk — Roadmap

Basado en la hoja de definiciones (§30 MVP, §31 posteriores). Estado a fecha de
arranque del proyecto.

## Hito 0 — Cimientos ✅ (hecho)

- [x] Workspace Cargo con 13 crates y perfiles de release.
- [x] `proto`: CleanDesk ID, permisos, perfiles de calidad, mensajes de
      señalización/sesión/media, framing length-delimited. **Tests verdes.**
- [x] `crypto`: identidad Ed25519, Argon2id, tokens, reto-respuesta. **Tests verdes.**
- [x] `signal-server`: registro, resolución de IDs, relay de señalización. Compila.
- [x] Documentación: README, ARCHITECTURE, SECURITY, SPEC.

## Hito 1 — MVP núcleo ✅ (hecho)

Objetivo: dos equipos Windows se conectan y hay control remoto real.

- [x] `transport`: transporte WebRTC (data channels control/video/input) +
      cliente de señalización WS. NAT traversal (STUN) y relay (TURN) fallback.
- [x] `capture`: DXGI Desktop Duplication, enumeración de monitores, frames BGRA,
      detección de tiles sucios.
- [x] `codec`: trait `VideoEncoder`/`VideoDecoder` + impl tiles+zstd+JPEG
      (keyframe/delta).
- [x] `input`: SendInput; mapeo de `InputEvent` (ratón absoluto normalizado,
      teclado por virtual-key, scroll) y respeto de permisos.
- [x] `core`: persistencia de identidad, config, agenda, historial, dispositivos
      de confianza; máquina de estados de sesión; gestor de permisos.
- [x] `host` + `client`: ensamblar los pipelines de captura/codificación/input.
- [x] `gui`: ventana principal (ID propio, copiar ID, conectar, recientes) +
      visor con barra de herramientas.
- [x] `app`: cablear modos GUI / `--host` / `--connect`.
- [x] `relay-server`: servidor TURN (RFC 5766) con credenciales de larga duración.
- [x] E2E: solicitud → aceptar → vídeo + control → desconectar → historial.

Cubre §30: app Windows, ID, señalización, conexión 2 equipos, captura, streaming,
control teclado/ratón, solicitud aceptar/rechazar, cifrado, relay, acceso
desatendido por contraseña, portapapeles básico, transferencia de archivos,
historial básico.

## Hito 2 — Robustez y UX

- [x] Multi-monitor (selección/cambio, §15), pantalla completa/escalado (§16).
- [ ] Portapapeles imágenes; chat en sesión (§17); progreso/cancelación de
      transferencias (§13).
- [x] Calidad adaptativa `Auto` por RTT medido (§8); ancho de banda como siguiente señal.
- [x] Panel de info de sesión (RTT/FPS/resolución/códec/ancho de banda, §26).
- [ ] Servicio de Windows (§24): inicio con Windows, acceso pre-login,
      reinicio remoto.
- [ ] Actualizaciones automáticas con verificación de integridad (§25).

## Hito 3 — Post-MVP (§31)

- [ ] Cuentas, agenda en la nube, equipos y roles (§21–23).
- [ ] MFA; PAKE para acceso desatendido (ver SECURITY.md).
- [ ] Grabación de sesiones, Wake-on-LAN, impresión remota, túneles TCP,
      terminal remota, API, webhooks.
- [ ] Códec H.264/HEVC por hardware (NVENC) tras el trait de `codec`.
- [ ] Compatibilidad macOS / Linux (capas de captura/input por plataforma).
- [ ] Cliente web y app móvil.
