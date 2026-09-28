# CleanDesk

**CleanDesk** es una plataforma de escritorio remoto rápida, ligera y segura,
escrita en **Rust**. Permite conectarse a otro equipo mediante un identificador
único (**CleanDesk ID**) para ver la pantalla, controlar teclado y ratón,
transferir archivos y dar soporte — usando **conexiones P2P** siempre que sea
posible y **relay** cuando no lo es.

> **Origen (obra original):** CleanDesk es una implementación **propia e
> independiente**, construida desde su [hoja de definiciones](docs/SPEC.md) sobre
> protocolos y técnicas estándar de dominio público (WebRTC/ICE/STUN/TURN, DXGI
> Desktop Duplication, SendInput). Identidad, protocolo, IDs y puertos son
> propios de CleanDesk.

---

## Estado

Funcional. **Modo comunitario por defecto**: no hace falta que nadie monte
servidores. Cada equipo se anuncia firmado en la red local (mDNS) y en la DHT de
BitTorrent, la señalización viaja por relés Nostr públicos cifrada extremo a
extremo, y UPnP + STUN + relays comunitarios atraviesan el NAT. El **modo
servidor privado** (CleanDesk Server + Relay) sigue disponible para empresas.
Consulta [docs/RUN.md](docs/RUN.md) para probarlo, [docs/ROADMAP.md](docs/ROADMAP.md)
para el detalle por hito y [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) para el diseño.

| Componente | Crate | Estado |
|---|---|---|
| Protocolo compartido | `crates/proto` | ✅ Implementado (tests) |
| Criptografía / identidad / auth | `crates/crypto` | ✅ Implementado (tests) |
| Servidor de señalización | `crates/signal-server` | ✅ Registro con prueba de identidad, rate-limit, roles (tests + e2e) |
| Transporte P2P (WebRTC) | `crates/transport` | ✅ Implementado (loopback test) |
| Captura de pantalla (DXGI) | `crates/capture` | ✅ Implementado (captura real verificada) |
| Códec de vídeo | `crates/codec` | ✅ Implementado (tests) |
| Inyección de input | `crates/input` | ✅ Implementado (tests) |
| Orquestación de sesión | `crates/core` | ✅ Implementado (tests) |
| Rol host / viewer | `crates/host`, `crates/client` | ✅ Implementado (anti fuerza bruta, keyframe bajo demanda, RTT/FPS/kbps, calidad Auto) |
| GUI (egui) | `crates/gui` | ✅ Implementada (tema oscuro, tarjetas, favoritos, ajustes, visor multi-monitor) |
| App / entry point | `crates/app` | ✅ GUI / `--host` / `--connect` / `--signal-url` / `--data-dir` (tests) |
| Relay (TURN fallback) | `crates/relay-server` | ✅ Servidor TURN (RFC 5766); modo comunitario anunciado en la DHT (tests) |
| Descubrimiento sin servidor | `crates/discovery` | ✅ mDNS, DHT BitTorrent (BEP 44), señalización Nostr NIP-44, UPnP (tests + e2e) |
| Integración con Windows | `crates/platform` | ✅ Inicio con Windows, servicio SCM, lock de presencia |
| Instalador | `installer/` | ✅ MSI (WiX) con accesos directos y reglas de firewall |

---

## Arquitectura en 3 componentes

```
                    ┌──────────────────────┐
                    │   CleanDesk Server    │  registro + resolución de IDs
                    │  (señalización WSS)   │  + relay de señalización WebRTC
                    └──────────┬───────────┘
              signaling        │        signaling
        ┌──────────────────────┴──────────────────────┐
        │                                              │
 ┌──────▼───────┐   P2P (WebRTC/DTLS/SRTP)     ┌──────▼───────┐
 │  Cliente A   │◄────────────────────────────►│  Cliente B   │
 │  (viewer)    │      cuando es posible        │  (host)      │
 └──────┬───────┘                              └──────┬───────┘
        │           ┌────────────────────┐            │
        └──────────►│  CleanDesk Relay   │◄───────────┘
          fallback  │  (TURN, cifrado    │  fallback
                    │   extremo a extremo)│
                    └────────────────────┘
```

## Compilar

Requisitos: Rust estable (1.85+) y Visual Studio Build Tools (MSVC).

> Si quieres compilar en otra unidad, copia `.cargo/config.example.toml` a
> `.cargo/config.toml` y ajusta `target-dir` (ese fichero no se versiona).

```powershell
cargo build --workspace            # compilar todo
cargo test  --workspace            # tests
cargo run -p cleandesk-signal-server   # arrancar el servidor de señalización
cargo run -p cleandesk-app             # arrancar la app (GUI)
```

## Seguridad

Toda la comunicación es cifrada; la identidad de cada dispositivo es un par de
claves Ed25519; la contraseña de acceso desatendido se guarda solo como hash
Argon2id. Detalles y modelo de amenazas en [docs/SECURITY.md](docs/SECURITY.md).

## Licencia

MIT OR Apache-2.0.
