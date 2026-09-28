# CleanDesk — Guía para agentes/IA

Escritorio remoto en Rust. Antes de tocar código, lee `docs/ARCHITECTURE.md` y
`docs/SPEC.md`.

## Reglas del proyecto

- **Obra original.** CleanDesk es un producto **independiente y original**.
  Implementa todo a partir del spec (`docs/SPEC.md`) y de fuentes estándar de
  dominio público (WebRTC/ICE/STUN/TURN, DXGI, SendInput). Usa solo código propio
  o de crates open-source con licencia compatible. No uses protocolos, nombres,
  puertos ni identificadores ajenos, ni menciones otros productos en código,
  comentarios o documentación.
- **`cleandesk-proto` es el contrato.** No cambies tipos del wire sin actualizar
  `PROTOCOL_VERSION` y los tests. Los mensajes que viajan por `postcard` deben
  ser enums **externamente etiquetados** (postcard no soporta `#[serde(tag=…)]`)
  y **solo se añaden variantes al final** (postcard codifica el índice de la
  variante; `crates/proto/tests/wire.rs` fija esos índices).
- **Modo comunitario.** `crates/discovery` es la única puerta a la DHT, mDNS,
  Nostr y UPnP. Todo lo que llega de esas fuentes es una *pista*: se verifica la
  firma del `Record` y que la clave derive al ID antes de usarlo. Los tests que
  tocan Internet van con `#[ignore]` (`cargo test -p cleandesk-discovery -- --ignored`).
- **Compilación.** `.cargo/config.toml` es local (no versionado); apunta
  `target-dir` a un disco NTFS con espacio. No lances dos `cargo` a la vez.
- **Seguridad no negociable.** El servidor solo registra un ID derivado de la
  clave pública y firmado (`RegisterChallenge`/`RegisterProof`); el host limita
  intentos desatendidos (`AuthThrottle`) y libera teclas al cerrar; el
  decodificador acota dimensiones y descompresión. No relajes estos límites sin
  un test que cubra el caso hostil.
- **Dependencias:** usa `.workspace = true` para las ya declaradas en el
  `Cargo.toml` raíz. Si necesitas una nueva, añádela al `Cargo.toml` de **tu
  crate** con versión fija; evita editar `[workspace.dependencies]` si trabajas
  en paralelo con otros agentes.
- **Aislamiento por crate:** cada tarea toca su propio crate. No edites crates
  ajenos salvo que se pida.

## Comandos

```bash
cargo check -p <crate>        # rápido
cargo test  -p <crate>        # tests del crate
cargo clippy --workspace      # lints
cargo build --workspace       # build completo
cargo run -p cleandesk-signal-server   # servidor de señalización
```

## Estilo

- Comentarios en el mismo idioma y densidad que el crate donde escribes (el
  código base documenta el *por qué*, no el *qué* obvio).
- `thiserror` para errores de librería, `anyhow` en binarios.
- Nada de `unwrap()`/`panic!` en rutas de red o de sesión; propaga errores.
- Respeta SIEMPRE los permisos (`Permissions`) antes de inyectar input o exponer
  datos. El host es la autoridad.

## Atribución de commits

Los commits que genere la IA terminan con la línea de co-autoría indicada por el
entorno de Claude Code en cada sesión.
