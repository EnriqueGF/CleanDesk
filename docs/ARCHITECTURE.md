# CleanDesk — Arquitectura

## Objetivo de diseño

Escritorio remoto de **baja latencia**, **seguro** y **ligero**, con conexión
**P2P por defecto** y **relay** solo como último recurso. Todo en Rust, con una
frontera de contrato clara (`cleandesk-proto`) que comparten cliente, host,
servidor y relay.

## Planos de comunicación

CleanDesk separa tres planos, cada uno con su serialización óptima:

| Plano | Canal | Serialización | Contenido |
|---|---|---|---|
| **Señalización** | WebSocket cliente↔servidor | JSON (`SignalMessage`) | registro, resolución de ID, solicitudes, relay de SDP/ICE |
| **Control** | Data channel fiable P2P | postcard (`SessionMessage`) | permisos, chat, portapapeles, ficheros, stats |
| **Media** | Data channels P2P | postcard (`VideoFrame`) / (`InputEvent`) | vídeo (host→viewer), input (viewer→host) |

> `SignalMessage` usa etiquetado interno de serde (legible en JSON). Los mensajes
> que viajan por **postcard** (binario, no autodescriptivo) usan etiquetado
> **externo** — es un requisito de postcard, verificado por tests en `frame.rs`.

## Crates del workspace

```
proto      ← contrato: IDs, permisos, mensajes, framing, versión           (sin deps pesadas)
crypto     ← identidad Ed25519, Argon2id, tokens, prueba reto-respuesta
transport  ← WebRTC (ICE/STUN/TURN/DTLS) + cliente de señalización WS
capture    ← DXGI Desktop Duplication (Windows), enumeración de monitores
codec      ← trait VideoEncoder/Decoder + impl tiles+zstd+JPEG (MVP)
input      ← SendInput (Windows), mapeo de InputEvent y códigos de tecla
core       ← config, almacenamiento, agenda, historial, máquina de estados de sesión
host       ← rol host: captura→codifica→envía; recibe→inyecta input
client     ← rol viewer: recibe→decodifica; captura→envía input
gui        ← eframe/egui: ventana principal + visor de sesión
app        ← binario: modos GUI / --host / --connect
signal-server ← binario: CleanDesk Server (señalización)
relay-server  ← binario: CleanDesk Relay (TURN fallback; --community se anuncia en la DHT)
platform   ← integración con el SO: inicio con Windows, servicio SCM, lock de presencia
discovery  ← rendezvous sin servidor: mDNS, DHT BitTorrent (BEP 44), Nostr, UPnP
```

Grafo de dependencias (simplificado):

```
app ─► gui ─► core ─► crypto ─► proto
        │      │
        ├─► host ─► capture, codec, input, transport
        └─► client ─► codec, transport
transport ─► proto     signal-server ─► proto, crypto
```

## Modo comunitario (sin servidor)

`cleandesk-discovery` sustituye al CleanDesk Server por infraestructura pública:

| Necesidad | Mecanismo |
|---|---|
| Encontrar un equipo en la LAN | mDNS `_cleandesk._tcp` con ID, clave y puerto en el TXT |
| Encontrar un equipo por ID en Internet | DHT mainline de BitTorrent: item mutable BEP 44 firmado con la clave del host, publicado bajo su clave y bajo una clave derivada del ID |
| Intercambiar SDP/ICE si el host es alcanzable | enlace TCP directo (puerto 7423) con reto-respuesta Ed25519 mutuo |
| Intercambiar SDP/ICE si no lo es | eventos efímeros (kind 27420) en relés Nostr públicos, cifrados NIP-44 y con firma de vinculación Ed25519↔Nostr |
| Ser alcanzable tras el router | UPnP/IGD: mapeo de 7423/TCP y 7424/UDP; la IP externa se anuncia como candidato ICE 1:1 |
| Plan B sin ruta directa | relays TURN comunitarios (`cleandesk-relay-server --community`) anunciados con `announce_peer` en un infohash conocido |

El host publica cada 10 min un `Record` firmado {clave, clave Nostr, endpoints,
hora}. El visor resuelve LAN → DHT por clave fijada → DHT por ID, verifica la
firma y que la clave derive al ID, y prueba directo → Nostr. `host` y `client`
no distinguen la vía: ambos trabajan sobre `SignalOut` + un canal de entrada, y
el host convierte `ConnectRequest` en `IncomingRequest` acuñando la sesión.

## Flujo de conexión (resumen)

1. Ambos clientes se registran en el **CleanDesk Server** (WS): envían su clave
   pública Ed25519 y el ID derivado de ella, firman el nonce del servidor
   (`RegisterChallenge` → `RegisterProof`) y reciben `Registered`. El servidor
   rechaza IDs que no se deriven de la clave o firmas inválidas.
2. El viewer envía `ConnectRequest{target}`. El servidor abre una sesión y
   entrega `IncomingRequest` al host.
3. El host muestra la solicitud (o valida acceso desatendido) y responde
   `Accept{granted}` / `Reject`.
4. Los pares intercambian **SDP + ICE** vía `Signal` (el servidor solo
   retransmite; no puede leer nada). ICE prueba rutas directas (host, srflx vía
   STUN, y relay TURN como fallback).
5. Se abren data channels: `control`, `video`, `input` (+ `files` bajo demanda).
   `video` es no fiable/no ordenado (un frame tardío no vale nada); `control`,
   `input` y `files` son fiables y ordenados (perder un *key-up* dejaría una
   tecla atascada).
   El cifrado es **DTLS** extremo a extremo, negociado entre los pares.
6. El host captura → codifica → envía `VideoFrame`; el viewer decodifica y
   pinta; el viewer envía `InputEvent`; el host los inyecta según permisos.
7. Cualquiera pulsa **Desconectar** (o el host **Finalizar sesión**) → cierre
   ordenado, liberación de teclas pulsadas y registro en historial.

## Rendimiento

- **Captura:** DXGI Desktop Duplication entrega solo frames con cambios; se
  calcula además una rejilla de tiles sucios (64×64) para no recodificar lo que
  no cambió.
- **Códec:** MVP = tiles JPEG + zstd (keyframe / delta). El trait `VideoEncoder`
  permite sustituirlo por H.264/HEVC (NVENC) sin tocar host/client.
- **Adaptación:** `QualityProfile::Auto` ajusta FPS/calidad según el RTT medido
  por `Ping`/`Pong` en el canal de control (`host::media::auto_params`). El host
  limita el ritmo de captura al FPS objetivo y, si la cola de envío se llena,
  descarta el frame y fuerza un keyframe (un delta perdido corrompería el lienzo).
- **Recuperación de pérdidas:** el visor detecta huecos de secuencia, deltas sin
  keyframe previo o errores de decodificación y pide `RequestKeyframe` (con
  límite de uno cada 500 ms).
- **Release profile:** LTO fino, `codegen-units=1`, `panic=abort`, símbolos
  eliminados.
