# Probar CleanDesk en local

Requisitos: Rust estable (1.85+) y Visual Studio Build Tools (MSVC). Para usar
CleanDesk sin compilar, instala el MSI de la release de GitHub.

## 0. Modo comunitario (por defecto): sin servidor

Al abrir CleanDesk el equipo se anuncia solo:

- en la **red local** por mDNS (`_cleandesk._tcp`), al instante;
- en la **DHT de BitTorrent** con un registro firmado (bajo su clave y bajo su
  ID), para que cualquier visor de Internet lo encuentre por el número;
- en **relés Nostr públicos**, donde recibe la señalización cifrada (NIP-44)
  cuando no es alcanzable directamente;
- y si el router tiene **UPnP**, abre los puertos 7423/TCP (señalización
  directa) y 7424/UDP (WebRTC) para que la conexión sea directa.

El visor escribe el ID y CleanDesk prueba en orden: LAN → directo → Nostr, y
usa STUN/relays comunitarios para atravesar NAT. La barra del visor indica la
vía usada. Tras la primera conexión la clave del equipo queda fijada
(trust-on-first-use); si alguien apareciera con el mismo ID y otra clave, la
conexión se rechaza y puedes comprobar la huella en **Seguridad**.

Para probarlo en una sola máquina abre dos instancias con `--data-dir`
distintos (ver §2) y conecta por ID: se encontrarán por mDNS.

Las secciones 1 a 3 describen el **modo servidor privado** (Ajustes → Red).

## 1. Arrancar el CleanDesk Server (señalización)

```powershell
# Terminal 1
cargo run -p cleandesk-signal-server
# Escucha en 0.0.0.0:7420 (cambia con CLEANDESK_SIGNAL_PORT)
```

## 2. Arrancar dos instancias de la app

Cada instancia se registra en el servidor y muestra su **CleanDesk ID**. Para
ejecutar dos instancias en la misma máquina, dales carpetas de datos distintas
(cada una tendrá su propia identidad y por tanto su propio ID):

```powershell
# Terminal 2 (equipo A)
cargo run -p cleandesk-app -- --signal-url ws://127.0.0.1:7420 --data-dir C:\tmp\cd-a

# Terminal 3 (equipo B) — en otra máquina de la LAN usa la IP del servidor
cargo run -p cleandesk-app -- --signal-url ws://127.0.0.1:7420 --data-dir C:\tmp\cd-b
```

En A, escribe el **CleanDesk ID** de B en "Conexión remota" y pulsa
**Conectar**. En B aparecerá la solicitud con los permisos pedidos: marca los que
concedas y pulsa **Aceptar**. A verá el escritorio de B y podrá controlarlo según
los permisos. B muestra un aviso ámbar mientras alguien está conectado, con un
botón **Finalizar sesión**.

> Conexión directa: `cargo run -p cleandesk-app -- --connect <ID>` abre la GUI y
> conecta directamente a ese ID. `--help` lista todas las opciones.

## 3. Acceso desatendido (sin que nadie acepte)

En el equipo que hará de host, abre la GUI → ⚙ **Ajustes** → **Acceso
desatendido**: escribe una contraseña (mínimo 6 caracteres) y marca *Permitir
conexiones desatendidas*. Se guarda la clave derivada (Argon2id), nunca la
contraseña en claro. Reinicia la app para que el host cargue la clave, o
ejecútalo sin interfaz:

```powershell
cargo run -p cleandesk-app -- --host --signal-url ws://127.0.0.1:7420
```

Desde el visor, marca **Acceso desatendido (con contraseña)** debajo del campo
de ID, escribe la contraseña y conecta. El host la verifica por reto-respuesta
(HMAC sobre la clave derivada) por el canal cifrado. Tras 3 intentos fallidos
el host bloquea a ese ID 30 s, doblando el tiempo en cada fallo siguiente.

## 4. Servicio de Windows y arranque con la sesión

En ⚙ **Ajustes → Sistema**:

- **Iniciar con Windows** añade CleanDesk a `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`: la GUI se abre al
  iniciar sesión (sin permisos de administrador).
- **Instalar como servicio** pide elevación (UAC) y registra el servicio
  `CleanDesk` (arranque automático, reinicio ante fallos). El servicio corre en
  la sesión 0, donde no hay escritorio, así que actúa de supervisor: lanza
  `cleandesk.exe --host` dentro de la sesión de consola activa (pantalla de
  inicio de sesión o escritorio del usuario) con `CreateProcessAsUser`, y lo
  relanza cuando muere o cambia la sesión (inicio/cierre de sesión).
- El host del servicio solo acepta **acceso desatendido**. Mientras la GUI está
  abierta, el host del servicio se aparta (fichero `gui.lock` en la carpeta de
  datos) y la GUI atiende las conexiones, incluidas las interactivas; al cerrar
  la GUI el servicio retoma el registro en segundos.
- Cambiar la contraseña desatendida en la GUI se aplica al host del servicio
  automáticamente (vigila `appdata.json`).
- Registros: `service.log`, `host.log` y `service-install.log` en la carpeta de
  datos (`%APPDATA%\CleanDesk\CleanDesk\data` o `--data-dir`).
- Manual: `cleandesk --install-service` / `cleandesk --uninstall-service` desde
  una consola de administrador.

## 5. Recordar contraseña

Al conectar con contraseña desatendida puedes marcar **Recordar**: el equipo se
guarda en Favoritos junto con la **clave derivada** (Argon2id de la contraseña
y el ID del host), nunca la contraseña en claro. Las tarjetas con 🔑 conectan
directamente en modo desatendido; pulsa la llave para olvidarla.

## 6. Relay comunitario

Cualquiera puede aportar un relay a la comunidad. Solo necesita una máquina con
IP pública y UDP abierto:

```powershell
:CLEANDESK_RELAY_COMMUNITY = "1"      # credenciales públicas + anuncio en la DHT
cargo run -p cleandesk-relay-server      # o cleandesk-relay-server.exe del MSI
# UDP 7421 (TURN) y 7422 (nodo DHT). CLEANDESK_RELAY_PUBLIC_IP si la
# autodetección por la DHT no acierta.
```

Los clientes en modo comunitario consultan la DHT al conectar y añaden los
relays encontrados como TURN de último recurso.

## 7. Relay TURN privado (cuando no hay ruta directa)

Cuando ambos equipos están tras NAT simétricos, ICE no encuentra una ruta
directa y la conexión caduca. Despliega el relay en una máquina con IP pública:

```powershell
$env:CLEANDESK_RELAY_PUBLIC_IP = "203.0.113.7"       # IP pública del relay
$env:CLEANDESK_RELAY_USERS     = "cleandesk:una-clave-larga"
cargo run -p cleandesk-relay-server
# UDP 7421 (CLEANDESK_RELAY_PORT); realm "cleandesk" (CLEANDESK_RELAY_REALM)
```

Y en **cada** app (host y visor) indica el relay:

```powershell
$env:CLEANDESK_TURN_URLS = "turn:203.0.113.7:7421?transport=udp"
$env:CLEANDESK_TURN_USER = "cleandesk"
$env:CLEANDESK_TURN_PASS = "una-clave-larga"
# Opcional: STUN propio en vez del público por defecto
$env:CLEANDESK_STUN_URLS = "stun:203.0.113.7:7421"
```

## Notas de red

- En la misma LAN, la conexión será **P2P directa** (candidatos ICE de host).
- A través de Internet hará falta desplegar el **CleanDesk Server** en una IP
  pública (puerto **7420/TCP**) y, para NAT restrictivas, el **CleanDesk
  Relay** (puerto **7421/UDP**).
- El transporte usa un STUN público por defecto solo para descubrir la IP
  reflexiva; ningún dato de sesión pasa por él.

## Ejecutar los tests

```powershell
cargo test --workspace                              # todo (~200 tests)
cargo test -p cleandesk-signal-server --test e2e    # smoke end-to-end (servidor+host+viewer)
cargo test -p cleandesk-signal-server --test protocol  # reglas de seguridad del servidor
cargo test -p cleandesk-codec --test hostile        # frames hostiles al decodificador
cargo clippy --workspace --all-targets -- -D warnings
```
