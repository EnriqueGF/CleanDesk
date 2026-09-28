# CleanDesk — Seguridad y modelo de amenazas

CleanDesk es una herramienta de **acceso remoto con consentimiento**. Cada
decisión de diseño asume que el control remoto de un equipo es una capacidad
sensible y debe estar siempre autorizada, ser visible y revocable.

## Principios

1. **Consentimiento explícito.** Toda conexión interactiva requiere que el host
   pulse *Aceptar*. El acceso desatendido requiere una contraseña configurada a
   propósito por el dueño del equipo.
2. **Visibilidad.** El host muestra confirmación visual de sesión activa
   (spec §18) y quién está conectado. Nada de conexiones ocultas.
3. **Revocabilidad.** Los permisos se pueden reducir o cortar la sesión en
   cualquier momento (spec §6, §28).
4. **Cifrado extremo a extremo.** El media y el control van por DTLS entre los
   pares; el servidor de señalización nunca ve las claves ni el contenido.
5. **Mínimo privilegio.** El viewer recibe solo los permisos que el host concede
   (`Permissions` es un bitset negociado; el host es la autoridad).

> CleanDesk **no** es software de vigilancia encubierta. El diseño impide, a
> propósito, el acceso silencioso sin conocimiento del usuario del equipo.

## Controles criptográficos (`cleandesk-crypto`)

| Amenaza | Control |
|---|---|
| Suplantación de dispositivo | Identidad **Ed25519** por dispositivo. El CleanDesk ID se **deriva** de la clave pública y el servidor exige al registrarse una **firma sobre un nonce** (`RegisterChallenge`/`RegisterProof`): nadie puede registrar un ID sin la clave privada. Fingerprint verificable fuera de banda. |
| Robo de la contraseña desatendida | Se guarda solo como **Argon2id** (PHC). Nunca en texto plano (spec §18). |
| Contraseña por la red | **Reto-respuesta HMAC**: la contraseña no cruza el cable; el host verifica. |
| Reutilización de credenciales | **Tokens** aleatorios con expiración; comparación en tiempo constante. |
| Fuerza bruta | Host: 3 fallos gratis y después bloqueo por ID de 30 s doblando hasta 15 min (`host::AuthThrottle`); timeout de 30 s para responder al reto. Servidor: token bucket de 5 `ConnectRequest` por 30 s por conexión, presupuesto de 10 mensajes malformados, mensajes WebSocket ≤ 64 KiB, plazos de handshake/registro/inactividad. |
| Suplantación del llamante | El servidor sobrescribe `from.id` con el ID registrado en la conexión; `Accept`/`Reject` solo se aceptan del callee y `Signal` solo de miembros de la sesión. |
| Entrada hostil por la red | `postcard` estricto (sin bytes sobrantes), `Reassembler` valida cabeceras/índices de chunk, el decodificador limita dimensiones (8192) y la descompresión zstd (64 MiB) para evitar bombas de memoria. |
| Teclas atascadas | El host libera toda tecla/botón que el visor dejó pulsado al terminar la sesión, termine como termine. |
| Interceptación de media/control | **DTLS** extremo a extremo (capa WebRTC en `transport`). |

## Límite conocido del MVP y plan

El proof reto-respuesta actual (`crypto::proof`) usa `HMAC(Argon2id(pw), reto)`.
Como el **servidor retransmite** reto y respuesta, un servidor malicioso podría
intentar un ataque de diccionario **offline**. En el MVP se acepta porque el
servidor es infraestructura de primera parte y la contraseña pasa por Argon2id.

**Plan post-MVP:** sustituir por un **PAKE** (p. ej. SPAKE2 / OPAQUE) para que ni
un servidor comprometido pueda derivar la contraseña. Rastreo: este documento.

## Almacenamiento local

- La clave privada de identidad se guarda en PKCS#8 PEM, protegida por ACLs del
  SO (y DPAPI en Windows como endurecimiento adicional). Excluida de git.
- Tokens y hashes de contraseña se guardan en el perfil de usuario, nunca en el
  repositorio (`.gitignore` cubre `/data`, `*.identity`, `*.token`).
- Junto al hash Argon2id se guarda la **clave HMAC derivada** (Argon2id de la
  contraseña con sal ligada al ID del host): el host la necesita para verificar
  el reto-respuesta. No es la contraseña, pero quien la obtenga puede autenticarse
  como visor desatendido de ese host; por eso el fichero se escribe con permisos
  restringidos y de forma atómica (`core::storage`). El PAKE post-MVP elimina
  también esta exposición.
- Los ficheros se escriben de forma atómica (temporal + rename) y un
  `appdata.json` corrupto se aparta como copia de seguridad en vez de impedir el
  arranque; `identity.pem` corrupto sí es un error duro (regenerarlo cambiaría el
  ID).

## Divulgación responsable

Los fallos de seguridad deben reportarse en privado a los mantenedores antes de
su divulgación pública.
