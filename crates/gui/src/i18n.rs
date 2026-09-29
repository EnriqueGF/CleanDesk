//! Internacionalización mínima de la interfaz.
//!
//! La clave de cada texto es la propia frase en inglés (lo que ve un usuario
//! anglófono); [`tr`] devuelve la traducción al idioma activo o la clave si no
//! hay entrada. Los textos con parámetros usan marcadores `{nombre}` y se
//! rellenan con [`trf`], de modo que el orden de las palabras pueda variar por
//! idioma sin tocar el código de llamada.
//!
//! El idioma activo es global al proceso (un `AtomicU8`): la GUI es de un solo
//! hilo y el cambio desde Ajustes debe verse en el siguiente fotograma sin
//! enhebrar el estado por todas las funciones de dibujo.

use std::sync::atomic::{AtomicU8, Ordering};

/// Idiomas disponibles en la interfaz.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    /// Inglés (por defecto).
    #[default]
    En,
    /// Español.
    Es,
}

impl Lang {
    /// Interpreta una etiqueta tipo BCP-47 (`"es"`, `"es-ES"`, `"en_US"`…).
    /// Cualquier valor desconocido cae en inglés.
    pub fn from_tag(tag: &str) -> Lang {
        let primary = tag
            .trim()
            .split(['-', '_', '.', '@'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        match primary.as_str() {
            "es" => Lang::Es,
            _ => Lang::En,
        }
    }

    /// Etiqueta corta para persistir en ajustes.
    pub fn tag(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Es => "es",
        }
    }

    /// Idioma del sistema operativo (español si la configuración regional
    /// empieza por `es`; inglés en cualquier otro caso o si no se puede leer).
    pub fn system() -> Lang {
        sys_locale::get_locale()
            .map(|l| Lang::from_tag(&l))
            .unwrap_or(Lang::En)
    }

    fn from_u8(v: u8) -> Lang {
        match v {
            1 => Lang::Es,
            _ => Lang::En,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Lang::En => 0,
            Lang::Es => 1,
        }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

/// Fija el idioma activo de la interfaz.
pub fn set_lang(lang: Lang) {
    CURRENT.store(lang.as_u8(), Ordering::Relaxed);
}

/// Idioma activo de la interfaz.
pub fn lang() -> Lang {
    Lang::from_u8(CURRENT.load(Ordering::Relaxed))
}

/// Traduce `en` al idioma activo. Si no hay traducción devuelve la clave.
pub fn tr(en: &'static str) -> &'static str {
    match lang() {
        Lang::En => en,
        Lang::Es => spanish(en).unwrap_or(en),
    }
}

/// Traduce una plantilla con marcadores `{nombre}` y los sustituye por `args`.
pub fn trf(en: &'static str, args: &[(&str, &str)]) -> String {
    let mut out = tr(en).to_string();
    for (name, value) in args {
        out = out.replace(&format!("{{{name}}}"), value);
    }
    out
}

/// Tabla inglés → español. Se omiten las entradas cuyo texto coincide en ambos
/// idiomas ("Chat", "Alias:", "Ping"…): `tr` devuelve la clave.
fn spanish(en: &str) -> Option<&'static str> {
    Some(match en {
        // --- Ventana principal: cabecera y pie ---
        "Settings" => "Ajustes",
        "Security" => "Seguridad",
        "Device identity and fingerprint" => "Identidad y huella del dispositivo",
        "Incoming session active" => "Sesión entrante activa",
        "Connecting…" => "Conectando…",
        "New session" => "Nueva sesión",
        "Community mode: announced (LAN · DHT · Nostr)" => "Modo comunitario: anunciado (LAN · DHT · Nostr)",
        "CleanDesk network ready (private server)" => "Red CleanDesk lista (servidor privado)",
        "Announcing on the community network…" => "Anunciando en la red comunitaria…",
        "Connecting to the server…" => "Conectando con el servidor…",
        "Offline; retrying" => "Sin conexión; reintentando",
        "no server" => "sin servidor",
        "Network mode (Settings → Network)" => "Modo de red (Ajustes → Red)",

        // --- Avisos y sesión entrante ---
        "Trust the new identity" => "Confiar en la nueva identidad",
        "Only if you verified the device fingerprint through another channel" => {
            "Solo si has comprobado la huella del equipo por otro canal"
        }
        "Previous key forgotten; connect again." => "Clave anterior olvidada; vuelve a conectar.",
        "{who} ({id}) is viewing your screen" => "{who} ({id}) está viendo tu pantalla",
        "End session" => "Finalizar sesión",
        "Incoming session ended: {reason}" => "Sesión entrante finalizada: {reason}",
        "terminated by the host" => "finalizada por el host",

        // --- Tarjeta "Tu dirección" ---
        "Your address" => "Tu dirección",
        "Copy" => "Copiar",
        "ID copied to the clipboard." => "ID copiado al portapapeles.",
        "Share this identifier so others can connect to your screen with your permission." => {
            "Comparte este identificador para que otros se conecten a tu pantalla con tu permiso."
        }
        "office-pc" => "pc-oficina",

        // --- Tarjeta "Conexión remota" ---
        "Remote connection" => "Conexión remota",
        "Enter remote ID…" => "Introduce ID remoto…",
        "Connect ›" => "Conectar ›",
        "Connect" => "Conectar",
        "Unattended access (with password)" => "Acceso desatendido (con contraseña)",
        "Password:" => "Contraseña:",
        "Remember" => "Recordar",
        "Saves the device to favorites with its derived key (never the plaintext password)" => {
            "Guarda el equipo en favoritos con su clave derivada (nunca la contraseña en claro)"
        }
        "Waiting for {target}…" => "Esperando a {target}…",
        "End-to-end encryption (DTLS) enabled by default" => "Cifrado extremo a extremo (DTLS) activado por defecto",
        "Invalid CleanDesk ID. Check the number." => "CleanDesk ID no válido. Revisa el número.",
        "Invalid CleanDesk ID." => "CleanDesk ID no válido.",
        "You cannot connect to your own ID." => "No puedes conectarte a tu propio ID.",
        "Could not derive the key: {err}" => "No se pudo derivar la clave: {err}",
        "Could not connect: {err}" => "No se pudo conectar: {err}",
        "The connection was interrupted before it was established." => {
            "La conexión se interrumpió antes de establecerse."
        }

        // --- Errores de conexión (friendly_error) ---
        "the remote device is offline." => "el equipo remoto no está en línea.",
        "the remote device already has an active session." => "el equipo remoto ya tiene una sesión activa.",
        "the remote device declined the connection." => "el equipo remoto rechazó la conexión.",
        "wrong or unconfigured unattended-access password." => {
            "contraseña de acceso desatendido incorrecta o no configurada."
        }
        "the remote device did not respond in time." => "el equipo remoto no respondió a tiempo.",
        "could not reach the CleanDesk server." => "no se pudo contactar con el servidor CleanDesk.",
        "the remote device is not announced (is it on, with CleanDesk running?)." => {
            "el equipo remoto no está anunciado (¿está encendido y con CleanDesk abierto?)."
        }
        "the remote device's identity has changed; verify its fingerprint before trusting the new key." => {
            "la identidad del equipo remoto ha cambiado; comprueba su huella antes de confiar en la nueva clave."
        }

        // --- Lista de equipos ---
        "Recent" => "Recientes",
        "Favorites" => "Favoritos",
        "Add device" => "Añadir dispositivo",
        "last connection {when}" => "última conexión {when}",
        "no connections" => "sin conexiones",
        "No connections yet. Connect to an ID to see it here." => {
            "Sin conexiones todavía. Conecta a un ID para verlo aquí."
        }
        "You have not saved any device yet." => "Aún no has guardado ningún dispositivo.",
        "Add to / remove from favorites" => "Guardar / quitar de favoritos",
        "Password remembered (click to forget it)" => "Contraseña recordada (clic para olvidarla)",
        "Password forgotten." => "Contraseña olvidada.",
        "just now" => "ahora",
        "{n} min ago" => "hace {n} min",
        "{n} h ago" => "hace {n} h",
        "{n} d ago" => "hace {n} d",

        // --- Ventana "Añadir dispositivo" ---
        "Save a permanent host to favorites" => "Guardar un host permanente en favoritos",
        "Name:" => "Nombre:",
        "Office laptop" => "Portátil oficina",
        "Save" => "Guardar",

        // --- Ventana "Seguridad" ---
        "This device's identity is an Ed25519 key pair. Your CleanDesk ID is derived from the public key and the server requires a signature to register it: nobody can impersonate your ID without the private key." => {
            "La identidad de este equipo es un par de claves Ed25519. Tu CleanDesk ID se deriva de la clave pública y el servidor exige una firma para registrarlo: nadie puede suplantar tu ID sin la clave privada."
        }
        "Identity fingerprint" => "Huella de identidad",
        "Compare it through another channel (phone, message) with the person connecting." => {
            "Compárala por otro canal (teléfono, mensaje) con la persona que se conecta."
        }
        "Encryption" => "Cifrado",
        "Video, input and control travel over end-to-end DTLS; the server only relays signaling." => {
            "Vídeo, input y control viajan por DTLS extremo a extremo; el servidor solo retransmite la señalización."
        }
        "The unattended-access password is stored only as an Argon2id hash and never crosses the network (HMAC challenge-response)." => {
            "La contraseña de acceso desatendido se guarda solo como hash Argon2id y nunca cruza la red (reto-respuesta HMAC)."
        }

        // --- Ventana "Ajustes" ---
        "Language" => "Idioma",
        "The remote device is served by its background service and only accepts unattended connections: tick \"Unattended access\" and enter its password." => "El equipo remoto lo sirve su servicio en segundo plano y solo acepta conexiones desatendidas: marca \"Acceso desatendido\" e introduce su contraseña.",
        "Several devices claim this ID. Compare the fingerprint with the owner and connect only if it matches." => "Varios equipos reclaman este ID. Compara la huella con el propietario y conecta solo si coincide.",
        "Ready to connect (privileged, hosted by the service)" => "Listo para conectar (privilegiado, lo sirve el servicio)",
        "Privileged control: drive administrator windows and UAC prompts" => "Control privilegiado: manejar ventanas de administrador y avisos de UAC",
        "With the service installed, the service (LocalSystem) hosts and can show the UAC secure desktop; only unattended (password) connections are accepted then. Without the service, CleanDesk asks for elevation when it starts." => "Con el servicio instalado, el servicio (LocalSystem) hace de host y puede mostrar el escritorio seguro de UAC; entonces solo se aceptan conexiones desatendidas (con contraseña). Sin el servicio, CleanDesk pide elevación al arrancar.",
        "Restart CleanDesk to apply privileged control." => "Reinicia CleanDesk para aplicar el control privilegiado.",
        "Active: the service hosts as LocalSystem" => "Activo: el servicio hace de host como LocalSystem",
        "Active: running elevated (administrator windows; UAC prompts need the service)" => "Activo: en ejecución elevada (ventanas de administrador; los avisos de UAC requieren el servicio)",
        "Not active in this run (elevation declined or pending restart)" => "No activo en esta ejecución (elevación rechazada o pendiente de reinicio)",
        "Off: administrator windows cannot be controlled" => "Desactivado: no se pueden controlar ventanas de administrador",
        "Updates" => "Actualizaciones",
        "Current version: {v}" => "Versión actual: {v}",
        "Check for updates automatically" => "Buscar actualizaciones automáticamente",
        "Check now" => "Buscar ahora",
        "Checking for updates…" => "Buscando actualizaciones…",
        "You are up to date." => "Estás al día.",
        "CleanDesk {v} is available." => "CleanDesk {v} está disponible.",
        "Update now" => "Actualizar ahora",
        "Later" => "Más tarde",
        "Release notes" => "Notas de la versión",
        "Downloading {v}… {done} / {total}" => "Descargando {v}… {done} / {total}",
        "Update downloaded and verified. CleanDesk will close, install {v} and reopen." => "Actualización descargada y verificada. CleanDesk se cerrará, instalará {v} y se volverá a abrir.",
        "Install and restart" => "Instalar y reiniciar",
        "Installing…" => "Instalando…",
        "Update failed: {err}" => "Error al actualizar: {err}",
        "See the banner on the Home page." => "Mira el aviso de la página de Inicio.",
        "Set a password below first (at least 6 characters)." => "Primero define una contraseña abajo (mínimo 6 caracteres).",
        "(set; type a new one to replace it)" => "(definida; escribe otra para sustituirla)",
        "at least 6 characters" => "mínimo 6 caracteres",
        "Save password" => "Guardar contraseña",
        "Password saved; unattended access enabled." => "Contraseña guardada; acceso desatendido activado.",
        "Anyone connecting with this password gets in without your approval. Only an Argon2id hash and a derived key are stored, never the password." => "Quien se conecte con esta contraseña entra sin tu aprobación. Solo se guarda un hash Argon2id y una clave derivada, nunca la contraseña.",
        "Chat" => "Chat",
        "Chat ({n})" => "Chat ({n})",
        "CleanDesk ID:" => "ID de CleanDesk:",
        "Frames" => "Fotogramas",
        "Ping" => "Ping",
        "Relay" => "Relay",
        "URL:" => "URL:",
        // --- Visor: acciones, portapapeles y archivos ---
        "Files" => "Archivos",
        "Files ({n})" => "Archivos ({n})",
        "File transfer was not granted by the host." => "El host no concedió la transferencia de archivos.",
        "Keep the text clipboard in sync with the remote device" => "Mantener el portapapeles de texto sincronizado con el equipo remoto",
        "Clipboard access was not granted by the host." => "El host no concedió el acceso al portapapeles.",
        "Actions" => "Acciones",
        "Send Ctrl+Alt+Del" => "Enviar Ctrl+Alt+Supr",
        "Secure-attention sequence (best effort without the service)" => "Secuencia de atención segura (lo mejor posible sin el servicio)",
        "Send Ctrl+Shift+Esc (Task Manager)" => "Enviar Ctrl+Mayús+Esc (Administrador de tareas)",
        "Send Win+D (show desktop)" => "Enviar Win+D (mostrar escritorio)",
        "Lock remote session (Win+L)" => "Bloquear sesión remota (Win+L)",
        "Unlock remote keyboard and mouse" => "Desbloquear teclado y ratón remotos",
        "Lock remote keyboard and mouse" => "Bloquear teclado y ratón remotos",
        "Nobody at the remote device can use it while locked; it is always unlocked when the session ends." => "Nadie podrá usar el equipo remoto mientras esté bloqueado; se desbloquea siempre al terminar la sesión.",
        "Restart remote device" => "Reiniciar equipo remoto",
        "Reboots the remote device now. Reconnect once it is back." => "Reinicia el equipo remoto ahora. Vuelve a conectar cuando arranque.",
        "Send file…" => "Enviar archivo…",
        "Drop files on the remote screen to send them." => "Suelta archivos sobre la pantalla remota para enviarlos.",
        "{name} ({size})" => "{name} ({size})",
        "The remote device wants to send you this file." => "El equipo remoto quiere enviarte este archivo.",
        "Accept" => "Aceptar",
        "Reject" => "Rechazar",
        "Cancel" => "Cancelar",
        "Completed" => "Completado",
        "Show in folder" => "Mostrar en la carpeta",
        "Failed: {reason}" => "Error: {reason}",
        // --- Diseño nuevo: navegación, banner, tarjetas, páginas ---
        "Home" => "Inicio",
        "Sessions" => "Sesiones",
        "Contacts" => "Contactos",
        "Invitations" => "Invitaciones",
        "Ready to connect (community network)" => "Listo para conectar (red comunitaria)",
        "Ready to connect (private server)" => "Listo para conectar (servidor privado)",
        "Secure connections. Your privacy first." => "Conexiones seguras. Tu privacidad primero.",
        "Your desktop,
anywhere" => "Tu escritorio,
en cualquier lugar",
        "Connect securely, quickly and simply with CleanDesk." => "Conéctate de forma segura, rápida y sencilla con CleanDesk.",
        "Your CleanDesk address" => "Tu dirección de CleanDesk",
        "Invite" => "Invitar",
        "Connect to remote desktop" => "Conectar a escritorio remoto",
        "Enter a CleanDesk address or device alias" => "Introducir dirección de CleanDesk o alias de dispositivo",
        "What's new in CleanDesk?" => "¿Qué hay de nuevo en CleanDesk?",
        "Discover the latest features and improvements." => "Descubre las últimas funciones y mejoras.",
        "See what's new" => "Ver novedades",
        "Set a password so you can reach this device without anyone accepting." => "Define una contraseña para acceder a este equipo sin que nadie acepte.",
        "Set up now" => "Configurar ahora",
        "Discover" => "Descubrir",
        "Find and connect to devices on your local network automatically." => "Encuentra y conéctate a dispositivos de tu red local automáticamente.",
        "Find devices" => "Buscar dispositivos",
        "Work better as a team" => "Trabaja mejor en equipo",
        "Share access, manage devices and keep everything secure." => "Comparte acceso, gestiona dispositivos y mantén todo seguro.",
        "Recent sessions" => "Sesiones recientes",
        "See all" => "Ver todo",
        "Connected {when}" => "Conectado {when}",
        "to a new device" => "a un nuevo dispositivo",
        "Copy ID" => "Copiar ID",
        "Remove from favorites" => "Quitar de favoritos",
        "Add to favorites" => "Añadir a favoritos",
        "Wake up (Wake-on-LAN)" => "Despertar (Wake-on-LAN)",
        "Forget remembered password" => "Olvidar contraseña recordada",
        "Wake-up packet sent." => "Paquete de despertar enviado.",
        "Could not send the wake-up packet: {err}" => "No se pudo enviar el paquete de despertar: {err}",
        "Every connection made from or to this device." => "Todas las conexiones hechas desde o hacia este equipo.",
        "Device" => "Equipo",
        "User" => "Usuario",
        "When" => "Cuándo",
        "Duration" => "Duración",
        "Type" => "Tipo",
        "State" => "Estado",
        "active" => "activa",
        "closed" => "cerrada",
        "rejected" => "rechazada",
        "failed" => "fallida",
        "unknown" => "desconocido",
        "Saved devices. Star a recent session to add it here." => "Equipos guardados. Marca con estrella una sesión reciente para añadirla aquí.",
        "Invite someone to connect to this device, or check requests waiting for your approval." => "Invita a alguien a conectarse a este equipo o revisa las solicitudes pendientes de tu aprobación.",
        "Send this text to the person who should connect to you:" => "Envía este texto a la persona que debe conectarse contigo:",
        "Copy invitation" => "Copiar invitación",
        "Invitation copied to the clipboard." => "Invitación copiada al portapapeles.",
        "They will need your approval unless unattended access is enabled with a password (Settings)." => "Necesitará tu aprobación salvo que el acceso desatendido esté activado con contraseña (Ajustes).",
        "Pending requests" => "Solicitudes pendientes",
        "No pending requests. Incoming requests appear as a dialog you can accept or reject." => "Sin solicitudes pendientes. Las solicitudes entrantes aparecen en un diálogo que puedes aceptar o rechazar.",
        "Connect to my desktop with CleanDesk.
My CleanDesk ID: {id}
Fingerprint: {fp}
Download: https://github.com/EnriqueGF/CleanDesk/releases" => "Conéctate a mi escritorio con CleanDesk.
Mi CleanDesk ID: {id}
Huella: {fp}
Descarga: https://github.com/EnriqueGF/CleanDesk/releases",
        "Nearby devices" => "Equipos cercanos",
        "Scanning the local network…" => "Rastreando la red local…",
        "Scan again" => "Rastrear de nuevo",
        "No CleanDesk devices found on this network." => "No se encontraron equipos CleanDesk en esta red.",
        "Device alias" => "Alias del equipo",
        "Shown to people you connect to and used to find you on the local network." => "Se muestra a quienes te conectas y sirve para encontrarte en la red local.",
        "Show CleanDesk" => "Mostrar CleanDesk",
        "Quit" => "Salir",
        "Tray" => "Bandeja",
        "Closing the window minimizes to the tray (the host keeps running)" => "Cerrar la ventana la minimiza a la bandeja (el host sigue activo)",
        "CleanDesk keeps running in the tray." => "CleanDesk sigue ejecutándose en la bandeja.",
        "System default" => "Predeterminado del sistema",
        "Default quality" => "Calidad por defecto",
        "Automatic" => "Automática",
        "Best quality" => "Máxima calidad",
        "Balanced" => "Equilibrado",
        "Best performance" => "Máximo rendimiento",
        "Unattended access" => "Acceso desatendido",
        "Allow unattended connections" => "Permitir conexiones desatendidas",
        "Anyone connecting with this password gets in without your approval. Restart the app after changing it so the host picks it up." => {
            "Quien conecte con esta contraseña entra sin que tengas que aceptar. Reinicia la app tras cambiarla para que el host la use."
        }
        "The unattended-access password must be at least 6 characters long." => {
            "La contraseña de acceso desatendido debe tener al menos 6 caracteres."
        }
        "Unattended access enabled." => "Acceso desatendido activado.",
        "Could not enable it: {err}" => "No se pudo activar: {err}",
        "Unattended access disabled." => "Acceso desatendido desactivado.",
        "System" => "Sistema",
        "Start with Windows (at sign-in)" => "Iniciar con Windows (al iniciar sesión)",
        "CleanDesk will open when you sign in." => "CleanDesk se abrirá al iniciar sesión.",
        "CleanDesk will no longer open when you sign in." => "CleanDesk ya no se abrirá al iniciar sesión.",
        "Could not change startup: {err}" => "No se pudo cambiar el arranque: {err}",
        "Could not locate the executable." => "No se pudo localizar el ejecutable.",
        "Install as a service (unattended access before sign-in)" => {
            "Instalar como servicio (acceso desatendido antes de iniciar sesión)"
        }
        "Requires administrator rights. The service keeps the unattended host running even when nobody is signed in; when you open CleanDesk, the GUI takes over." => {
            "Pide permisos de administrador. El servicio mantiene el host desatendido activo aunque nadie haya iniciado sesión; cuando abres CleanDesk, la GUI toma el relevo."
        }
        "Service installed and running" => "Servicio instalado y en ejecución",
        "Service installed (stopped)" => "Servicio instalado (parado)",
        "Service changing state…" => "Servicio cambiando de estado…",
        "Service not installed" => "Servicio no instalado",
        "The service only handles unattended access: set a password above to make it useful." => {
            "El servicio solo atiende acceso desatendido: activa una contraseña arriba para que sea útil."
        }
        "CleanDesk service installed and started." => "Servicio CleanDesk instalado y arrancado.",
        "CleanDesk service removed." => "Servicio CleanDesk eliminado.",
        "Operation cancelled: administrator rights are required." => {
            "Operación cancelada: se necesitan permisos de administrador."
        }
        "Could not change the service: {err}" => "No se pudo cambiar el servicio: {err}",
        "Network" => "Red",
        "Forced by --signal-url: {url}" => "Forzado por --signal-url: {url}",
        "Community (no server): LAN, BitTorrent DHT and Nostr relays" => {
            "Comunitario (sin servidor): LAN, DHT de BitTorrent y relés Nostr"
        }
        "Private CleanDesk server" => "Servidor privado CleanDesk",
        "ws://server:7420" => "ws://servidor:7420",
        "Your device announces itself, signed, on the DHT and your local network; nobody has to run servers. The first connection pins the remote device's key (fingerprint under Security)." => {
            "Tu equipo se anuncia firmado en la DHT y en tu red local; nadie tiene que mantener servidores. La primera conexión fija la clave del equipo remoto (huella en Seguridad)."
        }
        "All signaling goes through your server; useful for companies and closed networks." => {
            "Toda la señalización pasa por tu servidor; útil en empresas y redes cerradas."
        }
        "The server URL must start with ws:// or wss://" => "La URL del servidor debe empezar por ws:// o wss://",
        "Network mode updated; the host is restarting." => "Modo de red actualizado; el host se reinicia.",

        // --- Diálogo de aprobación ---
        "Connection request" => "Solicitud de conexión",
        "System: {os}" => "Sistema: {os}",
        "Authentication: {auth}" => "Autenticación: {auth}",
        "Granted permissions" => "Permisos concedidos",
        "Decline" => "Rechazar",
        "Interactive" => "Interactiva",
        "Trusted device" => "Dispositivo de confianza",
        "View screen" => "Ver pantalla",
        "Control keyboard" => "Controlar teclado",
        "Control mouse" => "Controlar ratón",
        "Clipboard" => "Portapapeles",
        "File transfer" => "Transferir archivos",
        "Remote audio" => "Audio remoto",
        "Restart machine" => "Reiniciar equipo",
        "Restart CleanDesk" => "Reiniciar CleanDesk",
        "Admin actions" => "Acciones administrativas",
        "Lock local keyboard/mouse" => "Bloquear teclado/ratón local",

        // --- Visor ---
        "remote device" => "equipo remoto",
        "Screen:" => "Pantalla:",
        "Quality:" => "Calidad:",
        "Fit" => "Ajustar",
        "Full screen" => "Pantalla completa",
        "Refresh image (request a keyframe)" => "Refrescar imagen (pedir keyframe)",
        "Disconnect" => "Desconectar",
        "· View only (no control granted)" => "· Solo visualización (sin control concedido)",
        "Session ended." => "Sesión finalizada.",
        " (primary)" => " (principal)",
        "Remote:" => "Remoto:",
        "Me:" => "Yo:",
        "Authentication rejected by the remote device." => "Autenticación rechazada por el equipo remoto.",
        "Disconnected: {reason}" => "Desconectado: {reason}",
        "The session was closed." => "La sesión se cerró.",
        "Waiting for the remote device's image…" => "Esperando imagen del equipo remoto…",
        "Direct" => "Directa",
        "Codec" => "Códec",
        "Connection" => "Conexión",
        "via" => "vía",
        "Gathering statistics…" => "Estableciendo estadísticas…",
        "Type a message…" => "Escribe un mensaje…",
        "Send" => "Enviar",

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Todas las claves de la tabla, para comprobar propiedades de la tabla
    /// entera sin depender de una estructura de datos iterable en producción.
    const KEYS: &[&str] = &[
        "Settings", "Security", "Device identity and fingerprint", "Incoming session active", "Connecting…",
        "New session", "Community mode: announced (LAN · DHT · Nostr)", "CleanDesk network ready (private server)",
        "Announcing on the community network…", "Connecting to the server…", "Offline; retrying", "no server",
        "Network mode (Settings → Network)", "Trust the new identity",
        "Only if you verified the device fingerprint through another channel", "Previous key forgotten; connect again.",
        "{who} ({id}) is viewing your screen", "End session", "Incoming session ended: {reason}",
        "terminated by the host", "Your address", "Copy", "ID copied to the clipboard.",
        "Share this identifier so others can connect to your screen with your permission.", "office-pc",
        "Remote connection", "Enter remote ID…", "Connect ›", "Connect", "Unattended access (with password)",
        "Password:", "Remember", "Saves the device to favorites with its derived key (never the plaintext password)",
        "Waiting for {target}…", "End-to-end encryption (DTLS) enabled by default",
        "Invalid CleanDesk ID. Check the number.", "Invalid CleanDesk ID.", "You cannot connect to your own ID.",
        "Could not derive the key: {err}", "Could not connect: {err}",
        "The connection was interrupted before it was established.", "the remote device is offline.",
        "the remote device already has an active session.", "the remote device declined the connection.",
        "wrong or unconfigured unattended-access password.", "the remote device did not respond in time.",
        "could not reach the CleanDesk server.",
        "the remote device is not announced (is it on, with CleanDesk running?).",
        "the remote device's identity has changed; verify its fingerprint before trusting the new key.",
        "Recent", "Favorites", "Add device", "last connection {when}", "no connections",
        "No connections yet. Connect to an ID to see it here.", "You have not saved any device yet.",
        "Add to / remove from favorites", "Password remembered (click to forget it)", "Password forgotten.",
        "just now", "{n} min ago", "{n} h ago", "{n} d ago", "Save a permanent host to favorites", "Name:",
        "Office laptop", "Save",
        "This device's identity is an Ed25519 key pair. Your CleanDesk ID is derived from the public key and the server requires a signature to register it: nobody can impersonate your ID without the private key.",
        "Identity fingerprint", "Compare it through another channel (phone, message) with the person connecting.",
        "Encryption", "Video, input and control travel over end-to-end DTLS; the server only relays signaling.",
        "The unattended-access password is stored only as an Argon2id hash and never crosses the network (HMAC challenge-response).",
        "Language", "System default", "Default quality", "Automatic", "Best quality", "Balanced", "Best performance",
        "Unattended access", "Allow unattended connections",
        "Anyone connecting with this password gets in without your approval. Restart the app after changing it so the host picks it up.",
        "The unattended-access password must be at least 6 characters long.", "Unattended access enabled.",
        "Could not enable it: {err}", "Unattended access disabled.", "System", "Start with Windows (at sign-in)",
        "CleanDesk will open when you sign in.", "CleanDesk will no longer open when you sign in.",
        "Could not change startup: {err}", "Could not locate the executable.",
        "Install as a service (unattended access before sign-in)",
        "Requires administrator rights. The service keeps the unattended host running even when nobody is signed in; when you open CleanDesk, the GUI takes over.",
        "Service installed and running", "Service installed (stopped)", "Service changing state…",
        "Service not installed", "The service only handles unattended access: set a password above to make it useful.",
        "CleanDesk service installed and started.", "CleanDesk service removed.",
        "Operation cancelled: administrator rights are required.", "Could not change the service: {err}", "Network",
        "Forced by --signal-url: {url}", "Community (no server): LAN, BitTorrent DHT and Nostr relays",
        "Private CleanDesk server", "ws://server:7420",
        "Your device announces itself, signed, on the DHT and your local network; nobody has to run servers. The first connection pins the remote device's key (fingerprint under Security).",
        "All signaling goes through your server; useful for companies and closed networks.",
        "The server URL must start with ws:// or wss://", "Network mode updated; the host is restarting.",
        "Connection request", "System: {os}", "Authentication: {auth}", "Granted permissions", "Accept", "Decline",
        "Interactive", "Trusted device", "View screen", "Control keyboard", "Control mouse", "Clipboard",
        "File transfer", "Remote audio", "Restart machine", "Restart CleanDesk", "Admin actions",
        "Lock local keyboard/mouse", "remote device", "Screen:", "Quality:", "Fit", "Full screen",
        "Refresh image (request a keyframe)", "Disconnect", "· View only (no control granted)", "Session ended.",
        " (primary)", "Remote:", "Me:", "Authentication rejected by the remote device.", "Disconnected: {reason}",
        "The session was closed.", "Waiting for the remote device's image…", "Direct", "Codec", "Connection", "via",
        "Gathering statistics…", "Type a message…", "Send",
    ];

    #[test]
    fn every_key_has_a_distinct_non_empty_spanish_entry() {
        for key in KEYS {
            let es = spanish(key).unwrap_or_else(|| panic!("missing Spanish entry for {key:?}"));
            assert!(!es.is_empty(), "empty translation for {key:?}");
            assert_ne!(es, *key, "translation identical to key for {key:?}");
        }
    }

    /// Recorre las fuentes de la GUI y exige una entrada española para cada
    /// literal pasado a `tr`/`trf`: así una clave nueva no puede quedarse en
    /// inglés sin que lo note la CI.
    #[test]
    fn every_literal_key_in_sources_has_a_spanish_entry() {
        let sources = [
            include_str!("mainwindow.rs"),
            include_str!("viewer.rs"),
            include_str!("approval.rs"),
            include_str!("app.rs"),
            include_str!("tray.rs"),
        ];
        let mut missing = Vec::new();
        for src in sources {
            for call in ["tr(\"", "trf(\""] {
                let mut rest = src;
                while let Some(pos) = rest.find(call) {
                    rest = &rest[pos + call.len()..];
                    // Fin del literal: la primera comilla no escapada.
                    let mut end = 0;
                    let bytes = rest.as_bytes();
                    while end < bytes.len() {
                        if bytes[end] == b'\\' {
                            end += 2;
                            continue;
                        }
                        if bytes[end] == b'"' {
                            break;
                        }
                        end += 1;
                    }
                    let raw = &rest[..end.min(rest.len())];
                    let key = raw.replace("\\n", "\n").replace("\\\"", "\"");
                    if key.is_empty() {
                        continue;
                    }
                    if spanish(&key).is_none() {
                        missing.push(key);
                    }
                }
            }
        }
        missing.sort();
        missing.dedup();
        assert!(missing.is_empty(), "missing Spanish entries: {missing:#?}");
    }

    #[test]
    fn placeholders_survive_translation() {
        // Cada marcador `{x}` de la clave debe aparecer en la traducción, o
        // `trf` perdería datos silenciosamente.
        for key in KEYS {
            let es = spanish(key).unwrap();
            let mut rest = *key;
            while let Some(start) = rest.find('{') {
                let end = rest[start..]
                    .find('}')
                    .map(|e| start + e + 1)
                    .expect("unclosed placeholder");
                let ph = &rest[start..end];
                assert!(
                    es.contains(ph),
                    "placeholder {ph} missing in Spanish for {key:?}"
                );
                rest = &rest[end..];
            }
        }
    }

    #[test]
    fn from_tag_parses_common_forms() {
        assert_eq!(Lang::from_tag("es"), Lang::Es);
        assert_eq!(Lang::from_tag("es-ES"), Lang::Es);
        assert_eq!(Lang::from_tag("es_MX.UTF-8"), Lang::Es);
        assert_eq!(Lang::from_tag("ES"), Lang::Es);
        assert_eq!(Lang::from_tag("en"), Lang::En);
        assert_eq!(Lang::from_tag("en_US"), Lang::En);
        assert_eq!(Lang::from_tag("fr-FR"), Lang::En);
        assert_eq!(Lang::from_tag(""), Lang::En);
        assert_eq!(Lang::from_tag(Lang::Es.tag()), Lang::Es);
        assert_eq!(Lang::from_tag(Lang::En.tag()), Lang::En);
    }

    #[test]
    fn ui_keys_present_in_table() {
        for key in [
            "Settings",
            "Security",
            "Add device",
            "Connection request",
            "Automatic",
            "Best quality",
            "Balanced",
            "Best performance",
            "View screen",
            "Trust the new identity",
            "· View only (no control granted)",
            "{n} min ago",
            "{who} ({id}) is viewing your screen",
        ] {
            assert!(
                spanish(key).is_some(),
                "UI key {key:?} missing from the Spanish table"
            );
        }
    }

    #[test]
    fn tr_and_trf_follow_the_active_language() {
        // Los tests corren en paralelo y comparten el atómico: restauramos al
        // final y solo comprobamos claves cuyo resultado no dependa de otros.
        set_lang(Lang::Es);
        assert_eq!(lang(), Lang::Es);
        assert_eq!(tr("Settings"), "Ajustes");
        assert_eq!(tr("Chat"), "Chat", "unknown keys fall back to the key");
        assert_eq!(trf("{n} min ago", &[("n", "5")]), "hace 5 min");
        set_lang(Lang::En);
        assert_eq!(tr("Settings"), "Settings");
        assert_eq!(trf("{n} min ago", &[("n", "5")]), "5 min ago");
    }
}
