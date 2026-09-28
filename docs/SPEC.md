# CleanDesk — Hoja de Definiciones del Software

> Fuente de verdad del producto (definición aportada por el propietario del
> proyecto). El código de `crates/proto` implementa estos conceptos.

## 1. Producto
Aplicación de acceso y control remoto de equipos por Internet o red local:
visualizar pantalla remota, controlar teclado/ratón, transferir archivos y dar
soporte sin presencia física. Inicialmente **Windows**, con arquitectura
preparada para macOS y Linux.

## 2. Objetivo
Rápida, ligera, segura, fácil, baja latencia, sin configuración de red compleja.
Adecuada para soporte técnico y acceso personal. Descargar, ejecutar y recibir
conexión en segundos.

## 3. Identificación
Cada instalación tiene un **CleanDesk ID** único (ej. `548 291 743`) y,
opcionalmente, un alias (ej. `pc-oficina.clean`).

## 4. Pantalla principal
- *Este dispositivo:* ID, alias, estado de conexión, botón copiar ID, estado del
  servicio.
- *Conectar a dispositivo:* campo "Introducir CleanDesk ID" + botón "Conectar";
  listado de conexiones recientes y dispositivos guardados.

## 5. Solicitud de conexión
El equipo remoto recibe: nombre del solicitante, ID, usuario, permisos
solicitados. Opciones: **Aceptar** / **Rechazar**.

## 6. Permisos de sesión (modificables en vivo)
Ver pantalla · controlar teclado · controlar ratón · portapapeles · transferir
archivos · audio remoto · reiniciar equipo · reiniciar CleanDesk · acciones
administrativas · bloquear teclado/ratón local.

## 7. Control remoto
Transmite: imagen de pantalla, ratón, teclado, estado del cursor, resolución,
info de sesión. Optimiza calidad según la conexión.

## 8. Modos de calidad
Automática · Máxima calidad · Equilibrado · Máximo rendimiento.

## 9. Acceso desatendido
Configurable con contraseña; el que conecta se autentica con ella.

## 10. Dispositivos de confianza
Permitir siempre, recordar permisos, no pedir confirmación, permitir desatendido.

## 11. Libreta de dispositivos
Nombre, ID, alias, descripción, grupo, última conexión, estado online/offline.

## 12. Historial de conexiones
Dispositivo, usuario, inicio, fin, duración, tipo de conexión, estado.

## 13. Transferencia de archivos
Enviar/descargar, drag&drop, carpetas, progreso, cancelar. Canal cifrado.

## 14. Portapapeles compartido
Texto y URLs (MVP); imágenes/archivos opcional. Desactivable por permisos.

## 15. Múltiples monitores
Seleccionar/cambiar/ver todos; adaptar resolución y escala.

## 16. Pantalla completa
Ventana, pantalla completa, escalado automático, resolución original, "ajustar a
ventana".

## 17. Chat en sesión
Mensajes entre usuario remoto y local durante la sesión.

## 18. Seguridad
Cifrado de comunicaciones, autenticación de dispositivos, IDs únicos, protección
frente a conexiones no autorizadas, validación de sesiones, expiración de tokens,
protección anti fuerza bruta, registro de accesos, confirmación visual de sesión
activa. Credenciales desatendidas nunca en texto plano.

## 19. Arquitectura de conexión
- **CleanDesk Client:** captura, inputs, codificación, sesiones, ficheros.
- **CleanDesk Server:** autenticación, registro, resolución de IDs, usuarios,
  coordinación, señalización.
- **CleanDesk Relay:** intermedio cuando no hay conexión directa.
Flujo: `A → P2P → B`; si no es posible, `A → Relay → B`.

## 20. NAT Traversal
UDP hole punching, STUN, ICE, TURN/Relay como fallback. Minimizar tráfico por los
servidores.

## 21–23. Usuarios, equipos, roles
Uso sin cuenta para conexiones simples; cuentas para agenda sincronizada,
favoritos, historial, equipos, desatendido centralizado. Equipos profesionales.
Roles: Administrador, Técnico, Usuario.

## 24. Servicio en segundo plano (Windows)
Inicio con Windows, acceso pre-login, desatendido, reinicio remoto, conexión tras
cerrar sesión.

## 25. Actualizaciones
Consultar, descargar, verificar integridad, instalar; "Buscar actualizaciones".

## 26. Información de sesión
Duración, latencia, FPS, resolución, códec, ancho de banda, tipo de conexión.

## 27. Barra de herramientas
Pantallas, calidad, pantalla completa, transferencia, chat, permisos, reiniciar,
info de conexión, desconectar.

## 28. Finalización de sesión
"Desconectar" cierra vídeo, inputs, transferencias y autenticación; se registra
en historial.

## 29. Estados de dispositivo
Online · Offline · En sesión · No disponible.

## 30. MVP
App Windows, ID, servidor de señalización, conexión 2 equipos, captura,
streaming, control teclado/ratón, solicitud aceptar/rechazar, conexión cifrada,
relay, acceso desatendido por contraseña, portapapeles básico, transferencia de
archivos, historial básico.

## 31. Posteriores
Cuentas, agenda en la nube, equipos, MFA, grabación, Wake-on-LAN, impresión
remota, túneles TCP, terminal remota, API, webhooks, móvil, web, macOS, Linux,
políticas empresariales, auditoría avanzada.

## 32. Resumen
Plataforma de escritorio remoto para conectarse rápido y seguro a otros equipos
mediante un identificador único, con visualización de pantalla, control remoto,
transferencia de archivos y acceso desatendido, usando P2P siempre que sea
posible y relay cuando no.
