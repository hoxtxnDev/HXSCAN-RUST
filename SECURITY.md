# Auditoría de Seguridad y Protección del Equipo de Origen (`SECURITY.md`)

Este documento registra los hallazgos de la auditoría de seguridad realizada sobre el repositorio `HXSCAN-RUST` (`tcpscan`) y los controles técnicos implementados para proteger el **equipo de origen del analista/auditor**.

---

## 1. Hallazgos en el Historial Git (OPSEC) y Remediación

Durante la auditoría forense de objetos Git históricos del repositorio original se detectaron **2 exposiciones OPSEC del equipo de origen**:

1. **Artefacto binario `.pyc` filtrado en el historial (`__pycache__/port_scanner.cpython-314.pyc`)**:
   - A pesar de haber sido eliminado del árbol de trabajo en commits posteriores, el blob binario seguía accesible en el historial de Git y contenía en texto plano la ruta local absoluta y el nombre de usuario Windows del equipo de origen.
   - **Remediación**: Se purgó por completo el historial de blobs antiguos reescribiendo la línea base del repositorio sin ningún binario `.pyc` ni rastro de rutas locales del sistema anfitrión.
2. **Exposición de correos personales en metadatos de autoría Git**:
   - Los commits históricos exponían direcciones de correo personales en los encabezados `Author` y `Committer`.
   - **Remediación**: Se configuró y reescribió la identidad de autoría del repositorio utilizando el correo anónimo oficial de GitHub (`hoxtxnDev <hoxtxnDev@users.noreply.github.com>`).

---

## 2. Controles de Protección Activa para el Equipo de Origen

Cuando un escáner de ciberseguridad interactúa con objetivos no confiables (servidores maliciosos, *honeypots*, *tarpits* o dominios controlados por atacantes), el propio equipo que ejecuta el escaneo puede ser víctima de ataques de rebote o agotamiento de recursos. Se implementaron **6 defensas activas**:

### 2.1. Escudo Anti-DNS Rebinding y Bloqueo de IPs Peligrosas (`Stage 1`)
- **Riesgo (CWE-350 / SSRF contra el host local)**: Un atacante configura un dominio externo para que resuelva a `127.0.0.1`, `::1`, `0.0.0.0` o `169.254.169.254`, engañando al analista para que escanee su propio equipo de origen o servicios *link-local*.
- **Protección implementada ([`validate_ip_safety`](src/stages/stage1_discovery.rs))**:
  - Bloquea incondicionalmente direcciones no especificadas (`0.0.0.0`, `::` que en macOS/Linux redirigen al propio `localhost`), Broadcast (`255.255.255.255`) y Multicast (`224.0.0.0/4`, `ff00::/8`).
  - Si el objetivo ingresado es un dominio externo (distinto de `localhost`) y el servidor DNS devuelve una IP `Loopback` (`127.0.0.0/8`, `::1`) o `LinkLocal` (`169.254.0.0/16`, `fe80::/10`), el escaneo se aborta inmediatamente con `DiscoveryError::DnsRebindingDetected`.
  - Bandera adicional `--protect-origin` (`--no-self-scan`) para prohibir explícitamente cualquier escaneo hacia interfaces `Loopback`.

### 2.2. Protección contra Agotamiento de Hilos, Sockets y Pánicos (`Stage 0` & `Stage 2`)
- **Riesgo (CWE-400 Resource Exhaustion)**: Pasar valores extremos como `--threads 1000000` o `--timeout 1e30` podía agotar los descriptores de archivo (`EMFILE`) del sistema operativo local o provocar un `panic` en `Duration::from_secs_f64`.
- **Protección implementada ([`src/cli.rs`](src/cli.rs) y [`src/stages/stage2_scanner.rs`](src/stages/stage2_scanner.rs))**:
  - Límite estricto `MAX_SAFE_THREADS = 2048`.
  - Validación de `--timeout` en el rango `[0.01s, 60.0s]` usando `Duration::try_from_secs_f64`.
  - Límite de reintentos `MAX_RETRIES = 5` y `MAX_DELAY_MS = 30000`.

### 2.3. Sanitización Completa de Secuencias de Escape ANSI CSI/OSC (`Stage 3`)
- **Riesgo (CWE-150 Terminal Escape Injection)**: Un servidor malicioso puede responder con secuencias ANSI (`\x1b[...` o `\x1b]0;...\x07`) en su banner SSH/HTTP para manipular el emulador de terminal del analista.
- **Protección implementada ([`strip_ansi_sequences`](src/stages/stage3_fingerprint.rs))**:
  - Máquina de estados que elimina por completo secuencias CSI y OSC antes de filtrar caracteres ASCII imprimibles y truncar la lectura a un buffer fijo de `512 bytes` (protección contra *Endlessh* / *Tarpits*).

### 2.4. Neutralización de Inyección de Fórmulas en CSV (`Stage 5`)
- **Riesgo (CWE-1236 CSV Formula Injection)**: Si un servidor remoto envía un banner malicioso como `=cmd|' /C calc'!A0` y el analista abre el reporte `--csv` en Excel o LibreOffice Calc en su equipo de origen, la hoja de cálculo podría ejecutar comandos locales.
- **Protección implementada ([`sanitize_csv_cell`](src/stages/stage5_report.rs))**:
  - Cualquier celda cuyo contenido comience con `=`, `+`, `-`, `@`, `|`, `\t` o `\r` es neutralizada anteponiendo una comilla simple (`'`) y escapando comillas dobles según RFC-4180.

### 2.5. Garantía de Seguridad de Memoria en Tiempo de Compilación (`#![forbid(unsafe_code)]`)
- Todos los objetivos de compilación ([`src/lib.rs`](src/lib.rs), [`src/main.rs`](src/main.rs), [`src/bin/hxscan.rs`](src/bin/hxscan.rs)) declaran `#![forbid(unsafe_code)]`, impidiendo bloques `unsafe` y garantizando ausencia de *buffer overflows* o *use-after-free*.

### 2.6. Endurecimiento del Lanzador Shell ([`tcpscan`](tcpscan))
- Configuración estricta con `set -eu`, `unset CDPATH`, `IFS` seguro y `LC_ALL=C` para impedir secuestros de rutas o variables de entorno al invocar `./tcpscan`.
