# Auditoría de Seguridad y Protección del Equipo de Origen (`SECURITY.md`)

Este documento registra los hallazgos de la auditoría de seguridad realizada sobre el repositorio `HXSCAN-RUST` (`tcpscan`) y los controles técnicos implementados para proteger el **equipo de origen del analista/auditor**.

> ⚠️ **Uso autorizado y alcance**: todas las capacidades descritas aquí (stealth, mutable, filtros anti-IA, decoys y análisis de honeypots) están destinadas exclusivamente a auditorías de seguridad con autorización escrita explícita. No son mecanismos de anonimato ni garantizan la evasión de AI/ML, IDS/IPS, EDR o soluciones de correlación. El operador es responsable de cumplir la ley, el alcance acordado (*Rules of Engagement*) y las políticas de la organización.

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

Cuando un escáner de ciberseguridad interactúa con objetivos no confiables (servidores maliciosos, *honeypots*, *tarpits* o dominios controlados por atacantes), el propio equipo que ejecuta el escaneo puede ser víctima de ataques de rebote o agotamiento de recursos. Se implementaron **6 defensas activas** para el equipo de origen:

> Los controles de legitimidad, mutación de tráfico, reconocimiento TLS/X.509 y clasificación de honeypots introducidos en las versiones 2.1 y 2.2 se documentan por separado en la **Sección 3**.

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

### 2.4. Neutralización de Inyección de Fórmulas en CSV (`Stage 6`)
- **Riesgo (CWE-1236 CSV Formula Injection)**: Si un servidor remoto envía un banner malicioso como `=cmd|' /C calc'!A0` y el analista abre el reporte `--csv` en Excel o LibreOffice Calc en su equipo de origen, la hoja de cálculo podría ejecutar comandos locales.
- **Protección implementada ([`sanitize_csv_cell`](src/stages/stage6_report.rs))**:
  - Cualquier celda cuyo contenido comience con `=`, `+`, `-`, `@`, `|`, `\t` o `\r` es neutralizada anteponiendo una comilla simple (`'`) y escapando comillas dobles según RFC-4180.

### 2.5. Garantía de Seguridad de Memoria en Tiempo de Compilación (`#![forbid(unsafe_code)]`)
- Todos los objetivos de compilación ([`src/lib.rs`](src/lib.rs), [`src/main.rs`](src/main.rs), [`src/bin/hxscan.rs`](src/bin/hxscan.rs)) declaran `#![forbid(unsafe_code)]`, impidiendo bloques `unsafe` y garantizando ausencia de *buffer overflows* o *use-after-free*.

### 2.6. Endurecimiento del Lanzador Shell ([`tcpscan`](tcpscan))
- Configuración estricta con `set -eu`, `unset CDPATH`, `IFS` seguro y `LC_ALL=C` para impedir secuestros de rutas o variables de entorno al invocar `./tcpscan`.

---

## 3. Controles de Legitimidad, Mutación, Reconocimiento TLS y Análisis de Engaño (v2.1 / v2.2)

La evolución v2.1 / v2.2 añade un **sobre de legitimidad**, **reconocimiento TLS/X.509 sin descifrado**, **extracción conservadora de versión de servicio** y un **clasificador conductual de honeypots**. Todos están diseñados para mejorar la calidad de una auditoría autorizada, no para ocultar actividad maliciosa. A diferencia de las defensas de la Sección 2, estos controles no protegen al equipo de origen de un atacante: protegen la **validez del ejercicio** y ayudan al analista a interpretar el entorno objetivo.

### 3.1. Sobre de cadencia y backoff adaptativo (`Stage 2` + [`stealth.rs`](src/stealth.rs))

- **Riesgo operativo**: un escaneo a máxima velocidad puede saturar enlaces, activar WAF/IPS/Fail2ban, disparar alertas de correlación o quedar atrapado en un *tarpit* que consuma hilos y descriptores.
- **Controles implementados ([`PacingController`](src/stealth.rs))**:
  - **Techo global `--max-pps`** (`0..=1000`; `0` = ilimitado) repartido entre los workers para que el agregado no supere el envelope configurado.
  - **Jitter uniforme `--jitter-ms`** (`0..=5000`) añadido a cada intervalo; internamente el pacing acota el jitter a `MAX_PACING_JITTER_MS = 60_000` para evitar esperas desbordadas.
  - **Ráfagas `--burst`** (`1..=64`) y **pausa `--burst-pause-ms`** (`0..=10_000`) para evitar patrones constantes y fácilmente correlacionables.
  - **Backoff exponencial adaptativo** (`--adaptive-pacing`) de `2x` hasta `8x` cuando el resultado es `Filtered` o `Error`, con reset a `1x` en `Open`/`Closed`. Evita escalar contra un firewall, IPS o tarpit.
  - **Perfiles conservadores**: `--stealth` usa 10 hilos, jitter de 120 ms, techo de 3 pps, ráfaga de 1 sonda con pausa de 900 ms y banners desactivados; `--mutable` usa 4 hilos, jitter de 80 ms, techo de 6 pps, ráfagas de 5 con pausa de 500 ms y banners activos.
- **Límites de recursos**: `MAX_SAFE_THREADS = 2048`, `MAX_JITTER_MS = 5000`, `MAX_PPS = 1000.0`, `MAX_BURST_SIZE = 64`, `MAX_BURST_PAUSE_MS = 10000` y `MAX_DECOY_PROBES = 128`. Todos los valores se validan en el CLI antes de construir `StealthConfig`.

### 3.2. Mutación de identidad y sanitización de cabeceras (`Stage 3` + [`stealth.rs`](src/stealth.rs))

- **Objetivo**: que las sondas HTTP activas se parezcan a tráfico empresarial normal en lugar de llevar una firma explícita de escáner.
- **Personas disponibles**: `generic`, `corporate`, `browser`, `windows-update` y `backup-agent`. Cada una selecciona un `User-Agent` coherente y variantes de `Accept`, `Accept-Language`, `Host`, `Connection` y `Upgrade-Insecure-Requests`.
- **Mutación**: [`build_http_probe`](src/stealth.rs) construye la petición HTTP con la persona configurada; `Stage 3` la usa mediante `inspect_live_stream_with_persona` / `grab_banner_from_rw_with_persona` cuando el modo no es `normal`.
- **Sanitización**: [`sanitize_header_value`](src/stealth.rs) elimina caracteres de control (incluidos `CR`/`LF`) y trunca a 255 caracteres antes de insertar el `Host` en la cabecera. Esto evita **header injection / request smuggling** a partir de un objetivo malicioso o de una entrada de usuario manipulada.
- **Límite explícito**: la mutación cambia cabeceras HTTP y la cadencia. **No suplanta direcciones IP, identidades criptográficas ni certificados TLS**, y no convierte el tráfico en anónimo.

### 3.3. Decoys acotados al mismo objetivo autorizado (`Stage 2`)

- **Riesgo**: generar tráfico señuelo hacia terceros podría constituir una agresión a sistemas fuera de alcance, además de un problema legal y operativo.
- **Control implementado ([`build_work_plan`](src/stealth.rs))**:
  - Los decoys se intercalan **solo contra el objetivo primario autorizado** del escaneo.
  - Se eligen de un pool de puertos empresariales habituales (`53`, `80`, `123`, `443`, `445`, `993`, `8080`, `8443`).
  - Máximo `MAX_DECOY_PROBES = 128` por ejecución; el CLI rechaza valores superiores.
  - Los resultados de los decoys se **descartan** y nunca llegan al Mediador, a la auditoría ni al reporte.
  - No hay *spoofing* de IP de origen, reflexión ni amplificación: cada sonda es una conexión TCP normal desde el equipo del auditor.
- **Advertencia**: incluso limitados al mismo objetivo, los decoys aumentan el volumen de tráfico. Úsalos solo si el alcance y la ventana de auditoría lo permiten.

### 3.4. Clasificación conductual de honeypots (`Stage 4`)

- **Objetivo defensivo**: identificar entornos de decepción **antes** de que el analista interactúe más profundamente con ellos, y explicar qué comportamiento motivó el veredicto.
- **Señales evaluadas por [`HoneypotColleague`](src/stages/stage4_honeypot.rs)**:
  - Firmas de frameworks conocidos (Cowrie, Kippo, Dionaea, Glastopf, Honeyd, Thinkst Canary, OpenCanary, Conpot, Endlessh, entre otras).
  - Puertos típicos de honeypot (`2222`, `22222`, `2323`, `4444`, `5555`, `8081`, `8082`, `9999`, `10000`, `31337`, `5038`) y clústeres de tres o más.
  - Incoherencia entre el protocolo del banner y el servicio/puerto declarado; banners que mezclan protocolos incompatibles.
  - Latencia de tarpit (> 2.5 s fuera de loopback), servicios interactivos sin banner, prompts de credenciales inesperados, versiones legacy/falsas y servicios en puertos efímeros (`≥ 49152`), además de anomalías de certificado TLS/X.509 (`self-signed-certificate`, `certificate-hostname-mismatch`, `expired-certificate`, `default-certificate-identity`).
  - Señales agregadas: exposición masiva (10+ abiertos y 35%+ del total escaneado), RTT sospechosamente uniforme (6+ abiertos con dispersión ≤ 200 µs), banners clonados (3+ idénticos) y clúster de puertos señuelo.
- **Veredictos**: `clean` (score < 30), `possible-honeypot` (30–69) y `honeypot` (≥ 70). El score y las evidencias se incluyen en el reporte humano, JSON y CSV.
- **Respuesta mediada**: `PossibleHoneypotDetected` o `ConfirmedHoneypotDetected` se convierten en alertas (`deception_alerts`) y en los contadores `possible_honeypot_count` / `confirmed_honeypot_count` del resumen de postura.
- **Control de interacción**: `HoneypotColleague` **no** envía credenciales, exploits ni payloads de explotación; solo analiza los banners y metadatos ya obtenidos por `Stage 2`/`Stage 3`. El buffer de lectura sigue acotado a 512 bytes y los timeouts/backoff limitan el impacto de tarpits.
- **Naturaleza del veredicto**: es una **hipótesis basada en comportamiento observable**, no una prueba forense. Un falso positivo es posible; corrobora con el propietario del activo, el contexto de red y la ventana de auditoría.

### 3.5. Reconocimiento TLS 1.2 y Parser X.509 Acotado (`Stage 2` / `Stage 3` + [`tls.rs`](src/tls.rs))

- **Alcance estrictamente de reconocimiento**: en puertos TLS habituales y solo cuando `grab_banners` está activo, el Mediador envía un `ClientHello` TLS 1.2 mínimo con SNI y lee el mensaje `Certificate` del servidor. **No completa el handshake, no deriva claves de sesión y no descifra ni intercepta tráfico de aplicación.**
- **Protección del equipo de origen en el parser DER/X.509**: lectura acotada por `banner_timeout`, tamaño máximo de respuesta (`16 KiB` / 8 registros TLS), límite de longitud de identidad (`128` caracteres) y máximo `16` entradas SAN, con sanitización de caracteres de control y almacenamiento en cold path (`Mutex<HashMap<u16, TlsCertificateInfo>>`).
- **Límite criptográfico**: el parser extrae metadatos X.509 para inventario y detección de anomalías, pero **no valida firmas criptográficas ni cadenas de confianza contra una CA raíz**.

### 3.6. Límites de los controles y advertencia legal

- **No hay garantía de evasión**: los sistemas defensivos pueden seguir detectando el escaneo por volumen, reputación de IP/ASN, JA3/JA4, timing, geolocalización, correlación con otros eventos o análisis humano. El score de legitimidad es una autoevaluación de configuración, no una promesa de invisibilidad.
- **`--ai-filter` no modifica el tráfico por sí solo**: activa el libro de contabilidad y la telemetría de legitimidad. Las palancas que cambian el comportamiento son `--jitter-ms`, `--max-pps`, `--burst`, `--persona` y `--adaptive-pacing`.
- **No hay anonimato**: la herramienta no oculta la IP de origen, no usa proxies ni VPN, y no cifra ni ofusca el tráfico a nivel de red. Si el alcance requiere anonimato, debe resolverse con la infraestructura autorizada del ejercicio.
- **Protección de artefactos**: los reportes JSON/CSV pueden contener banners, IPs, servicios y veredictos sensibles. Almacénalos con permisos restringidos y sigue la política de retención de evidencia de la organización.
- **Cumplimiento**: el uso de estas capacidades contra sistemas sin autorización puede constituir un delito. El operador es el único responsable.

---

## 4. Checklist de Uso Responsable

- [ ] Tener autorización escrita explícita y un alcance (*scope*) documentado antes de ejecutar cualquier modo.
- [ ] Confirmar que el objetivo y los puertos están dentro de la ventana y las reglas acordadas.
- [ ] Empezar con `--stealth` o `--mutable` y validar el impacto antes de subir `--max-pps` o `--threads`.
- [ ] Usar `--decoy-probes` solo si el alcance permite tráfico adicional contra el mismo objetivo.
- [ ] Revisar `deception_alerts` y los veredictos de honeypot antes de interactuar con servicios sospechosos.
- [ ] Conservar la evidencia de autorización y proteger los reportes generados.
- [ ] Detener el escaneo si se observan señales de saturación, bloqueo o impacto no previsto.
