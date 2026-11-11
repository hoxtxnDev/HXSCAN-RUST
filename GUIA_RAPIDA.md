# Guía rápida de `tcpscan` (HXSCAN-RUST v2.1)

> ⚠️ **Solo para auditorías autorizadas.** Usa esta herramienta únicamente contra sistemas propios o con autorización escrita explícita. Los modos `stealth`/`mutable` reducen firmas de escaneo, pero **no garantizan** evadir IDS/IPS, EDR o sistemas de IA. Consulta [`SECURITY.md`](SECURITY.md).

---

## 1. Instalación en 2 pasos

```bash
git clone https://github.com/hoxtxnDev/HXSCAN-RUST.git
cd HXSCAN-RUST
cargo build --release
```

El binario queda en `target/release/tcpscan` (en Windows, `target\release\tcpscan.exe`). También puedes usar `./tcpscan`, que compila automáticamente si hace falta.

---

## 2. Tu primer escaneo

```bash
# Escanea los puertos críticos por defecto
./tcpscan 127.0.0.1

# Objetivo + puertos (sin flags)
./tcpscan 192.168.1.10 22,80,443,8000-8010

# Sintaxis host:puerto
./tcpscan 192.168.1.10:8080
```

La salida muestra una tabla con estado, RTT, servicio, riesgo, veredicto de honeypot y banner.

---

## 3. Recetas listas para copiar

| Necesito… | Comando |
|-----------|---------|
| Escaneo rápido (top 20) | `./tcpscan 10.0.0.5 --quick` |
| Auditoría completa con banners | `./tcpscan 10.0.0.5 --profile audit` |
| Barrido de los 65.535 puertos | `./tcpscan 10.0.0.5 --full` |
| Bajo ruido (jitter + rate ceiling) | `./tcpscan 10.0.0.5 --stealth` |
| Camuflaje corporativo | `./tcpscan 10.0.0.5 --mutable` |
| Persona concreta | `./tcpscan 10.0.0.5 --mutable --persona windows-update` |
| Salida JSON para SIEM | `./tcpscan 10.0.0.5 --json` |
| Salida CSV para Excel | `./tcpscan 10.0.0.5 --csv` |
| Bloquear escaneo a loopback | `./tcpscan 10.0.0.5 --protect-origin` |
| Ajuste fino de sigilo | `./tcpscan 10.0.0.5 --stealth --jitter-ms 150 --max-pps 3 --burst 1 --burst-pause-ms 900` |
| Verbose del Mediador | `./tcpscan 10.0.0.5 -v` |

---

## 4. Modos de operación

| Modo | Para qué sirve | Hilos | Jitter | Techo | Banners |
|------|----------------|-------|--------|-------|---------|
| `normal` | Máxima velocidad | 100 | 0 ms | sin límite | sí |
| `--stealth` | Pasar desapercibido | 10 | 120 ms | 3 pps | no |
| `--mutable` | Mezclarse con tráfico corporativo | 4 | 80 ms | 6 pps | sí |

Personas disponibles: `generic`, `corporate`, `browser`, `windows-update`, `backup-agent`.

Ejemplo de camuflaje con ajuste fino:

```bash
./tcpscan 10.0.0.7 --mutable \
  --persona corporate \
  --jitter-ms 90 \
  --max-pps 5 \
  --burst 4 \
  --burst-pause-ms 700 \
  --decoy-probes 8
```

> `--decoy-probes` genera tráfico señuelo **solo contra el mismo objetivo autorizado**. Sus resultados se descartan y nunca se envían a terceros.

---

## 5. Cómo leer el reporte

- **State**: `open` (servicio alcanzable), `closed` (RST), `filtered` (firewall/ACL) o `error`.
- **RTT**: latencia del handshake TCP en milisegundos.
- **Risk**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` o `NONE`, según exposición y contexto.
- **Honeypot**:
  - `clean`: sin señales relevantes.
  - `POSSIBLE`: señales débiles/medias; corrobora antes de interactuar.
  - `HONEYPOT`: evidencia fuerte (firma conocida, puertos incoherentes, exposición masiva, etc.).
- **Legitimacy** (solo `stealth`/`mutable`): score `0–100` y grado `A–F`. Es una **autoevaluación de configuración**, no una garantía de invisibilidad.

---

## 6. Códigos de salida

| Código | Significado |
|--------|-------------|
| `0` | Se encontraron puertos abiertos |
| `1` | Error de configuración, rango inválido o fallo DNS |
| `2` | Escaneo completado sin puertos abiertos |
| `130` | Interrumpido con `Ctrl+C` |

---

## 7. Problemas comunes

| Síntoma | Solución |
|---------|----------|
| Todos los puertos salen `filtered` | Aumenta `--timeout 2` o `--retries 1`; verifica firewall/VPN. |
| `cargo` no se reconoce | Instala Rust desde <https://rustup.rs> y reinicia la terminal. |
| DNS falla | Comprueba conectividad y que el dominio resuelva; prueba con la IP directa. |
| Quiero ver puertos cerrados | Añade `--show-closed`. |
| La tabla se ve sin colores | Usa `--no-color` o revisa el soporte ANSI de tu terminal. |
| Salida JSON para automatizar | `./tcpscan <host> --json > reporte.json`. |

---

## 8. Checklist antes de escanear

- [ ] Tengo autorización escrita y alcance documentado.
- [ ] El objetivo y los puertos están dentro de la ventana acordada.
- [ ] Empecé con `--stealth` o `--mutable` y validé el impacto.
- [ ] `--decoy-probes` solo se usa si el alcance lo permite.
- [ ] Revisé los veredictos de honeypot antes de interactuar con servicios sospechosos.
- [ ] Guardé el reporte con permisos restringidos.

---

Documentación completa: [`README.md`](README.md) · Arquitectura: [`ARCHITECTURE_MEDIATOR_UML.md`](ARCHITECTURE_MEDIATOR_UML.md) · Seguridad: [`SECURITY.md`](SECURITY.md).
