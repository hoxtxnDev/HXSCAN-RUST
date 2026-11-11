//! # `tcpscan` (HXSCAN-RUST v3.0 — Mediator Pattern Architecture)
//!
//! High-performance, zero-dependency, staged modular TCP port scanner and
//! cybersecurity auditing toolkit built around the **Mediator Design Pattern**
//! (also known as *Intermediary* or *Controller*).
//!
//! ## v3.0 Highlights ("Ultimate Recon Edition")
//! - **Nmap / Naabu / RustScan CLI ergonomics**: `-sV`, `-A`, `-p-`, `-p<spec>`, `-F`,
//!   `--top-ports <N>`, `-T0`..`-T5`, `--exclude-ports`, `-iL`, `--silent`, `--grepable`,
//!   `-oN`, `-oJ`, `-oC`, `-oG`, `-o`.
//! - **CPE 2.3 & CVE Intelligence**: Passive NVD CPE 2.3 identifier generation, high-impact
//!   CVE/CWE correlation, and passive OS family hinting (`os_hint`).
//! - **Honeypot-Filtered Nmap Handoff (`--nmap-cmd`)**: Renders a clean `nmap -sV -sC -p ...`
//!   follow-up command in the report that automatically excludes suspected honeypot ports.
//! - **Multi-Target Discovery**: Bounded CIDR (`/22..=/32`), IP ranges (`10.0.0.1-20`),
//!   comma-separated host lists, and `-iL <file>` target lists (`MAX_MULTI_TARGETS = 1024`).
//!
//! ## v2.2 Highlights
//! - **TLS certificate reconnaissance**: minimal TLS 1.2 `ClientHello` exchange that
//!   retrieves the leaf certificate without completing the handshake or decrypting traffic.
//! - **X.509 intelligence**: subject/issuer CN, DNS SANs, expiry, self-signed heuristic,
//!   hostname mismatch and advertised chain length in human, JSON and CSV reports.
//! - **Service version extraction**: product versions parsed from SSH, HTTP, FTP, SMTP,
//!   MySQL and Redis banners and attached to every open port.
//! - **Certificate-backed deception signals**: self-signed, mismatched, expired and
//!   default-identity certificates contribute explainable honeypot evidence.
//!
//! ## v2.1 Highlights
//! - **Stealth mode**: jittered, rate-capped, shuffled probes with adaptive backoff.
//! - **Mutable mode**: enterprise traffic personas, human-like bursts and mutated HTTP headers.
//! - **Anti-AI legitimacy envelope**: bounded probe cadence, decoy probes on the same target
//!   and an honest legitimacy self-assessment for the final report.
//! - **Behavioral honeypot classification**: per-port `possible-honeypot` / `honeypot`
//!   verdicts with explainable behavior flags (Cowrie/Kippo signatures, protocol mismatches,
//!   mass-open services, uniform RTT, cloned banners, tarpits and more).
//!
//! ## Origin Host Security & Hardening (`#![forbid(unsafe_code)]`)
//! - **100% Safe Rust**: `#![forbid(unsafe_code)]` enforced across all targets.
//! - **Anti-DNS Rebinding & Unsafe IP Shield**: Blocks `0.0.0.0`, `::`, `255.255.255.255`, multicast,
//!   and external domains resolving to `127.0.0.0/8`, `::1`, or `169.254.0.0/16`.
//! - **Resource Exhaustion Caps**: Bounds worker threads (`1..=2048`), timeouts (`0.01s..=60.0s`),
//!   retries (`0..=5`), and rate-limiting delays (`0..=30000ms`).
//! - **Terminal & CSV Sanitization**: Strips full ANSI CSI/OSC escape sequences and neutralizes
//!   CWE-1236 CSV formula payloads (`=`, `+`, `-`, `@`, `|`).

#![forbid(unsafe_code)]

pub mod cli;
pub mod mediator;
pub mod stages;
pub mod stealth;
pub mod tls;

pub use cli::{
    ascii_banner, help_text, help_text_es, parse_cli_args, CliAction, ScanProfile,
    MAX_BURST_PAUSE_MS, MAX_BURST_SIZE, MAX_DECOY_PROBES, MAX_DELAY_MS, MAX_JITTER_MS, MAX_PPS,
    MAX_RETRIES, MAX_SAFE_THREADS, MAX_TIMEOUT_SECS, MIN_TIMEOUT_SECS,
};
pub use mediator::{
    AddressScope, AuditedPortResult, ComponentId, EnrichedPortResult, HoneypotAssessment,
    HoneypotBehavior, HoneypotVerdict, Language, MediatedEventRecord, MediatorDirective,
    MediatorState, OutputFormat, PipelineConfig, PipelineOutput, PortState, RawProbeResult,
    ReconIntelligence, ReportOptions, RiskLevel, ScanController, ScanEvent, ScanMediator,
    ScannerConfig, SecurityPostureSummary, StealthConfig, StealthMode, StealthTelemetry,
    TargetInfo, TlsCertificateInfo, TrafficPersona,
};
pub use stages::stage1_discovery::{
    expand_target_inputs, parse_port_spec, parse_port_spec_with_exclusions, resolve_target,
    shuffle_ports, validate_ip_safety, DiscoveryColleague, DiscoveryError, MAX_MULTI_TARGETS,
    TOP_PORTS_RANKED,
};
pub use stages::stage2_scanner::{
    classify_connect_error, execute_scan_stage, execute_scan_stage_with_prober,
    format_scan_progress, global_stdin_receiver, probe_single_port, ScannerColleague,
};
pub use stages::stage3_fingerprint::{
    enrich_probe_results, get_service_name, grab_banner_from_rw, grab_banner_from_stream,
    grab_banner_passive_from_rw, infer_service_from_banner, sanitize_banner, FingerprintColleague,
    SERVICE_TABLE,
};
pub use stages::stage4_honeypot::{analyze_honeypots, evaluate_honeypot_port, HoneypotColleague};
pub use stages::stage5_audit::{
    analyze_rtt_topology, build_cpe23, correlate_cves, detect_toxic_combinations,
    evaluate_port_security, evaluate_port_security_with_honeypot, execute_audit_stage,
    execute_audit_stage_with_honeypots, extract_shadow_assets, infer_host_role, infer_os_hint,
    synthesize_recon_intelligence, AuditColleague,
};
pub use stages::stage6_report::{
    build_clean_nmap_command, render_ascii_banner, render_report, render_report_with_stealth,
    sanitize_csv_cell, ReportColleague,
};
pub use stages::ScanPipeline;
pub use stealth::{
    assess_legitimacy, build_http_probe, build_work_plan, evaluate_scan_legitimacy,
    filtered_ratio_pct, next_rand, PacingController,
};

/// Execute the CLI workflow from an iterator of argument strings (excluding program name).
///
/// Returns `(exit_code, stdout_text, stderr_text)` so both `main.rs` and automated tests
/// can verify exact behavior and exit codes (`0` = open found, `1` = error, `2` = no open ports).
pub fn run_from_args<I, S>(args: I) -> (i32, String, String)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    match parse_cli_args(args) {
        Ok(CliAction::ShowHelp(help)) => (0, help, String::new()),
        Ok(CliAction::ShowVersion(ver)) => (0, format!("{ver}\n"), String::new()),
        Ok(CliAction::Run(config)) => {
            let targets =
                match expand_target_inputs(&config.target_input, config.input_file.as_deref()) {
                    Ok(list) => list,
                    Err(err) => return (1, String::new(), format!("[!] {err}\n")),
                };

            let output_file = config.output_file.clone();
            let mut combined_stdout = String::new();
            let mut any_open = false;

            if targets.len() == 1 {
                let mut single_cfg = config;
                single_cfg.target_input = targets.into_iter().next().unwrap();
                let controller = ScanController::new(single_cfg);
                match controller.execute() {
                    Ok(output) => {
                        if output.exit_code() == 0 {
                            any_open = true;
                        }
                        combined_stdout = output.formatted_report;
                    }
                    Err(err) => return (1, String::new(), format!("[!] {err}\n")),
                }
            } else {
                for target_item in targets {
                    let mut item_cfg = config.clone();
                    item_cfg.target_input = target_item;
                    let controller = ScanController::new(item_cfg);
                    match controller.execute() {
                        Ok(output) => {
                            if output.exit_code() == 0 {
                                any_open = true;
                            }
                            combined_stdout.push_str(&output.formatted_report);
                        }
                        Err(err) => return (1, String::new(), format!("[!] {err}\n")),
                    }
                }
            }

            if let Some(ref path) = output_file {
                if let Err(io_err) = std::fs::write(path, &combined_stdout) {
                    return (
                        1,
                        String::new(),
                        format!("[!] Failed to write output file '{path}': {io_err}\n"),
                    );
                }
            }

            let code = if any_open { 0 } else { 2 };
            (code, combined_stdout, String::new())
        }
        Err(err_msg) => (1, String::new(), format!("[!] {err_msg}\n")),
    }
}

/// Split an interactive command line into tokens, supporting quoted strings and stripping
/// an optional leading `tcpscan` / `hxscan` / `./tcpscan` command prefix.
pub fn parse_interactive_line(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quote: Option<char> = None;

    for ch in line.trim().chars() {
        match in_quote {
            Some(q) if ch == q => {
                in_quote = None;
            }
            Some(_) => current.push(ch),
            None if ch == '"' || ch == '\'' => {
                in_quote = Some(ch);
            }
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            None => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    if let Some(first) = tokens.first().map(|s| s.to_ascii_lowercase()) {
        let basename = first.rsplit(&['/', '\\'][..]).next().unwrap_or(&first);
        if matches!(
            basename,
            "tcpscan" | "tcpscan.exe" | "hxscan" | "hxscan.exe"
        ) {
            tokens.remove(0);
        }
    }

    tokens
}

/// Format the interactive console welcome header in the selected [`Language`].
pub fn format_interactive_welcome(lang: Language, use_color: bool) -> String {
    let logo = render_ascii_banner(lang, use_color);
    match lang {
        Language::English => format!(
            "{logo}
==============================================================================
  TCPSCAN / HXSCAN-RUST v3.0.0 — Interactive Console Mode [Language: EN]
==============================================================================
  Authorized security auditing only. Type a target or command below:
  • Press [ENTER] during any running scan to view real-time % progress & ETA.
  • Type 'lang es' (or 'es') to switch to Spanish | 'lang en' for English.

  Examples:
    127.0.0.1                           (Scan default critical ports on localhost)
    127.0.0.1 -sV -A                    (Full Audit + CPE/CVE + Nmap handoff cmd)
    scanme.nmap.org 22,80,443           (Scan official Nmap public test host)
    example.com:443                     (Inspect TLS 1.2 / X.509 certificate)
    192.168.1.1-5 --top-ports 20        (Scan IP range on top 20 ports)
    10.0.0.1 --stealth                  (Low-noise jittered scan)
    10.0.0.1 --mutable                  (Corporate workstation persona)
    lang es                             (Cambiar idioma a Español)
    help                                (Show full CLI flags & options)
    exit                                (Close console)
------------------------------------------------------------------------------
"
        ),
        Language::Spanish => format!(
            "{logo}
==============================================================================
  TCPSCAN / HXSCAN-RUST v3.0.0 — Modo Consola Interactiva [Idioma: ES]
==============================================================================
  Solo para auditorías de seguridad autorizadas. Escribe un objetivo o comando:
  • Presiona [ENTER] durante un escaneo para ver el % de avance y ETA en vivo.
  • Escribe 'lang en' (o 'en') para Inglés | 'lang es' (o 'es') para Español.

  Ejemplos:
    127.0.0.1                           (Escanear puertos críticos en localhost)
    127.0.0.1 -sV -A                    (Auditoría total + CPE/CVE + comando Nmap)
    scanme.nmap.org 22,80,443           (Escanear host público de prueba de Nmap)
    example.com:443                     (Inspeccionar certificado TLS 1.2 / X.509)
    192.168.1.1-5 --top-ports 20        (Escanear rango IP en el top 20 de puertos)
    10.0.0.1 --stealth                  (Modo sigiloso con jitter anti-IDS)
    10.0.0.1 --mutable                  (Camuflaje de estación corporativa)
    lang en                             (Switch language to English)
    ayuda                               (Ver todas las opciones y flags CLI)
    salir                               (Cerrar consola)
------------------------------------------------------------------------------
"
        ),
    }
}

/// Interactive console mode launched when `tcpscan.exe` is opened without arguments
/// (e.g. double-clicked on Windows Explorer) so the terminal window stays open.
pub fn run_interactive_shell() -> i32 {
    use std::io::{self, Write};

    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let mut shell_lang = Language::Spanish;

    let welcome = format_interactive_welcome(shell_lang, true);
    let _ = stdout.write_all(welcome.as_bytes());
    let _ = stdout.flush();

    let mut last_exit_code = 0;
    let rx_mutex = global_stdin_receiver();

    loop {
        let prompt = match shell_lang {
            Language::English => "\ntcpscan [EN]> ",
            Language::Spanish => "\ntcpscan [ES]> ",
        };
        let _ = stdout.write_all(prompt.as_bytes());
        let _ = stdout.flush();

        let line = match rx_mutex.lock().ok().and_then(|rx| rx.recv().ok()) {
            Some(s) => s,
            None => break, // EOF
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match trimmed.to_ascii_lowercase().as_str() {
            "exit" | "quit" | "q" | "salir" => break,
            "es" | "esp" | "spanish" | "espanol" | "español" | "lang es" | "idioma es" => {
                shell_lang = Language::Spanish;
                let msg = format_interactive_welcome(shell_lang, true);
                let _ = stdout.write_all(msg.as_bytes());
                let _ = stdout.flush();
                continue;
            }
            "en" | "eng" | "english" | "ingles" | "inglés" | "lang en" | "idioma en" => {
                shell_lang = Language::English;
                let msg = format_interactive_welcome(shell_lang, true);
                let _ = stdout.write_all(msg.as_bytes());
                let _ = stdout.flush();
                continue;
            }
            "help" | "ayuda" | "?" => {
                let flag = match shell_lang {
                    Language::English => "--help",
                    Language::Spanish => "--help-es",
                };
                let (_, help_out, _) = run_from_args([flag]);
                let _ = stdout.write_all(help_out.as_bytes());
                let _ = stdout.flush();
                continue;
            }
            "version" | "ver" => {
                let (_, ver_out, _) = run_from_args(["--version"]);
                let _ = stdout.write_all(ver_out.as_bytes());
                let _ = stdout.flush();
                continue;
            }
            "cls" | "clear" | "limpiar" => {
                let _ = stdout.write_all(b"\x1b[2J\x1b[H");
                let _ = stdout.flush();
                continue;
            }
            _ => {}
        }

        let mut tokens = parse_interactive_line(trimmed);
        if tokens.is_empty() {
            continue;
        }

        let has_explicit_lang = tokens.iter().any(|t| {
            matches!(
                t.as_str(),
                "--es"
                    | "-es"
                    | "--spanish"
                    | "--espanol"
                    | "--en"
                    | "-en"
                    | "--english"
                    | "--ingles"
                    | "--lang"
                    | "-L"
                    | "--help-es"
            )
        });
        if !has_explicit_lang && shell_lang == Language::Spanish {
            tokens.push("--es".to_string());
        }

        let (code, out_str, err_str) = run_from_args(&tokens);
        last_exit_code = code;

        if !err_str.is_empty() {
            let _ = stderr.write_all(err_str.as_bytes());
            let _ = stderr.flush();
        }
        if !out_str.is_empty() {
            let _ = stdout.write_all(out_str.as_bytes());
            let _ = stdout.flush();
        }
    }

    last_exit_code
}

#[cfg(test)]
mod interactive_tests {
    use super::*;

    #[test]
    fn test_parse_interactive_line_handles_prefixes_and_quotes() {
        assert_eq!(
            parse_interactive_line("127.0.0.1 22,80,443 --stealth"),
            vec!["127.0.0.1", "22,80,443", "--stealth"]
        );
        assert_eq!(
            parse_interactive_line("tcpscan 10.0.0.1 -p \"22, 80, 443\""),
            vec!["10.0.0.1", "-p", "22, 80, 443"]
        );
        assert_eq!(
            parse_interactive_line("hxscan.exe scanme.nmap.org"),
            vec!["scanme.nmap.org"]
        );
        assert_eq!(
            parse_interactive_line(
                "C:\\Users\\Cutu\\.cargo\\bin\\tcpscan.exe 127.0.0.1 -p 22,8080 -A"
            ),
            vec!["127.0.0.1", "-p", "22,8080", "-A"]
        );
    }

    #[test]
    fn test_format_interactive_welcome_bilingual_and_banner() {
        let es = format_interactive_welcome(Language::Spanish, false);
        assert!(es.contains("Modo Consola Interactiva [Idioma: ES]"));
        assert!(es.contains("lang en"));
        assert!(es.contains("Motor Definitivo de Recon Hibrido"));

        let en = format_interactive_welcome(Language::English, false);
        assert!(en.contains("Interactive Console Mode [Language: EN]"));
        assert!(en.contains("lang es"));
        assert!(en.contains("Ultimate Recon & Hybrid Attack-Path Engine"));
    }
}
