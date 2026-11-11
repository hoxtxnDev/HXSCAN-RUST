//! # `tcpscan` (HXSCAN-RUST v2.2 — Mediator Pattern Architecture)
//!
//! High-performance, zero-dependency, staged modular TCP port scanner and
//! cybersecurity auditing toolkit built around the **Mediator Design Pattern**
//! (also known as *Intermediary* or *Controller*).
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
    parse_cli_args, CliAction, ScanProfile, MAX_BURST_PAUSE_MS, MAX_BURST_SIZE, MAX_DECOY_PROBES,
    MAX_DELAY_MS, MAX_JITTER_MS, MAX_PPS, MAX_RETRIES, MAX_SAFE_THREADS, MAX_TIMEOUT_SECS,
    MIN_TIMEOUT_SECS,
};
pub use mediator::{
    AddressScope, AuditedPortResult, ComponentId, EnrichedPortResult, HoneypotAssessment,
    HoneypotBehavior, HoneypotVerdict, MediatedEventRecord, MediatorDirective, MediatorState,
    OutputFormat, PipelineConfig, PipelineOutput, PortState, RawProbeResult, ReportOptions,
    RiskLevel, ScanController, ScanEvent, ScanMediator, ScannerConfig, SecurityPostureSummary,
    StealthConfig, StealthMode, StealthTelemetry, TargetInfo, TlsCertificateInfo, TrafficPersona,
};
pub use stages::stage1_discovery::{
    parse_port_spec, resolve_target, shuffle_ports, validate_ip_safety, DiscoveryColleague,
    DiscoveryError,
};
pub use stages::stage2_scanner::{
    classify_connect_error, execute_scan_stage, execute_scan_stage_with_prober, probe_single_port,
    ScannerColleague,
};
pub use stages::stage3_fingerprint::{
    enrich_probe_results, get_service_name, grab_banner_from_rw, grab_banner_from_stream,
    infer_service_from_banner, sanitize_banner, FingerprintColleague, SERVICE_TABLE,
};
pub use stages::stage4_honeypot::{analyze_honeypots, evaluate_honeypot_port, HoneypotColleague};
pub use stages::stage5_audit::{
    evaluate_port_security, evaluate_port_security_with_honeypot, execute_audit_stage,
    execute_audit_stage_with_honeypots, AuditColleague,
};
pub use stages::stage6_report::{
    render_report, render_report_with_stealth, sanitize_csv_cell, ReportColleague,
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
            let controller = ScanController::new(config);
            match controller.execute() {
                Ok(output) => {
                    let code = output.exit_code();
                    (code, output.formatted_report, String::new())
                }
                Err(err) => (1, String::new(), format!("[!] {err}\n")),
            }
        }
        Err(err_msg) => (1, String::new(), format!("[!] {err_msg}\n")),
    }
}
