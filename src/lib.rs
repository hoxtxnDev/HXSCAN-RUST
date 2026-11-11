//! # `tcpscan` (HXSCAN-RUST v2.0 — Mediator Pattern Architecture)
//!
//! High-performance, zero-dependency, staged modular TCP port scanner and
//! cybersecurity auditing toolkit built around the **Mediator Design Pattern**
//! (also known as *Intermediary* or *Controller*).
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

pub use cli::{
    parse_cli_args, CliAction, ScanProfile, MAX_DELAY_MS, MAX_RETRIES, MAX_SAFE_THREADS,
    MAX_TIMEOUT_SECS, MIN_TIMEOUT_SECS,
};
pub use mediator::{
    AddressScope, AuditedPortResult, ComponentId, EnrichedPortResult, MediatedEventRecord,
    MediatorDirective, MediatorState, OutputFormat, PipelineConfig, PipelineOutput, PortState,
    RawProbeResult, ReportOptions, RiskLevel, ScanController, ScanEvent, ScanMediator,
    ScannerConfig, SecurityPostureSummary, TargetInfo,
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
pub use stages::stage4_audit::{evaluate_port_security, execute_audit_stage, AuditColleague};
pub use stages::stage5_report::{render_report, sanitize_csv_cell, ReportColleague};
pub use stages::ScanPipeline;

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
