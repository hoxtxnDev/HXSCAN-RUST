//! # Stage 5 Colleague: `ReportColleague` (`stage5_report`)
//!
//! Concrete Colleague in the **Mediator Pattern** responsible for:
//! 1. Rendering the audited results mediated by [`ScanController`] into `Human` (ANSI table),
//!    `Json` (SIEM/SOAR), or `Csv` format.
//! 2. Emitting [`ScanEvent::ReportRendered`] back to the [`ScanController`] Mediator.
//!
//! **Decoupling Guarantee**: Zero imports from `stage1`, `stage2`, `stage3`, or `stage4`.

use std::fmt::Write as FmtWrite;
use std::time::Duration;

use crate::mediator::{
    AuditedPortResult, ComponentId, MediatorDirective, OutputFormat, PortState, ReportOptions,
    RiskLevel, ScanController, ScanEvent, ScanMediator, SecurityPostureSummary, TargetInfo,
};

/// **Colleague 5 (`ReportColleague`)**: Multi-Format Telemetry & Reporting Colleague.
pub struct ReportColleague;

impl ReportColleague {
    /// Render the final report from the Mediator's state and emit [`ScanEvent::ReportRendered`].
    pub fn run(mediator: &mut ScanController, elapsed: Duration) -> MediatorDirective {
        let target = mediator
            .target
            .as_ref()
            .expect("TargetInfo must be present before ReportColleague runs");
        let summary = mediator
            .summary
            .as_ref()
            .expect("SecurityPostureSummary must be present before ReportColleague runs");

        let formatted_report = render_report(
            target,
            &mediator.audited_results,
            summary,
            elapsed,
            &mediator.config.report_options,
        );

        mediator.notify(
            ComponentId::ReportColleague,
            ScanEvent::ReportRendered { formatted_report },
        )
    }
}

/// Render the complete Stage 5 report as a `String`.
pub fn render_report(
    target: &TargetInfo,
    results: &[AuditedPortResult],
    summary: &SecurityPostureSummary,
    elapsed: Duration,
    options: &ReportOptions,
) -> String {
    match options.format {
        OutputFormat::Human => render_human_report(target, results, summary, elapsed, options),
        OutputFormat::Json => render_json_report(target, results, summary, elapsed),
        OutputFormat::Csv => render_csv_report(target, results),
    }
}

fn colorize(text: &str, ansi_code: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{ansi_code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn risk_badge(risk: RiskLevel, use_color: bool) -> String {
    let padded = format!("{:<8}", risk.as_str());
    match risk {
        RiskLevel::Critical => colorize(&padded, "1;31", use_color),
        RiskLevel::High => colorize(&padded, "31", use_color),
        RiskLevel::Medium => colorize(&padded, "33", use_color),
        RiskLevel::Low => colorize(&padded, "36", use_color),
        RiskLevel::Info => colorize(&padded, "32", use_color),
        RiskLevel::None => colorize(&padded, "90", use_color),
    }
}

fn state_badge(state: &PortState, use_color: bool) -> String {
    let padded = format!("{:<10}", state.as_str());
    match state {
        PortState::Open => colorize(&padded, "1;32", use_color),
        PortState::Closed => colorize(&padded, "90", use_color),
        PortState::Filtered => colorize(&padded, "33", use_color),
        PortState::Error(_) => colorize(&padded, "31", use_color),
    }
}

fn render_human_report(
    target: &TargetInfo,
    results: &[AuditedPortResult],
    summary: &SecurityPostureSummary,
    elapsed: Duration,
    options: &ReportOptions,
) -> String {
    let mut out = String::with_capacity(2048);
    let c = options.use_color;
    let sep = "=".repeat(78);
    let subsep = "-".repeat(78);

    let elapsed_secs = elapsed.as_secs_f64();
    let rate = if elapsed_secs > 0.0 {
        (summary.total_scanned as f64) / elapsed_secs
    } else {
        summary.total_scanned as f64
    };

    let _ = writeln!(out, "\n{sep}");
    if target.raw_input != target.primary_ip.to_string() {
        let _ = writeln!(
            out,
            "{} — {} ({}) [Scope: {}]",
            colorize("TCPSCAN / HXSCAN v2.0 Audit Report", "1;36", c),
            target.raw_input,
            target.primary_ip,
            target.scope
        );
    } else {
        let _ = writeln!(
            out,
            "{} — {} [Scope: {}]",
            colorize("TCPSCAN / HXSCAN v2.0 Audit Report", "1;36", c),
            target.primary_ip,
            target.scope
        );
    }
    let _ = writeln!(
        out,
        "Duration: {:.2}ms | Throughput: {:.0} ports/s | Firewall Drop Detected: {}",
        elapsed.as_secs_f64() * 1000.0,
        rate,
        if summary.firewall_detected { "Yes" } else { "No" }
    );
    let _ = writeln!(out, "{sep}");

    let open_ports: Vec<&AuditedPortResult> = results
        .iter()
        .filter(|r| r.state == PortState::Open)
        .collect();

    if open_ports.is_empty() && !options.show_closed {
        let _ = writeln!(out, "No open ports found.");
    } else {
        let _ = writeln!(
            out,
            "\n{:<8} {:<10} {:<10} {:<16} {:<8} {}",
            "Port", "State", "RTT", "Service", "Risk", "Banner / Details"
        );
        let _ = writeln!(out, "{subsep}");

        for r in &open_ports {
            let rtt_str = r
                .rtt_ms()
                .map(|ms| format!("{ms:.2}ms"))
                .unwrap_or_else(|| "-".to_string());
            let detail = r.banner.as_deref().unwrap_or(r.category);
            let _ = writeln!(
                out,
                "{:<8} {} {:<10} {:<16} {} {}",
                r.port,
                state_badge(&r.state, c),
                rtt_str,
                r.service,
                risk_badge(r.risk, c),
                detail
            );
        }

        if options.show_closed {
            for r in results.iter().filter(|r| r.state != PortState::Open) {
                let rtt_str = r
                    .rtt_ms()
                    .map(|ms| format!("{ms:.2}ms"))
                    .unwrap_or_else(|| "-".to_string());
                let detail = r.banner.as_deref().unwrap_or(r.category);
                let _ = writeln!(
                    out,
                    "{:<8} {} {:<10} {:<16} {} {}",
                    r.port,
                    state_badge(&r.state, c),
                    rtt_str,
                    r.service,
                    risk_badge(r.risk, c),
                    detail
                );
            }
        }
    }

    if !open_ports.is_empty() {
        let _ = writeln!(
            out,
            "\n{}",
            colorize("[Security Audit & Hardening Advisories]", "1;33", c)
        );
        for r in &open_ports {
            if !r.advisory.is_empty() {
                let _ = writeln!(
                    out,
                    "  • Port {:<5} ({}): [{}] {}",
                    r.port, r.service, r.risk, r.advisory
                );
            }
        }
    }

    let _ = writeln!(
        out,
        "\nScanned: {} port(s) | Open: {} | Closed: {} | Filtered: {} | Posture Grade: {} (Score: {}/100)",
        summary.total_scanned,
        summary.open_count,
        summary.closed_count,
        summary.filtered_count,
        summary.posture_grade,
        summary.exposure_score
    );
    let _ = writeln!(out, "{sep}\n");

    out
}

fn escape_json_str(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len() + 4);
    for ch in s.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(escaped, "\\u{:04x}", c as u32);
            }
            c => escaped.push(c),
        }
    }
    escaped
}

fn render_json_report(
    target: &TargetInfo,
    results: &[AuditedPortResult],
    summary: &SecurityPostureSummary,
    elapsed: Duration,
) -> String {
    let mut out = String::with_capacity(2048);
    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "  \"scanner\": \"tcpscan-rs\",");
    let _ = writeln!(out, "  \"version\": \"2.0.0\",");
    let _ = writeln!(out, "  \"pattern\": \"Mediator\",");
    let _ = writeln!(
        out,
        "  \"target\": {{ \"input\": \"{}\", \"ip\": \"{}\", \"scope\": \"{}\" }},",
        escape_json_str(&target.raw_input),
        target.primary_ip,
        target.scope
    );
    let _ = writeln!(
        out,
        "  \"duration_ms\": {:.3},",
        elapsed.as_secs_f64() * 1000.0
    );
    let _ = writeln!(
        out,
        "  \"summary\": {{ \"total_scanned\": {}, \"open\": {}, \"closed\": {}, \"filtered\": {}, \"errors\": {}, \"critical\": {}, \"high\": {}, \"medium\": {}, \"exposure_score\": {}, \"posture_grade\": \"{}\", \"firewall_detected\": {} }},",
        summary.total_scanned,
        summary.open_count,
        summary.closed_count,
        summary.filtered_count,
        summary.error_count,
        summary.critical_count,
        summary.high_count,
        summary.medium_count,
        summary.exposure_score,
        summary.posture_grade,
        summary.firewall_detected
    );
    let _ = writeln!(out, "  \"ports\": [");

    for (idx, r) in results.iter().enumerate() {
        let comma = if idx + 1 < results.len() { "," } else { "" };
        let banner_json = match r.banner {
            Some(ref b) => format!("\"{}\"", escape_json_str(b)),
            None => "null".to_string(),
        };
        let rtt_json = match r.rtt_ms() {
            Some(ms) => format!("{ms:.3}"),
            None => "null".to_string(),
        };
        let _ = writeln!(
            out,
            "    {{ \"port\": {}, \"state\": \"{}\", \"service\": \"{}\", \"risk\": \"{}\", \"category\": \"{}\", \"rtt_ms\": {}, \"banner\": {}, \"advisory\": \"{}\" }}{}",
            r.port,
            r.state.as_str(),
            escape_json_str(&r.service),
            r.risk.as_str(),
            escape_json_str(r.category),
            rtt_json,
            banner_json,
            escape_json_str(&r.advisory),
            comma
        );
    }

    let _ = writeln!(out, "  ]");
    let _ = writeln!(out, "}}");
    out
}

/// Neutralize CSV Formula Injection (CWE-1236) and apply RFC-4180 double-quote escaping
/// so malicious remote banners (`=cmd|...`, `+`, `-`, `@`) cannot execute formulas in Excel/Calc
/// on the auditor's originating machine.
pub fn sanitize_csv_cell(input: &str) -> String {
    let trimmed = input.trim_start();
    let needs_formula_prefix = trimmed.starts_with('=')
        || trimmed.starts_with('+')
        || trimmed.starts_with('-')
        || trimmed.starts_with('@')
        || trimmed.starts_with('|')
        || input.starts_with('\t')
        || input.starts_with('\r');

    let escaped = input.replace('"', "\"\"");
    if needs_formula_prefix {
        format!("\"'{}\"", escaped)
    } else {
        format!("\"{}\"", escaped)
    }
}

fn render_csv_report(target: &TargetInfo, results: &[AuditedPortResult]) -> String {
    let mut out =
        String::from("target,ip,port,state,service,risk,category,rtt_ms,banner,advisory\n");
    for r in results {
        let rtt = r
            .rtt_ms()
            .map(|ms| format!("{ms:.3}"))
            .unwrap_or_default();
        let banner_cell = sanitize_csv_cell(r.banner.as_deref().unwrap_or(""));
        let adv_cell = sanitize_csv_cell(&r.advisory);
        let target_cell = sanitize_csv_cell(&target.raw_input);
        let service_cell = sanitize_csv_cell(&r.service);
        let category_cell = sanitize_csv_cell(r.category);
        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},{}",
            target_cell,
            target.primary_ip,
            r.port,
            r.state.as_str(),
            service_cell,
            r.risk.as_str(),
            category_cell,
            rtt,
            banner_cell,
            adv_cell
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediator::AddressScope;

    fn sample_target() -> TargetInfo {
        TargetInfo {
            raw_input: "127.0.0.1".to_string(),
            primary_ip: "127.0.0.1".parse().unwrap(),
            all_ips: vec!["127.0.0.1".parse().unwrap()],
            scope: AddressScope::Loopback,
            inline_port: None,
        }
    }

    fn sample_summary(open_count: usize, closed_count: usize) -> SecurityPostureSummary {
        SecurityPostureSummary {
            total_scanned: open_count + closed_count,
            open_count,
            closed_count,
            filtered_count: 0,
            error_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            exposure_score: 5,
            posture_grade: 'B',
            firewall_detected: false,
        }
    }

    #[test]
    fn test_human_report_hides_closed_ports_by_default() {
        let target = sample_target();
        let audited = vec![
            AuditedPortResult {
                port: 22,
                state: PortState::Open,
                service: "SSH".to_string(),
                banner: None,
                rtt_micros: Some(400),
                risk: RiskLevel::Low,
                category: "Remote Access",
                advisory: "Verify key auth".to_string(),
            },
            AuditedPortResult {
                port: 80,
                state: PortState::Closed,
                service: "unknown".to_string(),
                banner: None,
                rtt_micros: Some(100),
                risk: RiskLevel::None,
                category: "Closed",
                advisory: String::new(),
            },
        ];
        let summary = sample_summary(1, 1);
        let opts = ReportOptions {
            format: OutputFormat::Human,
            show_closed: false,
            use_color: false,
        };
        let text = render_report(&target, &audited, &summary, Duration::from_millis(12), &opts);
        assert!(text.contains("22"));
        assert!(text.contains("SSH"));
        assert!(!text.contains("80       closed"));
        assert!(text.contains("Scanned: 2 port(s) | Open: 1"));
    }

    #[test]
    fn test_json_report_contains_valid_structure() {
        let target = sample_target();
        let audited = vec![AuditedPortResult {
            port: 443,
            state: PortState::Open,
            service: "HTTPS".to_string(),
            banner: None,
            rtt_micros: Some(300),
            risk: RiskLevel::Info,
            category: "TLS Encrypted Service",
            advisory: "Verify TLS".to_string(),
        }];
        let summary = sample_summary(1, 0);
        let opts = ReportOptions {
            format: OutputFormat::Json,
            show_closed: false,
            use_color: false,
        };
        let json = render_report(&target, &audited, &summary, Duration::from_millis(5), &opts);
        assert!(json.contains("\"scanner\": \"tcpscan-rs\""));
        assert!(json.contains("\"pattern\": \"Mediator\""));
        assert!(json.contains("\"port\": 443"));
        assert!(json.contains("\"service\": \"HTTPS\""));
        assert!(json.contains("\"open\": 1"));
    }
}
