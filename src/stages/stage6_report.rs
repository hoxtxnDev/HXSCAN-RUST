//! # Stage 6 Colleague: `ReportColleague` (`stage6_report`)
//!
//! Concrete Colleague in the **Mediator Pattern** responsible for:
//! 1. Rendering the audited results mediated by [`ScanController`] into `Human` (ANSI table),
//!    `Json` (SIEM/SOAR), or `Csv` format.
//! 2. Including stealth/anti-AI legitimacy telemetry and per-port honeypot behavior verdicts.
//! 3. Emitting [`ScanEvent::ReportRendered`] back to the [`ScanController`] Mediator.
//!
//! **Decoupling Guarantee**: Zero imports from `stage1`, `stage2`, `stage3`, `stage4` or `stage5`.

use std::fmt::Write as FmtWrite;
use std::time::Duration;

use crate::mediator::{
    AuditedPortResult, ComponentId, HoneypotVerdict, MediatorDirective, OutputFormat, PortState,
    ReportOptions, RiskLevel, ScanController, ScanEvent, ScanMediator, SecurityPostureSummary,
    StealthTelemetry, TargetInfo,
};

/// **Colleague 6 (`ReportColleague`)**: Multi-Format Telemetry & Reporting Colleague.
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
        let stealth = mediator.stealth_telemetry.clone().unwrap_or_default();

        let formatted_report = render_report_with_stealth(
            target,
            &mediator.audited_results,
            summary,
            elapsed,
            &mediator.config.report_options,
            &stealth,
        );

        mediator.notify(
            ComponentId::ReportColleague,
            ScanEvent::ReportRendered { formatted_report },
        )
    }
}

/// Backward-compatible report renderer (uses neutral stealth telemetry).
pub fn render_report(
    target: &TargetInfo,
    results: &[AuditedPortResult],
    summary: &SecurityPostureSummary,
    elapsed: Duration,
    options: &ReportOptions,
) -> String {
    render_report_with_stealth(
        target,
        results,
        summary,
        elapsed,
        options,
        &StealthTelemetry::default(),
    )
}

/// Render the complete Stage 6 report with stealth/anti-AI telemetry.
pub fn render_report_with_stealth(
    target: &TargetInfo,
    results: &[AuditedPortResult],
    summary: &SecurityPostureSummary,
    elapsed: Duration,
    options: &ReportOptions,
    stealth: &StealthTelemetry,
) -> String {
    match options.format {
        OutputFormat::Human => {
            render_human_report(target, results, summary, elapsed, options, stealth)
        }
        OutputFormat::Json => render_json_report(target, results, summary, elapsed, stealth),
        OutputFormat::Csv => render_csv_report(target, results),
        OutputFormat::Grepable => render_grepable_report(target, results, summary),
        OutputFormat::Silent => render_silent_report(target, results),
    }
}

/// Build a honeypot-filtered Nmap follow-up command (`nmap -sV -sC -p <clean_ports> <ip>`)
/// excluding any open port flagged as `PossibleHoneypot` or `Honeypot` by Stage 4.
/// Never executes an external process; returns only the command string for the operator.
pub fn build_clean_nmap_command(
    target: &TargetInfo,
    results: &[AuditedPortResult],
) -> Option<String> {
    let clean_ports: Vec<String> = results
        .iter()
        .filter(|r| r.state == PortState::Open && !r.honeypot.is_suspicious())
        .map(|r| r.port.to_string())
        .collect();
    if clean_ports.is_empty() {
        None
    } else {
        Some(format!(
            "nmap -sV -sC -p {} {}",
            clean_ports.join(","),
            target.primary_ip
        ))
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

fn honeypot_badge(verdict: HoneypotVerdict, use_color: bool) -> String {
    let padded = format!("{:<10}", verdict.badge());
    match verdict {
        HoneypotVerdict::Clean => colorize(&padded, "90", use_color),
        HoneypotVerdict::PossibleHoneypot => colorize(&padded, "33", use_color),
        HoneypotVerdict::Honeypot => colorize(&padded, "1;35", use_color),
    }
}

fn render_human_report(
    target: &TargetInfo,
    results: &[AuditedPortResult],
    summary: &SecurityPostureSummary,
    elapsed: Duration,
    options: &ReportOptions,
    stealth: &StealthTelemetry,
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
            colorize("TCPSCAN / HXSCAN v3.0 Audit Report", "1;36", c),
            target.raw_input,
            target.primary_ip,
            target.scope
        );
    } else {
        let _ = writeln!(
            out,
            "{} — {} [Scope: {}]",
            colorize("TCPSCAN / HXSCAN v3.0 Audit Report", "1;36", c),
            target.primary_ip,
            target.scope
        );
    }
    let _ = writeln!(
        out,
        "Duration: {:.2}ms | Throughput: {:.0} ports/s | Firewall Drop Detected: {}",
        elapsed.as_secs_f64() * 1000.0,
        rate,
        if summary.firewall_detected {
            "Yes"
        } else {
            "No"
        }
    );
    let os_suffix = summary
        .os_hint
        .as_deref()
        .map(|os| format!(" | OS Hint: {os}"))
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "Mode: {} | Persona: {} | AI-Filter: {} | Legitimacy: {}/100 ({}){}",
        stealth.mode,
        stealth.persona,
        if stealth.ai_filter { "on" } else { "off" },
        stealth.legitimacy_score,
        stealth.legitimacy_grade,
        os_suffix
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
            "\n{:<8} {:<10} {:<10} {:<16} {:<18} {:<8} {:<10} {}",
            "Port", "State", "RTT", "Service", "Version", "Risk", "Honeypot", "Banner / Details"
        );
        let _ = writeln!(out, "{subsep}");

        for r in &open_ports {
            let rtt_str = r
                .rtt_ms()
                .map(|ms| format!("{ms:.2}ms"))
                .unwrap_or_else(|| "-".to_string());
            let version_str = r.service_version.as_deref().unwrap_or("-");
            let detail = r.banner.as_deref().unwrap_or(r.category);
            let _ = writeln!(
                out,
                "{:<8} {} {:<10} {:<16} {:<18} {} {} {}",
                r.port,
                state_badge(&r.state, c),
                rtt_str,
                r.service,
                version_str,
                risk_badge(r.risk, c),
                honeypot_badge(r.honeypot.verdict, c),
                detail
            );
        }

        if options.show_closed {
            for r in results.iter().filter(|r| r.state != PortState::Open) {
                let rtt_str = r
                    .rtt_ms()
                    .map(|ms| format!("{ms:.2}ms"))
                    .unwrap_or_else(|| "-".to_string());
                let version_str = r.service_version.as_deref().unwrap_or("-");
                let detail = r.banner.as_deref().unwrap_or(r.category);
                let _ = writeln!(
                    out,
                    "{:<8} {} {:<10} {:<16} {:<18} {} {} {}",
                    r.port,
                    state_badge(&r.state, c),
                    rtt_str,
                    r.service,
                    version_str,
                    risk_badge(r.risk, c),
                    honeypot_badge(r.honeypot.verdict, c),
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

    let tls_ports: Vec<&AuditedPortResult> = results.iter().filter(|r| r.tls.is_some()).collect();
    if !tls_ports.is_empty() {
        let _ = writeln!(
            out,
            "\n{}",
            colorize("[TLS Certificate Intelligence]", "1;36", c)
        );
        for r in &tls_ports {
            if let Some(ref tls) = r.tls {
                let expiry = match (tls.not_after.as_deref(), tls.days_until_expiry) {
                    (Some(date), Some(days)) => format!("{date} ({days}d)"),
                    (Some(date), None) => date.to_string(),
                    _ => "unknown".to_string(),
                };
                let sans = if tls.sans.is_empty() {
                    "-".to_string()
                } else {
                    tls.sans
                        .iter()
                        .take(4)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let _ = writeln!(
                    out,
                    "  • Port {:<5} CN={} | issuer={} | expires={} | self-signed={} | SANs={} | chain={}",
                    r.port,
                    tls.identity(),
                    tls.issuer_cn.as_deref().unwrap_or("-"),
                    expiry,
                    if tls.self_signed { "yes" } else { "no" },
                    sans,
                    tls.chain_length
                );
                if tls.hostname_mismatch {
                    let _ = writeln!(out, "    certificate does not match the requested hostname");
                }
            }
        }
    }

    let cpe_ports: Vec<&AuditedPortResult> = results
        .iter()
        .filter(|r| r.state == PortState::Open && (r.cpe.is_some() || !r.cves.is_empty()))
        .collect();
    if !cpe_ports.is_empty() {
        let _ = writeln!(
            out,
            "\n{}",
            colorize("[CPE & Vulnerability Intelligence (CVE)]", "1;31", c)
        );
        for r in &cpe_ports {
            let cpe_str = r.cpe.as_deref().unwrap_or("-");
            let cve_str = if r.cves.is_empty() {
                "none".to_string()
            } else {
                r.cves.join(", ")
            };
            let _ = writeln!(
                out,
                "  • Port {:<5} ({}): CPE={} | CVEs={}",
                r.port, r.service, cpe_str, cve_str
            );
        }
    }

    let suspicious: Vec<&AuditedPortResult> = results
        .iter()
        .filter(|r| r.honeypot.is_suspicious())
        .collect();
    let suspicious_count = suspicious.len();
    let _ = writeln!(
        out,
        "\n{}",
        colorize("[Honeypot & Deception Behavior Analysis]", "1;35", c)
    );
    if suspicious.is_empty() {
        let _ = writeln!(out, "  No deception indicators detected.");
    } else {
        for r in suspicious {
            let _ = writeln!(
                out,
                "  • Port {:<5} ({}): {} {}/100 — {}",
                r.port,
                r.service,
                r.honeypot.verdict.badge(),
                r.honeypot.score,
                r.honeypot.behavior_summary()
            );
            if !r.honeypot.notes.is_empty() {
                let _ = writeln!(out, "    {}", r.honeypot.notes);
            }
        }
    }

    if options.show_nmap_cmd {
        let _ = writeln!(
            out,
            "\n{}",
            colorize("[Honeypot-Filtered Nmap Handoff Command]", "1;32", c)
        );
        match build_clean_nmap_command(target, results) {
            Some(cmd) => {
                let _ = writeln!(
                    out,
                    "  • {}  (excluded {} suspected honeypot port(s))",
                    cmd, suspicious_count
                );
            }
            None => {
                let _ = writeln!(
                    out,
                    "  • No clean non-honeypot open ports available for Nmap handoff."
                );
            }
        }
    }

    let _ = writeln!(
        out,
        "\nScanned: {} port(s) | Open: {} | Closed: {} | Filtered: {} | Honeypots: {} confirmed / {} possible | Posture Grade: {} (Score: {}/100)",
        summary.total_scanned,
        summary.open_count,
        summary.closed_count,
        summary.filtered_count,
        summary.confirmed_honeypot_count,
        summary.possible_honeypot_count,
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

fn json_optional_string(value: Option<&str>) -> String {
    match value {
        Some(text) => format!("\"{}\"", escape_json_str(text)),
        None => "null".to_string(),
    }
}

fn render_json_report(
    target: &TargetInfo,
    results: &[AuditedPortResult],
    summary: &SecurityPostureSummary,
    elapsed: Duration,
    stealth: &StealthTelemetry,
) -> String {
    let mut out = String::with_capacity(2048);
    let nmap_cmd = build_clean_nmap_command(target, results);
    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "  \"scanner\": \"tcpscan-rs\",");
    let _ = writeln!(out, "  \"version\": \"3.0.0\",");
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
        "  \"nmap_command\": {},",
        json_optional_string(nmap_cmd.as_deref())
    );
    let _ = writeln!(
        out,
        "  \"stealth\": {{ \"mode\": \"{}\", \"persona\": \"{}\", \"ai_filter\": {}, \"max_pps\": {}, \"jitter_ms\": {}, \"burst_size\": {}, \"burst_pause_ms\": {}, \"decoy_probes\": {}, \"adaptive_backoff\": {}, \"filtered_ratio_pct\": {}, \"legitimacy_score\": {}, \"legitimacy_grade\": \"{}\" }},",
        stealth.mode.as_str(),
        stealth.persona.as_str(),
        stealth.ai_filter,
        stealth.max_pps,
        stealth.jitter_ms,
        stealth.burst_size,
        stealth.burst_pause_ms,
        stealth.decoy_probes,
        stealth.adaptive_backoff,
        stealth.filtered_ratio_pct,
        stealth.legitimacy_score,
        stealth.legitimacy_grade
    );
    let _ = writeln!(
        out,
        "  \"summary\": {{ \"total_scanned\": {}, \"open\": {}, \"closed\": {}, \"filtered\": {}, \"errors\": {}, \"critical\": {}, \"high\": {}, \"medium\": {}, \"exposure_score\": {}, \"posture_grade\": \"{}\", \"firewall_detected\": {}, \"possible_honeypots\": {}, \"confirmed_honeypots\": {}, \"os_hint\": {} }},",
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
        summary.firewall_detected,
        summary.possible_honeypot_count,
        summary.confirmed_honeypot_count,
        json_optional_string(summary.os_hint.as_deref())
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
        let behaviors_json = r
            .honeypot
            .behaviors
            .iter()
            .map(|behavior| format!("\"{}\"", behavior.as_str()))
            .collect::<Vec<_>>()
            .join(",");
        let honeypot_json = format!(
            "{{ \"verdict\": \"{}\", \"score\": {}, \"behaviors\": [{}], \"notes\": \"{}\" }}",
            r.honeypot.verdict.as_str(),
            r.honeypot.score,
            behaviors_json,
            escape_json_str(&r.honeypot.notes)
        );
        let version_json = json_optional_string(r.service_version.as_deref());
        let cpe_json = json_optional_string(r.cpe.as_deref());
        let cves_json = r
            .cves
            .iter()
            .map(|cve| format!("\"{}\"", escape_json_str(cve)))
            .collect::<Vec<_>>()
            .join(",");
        let tls_json = match r.tls.as_ref() {
            Some(tls) => {
                let sans_json = tls
                    .sans
                    .iter()
                    .map(|san| format!("\"{}\"", escape_json_str(san)))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "{{ \"subject_cn\": {}, \"issuer_cn\": {}, \"sans\": [{}], \"not_after\": {}, \"days_until_expiry\": {}, \"self_signed\": {}, \"hostname_mismatch\": {}, \"chain_length\": {} }}",
                    json_optional_string(tls.subject_cn.as_deref()),
                    json_optional_string(tls.issuer_cn.as_deref()),
                    sans_json,
                    json_optional_string(tls.not_after.as_deref()),
                    tls.days_until_expiry
                        .map(|days| days.to_string())
                        .unwrap_or_else(|| "null".to_string()),
                    tls.self_signed,
                    tls.hostname_mismatch,
                    tls.chain_length
                )
            }
            None => "null".to_string(),
        };
        let _ = writeln!(
            out,
            "    {{ \"port\": {}, \"state\": \"{}\", \"service\": \"{}\", \"service_version\": {}, \"cpe\": {}, \"cves\": [{}], \"risk\": \"{}\", \"category\": \"{}\", \"rtt_ms\": {}, \"banner\": {}, \"advisory\": \"{}\", \"tls\": {}, \"honeypot\": {} }}{}",
            r.port,
            r.state.as_str(),
            escape_json_str(&r.service),
            version_json,
            cpe_json,
            cves_json,
            r.risk.as_str(),
            escape_json_str(r.category),
            rtt_json,
            banner_json,
            escape_json_str(&r.advisory),
            tls_json,
            honeypot_json,
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
    let mut out = String::from(
        "target,ip,port,state,service,service_version,risk,category,rtt_ms,banner,advisory,tls_subject_cn,tls_issuer_cn,tls_self_signed,tls_hostname_mismatch,tls_days_until_expiry,tls_not_after,tls_sans,honeypot_verdict,honeypot_score,honeypot_behaviors,cpe,cves\n",
    );
    for r in results {
        let rtt = r.rtt_ms().map(|ms| format!("{ms:.3}")).unwrap_or_default();
        let banner_cell = sanitize_csv_cell(r.banner.as_deref().unwrap_or(""));
        let adv_cell = sanitize_csv_cell(&r.advisory);
        let target_cell = sanitize_csv_cell(&target.raw_input);
        let service_cell = sanitize_csv_cell(&r.service);
        let version_cell = sanitize_csv_cell(r.service_version.as_deref().unwrap_or(""));
        let category_cell = sanitize_csv_cell(r.category);
        let honeypot_behaviors = sanitize_csv_cell(&r.honeypot.behavior_summary());
        let cpe_cell = sanitize_csv_cell(r.cpe.as_deref().unwrap_or(""));
        let cves_cell = sanitize_csv_cell(&r.cves.join("; "));
        let (tls_subject, tls_issuer, tls_self, tls_mismatch, tls_days, tls_not_after, tls_sans) =
            match r.tls.as_ref() {
                Some(tls) => (
                    sanitize_csv_cell(tls.subject_cn.as_deref().unwrap_or("")),
                    sanitize_csv_cell(tls.issuer_cn.as_deref().unwrap_or("")),
                    if tls.self_signed {
                        "true".to_string()
                    } else {
                        "false".to_string()
                    },
                    if tls.hostname_mismatch {
                        "true".to_string()
                    } else {
                        "false".to_string()
                    },
                    tls.days_until_expiry
                        .map(|days| days.to_string())
                        .unwrap_or_default(),
                    sanitize_csv_cell(tls.not_after.as_deref().unwrap_or("")),
                    sanitize_csv_cell(&tls.sans.join("; ")),
                ),
                None => (
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ),
            };
        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            target_cell,
            target.primary_ip,
            r.port,
            r.state.as_str(),
            service_cell,
            version_cell,
            r.risk.as_str(),
            category_cell,
            rtt,
            banner_cell,
            adv_cell,
            tls_subject,
            tls_issuer,
            tls_self,
            tls_mismatch,
            tls_days,
            tls_not_after,
            tls_sans,
            r.honeypot.verdict.as_str(),
            r.honeypot.score,
            honeypot_behaviors,
            cpe_cell,
            cves_cell
        );
    }
    out
}

fn render_grepable_report(
    target: &TargetInfo,
    results: &[AuditedPortResult],
    summary: &SecurityPostureSummary,
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# tcpscan 3.0.0 grepable report for {} ({})",
        target.raw_input, target.primary_ip
    );
    let ports_desc: Vec<String> = results
        .iter()
        .filter(|r| r.state == PortState::Open)
        .map(|r| {
            format!(
                "{}/open/tcp//{}/{}/{}",
                r.port,
                r.service,
                r.service_version.as_deref().unwrap_or(""),
                r.honeypot.verdict.as_str()
            )
        })
        .collect();
    let _ = writeln!(
        out,
        "Host: {} ({})\tStatus: Up\tPorts: {}\tIgnored State: closed ({}) filtered ({})",
        target.primary_ip,
        target.raw_input,
        ports_desc.join(", "),
        summary.closed_count,
        summary.filtered_count
    );
    out
}

fn render_silent_report(target: &TargetInfo, results: &[AuditedPortResult]) -> String {
    let mut out = String::new();
    for r in results
        .iter()
        .filter(|r| r.state == PortState::Open && !r.honeypot.is_suspicious())
    {
        let _ = writeln!(out, "{}:{}", target.primary_ip, r.port);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediator::{AddressScope, HoneypotAssessment};

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
            possible_honeypot_count: 0,
            confirmed_honeypot_count: 0,
            os_hint: None,
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
                service_version: Some("OpenSSH_9.7p1".to_string()),
                cpe: Some("cpe:2.3:a:openbsd:openssh:9.7p1:*:*:*:*:*:*:*".to_string()),
                cves: vec!["CVE-2024-6387".to_string()],
                banner: None,
                rtt_micros: Some(400),
                risk: RiskLevel::Low,
                category: "Remote Access",
                advisory: "Verify key auth".to_string(),
                tls: None,
                honeypot: HoneypotAssessment::clean(22),
            },
            AuditedPortResult {
                port: 80,
                state: PortState::Closed,
                service: "unknown".to_string(),
                service_version: None,
                cpe: None,
                cves: Vec::new(),
                banner: None,
                rtt_micros: Some(100),
                risk: RiskLevel::None,
                category: "Closed",
                advisory: String::new(),
                tls: None,
                honeypot: HoneypotAssessment::clean(80),
            },
        ];
        let summary = sample_summary(1, 1);
        let opts = ReportOptions {
            format: OutputFormat::Human,
            show_closed: false,
            use_color: false,
            show_nmap_cmd: true,
        };
        let text = render_report(
            &target,
            &audited,
            &summary,
            Duration::from_millis(12),
            &opts,
        );
        assert!(text.contains("22"));
        assert!(text.contains("SSH"));
        assert!(!text.contains("80       closed"));
        assert!(text.contains("Scanned: 2 port(s) | Open: 1"));
        assert!(text.contains("CVE-2024-6387"));
        assert!(text.contains("nmap -sV -sC -p 22 127.0.0.1"));
    }

    #[test]
    fn test_json_report_contains_valid_structure() {
        let target = sample_target();
        let audited = vec![AuditedPortResult {
            port: 443,
            state: PortState::Open,
            service: "HTTPS".to_string(),
            service_version: None,
            cpe: None,
            cves: Vec::new(),
            banner: None,
            rtt_micros: Some(300),
            risk: RiskLevel::Info,
            category: "TLS Encrypted Service",
            advisory: "Verify TLS".to_string(),
            tls: Some(crate::mediator::TlsCertificateInfo {
                subject_cn: Some("portal.example.test".to_string()),
                issuer_cn: Some("Test CA".to_string()),
                sans: vec!["portal.example.test".to_string()],
                not_after: Some("301231235959Z".to_string()),
                days_until_expiry: Some(1_000),
                self_signed: false,
                hostname_mismatch: false,
                chain_length: 2,
            }),
            honeypot: HoneypotAssessment::clean(443),
        }];
        let summary = sample_summary(1, 0);
        let opts = ReportOptions {
            format: OutputFormat::Json,
            show_closed: false,
            use_color: false,
            show_nmap_cmd: false,
        };
        let json = render_report(&target, &audited, &summary, Duration::from_millis(5), &opts);
        assert!(json.contains("\"scanner\": \"tcpscan-rs\""));
        assert!(json.contains("\"pattern\": \"Mediator\""));
        assert!(json.contains("\"port\": 443"));
        assert!(json.contains("\"service\": \"HTTPS\""));
        assert!(json.contains("\"open\": 1"));
        assert!(json.contains("\"service_version\": null"));
        assert!(json.contains("\"subject_cn\": \"portal.example.test\""));
        assert!(json.contains("\"issuer_cn\": \"Test CA\""));
        assert!(json.contains("\"days_until_expiry\": 1000"));
        assert!(json.contains("\"self_signed\": false"));
        assert!(json.contains("\"chain_length\": 2"));
    }

    #[test]
    fn test_human_report_renders_tls_section_and_version_column() {
        let target = sample_target();
        let audited = vec![AuditedPortResult {
            port: 443,
            state: PortState::Open,
            service: "HTTPS".to_string(),
            service_version: Some("nginx/1.26.2".to_string()),
            cpe: None,
            cves: Vec::new(),
            banner: None,
            rtt_micros: Some(300),
            risk: RiskLevel::Info,
            category: "TLS Encrypted Service",
            advisory: "Verify TLS".to_string(),
            tls: Some(crate::mediator::TlsCertificateInfo {
                subject_cn: Some("portal.example.test".to_string()),
                issuer_cn: Some("Test CA".to_string()),
                sans: vec!["portal.example.test".to_string()],
                not_after: Some("301231235959Z".to_string()),
                days_until_expiry: Some(1_000),
                self_signed: true,
                hostname_mismatch: true,
                chain_length: 2,
            }),
            honeypot: HoneypotAssessment::clean(443),
        }];
        let summary = sample_summary(1, 0);
        let opts = ReportOptions {
            format: OutputFormat::Human,
            show_closed: false,
            use_color: false,
            show_nmap_cmd: false,
        };
        let text = render_report(
            &target,
            &audited,
            &summary,
            Duration::from_millis(12),
            &opts,
        );
        assert!(text.contains("Version"));
        assert!(text.contains("nginx/1.26.2"));
        assert!(text.contains("[TLS Certificate Intelligence]"));
        assert!(text.contains("portal.example.test"));
        assert!(text.contains("self-signed=yes"));
        assert!(text.contains("does not match the requested hostname"));
    }

    #[test]
    fn test_csv_report_contains_tls_columns() {
        let target = sample_target();
        let audited = vec![AuditedPortResult {
            port: 443,
            state: PortState::Open,
            service: "HTTPS".to_string(),
            service_version: Some("nginx/1.26.2".to_string()),
            cpe: Some("cpe:2.3:a:f5:nginx:1.26.2:*:*:*:*:*:*:*".to_string()),
            cves: Vec::new(),
            banner: None,
            rtt_micros: Some(300),
            risk: RiskLevel::Info,
            category: "TLS Encrypted Service",
            advisory: "Verify TLS".to_string(),
            tls: Some(crate::mediator::TlsCertificateInfo {
                subject_cn: Some("portal.example.test".to_string()),
                issuer_cn: Some("Test CA".to_string()),
                sans: vec![
                    "portal.example.test".to_string(),
                    "www.example.test".to_string(),
                ],
                not_after: Some("301231235959Z".to_string()),
                days_until_expiry: Some(1_000),
                self_signed: false,
                hostname_mismatch: false,
                chain_length: 2,
            }),
            honeypot: HoneypotAssessment::clean(443),
        }];
        let summary = sample_summary(1, 0);
        let opts = ReportOptions {
            format: OutputFormat::Csv,
            show_closed: false,
            use_color: false,
            show_nmap_cmd: false,
        };
        let csv = render_report(&target, &audited, &summary, Duration::from_millis(5), &opts);
        let header = csv.lines().next().unwrap();
        assert!(header.contains("service_version"));
        assert!(header.contains("tls_subject_cn"));
        assert!(header.contains("tls_self_signed"));
        assert!(header.contains("tls_sans"));
        assert!(header.contains("cpe,cves"));
        assert!(csv.contains("\"portal.example.test\""));
        assert!(csv.contains("\"portal.example.test; www.example.test\""));
        assert!(csv.contains(",\"nginx/1.26.2\","));
        assert!(csv.contains(",false,false,1000,"));
    }

    #[test]
    fn test_nmap_handoff_filters_out_honeypots_and_silent_mode() {
        let target = sample_target();
        let audited = vec![
            AuditedPortResult {
                port: 22,
                state: PortState::Open,
                service: "SSH".to_string(),
                service_version: Some("OpenSSH 9.6p1".to_string()),
                cpe: None,
                cves: Vec::new(),
                banner: None,
                rtt_micros: Some(300),
                risk: RiskLevel::Low,
                category: "Remote Access",
                advisory: String::new(),
                tls: None,
                honeypot: HoneypotAssessment::clean(22),
            },
            AuditedPortResult {
                port: 2222,
                state: PortState::Open,
                service: "SSH".to_string(),
                service_version: None,
                cpe: None,
                cves: Vec::new(),
                banner: None,
                rtt_micros: Some(500),
                risk: RiskLevel::Low,
                category: "Remote Access",
                advisory: String::new(),
                tls: None,
                honeypot: HoneypotAssessment {
                    port: 2222,
                    verdict: HoneypotVerdict::Honeypot,
                    score: 85,
                    behaviors: Vec::new(),
                    notes: "Cowrie".to_string(),
                },
            },
        ];
        let cmd = build_clean_nmap_command(&target, &audited).unwrap();
        assert_eq!(cmd, "nmap -sV -sC -p 22 127.0.0.1");

        let silent = render_silent_report(&target, &audited);
        assert_eq!(silent, "127.0.0.1:22\n");
    }
}
