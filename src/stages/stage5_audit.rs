//! # Stage 5 Colleague: `AuditColleague` (`stage5_audit`)
//!
//! Concrete Colleague in the **Mediator Pattern** responsible for:
//! 1. Assigning a [`RiskLevel`] (`None`, `Info`, `Low`, `Medium`, `High`, `Critical`) based on
//!    protocol cleartext exposure, lateral-movement potential, database exposure, network scope
//!    (`Public` vs `Loopback`), and active banner indicators.
//! 2. Attaching the Stage 4 [`HoneypotAssessment`] to every audited port and counting
//!    possible/confirmed deception verdicts in the [`SecurityPostureSummary`].
//! 3. Emitting immediate [`ScanEvent::CriticalFindingDetected`] notifications to the [`ScanController`]
//!    Mediator whenever a `Critical` risk exposure is identified.
//! 4. Emitting [`ScanEvent::AuditCompleted`] with the [`SecurityPostureSummary`] (`0..=100` score & grade `A`–`F`).
//!
//! **Decoupling Guarantee**: Zero imports from `stage1`, `stage2`, `stage3`, `stage4` or `stage6`.

use crate::mediator::{
    AddressScope, AuditedPortResult, ComponentId, EnrichedPortResult, HoneypotAssessment,
    HoneypotVerdict, MediatorDirective, MediatorState, PortState, ReconIntelligence, RiskLevel,
    ScanController, ScanEvent, ScanMediator, SecurityPostureSummary,
};

/// **Colleague 5 (`AuditColleague`)**: Cybersecurity Risk & Attack Surface Audit Colleague.
pub struct AuditColleague;

impl AuditColleague {
    /// Evaluate all enriched port results from the Mediator, emit [`ScanEvent::CriticalFindingDetected`]
    /// for each critical finding, and finish with [`ScanEvent::AuditCompleted`].
    pub fn run(mediator: &mut ScanController) -> MediatorDirective {
        mediator.transition_to(MediatorState::Auditing);
        let scope = mediator
            .target
            .as_ref()
            .map(|t| t.scope)
            .unwrap_or(AddressScope::Private);
        let target_raw = mediator
            .target
            .as_ref()
            .map(|t| t.raw_input.clone())
            .unwrap_or_default();
        let enriched = std::mem::take(&mut mediator.enriched_results);
        let (audited_results, mut summary) =
            execute_audit_stage_with_honeypots(enriched, scope, &mediator.honeypot_assessments);
        summary.recon =
            synthesize_recon_intelligence(&target_raw, &audited_results, summary.filtered_count);

        // Notify the Mediator immediately for each critical security finding
        for item in &audited_results {
            if item.state == PortState::Open && item.risk == RiskLevel::Critical {
                mediator.notify(
                    ComponentId::AuditColleague,
                    ScanEvent::CriticalFindingDetected {
                        port: item.port,
                        service: item.service.clone(),
                        advisory: item.advisory.clone(),
                    },
                );
            }
        }

        mediator.notify(
            ComponentId::AuditColleague,
            ScanEvent::AuditCompleted {
                audited_results,
                summary,
            },
        )
    }
}

/// Evaluate a single [`EnrichedPortResult`] in the context of the target's [`AddressScope`].
pub fn evaluate_port_security(item: EnrichedPortResult, scope: AddressScope) -> AuditedPortResult {
    let honeypot = HoneypotAssessment::clean(item.port);
    evaluate_port_security_with_honeypot(item, scope, honeypot)
}

/// Evaluate an [`EnrichedPortResult`] and attach its Stage 4 deception assessment.
pub fn evaluate_port_security_with_honeypot(
    item: EnrichedPortResult,
    scope: AddressScope,
    honeypot: HoneypotAssessment,
) -> AuditedPortResult {
    if item.state != PortState::Open {
        let (category, advisory) = match item.state {
            PortState::Filtered => (
                "Packet Filtered",
                "Probe timed out; likely protected by stateful firewall or ACL".to_string(),
            ),
            PortState::Closed => ("Closed", String::new()),
            PortState::Error(ref e) => ("Probe Error", e.clone()),
            PortState::Open => unreachable!(),
        };

        return AuditedPortResult {
            port: item.port,
            state: item.state,
            service: item.service,
            service_version: item.service_version,
            cpe: None,
            cves: Vec::new(),
            banner: item.banner,
            rtt_micros: item.rtt_micros,
            risk: RiskLevel::None,
            category,
            advisory,
            tls: item.tls,
            honeypot,
        };
    }

    let (mut risk, category, mut advisory) = classify_open_port(item.port, &item.service);

    if scope == AddressScope::Public && risk == RiskLevel::High {
        risk = RiskLevel::Critical;
        advisory.push_str(" [PUBLIC INTERNET EXPOSURE]");
    }

    if let Some(ref banner) = item.banner {
        let upper = banner.to_ascii_uppercase();
        if upper.starts_with("+PONG") {
            risk = RiskLevel::Critical;
            advisory =
                "Unauthenticated Redis instance (+PONG); enforce requirepass & bind 127.0.0.1"
                    .to_string();
        } else if upper.contains("VSFTPD 2.3.4") {
            risk = RiskLevel::Critical;
            advisory = "Backdoored vsFTPd 2.3.4 banner detected (CVE-2011-2523)!".to_string();
        } else if upper.contains("OPENSSH_5.") || upper.contains("OPENSSH_6.") {
            if risk < RiskLevel::High {
                risk = RiskLevel::High;
            }
            advisory.push_str(" (Legacy OpenSSH version disclosed in banner)");
        } else if upper.contains("SERVER:") || upper.starts_with("SSH-") {
            advisory.push_str(" (Service version disclosed in banner)");
        }
    }

    let cpe = build_cpe23(
        &item.service,
        item.service_version.as_deref(),
        item.banner.as_deref(),
    );
    let cves = correlate_cves(
        item.port,
        &item.service,
        item.service_version.as_deref(),
        item.banner.as_deref(),
    );
    if !cves.is_empty() {
        if cves.iter().any(|c| {
            c == "CVE-2024-6387"
                || c == "CVE-2011-2523"
                || c == "CVE-2021-41773"
                || c == "CVE-2021-42013"
                || c == "CVE-2015-3306"
                || c == "CVE-2019-10149"
        }) {
            risk = RiskLevel::Critical;
        } else if risk < RiskLevel::High {
            risk = RiskLevel::High;
        }
        let joined = cves.join(", ");
        if !advisory.contains(&joined) {
            advisory.push_str(&format!(" [Vuln Intel: {joined}]"));
        }
    }

    if let Some(ref tls) = item.tls {
        if tls.self_signed {
            advisory.push_str(" [self-signed certificate]");
        }
        if tls.hostname_mismatch {
            advisory.push_str(" [certificate/hostname mismatch]");
        }
        if tls.is_expired() {
            advisory.push_str(" [expired certificate]");
        }
    }

    AuditedPortResult {
        port: item.port,
        state: item.state,
        service: item.service,
        service_version: item.service_version,
        cpe,
        cves,
        banner: item.banner,
        rtt_micros: item.rtt_micros,
        risk,
        category,
        advisory,
        tls: item.tls,
        honeypot,
    }
}

/// Build an NVD-compatible CPE 2.3 identifier (`cpe:2.3:a:vendor:product:version:...`)
/// from extracted service/version or raw banner metadata.
pub fn build_cpe23(
    service: &str,
    service_version: Option<&str>,
    banner: Option<&str>,
) -> Option<String> {
    let combined = service_version.or(banner)?;
    let lower = combined.to_ascii_lowercase();

    let (vendor, product, raw_ver) = if lower.contains("openssh") {
        (
            "openbsd",
            "openssh",
            extract_version_after(&lower, "openssh"),
        )
    } else if lower.contains("nginx") {
        ("f5", "nginx", extract_version_after(&lower, "nginx"))
    } else if lower.contains("apache") {
        (
            "apache",
            "http_server",
            extract_version_after(&lower, "apache"),
        )
    } else if lower.contains("vsftpd") {
        (
            "vsftpd_project",
            "vsftpd",
            extract_version_after(&lower, "vsftpd"),
        )
    } else if lower.contains("proftpd") {
        (
            "proftpd",
            "proftpd",
            extract_version_after(&lower, "proftpd"),
        )
    } else if lower.contains("postfix") {
        (
            "postfix",
            "postfix",
            extract_version_after(&lower, "postfix"),
        )
    } else if lower.contains("exim") {
        ("exim", "exim", extract_version_after(&lower, "exim"))
    } else if lower.contains("dovecot") {
        (
            "dovecot",
            "dovecot",
            extract_version_after(&lower, "dovecot"),
        )
    } else if lower.contains("mariadb") {
        (
            "mariadb",
            "mariadb",
            extract_version_after(&lower, "mariadb"),
        )
    } else if lower.contains("mysql") {
        ("oracle", "mysql", extract_version_after(&lower, "mysql"))
    } else if lower.contains("redis") {
        ("redis", "redis", extract_version_after(&lower, "redis"))
    } else if lower.contains("microsoft-iis") || lower.contains("iis/") {
        (
            "microsoft",
            "internet_information_services",
            extract_version_after(&lower, "iis"),
        )
    } else if lower.contains("caddy") {
        (
            "caddyserver",
            "caddy",
            extract_version_after(&lower, "caddy"),
        )
    } else if service.eq_ignore_ascii_case("SSH") && lower.starts_with("ssh-2.0-") {
        ("ietf", "ssh", Some("*".to_string()))
    } else {
        return None;
    };

    let ver = raw_ver.unwrap_or_else(|| "*".to_string());
    Some(format!("cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"))
}

fn extract_version_after(haystack_lower: &str, token: &str) -> Option<String> {
    let idx = haystack_lower.find(token)?;
    let rest = &haystack_lower[idx + token.len()..];
    let trimmed = rest.trim_start_matches(&[' ', '/', '_', '-', ':'][..]);
    let ver: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .collect();
    let ver = ver.trim_matches(&['.', '-'][..]);
    if ver
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        Some(ver.to_string())
    } else {
        None
    }
}

/// Passively correlate extracted service version and banner strings against high-impact
/// CVEs and CWEs for defensive posture reporting (zero active exploitation).
pub fn correlate_cves(
    port: u16,
    service: &str,
    service_version: Option<&str>,
    banner: Option<&str>,
) -> Vec<String> {
    let mut out = Vec::new();
    let combined = format!(
        "{} {} {}",
        service,
        service_version.unwrap_or(""),
        banner.unwrap_or("")
    )
    .to_ascii_lowercase();

    if combined.contains("vsftpd 2.3.4") || combined.contains("vsftpd/2.3.4") {
        out.push("CVE-2011-2523".to_string());
    }

    if let Some(ssh_ver) = extract_version_after(&combined, "openssh") {
        if is_openssh_regresshion_vulnerable(&ssh_ver) {
            out.push("CVE-2024-6387".to_string());
        } else if ssh_ver.starts_with("5.")
            || ssh_ver.starts_with("6.")
            || ssh_ver.starts_with("7.0")
            || ssh_ver.starts_with("7.1")
            || ssh_ver.starts_with("7.2")
        {
            out.push("CVE-2016-0777".to_string());
        }
    }

    if combined.contains("apache/2.4.49") || combined.contains("apache 2.4.49") {
        out.push("CVE-2021-41773".to_string());
    }
    if combined.contains("apache/2.4.50") || combined.contains("apache 2.4.50") {
        out.push("CVE-2021-42013".to_string());
    }
    if combined.contains("proftpd 1.3.5") || combined.contains("proftpd/1.3.5") {
        out.push("CVE-2015-3306".to_string());
    }
    if combined.contains("exim 4.87")
        || combined.contains("exim 4.88")
        || combined.contains("exim 4.89")
        || combined.contains("exim 4.90")
        || combined.contains("exim 4.91")
    {
        out.push("CVE-2019-10149".to_string());
    }

    if banner
        .map(|b| b.to_ascii_uppercase().starts_with("+PONG"))
        .unwrap_or(false)
        || port == 2375
    {
        out.push("CWE-306".to_string());
    }

    out
}

fn is_openssh_regresshion_vulnerable(ver: &str) -> bool {
    // OpenSSH 8.5p1 <= ver < 9.8p1 (CVE-2024-6387 regreSSHion)
    let numeric: String = ver
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut parts = numeric.split('.');
    let major = match parts.next().and_then(|s| s.parse::<u32>().ok()) {
        Some(v) => v,
        None => return false,
    };
    let minor = match parts.next().and_then(|s| s.parse::<u32>().ok()) {
        Some(v) => v,
        None => return false,
    };
    (major == 8 && (5..=9).contains(&minor)) || (major == 9 && minor <= 6)
}

/// Passively infer the target Operating System family from service banners and open port profiles.
pub fn infer_os_hint(audited: &[AuditedPortResult]) -> Option<String> {
    let mut has_windows_ports = false;
    let mut has_ssh = false;

    for item in audited.iter().filter(|r| r.state == PortState::Open) {
        if let Some(ref banner) = item.banner {
            let lower = banner.to_ascii_lowercase();
            if lower.contains("ubuntu") {
                return Some("Linux (Ubuntu)".to_string());
            }
            if lower.contains("debian") {
                return Some("Linux (Debian)".to_string());
            }
            if lower.contains("freebsd") {
                return Some("FreeBSD".to_string());
            }
            if lower.contains("centos") || lower.contains("red hat") || lower.contains("rhel") {
                return Some("Linux (RHEL/CentOS)".to_string());
            }
            if lower.contains("alpine") {
                return Some("Linux (Alpine)".to_string());
            }
            if lower.contains("microsoft-iis") || lower.contains("windows") {
                return Some("Microsoft Windows".to_string());
            }
        }
        if matches!(item.port, 135 | 139 | 445 | 3389 | 5985 | 5986) {
            has_windows_ports = true;
        }
        if item.port == 22 || item.service.eq_ignore_ascii_case("SSH") {
            has_ssh = true;
        }
    }

    if has_windows_ports {
        Some("Microsoft Windows (SMB/RPC/RDP port profile)".to_string())
    } else if has_ssh {
        Some("Linux / Unix-like (SSH service profile)".to_string())
    } else {
        None
    }
}

fn classify_open_port(port: u16, service: &str) -> (RiskLevel, &'static str, String) {
    match port {
        23 => (
            RiskLevel::Critical,
            "Cleartext Legacy",
            "Telnet transmits credentials in cleartext; disable and replace with SSH".to_string(),
        ),
        2375 => (
            RiskLevel::Critical,
            "Container Control Plane",
            "Unencrypted Docker API socket allows root host takeover; restrict or enforce TLS (2376)"
                .to_string(),
        ),
        2379 | 10250 => (
            RiskLevel::Critical,
            "Cluster Control Plane",
            "Exposed Kubernetes/Etcd control port; verify mTLS and RBAC restrictions".to_string(),
        ),
        445 | 139 | 135 => (
            RiskLevel::High,
            "Lateral Movement / SMB-RPC",
            "High-value Windows lateral movement vector; block external access & enforce SMB signing"
                .to_string(),
        ),
        3389 | 5900 | 5901 | 5985 => (
            RiskLevel::High,
            "Remote Desktop / WinRM",
            "Interactive remote administration exposed; place behind VPN/Zero-Trust & enforce MFA/NLA"
                .to_string(),
        ),
        21 | 20 | 69 | 873 => (
            RiskLevel::High,
            "Cleartext File Transfer",
            "Unencrypted file transfer service; disable anonymous access and migrate to SFTP/SCP"
                .to_string(),
        ),
        1433 | 1521 | 3306 | 5432 | 6379 | 9042 | 9200 | 11211 | 27017 => (
            RiskLevel::High,
            "Data Store Exposure",
            "Database/cache port directly reachable; restrict to application subnet & verify authentication"
                .to_string(),
        ),
        111 | 2049 => (
            RiskLevel::High,
            "Network File System",
            "RPC/NFS exposure can leak host shares; restrict export ACLs and firewall port 111/2049"
                .to_string(),
        ),
        22 => (
            RiskLevel::Low,
            "Remote Access",
            "Verify key-based auth, disable RootLogin/PasswordAuth, and rate-limit brute force"
                .to_string(),
        ),
        80 | 3000 | 5000 | 5601 | 8000 | 8080 | 8888 | 9090 => (
            RiskLevel::Medium,
            "Cleartext Web / API",
            "Unencrypted HTTP endpoint; enforce HTTPS redirection, HSTS, and review exposed endpoints"
                .to_string(),
        ),
        25 | 110 | 143 | 389 => (
            RiskLevel::Medium,
            "Cleartext Mail / Directory",
            "Cleartext protocol; enforce STARTTLS or migrate to implicit TLS (465/993/995/636)"
                .to_string(),
        ),
        443 | 465 | 636 | 853 | 993 | 995 | 2376 | 5986 | 6443 | 8443 | 8883 | 9443 => (
            RiskLevel::Info,
            "TLS Encrypted Service",
            "Verify TLS 1.2+/1.3 cipher suites, certificate validity, and endpoint authentication"
                .to_string(),
        ),
        53 | 88 | 123 => (
            RiskLevel::Low,
            "Core Network Infrastructure",
            "Ensure recursion/zone-transfers (AXFR) are restricted to authorized clients"
                .to_string(),
        ),
        _ => {
            if service.eq_ignore_ascii_case("SSH") {
                (
                    RiskLevel::Low,
                    "Remote Access (Non-Std Port)",
                    "SSH on non-standard port; enforce public-key authentication".to_string(),
                )
            } else if service.eq_ignore_ascii_case("HTTP") {
                (
                    RiskLevel::Medium,
                    "Cleartext Web (Non-Std Port)",
                    "HTTP service on custom port; verify authentication and TLS termination"
                        .to_string(),
                )
            } else {
                (
                    RiskLevel::Medium,
                    "Unclassified Open Port",
                    "Inspect running daemon, verify business necessity, and restrict via host firewall"
                        .to_string(),
                )
            }
        }
    }
}

/// Run Stage 5 audit across all enriched port results and compute the [`SecurityPostureSummary`].
pub fn execute_audit_stage(
    enriched: Vec<EnrichedPortResult>,
    scope: AddressScope,
) -> (Vec<AuditedPortResult>, SecurityPostureSummary) {
    execute_audit_stage_with_honeypots(enriched, scope, &[])
}

/// Run Stage 5 audit attaching Stage 4 honeypot assessments by port.
pub fn execute_audit_stage_with_honeypots(
    enriched: Vec<EnrichedPortResult>,
    scope: AddressScope,
    honeypots: &[HoneypotAssessment],
) -> (Vec<AuditedPortResult>, SecurityPostureSummary) {
    let total_scanned = enriched.len();
    let mut open_count = 0usize;
    let mut closed_count = 0usize;
    let mut filtered_count = 0usize;
    let mut error_count = 0usize;
    let mut critical_count = 0usize;
    let mut high_count = 0usize;
    let mut medium_count = 0usize;
    let mut possible_honeypot_count = 0usize;
    let mut confirmed_honeypot_count = 0usize;
    let mut raw_risk_points = 0u32;

    let audited: Vec<AuditedPortResult> = enriched
        .into_iter()
        .enumerate()
        .map(|(idx, item)| {
            let assessment = honeypots
                .get(idx)
                .filter(|assessment| assessment.port == item.port)
                .cloned()
                .or_else(|| {
                    honeypots
                        .binary_search_by_key(&item.port, |assessment| assessment.port)
                        .ok()
                        .map(|pos| honeypots[pos].clone())
                })
                .or_else(|| {
                    honeypots
                        .iter()
                        .find(|assessment| assessment.port == item.port)
                        .cloned()
                })
                .unwrap_or_else(|| HoneypotAssessment::clean(item.port));
            let res = evaluate_port_security_with_honeypot(item, scope, assessment);
            match res.state {
                PortState::Open => {
                    open_count += 1;
                    raw_risk_points = raw_risk_points.saturating_add(res.risk.weight());
                    match res.risk {
                        RiskLevel::Critical => critical_count += 1,
                        RiskLevel::High => high_count += 1,
                        RiskLevel::Medium => medium_count += 1,
                        _ => {}
                    }
                    match res.honeypot.verdict {
                        HoneypotVerdict::PossibleHoneypot => possible_honeypot_count += 1,
                        HoneypotVerdict::Honeypot => confirmed_honeypot_count += 1,
                        HoneypotVerdict::Clean => {}
                    }
                }
                PortState::Closed => closed_count += 1,
                PortState::Filtered => filtered_count += 1,
                PortState::Error(_) => error_count += 1,
            }
            res
        })
        .collect();

    let exposure_score = raw_risk_points.min(100) as u8;
    let posture_grade = if critical_count > 0 || exposure_score >= 75 {
        'F'
    } else if high_count > 0 || exposure_score >= 45 {
        'D'
    } else if medium_count > 1 || exposure_score >= 20 {
        'C'
    } else if open_count > 0 {
        'B'
    } else {
        'A'
    };

    let os_hint = infer_os_hint(&audited);
    let recon = synthesize_recon_intelligence("", &audited, filtered_count);

    let summary = SecurityPostureSummary {
        total_scanned,
        open_count,
        closed_count,
        filtered_count,
        error_count,
        critical_count,
        high_count,
        medium_count,
        exposure_score,
        posture_grade,
        firewall_detected: filtered_count > 0,
        possible_honeypot_count,
        confirmed_honeypot_count,
        os_hint,
        recon,
    };

    (audited, summary)
}

/// Synthesize multi-port Hybrid Reconnaissance Intelligence across all audited ports:
/// 1. Architectural Host Role (`host_role`)
/// 2. Network Proximity & Reverse-Proxy / DNAT RTT Split Detection (`network_topology`, `rtt_split_anomaly`)
/// 3. Shadow-Asset / Subdomain Pivot Extraction from X.509 SANs & Banners (`shadow_assets`)
/// 4. Cross-Port Toxic Exposure Combinations (`toxic_combinations`)
pub fn synthesize_recon_intelligence(
    target_input: &str,
    audited: &[AuditedPortResult],
    filtered_count: usize,
) -> ReconIntelligence {
    let host_role = infer_host_role(audited, filtered_count);
    let (network_topology, rtt_split_anomaly) = analyze_rtt_topology(audited);
    let shadow_assets = extract_shadow_assets(target_input, audited);
    let toxic_combinations = detect_toxic_combinations(audited);

    ReconIntelligence {
        host_role,
        network_topology,
        rtt_split_anomaly,
        shadow_assets,
        toxic_combinations,
    }
}

/// Infer the target host's architectural role from its clean (non-honeypot) open port profile.
pub fn infer_host_role(audited: &[AuditedPortResult], filtered_count: usize) -> String {
    let open_any: Vec<&AuditedPortResult> = audited
        .iter()
        .filter(|r| r.state == PortState::Open)
        .collect();
    if open_any.is_empty() {
        return "No Exposed TCP Services".to_string();
    }

    let clean_ports: Vec<u16> = open_any
        .iter()
        .filter(|r| !r.honeypot.is_suspicious())
        .map(|r| r.port)
        .collect();

    if clean_ports.is_empty() {
        return "Dedicated Deception Host / Honeypot Node".to_string();
    }

    let has = |p: u16| clean_ports.contains(&p);
    let has_any = |list: &[u16]| list.iter().any(|p| clean_ports.contains(p));

    if has(88) && has_any(&[53, 389, 445, 636]) {
        "Active Directory Domain Controller".to_string()
    } else if has_any(&[2375, 2376, 2379, 6443, 10250]) {
        "Container / Kubernetes Control Node".to_string()
    } else if has_any(&[80, 443, 3000, 5000, 8000, 8080, 8443, 8888])
        && has_any(&[1433, 1521, 3306, 5432, 6379, 9042, 9200, 11211, 27017])
    {
        "Web + Database Monolith (Co-Resident Stack)".to_string()
    } else if has_any(&[25, 465, 587]) && has_any(&[110, 143, 993, 995]) {
        "Mail Gateway / Groupware Server".to_string()
    } else if has_any(&[135, 139, 445]) && has_any(&[3389, 5985, 5986]) {
        "Windows Server / Admin Workstation".to_string()
    } else if clean_ports.len() == 1 && has(22) && filtered_count > 0 {
        "Hardened Bastion / SSH Jump Host".to_string()
    } else if has_any(&[80, 443, 3000, 5000, 8000, 8080, 8443, 8888]) {
        "Web / API Application Server".to_string()
    } else if has_any(&[1433, 1521, 3306, 5432, 6379, 9042, 9200, 11211, 27017]) {
        "Dedicated Database / Cache Node".to_string()
    } else {
        "General Network Service Host".to_string()
    }
}

/// Detect multi-port toxic combinations where co-resident services on the same host
/// create compound attack paths (e.g., SSRF-to-DB, Windows Lateral Movement Triad).
pub fn detect_toxic_combinations(audited: &[AuditedPortResult]) -> Vec<String> {
    let clean_ports: Vec<u16> = audited
        .iter()
        .filter(|r| r.state == PortState::Open && !r.honeypot.is_suspicious())
        .map(|r| r.port)
        .collect();
    let has_any = |list: &[u16]| list.iter().any(|p| clean_ports.contains(p));
    let mut combos = Vec::new();

    if has_any(&[80, 443, 3000, 5000, 8000, 8080, 8443, 8888])
        && has_any(&[1433, 1521, 3306, 5432, 6379, 9042, 9200, 11211, 27017])
    {
        combos.push(
            "Web + Data Store Co-Residency: public HTTP/HTTPS co-hosted with reachable DB/cache (SSRF / credential leak pivot)"
                .to_string(),
        );
    }

    if has_any(&[135, 139, 445]) && has_any(&[3389, 5985, 5986]) {
        combos.push(
            "Windows Lateral Movement Triad: SMB/RPC exposed alongside RDP/WinRM interactive execution"
                .to_string(),
        );
    }

    if has_any(&[2375, 2376, 6443, 10250]) && has_any(&[22, 3389, 5985]) {
        combos.push(
            "Control-Plane + Host-Admin Dual Exposure: container/cluster API co-exposed with host remote administration"
                .to_string(),
        );
    }

    if has_any(&[21, 23, 80, 110, 143]) && has_any(&[22, 443, 993, 995, 8443]) {
        combos.push(
            "Cleartext + TLS Dual Stack: cleartext protocol co-exists with encrypted service (credential reuse / downgrade surface)"
                .to_string(),
        );
    }

    if clean_ports.contains(&88) && has_any(&[389, 445, 636]) {
        combos.push(
            "Active Directory Identity Core: Kerberos (88) + LDAP/SMB exposed (ticket & relay attack surface)"
                .to_string(),
        );
    }

    combos
}

/// Analyze TCP connect RTT micro-variance across clean open ports to infer network proximity
/// and detect Reverse-Proxy / DNAT Backend Split anomalies (`>= 4x` RTT ratio & `>= 15ms` delta).
pub fn analyze_rtt_topology(audited: &[AuditedPortResult]) -> (String, Option<String>) {
    let rtt_samples: Vec<(u16, u64)> = audited
        .iter()
        .filter(|r| r.state == PortState::Open && !r.honeypot.is_suspicious())
        .filter_map(|r| r.rtt_micros.map(|us| (r.port, us.max(1))))
        .collect();

    if rtt_samples.is_empty() {
        return ("Unknown / No Open RTT Samples".to_string(), None);
    }

    let &(min_port, min_us) = rtt_samples.iter().min_by_key(|(_, us)| *us).unwrap();
    let &(max_port, max_us) = rtt_samples.iter().max_by_key(|(_, us)| *us).unwrap();

    let topology = if min_us < 1_500 {
        "Loopback / Local VSwitch (<1.5ms)".to_string()
    } else if min_us <= 15_000 {
        "LAN / Local L2-L3 Segment (1.5-15ms)".to_string()
    } else if min_us <= 80_000 {
        "Regional WAN / Cloud Peer (15-80ms)".to_string()
    } else {
        "Long-Haul WAN / Multi-Hop (>80ms)".to_string()
    };

    let split_anomaly = if rtt_samples.len() >= 2
        && max_us >= min_us.saturating_mul(4)
        && max_us.saturating_sub(min_us) >= 15_000
    {
        let ratio = (max_us as f64) / (min_us as f64);
        Some(format!(
            "Port {} ({:.2}ms) vs Port {} ({:.2}ms): {:.1}x RTT delta suggests Reverse-Proxy edge termination or DNAT port-forwarding to a remote backend",
            min_port,
            (min_us as f64) / 1000.0,
            max_port,
            (max_us as f64) / 1000.0,
            ratio
        ))
    } else {
        None
    };

    (topology, split_anomaly)
}

/// Extract unique shadow hostnames / subdomains discovered in TLS X.509 `SAN`/`subject_cn`
/// fields or SMTP/FTP ESMTP banners on clean open ports.
pub fn extract_shadow_assets(target_input: &str, audited: &[AuditedPortResult]) -> Vec<String> {
    let base_target = target_input
        .split(':')
        .next()
        .unwrap_or(target_input)
        .trim()
        .to_ascii_lowercase();
    let mut assets = Vec::new();

    let mut push_candidate = |candidate: &str| {
        let cleaned = candidate
            .trim()
            .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != '*')
            .to_ascii_lowercase();
        if cleaned.len() >= 4
            && cleaned.contains('.')
            && cleaned != base_target
            && cleaned != "localhost"
            && cleaned != "localhost.localdomain"
            && cleaned.parse::<std::net::IpAddr>().is_err()
            && !assets.contains(&cleaned)
        {
            assets.push(cleaned);
        }
    };

    for item in audited
        .iter()
        .filter(|r| r.state == PortState::Open && !r.honeypot.is_suspicious())
    {
        if let Some(ref tls) = item.tls {
            if let Some(ref cn) = tls.subject_cn {
                push_candidate(cn);
            }
            for san in &tls.sans {
                push_candidate(san);
            }
        }
        if let Some(ref banner) = item.banner {
            // Check 220 <fqdn> ESMTP/FTP greeting banners
            let tokens: Vec<&str> = banner.split_whitespace().collect();
            if tokens.len() >= 2 && tokens[0] == "220" && tokens[1].contains('.') {
                push_candidate(tokens[1]);
            }
        }
    }

    assets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telnet_and_docker_api_are_critical() {
        let telnet = EnrichedPortResult {
            port: 23,
            state: PortState::Open,
            service: "Telnet".to_string(),
            service_version: None,
            banner: None,
            rtt_micros: None,
            tls: None,
        };
        let audited = evaluate_port_security(telnet, AddressScope::Private);
        assert_eq!(audited.risk, RiskLevel::Critical);

        let docker = EnrichedPortResult {
            port: 2375,
            state: PortState::Open,
            service: "Docker-API".to_string(),
            service_version: None,
            banner: None,
            rtt_micros: None,
            tls: None,
        };
        let audited_docker = evaluate_port_security(docker, AddressScope::Loopback);
        assert_eq!(audited_docker.risk, RiskLevel::Critical);
    }

    #[test]
    fn test_public_scope_escalates_high_risk_ports_to_critical() {
        let rdp = EnrichedPortResult {
            port: 3389,
            state: PortState::Open,
            service: "RDP".to_string(),
            service_version: None,
            banner: None,
            rtt_micros: None,
            tls: None,
        };
        let private_eval = evaluate_port_security(rdp.clone(), AddressScope::Private);
        assert_eq!(private_eval.risk, RiskLevel::High);

        let public_eval = evaluate_port_security(rdp, AddressScope::Public);
        assert_eq!(public_eval.risk, RiskLevel::Critical);
        assert!(public_eval.advisory.contains("PUBLIC INTERNET EXPOSURE"));
    }

    #[test]
    fn test_unauthenticated_redis_banner_escalates_to_critical() {
        let redis = EnrichedPortResult {
            port: 6379,
            state: PortState::Open,
            service: "Redis".to_string(),
            service_version: None,
            banner: Some("+PONG".to_string()),
            rtt_micros: None,
            tls: None,
        };
        let audited = evaluate_port_security(redis, AddressScope::Loopback);
        assert_eq!(audited.risk, RiskLevel::Critical);
        assert!(audited.advisory.contains("Unauthenticated Redis"));
    }

    #[test]
    fn test_posture_summary_scoring_and_grades() {
        let items = vec![
            EnrichedPortResult {
                port: 443,
                state: PortState::Open,
                service: "HTTPS".to_string(),
                service_version: None,
                banner: None,
                rtt_micros: None,
                tls: None,
            },
            EnrichedPortResult {
                port: 80,
                state: PortState::Closed,
                service: "unknown".to_string(),
                service_version: None,
                banner: None,
                rtt_micros: None,
                tls: None,
            },
            EnrichedPortResult {
                port: 8080,
                state: PortState::Filtered,
                service: "unknown".to_string(),
                service_version: None,
                banner: None,
                rtt_micros: None,
                tls: None,
            },
        ];
        let (_, summary) = execute_audit_stage(items, AddressScope::Private);
        assert_eq!(summary.total_scanned, 3);
        assert_eq!(summary.open_count, 1);
        assert_eq!(summary.closed_count, 1);
        assert_eq!(summary.filtered_count, 1);
        assert!(summary.firewall_detected);
        assert_eq!(summary.posture_grade, 'B');
    }

    #[test]
    fn test_cpe23_and_cve_correlation_and_os_hint() {
        let ssh = EnrichedPortResult {
            port: 22,
            state: PortState::Open,
            service: "SSH".to_string(),
            service_version: Some("OpenSSH 9.2p1".to_string()),
            banner: Some("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2".to_string()),
            rtt_micros: Some(400),
            tls: None,
        };
        let apache = EnrichedPortResult {
            port: 80,
            state: PortState::Open,
            service: "HTTP".to_string(),
            service_version: Some("Apache 2.4.49".to_string()),
            banner: Some("HTTP/1.1 200 OK | Server: Apache/2.4.49 (Ubuntu)".to_string()),
            rtt_micros: Some(500),
            tls: None,
        };

        let (audited, summary) = execute_audit_stage(vec![ssh, apache], AddressScope::Private);
        assert_eq!(
            audited[0].cpe.as_deref(),
            Some("cpe:2.3:a:openbsd:openssh:9.2p1:*:*:*:*:*:*:*")
        );
        assert!(audited[0].cves.contains(&"CVE-2024-6387".to_string()));
        assert_eq!(audited[0].risk, RiskLevel::Critical);

        assert_eq!(
            audited[1].cpe.as_deref(),
            Some("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        );
        assert!(audited[1].cves.contains(&"CVE-2021-41773".to_string()));
        assert_eq!(audited[1].risk, RiskLevel::Critical);
        assert_eq!(summary.os_hint.as_deref(), Some("Linux (Debian)"));
    }

    #[test]
    fn test_infer_host_role_classifications() {
        let open_port = |port: u16, service: &str| EnrichedPortResult {
            port,
            state: PortState::Open,
            service: service.to_string(),
            service_version: None,
            banner: None,
            rtt_micros: Some(1_000),
            tls: None,
        };

        // 1. Active Directory Domain Controller (88 + 389 + 445)
        let (_, ad_summary) = execute_audit_stage(
            vec![
                open_port(88, "Kerberos"),
                open_port(389, "LDAP"),
                open_port(445, "SMB"),
            ],
            AddressScope::Private,
        );
        assert_eq!(
            ad_summary.recon.host_role,
            "Active Directory Domain Controller"
        );

        // 2. Web + Database Monolith (443 + 5432)
        let (_, web_db_summary) = execute_audit_stage(
            vec![open_port(443, "HTTPS"), open_port(5432, "PostgreSQL")],
            AddressScope::Private,
        );
        assert_eq!(
            web_db_summary.recon.host_role,
            "Web + Database Monolith (Co-Resident Stack)"
        );

        // 3. Hardened Bastion (only 22 open + filtered ports)
        let (_, bastion_summary) = execute_audit_stage(
            vec![
                open_port(22, "SSH"),
                EnrichedPortResult {
                    port: 443,
                    state: PortState::Filtered,
                    service: "HTTPS".to_string(),
                    service_version: None,
                    banner: None,
                    rtt_micros: None,
                    tls: None,
                },
            ],
            AddressScope::Public,
        );
        assert_eq!(
            bastion_summary.recon.host_role,
            "Hardened Bastion / SSH Jump Host"
        );
    }

    #[test]
    fn test_detect_toxic_combinations_web_db_and_windows_triad() {
        let open_port = |port: u16, service: &str| EnrichedPortResult {
            port,
            state: PortState::Open,
            service: service.to_string(),
            service_version: None,
            banner: None,
            rtt_micros: Some(2_000),
            tls: None,
        };

        let (audited, summary) = execute_audit_stage(
            vec![
                open_port(80, "HTTP"),
                open_port(443, "HTTPS"),
                open_port(6379, "Redis"),
                open_port(445, "SMB"),
                open_port(3389, "RDP"),
            ],
            AddressScope::Private,
        );
        let combos = detect_toxic_combinations(&audited);
        assert!(combos
            .iter()
            .any(|c| c.contains("Web + Data Store Co-Residency")));
        assert!(combos
            .iter()
            .any(|c| c.contains("Windows Lateral Movement Triad")));
        assert!(combos
            .iter()
            .any(|c| c.contains("Cleartext + TLS Dual Stack")));
        assert_eq!(summary.recon.toxic_combinations.len(), 3);
    }

    #[test]
    fn test_analyze_rtt_topology_and_dnat_split_detection() {
        let edge_https = EnrichedPortResult {
            port: 443,
            state: PortState::Open,
            service: "HTTPS".to_string(),
            service_version: None,
            banner: None,
            rtt_micros: Some(2_000), // 2.00ms (local reverse proxy edge)
            tls: None,
        };
        let tunneled_ssh = EnrichedPortResult {
            port: 2222,
            state: PortState::Open,
            service: "SSH".to_string(),
            service_version: None,
            banner: None,
            rtt_micros: Some(42_000), // 42.00ms (DNAT/tunneled to remote origin)
            tls: None,
        };

        let (audited, _) =
            execute_audit_stage(vec![edge_https, tunneled_ssh], AddressScope::Public);
        let (topology, anomaly) = analyze_rtt_topology(&audited);
        assert_eq!(topology, "LAN / Local L2-L3 Segment (1.5-15ms)");
        let anomaly_text = anomaly.expect("Expected DNAT/Reverse-Proxy RTT split anomaly");
        assert!(anomaly_text.contains("Port 443 (2.00ms) vs Port 2222 (42.00ms)"));
        assert!(anomaly_text.contains("21.0x RTT delta"));
    }

    #[test]
    fn test_extract_shadow_assets_from_tls_sans_and_banners() {
        let https = EnrichedPortResult {
            port: 443,
            state: PortState::Open,
            service: "HTTPS".to_string(),
            service_version: None,
            banner: None,
            rtt_micros: Some(1_200),
            tls: Some(crate::mediator::TlsCertificateInfo {
                subject_cn: Some("portal.corp.example.com".to_string()),
                issuer_cn: Some("Corp CA".to_string()),
                sans: vec![
                    "portal.corp.example.com".to_string(),
                    "staging-api.corp.example.com".to_string(),
                    "vault.internal.example.com".to_string(),
                ],
                not_after: None,
                days_until_expiry: Some(90),
                self_signed: false,
                hostname_mismatch: false,
                chain_length: 2,
            }),
        };
        let smtp = EnrichedPortResult {
            port: 25,
            state: PortState::Open,
            service: "SMTP".to_string(),
            service_version: None,
            banner: Some("220 mail-gw01.internal.example.com ESMTP Postfix".to_string()),
            rtt_micros: Some(1_400),
            tls: None,
        };

        let (audited, _) = execute_audit_stage(vec![https, smtp], AddressScope::Private);
        let assets = extract_shadow_assets("portal.corp.example.com", &audited);
        // Should exclude the requested target itself ("portal.corp.example.com") and return only pivot shadow assets:
        assert_eq!(
            assets,
            vec![
                "staging-api.corp.example.com".to_string(),
                "vault.internal.example.com".to_string(),
                "mail-gw01.internal.example.com".to_string(),
            ]
        );
    }
}
