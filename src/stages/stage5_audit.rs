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
    HoneypotVerdict, MediatorDirective, MediatorState, PortState, RiskLevel, ScanController,
    ScanEvent, ScanMediator, SecurityPostureSummary,
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
        let enriched = std::mem::take(&mut mediator.enriched_results);
        let (audited_results, summary) =
            execute_audit_stage_with_honeypots(enriched, scope, &mediator.honeypot_assessments);

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
        banner: item.banner,
        rtt_micros: item.rtt_micros,
        risk,
        category,
        advisory,
        tls: item.tls,
        honeypot,
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
    };

    (audited, summary)
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
}
