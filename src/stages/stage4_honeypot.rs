//! # Stage 4 Colleague: `HoneypotColleague` (`stage4_honeypot`)
//!
//! Concrete Colleague in the **Mediator Pattern** responsible for classifying open
//! services as **clean**, **possible honeypot** or **honeypot**, while recording the
//! observed *behavior* that motivated the verdict.
//!
//! ## Behavioral signals
//! - Known deception-framework banners (Cowrie, Kippo, Dionaea, Glastopf, Honeyd,
//!   Thinkst Canary, Conpot, Endlessh, etc.).
//! - Honeypot-typical ports and clusters of them.
//! - Protocol/port contradictions (`HTTP` banner on `22`, `SSH` on `80`, mixed protocols).
//! - Tarpit-like latency, bannerless interactive services and ephemeral services.
//! - Aggregate signals: mass-open services, cloned banners and suspiciously uniform RTT.
//!
//! Emits [`ScanEvent::HoneypotAssessmentCompleted`] and returns a reactive
//! [`MediatorDirective::PossibleHoneypotDetected`] or
//! [`MediatorDirective::ConfirmedHoneypotDetected`] to the [`ScanController`].
//!
//! **Decoupling Guarantee**: Zero imports from `stage1`, `stage2`, `stage3`, `stage5` or `stage6`.

use crate::mediator::{
    AddressScope, ComponentId, EnrichedPortResult, HoneypotAssessment, HoneypotBehavior,
    HoneypotVerdict, MediatorDirective, PortState, ScanController, ScanEvent, ScanMediator,
};

/// Banner fragments strongly associated with public deception frameworks.
const KNOWN_HONEYPOT_SIGNATURES: &[&str] = &[
    "cowrie",
    "kippo",
    "dionaea",
    "glastopf",
    "honeyd",
    "honeypot",
    "thinkst canary",
    "thinkst",
    "canarytokens",
    "opencanary",
    "amun",
    "nepenthes",
    "wordpot",
    "hellpot",
    "endlessh",
    "tarpit",
    "labrea",
    "la brea",
    "conpot",
    "gridpot",
    "snare",
    "modern honey network",
];

/// Ports frequently used by honeypot deployments. A single hit is weak evidence;
/// a cluster of three or more is a strong aggregate signal.
const HONEYPOT_PORT_HINTS: &[u16] = &[
    2222, 22222, 2323, 4444, 5555, 8081, 8082, 9999, 10000, 31337, 5038,
];

/// Services that normally speak first or expose an interactive prompt.
const INTERACTIVE_PORTS: &[u16] = &[21, 22, 23, 25, 110, 143, 389, 3306, 5432, 5900, 6379];

/// Aggregate context derived from the complete scan before per-port classification.
#[derive(Debug, Default, Clone, Copy)]
struct HoneypotContext {
    mass_open: bool,
    uniform_rtt: bool,
    cloned_banners: bool,
    honeypot_port_cluster: bool,
}

/// **Colleague 4 (`HoneypotColleague`)**: Honeypot & Deception Behavior Analysis Colleague.
pub struct HoneypotColleague;

impl HoneypotColleague {
    /// Analyze every enriched result, store the assessments in the Mediator blackboard and
    /// emit [`ScanEvent::HoneypotAssessmentCompleted`].
    pub fn run(mediator: &mut ScanController) -> MediatorDirective {
        let scope = mediator
            .target
            .as_ref()
            .map(|t| t.scope)
            .unwrap_or(AddressScope::Private);
        let assessments = analyze_honeypots(&mediator.enriched_results, scope);
        mediator.honeypot_assessments = assessments.clone();

        mediator.notify(
            ComponentId::HoneypotColleague,
            ScanEvent::HoneypotAssessmentCompleted { assessments },
        )
    }
}

/// Analyze a batch of enriched ports and return one [`HoneypotAssessment`] per port.
pub fn analyze_honeypots(
    enriched: &[EnrichedPortResult],
    scope: AddressScope,
) -> Vec<HoneypotAssessment> {
    let open: Vec<&EnrichedPortResult> = enriched
        .iter()
        .filter(|item| item.state == PortState::Open)
        .collect();
    let context = build_context(&open, enriched.len(), scope);

    enriched
        .iter()
        .map(|item| {
            if item.state != PortState::Open {
                HoneypotAssessment::clean(item.port)
            } else {
                evaluate_honeypot_port_with_context(item, scope, context)
            }
        })
        .collect()
}

fn build_context(
    open: &[&EnrichedPortResult],
    total_scanned: usize,
    scope: AddressScope,
) -> HoneypotContext {
    let open_count = open.len();
    let mass_open =
        open_count >= 10 && open_count.saturating_mul(100) >= total_scanned.saturating_mul(35);

    let honeypot_port_hits = open
        .iter()
        .filter(|item| HONEYPOT_PORT_HINTS.contains(&item.port))
        .count();

    let mut rtts: Vec<u64> = Vec::with_capacity(open_count);
    for item in open {
        if let Some(rtt) = item.rtt_micros {
            rtts.push(rtt);
        }
    }
    let uniform_rtt = scope != AddressScope::Loopback
        && open_count >= 6
        && rtts.len() == open_count
        && rtts
            .iter()
            .max()
            .copied()
            .unwrap_or(0)
            .saturating_sub(rtts.iter().min().copied().unwrap_or(0))
            <= 200;

    let mut banner_counts: Vec<(String, usize)> = Vec::new();
    for item in open {
        if let Some(ref banner) = item.banner {
            if banner.len() < 8 {
                continue;
            }
            if let Some(entry) = banner_counts.iter_mut().find(|(value, _)| value == banner) {
                entry.1 += 1;
            } else {
                banner_counts.push((banner.clone(), 1));
            }
        }
    }
    let cloned_banners = banner_counts.iter().any(|(_, count)| *count >= 3);

    HoneypotContext {
        mass_open,
        uniform_rtt,
        cloned_banners,
        honeypot_port_cluster: honeypot_port_hits >= 3,
    }
}

/// Evaluate a single open/enriched port without aggregate scan context.
pub fn evaluate_honeypot_port(
    item: &EnrichedPortResult,
    scope: AddressScope,
) -> HoneypotAssessment {
    evaluate_honeypot_port_with_context(item, scope, HoneypotContext::default())
}

fn evaluate_honeypot_port_with_context(
    item: &EnrichedPortResult,
    scope: AddressScope,
    context: HoneypotContext,
) -> HoneypotAssessment {
    if item.state != PortState::Open {
        return HoneypotAssessment::clean(item.port);
    }

    let mut behaviors: Vec<HoneypotBehavior> = Vec::with_capacity(6);
    let mut notes: Vec<String> = Vec::with_capacity(6);
    let banner_lower = item
        .banner
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();

    if KNOWN_HONEYPOT_SIGNATURES
        .iter()
        .any(|signature| banner_lower.contains(signature))
    {
        push_behavior(&mut behaviors, HoneypotBehavior::KnownHoneypotSignature);
        notes.push("banner matches a known deception framework".to_string());
    }

    if HONEYPOT_PORT_HINTS.contains(&item.port) {
        push_behavior(&mut behaviors, HoneypotBehavior::HoneypotPort);
        notes.push("port is frequently used by honeypot deployments".to_string());
    }

    if let Some(protocol) = infer_banner_protocol(&banner_lower) {
        if !service_matches_protocol(&item.service, protocol) {
            push_behavior(&mut behaviors, HoneypotBehavior::ServicePortMismatch);
            notes.push(format!(
                "banner speaks {protocol} but the service label is '{}'",
                item.service
            ));
        }
    }

    if banner_has_contradictory_protocols(&banner_lower) {
        push_behavior(&mut behaviors, HoneypotBehavior::ContradictoryBanner);
        notes.push("banner mixes multiple incompatible protocols".to_string());
    }

    if item.rtt_micros.unwrap_or(0) > 2_500_000 && scope != AddressScope::Loopback {
        push_behavior(&mut behaviors, HoneypotBehavior::TarpitLatency);
        notes.push("abnormally slow handshake suggests a tarpit".to_string());
    }

    if item.port >= 49_152 {
        push_behavior(&mut behaviors, HoneypotBehavior::UnusualEphemeralService);
        notes.push("service exposed on an ephemeral/high port".to_string());
    }

    if INTERACTIVE_PORTS.contains(&item.port) && item.banner.is_none() {
        push_behavior(
            &mut behaviors,
            HoneypotBehavior::BannerlessInteractiveService,
        );
        notes.push("interactive service accepted the connection but sent no banner".to_string());
    }

    if has_credential_prompt(&banner_lower) {
        push_behavior(&mut behaviors, HoneypotBehavior::DefaultCredentialPrompt);
        notes.push("unexpected interactive credential prompt".to_string());
    }

    if has_legacy_or_fake_version(&banner_lower) {
        push_behavior(&mut behaviors, HoneypotBehavior::FakeVersionDisclosure);
        notes.push("legacy/fake version string commonly used by deception frameworks".to_string());
    }

    if context.mass_open {
        push_behavior(&mut behaviors, HoneypotBehavior::MassOpenServices);
        notes.push("large number of open services on the same target".to_string());
    }
    if context.uniform_rtt {
        push_behavior(&mut behaviors, HoneypotBehavior::UniformRtt);
        notes.push("suspiciously uniform RTT across many services".to_string());
    }
    if context.cloned_banners {
        push_behavior(&mut behaviors, HoneypotBehavior::ClonedBanners);
        notes.push("multiple services returned the exact same banner".to_string());
    }
    if context.honeypot_port_cluster {
        push_behavior(&mut behaviors, HoneypotBehavior::HoneypotPortCluster);
        notes.push("multiple honeypot-typical ports are open".to_string());
    }

    let score = behaviors
        .iter()
        .map(HoneypotBehavior::weight)
        .fold(0u16, |acc, weight| acc.saturating_add(u16::from(weight)))
        .min(100) as u8;

    let verdict = if score >= 70 {
        HoneypotVerdict::Honeypot
    } else if score >= 30 {
        HoneypotVerdict::PossibleHoneypot
    } else {
        HoneypotVerdict::Clean
    };

    HoneypotAssessment {
        port: item.port,
        verdict,
        score,
        behaviors,
        notes: notes.join("; "),
    }
}

fn push_behavior(behaviors: &mut Vec<HoneypotBehavior>, behavior: HoneypotBehavior) {
    if !behaviors.contains(&behavior) {
        behaviors.push(behavior);
    }
}

fn infer_banner_protocol(banner: &str) -> Option<&'static str> {
    if banner.starts_with("ssh-") {
        Some("SSH")
    } else if banner.starts_with("http/") {
        Some("HTTP")
    } else if banner.starts_with("rfb ") {
        Some("VNC")
    } else if banner.starts_with("+pong") || banner.starts_with("-noauth") {
        Some("Redis")
    } else if banner.starts_with("220 ") && (banner.contains("smtp") || banner.contains("esmtp")) {
        Some("SMTP")
    } else if banner.starts_with("220 ") && banner.contains("ftp") {
        Some("FTP")
    } else if banner.starts_with("+ok") {
        Some("POP3")
    } else if banner.starts_with("* ok") && banner.contains("imap") {
        Some("IMAP")
    } else if banner.contains("mariadb") || banner.contains("mysql") {
        Some("MySQL")
    } else {
        None
    }
}

fn service_matches_protocol(service: &str, protocol: &str) -> bool {
    let service = service.to_ascii_lowercase();
    if service.is_empty() || service == "unknown" {
        return true;
    }

    match protocol {
        "SSH" => service.contains("ssh"),
        "HTTP" => {
            service.contains("http")
                || service.contains("web")
                || service.contains("kubernetes")
                || service.contains("docker")
                || service.contains("kibana")
                || service.contains("elasticsearch")
                || service.contains("winrm")
        }
        "SMTP" => service.contains("smtp") || service.contains("mail"),
        "FTP" => service.contains("ftp"),
        "POP3" => service.contains("pop3"),
        "IMAP" => service.contains("imap"),
        "Redis" => service.contains("redis"),
        "MySQL" => service.contains("mysql") || service.contains("maria"),
        "VNC" => service.contains("vnc"),
        other => service.contains(other.to_ascii_lowercase().as_str()),
    }
}

fn banner_has_contradictory_protocols(banner: &str) -> bool {
    let mut markers = 0u8;
    if banner.contains("ssh-2.0") || banner.starts_with("ssh-") {
        markers += 1;
    }
    if banner.contains("http/") {
        markers += 1;
    }
    if banner.contains("220 ") && (banner.contains("smtp") || banner.contains("ftp")) {
        markers += 1;
    }
    if banner.contains("+pong") || banner.contains("-noauth") {
        markers += 1;
    }
    if banner.contains("rfb ") {
        markers += 1;
    }
    if banner.contains("mysql") || banner.contains("mariadb") {
        markers += 1;
    }
    markers >= 2
}

fn has_credential_prompt(banner: &str) -> bool {
    banner.contains("login:")
        || banner.contains("password:")
        || banner.contains("login as:")
        || banner.contains("root@")
        || banner.contains("admin@")
}

fn has_legacy_or_fake_version(banner: &str) -> bool {
    banner.contains("openssh_2.")
        || banner.contains("openssh_3.")
        || banner.contains("openssh_4.")
        || banner.contains("openssh_5.")
        || banner.contains("openssh_6.")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_port(port: u16, service: &str, banner: Option<&str>) -> EnrichedPortResult {
        EnrichedPortResult {
            port,
            state: PortState::Open,
            service: service.to_string(),
            banner: banner.map(str::to_string),
            rtt_micros: Some(1_200),
        }
    }

    #[test]
    fn test_known_honeypot_signature_is_confirmed() {
        let item = open_port(2222, "SSH", Some("SSH-2.0-Cowrie-1.0"));
        let assessment = evaluate_honeypot_port(&item, AddressScope::Private);
        assert_eq!(assessment.verdict, HoneypotVerdict::Honeypot);
        assert!(assessment
            .behaviors
            .contains(&HoneypotBehavior::KnownHoneypotSignature));
        assert!(assessment.score >= 70);
    }

    #[test]
    fn test_service_port_mismatch_is_possible_honeypot() {
        let item = open_port(22, "SSH", Some("HTTP/1.1 200 OK (nginx/1.26.0)"));
        let assessment = evaluate_honeypot_port(&item, AddressScope::Private);
        assert_eq!(assessment.verdict, HoneypotVerdict::PossibleHoneypot);
        assert!(assessment
            .behaviors
            .contains(&HoneypotBehavior::ServicePortMismatch));
    }

    #[test]
    fn test_clean_ssh_service_is_not_flagged() {
        let item = open_port(22, "SSH", Some("SSH-2.0-OpenSSH_9.7p1"));
        let assessment = evaluate_honeypot_port(&item, AddressScope::Private);
        assert_eq!(assessment.verdict, HoneypotVerdict::Clean);
        assert!(assessment.behaviors.is_empty());
    }

    #[test]
    fn test_mass_open_and_uniform_rtt_escalate() {
        let mut items = Vec::new();
        for port in 1000..1012 {
            let mut item = open_port(port, "unknown", Some("Service-Ready"));
            item.rtt_micros = Some(500);
            items.push(item);
        }
        let assessments = analyze_honeypots(&items, AddressScope::Private);
        assert_eq!(assessments.len(), 12);
        assert!(assessments
            .iter()
            .all(|a| a.verdict != HoneypotVerdict::Clean));
        assert!(assessments[0]
            .behaviors
            .contains(&HoneypotBehavior::MassOpenServices));
        assert!(assessments[0]
            .behaviors
            .contains(&HoneypotBehavior::UniformRtt));
    }

    #[test]
    fn test_closed_port_is_clean() {
        let item = EnrichedPortResult {
            port: 2222,
            state: PortState::Filtered,
            service: "unknown".to_string(),
            banner: None,
            rtt_micros: None,
        };
        let assessment = evaluate_honeypot_port(&item, AddressScope::Public);
        assert_eq!(assessment.verdict, HoneypotVerdict::Clean);
        assert_eq!(assessment.score, 0);
    }
}
