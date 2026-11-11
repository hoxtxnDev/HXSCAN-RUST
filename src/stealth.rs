//! # Anti-AI Legitimacy Envelope & Traffic Mutation (`stealth`)
//!
//! Shared, dependency-free utilities used by **Stage 2** (adaptive pacing and decoy
//! planning) and **Stage 3** (HTTP request mutation). They implement a *legitimacy
//! envelope* for authorized security audits:
//!
//! - Bounded probe rate (`max_pps`) and configurable per-probe jitter.
//! - Human-like burst/pause shaping instead of deterministic constant-rate bursts.
//! - Additive/multiplicative backoff when filtered probes suggest defensive feedback.
//! - Enterprise client personas with mutating, browser/agent-like HTTP headers.
//! - Decoy probes interleaved **only against the same authorized target**.
//!
//! ## Security & Ethics Notice
//! These controls are intended to reduce obvious scanner fingerprints so that a
//! defensive stack does not automatically classify an **authorized** audit as
//! malicious. They are **not** a guarantee of evading AI/ML, IDS/IPS or EDR systems.
//! Never use this software against systems without explicit written authorization.

use std::time::Duration;

use crate::mediator::{
    PortState, ScannerConfig, SecurityPostureSummary, StealthConfig, StealthMode, StealthTelemetry,
    TrafficPersona,
};

/// Maximum number of jitter milliseconds accepted by the pacing controller.
pub const MAX_PACING_JITTER_MS: u64 = 60_000;

/// Maximum number of decoy probes interleaved in a single scan.
pub const MAX_DECOY_PROBES: usize = 128;

/// Decoy pool: common enterprise infrastructure ports used to dilute sequential
/// scanner signatures. Probes are sent only to the scan's primary authorized target.
const DECOY_POOL: [u16; 8] = [53, 80, 123, 443, 445, 993, 8080, 8443];

/// Deterministic xorshift64 PRNG used to avoid external dependencies.
#[inline]
pub fn next_rand(state: &mut u64) -> u64 {
    let mut x = if *state == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        *state
    };
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

/// Per-worker adaptive pacing state implementing the anti-AI legitimacy envelope.
pub struct PacingController {
    base_interval: Duration,
    jitter: Duration,
    burst_size: usize,
    burst_pause: Duration,
    adaptive: bool,
    probes_since_pause: usize,
    backoff: u32,
    rng: u64,
}

impl PacingController {
    /// Build a pacing controller for one worker.
    ///
    /// `worker_count` distributes the global `max_pps` ceiling across workers so the
    /// aggregate scan remains inside the configured envelope.
    pub fn new(config: &ScannerConfig, worker_count: usize, seed: u64) -> Self {
        let stealth = &config.stealth;
        let workers = worker_count.max(1) as f64;
        let rate_interval = if stealth.max_pps.is_finite() && stealth.max_pps > 0.0 {
            Duration::from_secs_f64((workers / stealth.max_pps).min(3600.0))
        } else {
            Duration::ZERO
        };

        Self {
            base_interval: rate_interval.max(config.delay),
            jitter: stealth
                .jitter
                .min(Duration::from_millis(MAX_PACING_JITTER_MS)),
            burst_size: stealth.burst_size,
            burst_pause: stealth.burst_pause,
            adaptive: stealth.adaptive_backoff,
            probes_since_pause: 0,
            backoff: 1,
            rng: if seed == 0 {
                0x51ED_270B_9E37_79B9
            } else {
                seed
            },
        }
    }

    fn random_jitter(&mut self) -> Duration {
        if self.jitter.is_zero() {
            return Duration::ZERO;
        }
        let max_ms = self
            .jitter
            .as_millis()
            .min(u128::from(MAX_PACING_JITTER_MS)) as u64;
        if max_ms == 0 {
            Duration::ZERO
        } else {
            Duration::from_millis(next_rand(&mut self.rng) % (max_ms + 1))
        }
    }

    /// Record a completed probe and return the delay to apply before the next probe.
    ///
    /// Filtered/error outcomes trigger exponential backoff (capped at 8x) to avoid
    /// escalating against a firewall, IPS or a tarpit. Successful/closed probes reset
    /// the backoff, keeping the envelope stable during normal operation.
    pub fn on_probe_complete(&mut self, state: &PortState) -> Duration {
        let mut delay = self.base_interval + self.random_jitter();

        if self.adaptive {
            match state {
                PortState::Filtered | PortState::Error(_) => {
                    self.backoff = (self.backoff.saturating_mul(2)).min(8);
                    delay += self.base_interval * (self.backoff - 1);
                }
                PortState::Open | PortState::Closed => {
                    self.backoff = 1;
                }
            }
        }

        if self.burst_size > 0 {
            self.probes_since_pause += 1;
            if self.probes_since_pause >= self.burst_size {
                self.probes_since_pause = 0;
                delay += self.burst_pause + self.random_jitter();
            }
        }

        delay
    }
}

/// Build the interleaved `(port, is_decoy)` work plan for Stage 2.
///
/// Real ports preserve their order (already shuffled by Stage 1 when configured);
/// decoys are inserted at random positions and their results are discarded by the
/// scanner. Decoy traffic never leaves the primary target.
pub fn build_work_plan(ports: &[u16], decoy_probes: usize, seed: u64) -> Vec<(u16, bool)> {
    let mut plan: Vec<(u16, bool)> = ports.iter().map(|&port| (port, false)).collect();
    if ports.is_empty() || decoy_probes == 0 {
        return plan;
    }

    let mut rng = if seed == 0 {
        0xA5A5_5A5A_F0F0_0F0F
    } else {
        seed
    };
    for _ in 0..decoy_probes.min(MAX_DECOY_PROBES) {
        let decoy_port = DECOY_POOL[(next_rand(&mut rng) as usize) % DECOY_POOL.len()];
        let position = (next_rand(&mut rng) as usize) % (plan.len() + 1);
        plan.insert(position, (decoy_port, true));
    }
    plan
}

/// Strip CR/LF and control characters from a value inserted into an HTTP header.
fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(255)
        .collect()
}

/// Select a realistic User-Agent for the configured persona, with mutation variants.
fn persona_user_agent(persona: TrafficPersona, seed: u64) -> &'static str {
    match persona {
        TrafficPersona::Generic => match seed % 2 {
            0 => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            _ => "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        },
        TrafficPersona::CorporateWorkstation => match seed % 2 {
            0 => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
            _ => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
        },
        TrafficPersona::Browser => match seed % 2 {
            0 => "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
            _ => "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        },
        TrafficPersona::MicrosoftUpdate => match seed % 2 {
            0 => "Microsoft-Delivery-Optimization/10.0",
            _ => "Windows-Update-Agent/10.0.19041.1 Client-Protocol/2.0",
        },
        TrafficPersona::BackupAgent => match seed % 2 {
            0 => "Microsoft BITS/7.8",
            _ => "Commvault-Backup-Agent/11.36",
        },
    }
}

fn persona_accept(persona: TrafficPersona) -> &'static str {
    match persona {
        TrafficPersona::Browser | TrafficPersona::CorporateWorkstation => {
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        }
        TrafficPersona::Generic | TrafficPersona::MicrosoftUpdate | TrafficPersona::BackupAgent => {
            "*/*"
        }
    }
}

fn persona_accept_language(persona: TrafficPersona, seed: u64) -> &'static str {
    match persona {
        TrafficPersona::Browser | TrafficPersona::CorporateWorkstation => match seed % 3 {
            0 => "es-ES,es;q=0.9,en;q=0.8",
            1 => "en-US,en;q=0.9",
            _ => "es-MX,es;q=0.9,en;q=0.7",
        },
        _ => "en-US,en;q=0.9",
    }
}

/// Build a mutated HTTP/1.1 probe that resembles the selected enterprise persona.
///
/// The request intentionally uses `Accept-Encoding: identity` to keep banner bytes
/// printable and sanitizable, while preserving realistic browser/agent headers.
pub fn build_http_probe(persona: TrafficPersona, host: &str, seed: u64) -> Vec<u8> {
    let host = sanitize_header_value(host);
    let host = if host.is_empty() { "localhost" } else { &host };
    let method = match persona {
        TrafficPersona::Browser | TrafficPersona::CorporateWorkstation => "GET",
        TrafficPersona::Generic | TrafficPersona::MicrosoftUpdate | TrafficPersona::BackupAgent => {
            "HEAD"
        }
    };
    let user_agent = persona_user_agent(persona, seed);
    let accept = persona_accept(persona);
    let language = persona_accept_language(persona, seed);

    let mut request = format!(
        "{method} / HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {user_agent}\r\n\
         Accept: {accept}\r\n\
         Accept-Language: {language}\r\n\
         Accept-Encoding: identity\r\n\
         Connection: close\r\n"
    );

    if matches!(
        persona,
        TrafficPersona::Browser | TrafficPersona::CorporateWorkstation
    ) {
        request.push_str("Upgrade-Insecure-Requests: 1\r\n");
    }
    request.push_str("\r\n");
    request.into_bytes()
}

/// Evaluate the configured stealth posture and defensive feedback into report telemetry.
///
/// The score is an honest *self-assessment* of how closely the configuration resembles
/// legitimate enterprise traffic. A high score does not prove evasion.
pub fn assess_legitimacy(
    config: &StealthConfig,
    grab_banners: bool,
    filtered_ratio_pct: u8,
) -> StealthTelemetry {
    let mut score: i32 = 65;

    match config.mode {
        StealthMode::Normal => {}
        StealthMode::Stealth => score += 20,
        StealthMode::Mutable => score += 25,
    }

    if config.ai_filter {
        score += 8;
    }
    if !config.jitter.is_zero() {
        score += 5;
        if config.jitter >= Duration::from_millis(50) {
            score += 3;
        }
    }
    if config.max_pps > 0.0 {
        if config.max_pps <= 10.0 {
            score += 10;
        } else if config.max_pps <= 50.0 {
            score += 6;
        } else if config.max_pps <= 100.0 {
            score += 2;
        } else if config.max_pps > 200.0 {
            score -= 10;
        }
    }
    if config.burst_size > 0 {
        score += 4;
    }
    if config.persona != TrafficPersona::Generic {
        score += 4;
    }
    if config.adaptive_backoff {
        score += 4;
    }
    if !grab_banners {
        score += 2;
    } else if config.persona == TrafficPersona::Generic {
        score -= 8;
    }
    if filtered_ratio_pct > 50 {
        score -= 15;
    } else if filtered_ratio_pct > 20 {
        score -= 5;
    }

    let legitimacy_score = score.clamp(0, 100) as u8;
    let legitimacy_grade = if legitimacy_score >= 85 {
        'A'
    } else if legitimacy_score >= 70 {
        'B'
    } else if legitimacy_score >= 55 {
        'C'
    } else if legitimacy_score >= 40 {
        'D'
    } else {
        'F'
    };

    StealthTelemetry {
        mode: config.mode,
        persona: config.persona,
        ai_filter: config.ai_filter,
        max_pps: config.max_pps,
        jitter_ms: config.jitter.as_millis().min(u128::from(u64::MAX)) as u64,
        burst_size: config.burst_size,
        burst_pause_ms: config.burst_pause.as_millis().min(u128::from(u64::MAX)) as u64,
        decoy_probes: config.decoy_probes.min(MAX_DECOY_PROBES),
        adaptive_backoff: config.adaptive_backoff,
        filtered_ratio_pct,
        legitimacy_score,
        legitimacy_grade,
    }
}

/// Compute the filtered ratio used by the adaptive-pacing directive and telemetry.
pub fn filtered_ratio_pct(summary: &SecurityPostureSummary) -> u8 {
    if summary.total_scanned == 0 {
        0
    } else {
        ((summary.filtered_count.saturating_mul(100)) / summary.total_scanned).min(100) as u8
    }
}

/// Convenience helper used by the Mediator before invoking the reporting stage.
pub fn evaluate_scan_legitimacy(
    scanner: &ScannerConfig,
    grab_banners: bool,
    summary: &SecurityPostureSummary,
) -> StealthTelemetry {
    assess_legitimacy(&scanner.stealth, grab_banners, filtered_ratio_pct(summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pacing_controller_jitter_and_adaptive_backoff() {
        let config = StealthConfig {
            mode: StealthMode::Mutable,
            persona: TrafficPersona::CorporateWorkstation,
            jitter: Duration::from_millis(20),
            max_pps: 10.0,
            burst_size: 2,
            burst_pause: Duration::from_millis(30),
            adaptive_backoff: true,
            decoy_probes: 0,
            ai_filter: true,
        };
        let scanner_config = ScannerConfig {
            threads: 2,
            timeout: Duration::from_millis(500),
            retries: 0,
            delay: Duration::ZERO,
            stealth: config,
        };
        let mut pacer = PacingController::new(&scanner_config, 2, 42);

        let normal = pacer.on_probe_complete(&PortState::Open);
        assert!(normal >= Duration::from_millis(100));

        let mut filtered_delay = Duration::ZERO;
        for _ in 0..4 {
            filtered_delay = pacer.on_probe_complete(&PortState::Filtered);
        }
        assert!(filtered_delay >= normal);
    }

    #[test]
    fn test_work_plan_interleaves_decoys_and_keeps_real_ports() {
        let plan = build_work_plan(&[22, 80, 443], 3, 7);
        assert_eq!(plan.len(), 6);
        assert_eq!(plan.iter().filter(|(_, decoy)| !decoy).count(), 3);
        assert_eq!(plan.iter().filter(|(_, decoy)| *decoy).count(), 3);

        let real_ports: Vec<u16> = plan
            .iter()
            .filter(|(_, decoy)| !decoy)
            .map(|(port, _)| *port)
            .collect();
        assert_eq!(real_ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_http_probe_uses_persona_and_hides_scanner_identity() {
        let request = build_http_probe(
            TrafficPersona::CorporateWorkstation,
            "portal.example.test",
            11,
        );
        let text = String::from_utf8_lossy(&request);
        assert!(text.starts_with("GET / HTTP/1.1\r\n"));
        assert!(text.contains("Host: portal.example.test"));
        assert!(text.contains("Edg/"));
        assert!(!text.to_ascii_lowercase().contains("tcpscan"));
    }

    #[test]
    fn test_legitimacy_mutable_profile_is_high_and_normal_is_honest() {
        let mutable = StealthConfig {
            mode: StealthMode::Mutable,
            persona: TrafficPersona::CorporateWorkstation,
            jitter: Duration::from_millis(80),
            max_pps: 6.0,
            burst_size: 5,
            burst_pause: Duration::from_millis(500),
            adaptive_backoff: true,
            decoy_probes: 2,
            ai_filter: true,
        };
        let telemetry = assess_legitimacy(&mutable, true, 0);
        assert!(telemetry.legitimacy_score >= 85);
        assert_eq!(telemetry.legitimacy_grade, 'A');

        let normal = StealthConfig::default();
        let normal_telemetry = assess_legitimacy(&normal, true, 0);
        assert!(normal_telemetry.legitimacy_score < telemetry.legitimacy_score);
    }

    #[test]
    fn test_filtered_ratio() {
        let summary = SecurityPostureSummary {
            total_scanned: 10,
            open_count: 2,
            closed_count: 3,
            filtered_count: 5,
            error_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            exposure_score: 10,
            posture_grade: 'C',
            firewall_detected: true,
            possible_honeypot_count: 0,
            confirmed_honeypot_count: 0,
        };
        assert_eq!(filtered_ratio_pct(&summary), 50);
    }
}
