//! # Concrete Mediator / Controller (`mediator::controller`)
//!
//! Implements [`ScanController`] (the Concrete **Mediator**, **Intermediary**, or **Controller**),
//! which coordinates all 6 Colleague components (`DiscoveryColleague`, `ScannerColleague`,
//! `FingerprintColleague`, `HoneypotColleague`, `AuditColleague`, `ReportColleague`) without any
//! colleague referencing another colleague directly.
//!
//! ## Key Responsibilities of `ScanController`
//! 1. **Centralized Communication Hub (Star Topology)**: Receives [`ScanEvent`] notifications from
//!    every Colleague and records a verifiable [`MediatedEventRecord`] trace.
//! 2. **Reactive Orchestration & Adaptive Directives**: Issues [`MediatorDirective`] responses when
//!    special network conditions arise (e.g., `PublicTargetHardeningMode`, `FirewallDropDetected`,
//!    `AdaptivePacingEngaged`, `ConfirmedHoneypotDetected`, `EscalateCriticalAlert`).
//! 3. **Decoupled Stream Mediation**: Implements [`ScanMediator::mediate_open_stream`] so
//!    `ScannerColleague` can hand off an open `TcpStream` to the Mediator without knowing
//!    `FingerprintColleague` exists. In stealth/mutable mode the Mediator injects the configured
//!    traffic persona so active probes resemble legitimate enterprise clients.

use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::mediator::contract::{
    AuditedPortResult, ComponentId, EnrichedPortResult, HoneypotAssessment, MediatedEventRecord,
    MediatorDirective, MediatorState, RawProbeResult, ReportOptions, ScanEvent, ScanMediator,
    ScannerConfig, SecurityPostureSummary, StealthMode, StealthTelemetry, TargetInfo,
};
use crate::stages::stage1_discovery::{DiscoveryColleague, DiscoveryError};
use crate::stages::stage2_scanner::ScannerColleague;
use crate::stages::stage3_fingerprint::FingerprintColleague;
use crate::stages::stage4_honeypot::HoneypotColleague;
use crate::stages::stage5_audit::AuditColleague;
use crate::stages::stage6_report::ReportColleague;
use crate::stealth::evaluate_scan_legitimacy;

/// Configuration passed into the [`ScanController`] Mediator.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub target_input: String,
    pub port_spec: String,
    pub scanner: ScannerConfig,
    pub grab_banners: bool,
    pub banner_timeout: Duration,
    pub shuffle: bool,
    pub protect_origin: bool,
    pub verbose: bool,
    pub report_options: ReportOptions,
}

/// Complete output artifact produced after the [`ScanController`] finishes mediating all colleagues.
#[derive(Debug, Clone)]
pub struct PipelineOutput {
    pub target: TargetInfo,
    pub audited_ports: Vec<AuditedPortResult>,
    pub summary: SecurityPostureSummary,
    pub elapsed: Duration,
    pub formatted_report: String,
    /// Full audit trail of all [`ScanEvent`] messages mediated by the Controller.
    pub event_trace: Vec<MediatedEventRecord>,
    /// Immediate critical alerts captured during `AuditColleague` mediation.
    pub critical_alerts: Vec<String>,
    /// Deception/honeypot alerts captured during Stage 4 mediation.
    pub deception_alerts: Vec<String>,
    /// Per-port honeypot behavior assessments produced by Stage 4.
    pub honeypot_assessments: Vec<HoneypotAssessment>,
    /// Stealth/anti-AI legitimacy telemetry rendered by Stage 6.
    pub stealth_telemetry: StealthTelemetry,
}

impl PipelineOutput {
    /// Compute standard CLI exit code (`0` = open ports found, `2` = no open ports found).
    pub fn exit_code(&self) -> i32 {
        if self.summary.open_count > 0 {
            0
        } else {
            2
        }
    }
}

/// **Concrete Mediator (`ScanController`)** — coordinates all Colleague components.
///
/// Also aliased as `ScanPipeline` for backward compatibility.
pub struct ScanController {
    pub config: PipelineConfig,
    state: MediatorState,
    event_trace: Vec<MediatedEventRecord>,
    critical_alerts: Vec<String>,
    deception_alerts: Vec<String>,
    // Shared blackboard state mediated across Colleagues:
    pub(crate) target: Option<TargetInfo>,
    pub(crate) ports: Vec<u16>,
    pub(crate) raw_results: Vec<RawProbeResult>,
    pub(crate) enriched_results: Vec<EnrichedPortResult>,
    pub(crate) honeypot_assessments: Vec<HoneypotAssessment>,
    pub(crate) audited_results: Vec<AuditedPortResult>,
    pub(crate) summary: Option<SecurityPostureSummary>,
    pub(crate) stealth_telemetry: Option<StealthTelemetry>,
    pub(crate) formatted_report: Option<String>,
}

impl ScanController {
    /// Construct a new [`ScanController`] Mediator in `MediatorState::Idle`.
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            config,
            state: MediatorState::Idle,
            event_trace: Vec::with_capacity(10),
            critical_alerts: Vec::new(),
            deception_alerts: Vec::new(),
            target: None,
            ports: Vec::new(),
            raw_results: Vec::new(),
            enriched_results: Vec::new(),
            honeypot_assessments: Vec::new(),
            audited_results: Vec::new(),
            summary: None,
            stealth_telemetry: None,
            formatted_report: None,
        }
    }

    /// Return the current lifecycle state of the Mediator.
    pub fn state(&self) -> MediatorState {
        self.state
    }

    /// Allow a Colleague to announce the lifecycle phase it is entering without
    /// emitting a domain event (keeps the event trace focused on actionable telemetry).
    pub(crate) fn transition_to(&mut self, state: MediatorState) {
        self.state = state;
    }

    /// Return the chronological trace of all mediated events.
    pub fn event_trace(&self) -> &[MediatedEventRecord] {
        &self.event_trace
    }

    fn log_diagnostic(&self, sender: ComponentId, detail: &str) {
        if self.config.verbose {
            eprintln!("[Mediator <- {sender}] {detail}");
        }
    }

    /// Execute the full 6-colleague mediated workflow using a custom Stage 2 port prober closure.
    pub fn execute_with_prober<P>(mut self, prober: P) -> Result<PipelineOutput, DiscoveryError>
    where
        P: Fn(u16) -> RawProbeResult + Sync,
    {
        let start_time = Instant::now();
        self.state = MediatorState::Discovering;

        // Colleague 1: DiscoveryColleague
        if let Err(err) = DiscoveryColleague::run(&mut self, 0xA5A5_5A5A_F0F0_0F0F) {
            self.state = MediatorState::Failed;
            return Err(err);
        }

        // Colleague 2: ScannerColleague (with custom prober)
        ScannerColleague::run_with_prober(&mut self, prober);

        // Colleague 3: FingerprintColleague
        FingerprintColleague::run(&mut self);

        // Colleague 4: HoneypotColleague (deception behavior classification)
        HoneypotColleague::run(&mut self);

        // Colleague 5: AuditColleague
        AuditColleague::run(&mut self);

        // Compute stealth/anti-AI legitimacy telemetry before reporting.
        self.refresh_stealth_telemetry();

        // Colleague 6: ReportColleague
        let elapsed = start_time.elapsed();
        ReportColleague::run(&mut self, elapsed);

        Ok(self.into_output(elapsed))
    }

    /// Execute the full 6-colleague mediated workflow against the live network stack.
    pub fn execute(mut self) -> Result<PipelineOutput, DiscoveryError> {
        let start_time = Instant::now();
        let seed = start_time.elapsed().as_nanos() as u64 ^ 0xA5A5_5A5A_F0F0_0F0F;
        self.state = MediatorState::Discovering;

        // Colleague 1: DiscoveryColleague
        if let Err(err) = DiscoveryColleague::run(&mut self, seed) {
            self.state = MediatorState::Failed;
            return Err(err);
        }

        // Colleague 2: ScannerColleague (live TCP probing, mediated banner handoff)
        ScannerColleague::run_live(&mut self);

        // Colleague 3: FingerprintColleague
        FingerprintColleague::run(&mut self);

        // Colleague 4: HoneypotColleague (deception behavior classification)
        HoneypotColleague::run(&mut self);

        // Colleague 5: AuditColleague
        AuditColleague::run(&mut self);

        // Compute stealth/anti-AI legitimacy telemetry before reporting.
        self.refresh_stealth_telemetry();

        // Colleague 6: ReportColleague
        let elapsed = start_time.elapsed();
        ReportColleague::run(&mut self, elapsed);

        Ok(self.into_output(elapsed))
    }

    fn refresh_stealth_telemetry(&mut self) {
        if let Some(summary) = self.summary.as_ref() {
            let telemetry =
                evaluate_scan_legitimacy(&self.config.scanner, self.config.grab_banners, summary);
            self.stealth_telemetry = Some(telemetry);
        }
    }

    fn into_output(self, elapsed: Duration) -> PipelineOutput {
        PipelineOutput {
            target: self.target.expect("TargetInfo mediated in Stage 1"),
            audited_ports: self.audited_results,
            summary: self
                .summary
                .expect("SecurityPostureSummary mediated in Stage 5"),
            elapsed,
            formatted_report: self.formatted_report.unwrap_or_default(),
            event_trace: self.event_trace,
            critical_alerts: self.critical_alerts,
            deception_alerts: self.deception_alerts,
            honeypot_assessments: self.honeypot_assessments,
            stealth_telemetry: self.stealth_telemetry.unwrap_or_default(),
        }
    }
}

impl ScanMediator for ScanController {
    fn notify(&mut self, sender: ComponentId, event: ScanEvent) -> MediatorDirective {
        let event_name = event.event_name();

        let directive = match event {
            ScanEvent::TargetDiscovered { target, ports } => {
                self.log_diagnostic(
                    sender,
                    &format!(
                        "Resolved '{}' -> {} (Scope: {}, Ports: {})",
                        target.raw_input,
                        target.primary_ip,
                        target.scope,
                        ports.len()
                    ),
                );
                let is_public = target.scope == crate::mediator::contract::AddressScope::Public;
                self.target = Some(target);
                self.ports = ports;
                self.state = MediatorState::Probing;

                if is_public {
                    MediatorDirective::PublicTargetHardeningMode
                } else {
                    MediatorDirective::Proceed
                }
            }

            ScanEvent::ProbingCompleted { raw_results } => {
                let filtered_ports = raw_results
                    .iter()
                    .filter(|r| r.state == crate::mediator::contract::PortState::Filtered)
                    .count();
                self.log_diagnostic(
                    sender,
                    &format!(
                        "Probed {} port(s) (Filtered/Dropped: {})",
                        raw_results.len(),
                        filtered_ports
                    ),
                );
                let total_ports = raw_results.len();
                self.raw_results = raw_results;
                self.state = MediatorState::Fingerprinting;

                if filtered_ports > 0 {
                    let filtered_rate_pct = if total_ports == 0 {
                        0
                    } else {
                        ((filtered_ports.saturating_mul(100)) / total_ports).min(100) as u8
                    };
                    let stealth_active = self.config.scanner.stealth.mode != StealthMode::Normal
                        && self.config.scanner.stealth.adaptive_backoff;
                    if stealth_active && filtered_rate_pct >= 25 {
                        MediatorDirective::AdaptivePacingEngaged { filtered_rate_pct }
                    } else {
                        MediatorDirective::FirewallDropDetected { filtered_ports }
                    }
                } else {
                    MediatorDirective::Proceed
                }
            }

            ScanEvent::FingerprintingCompleted { enriched_results } => {
                self.log_diagnostic(
                    sender,
                    &format!("Fingerprinted {} port result(s)", enriched_results.len()),
                );
                self.enriched_results = enriched_results;
                self.state = MediatorState::HoneypotAnalysis;
                MediatorDirective::Proceed
            }

            ScanEvent::HoneypotAssessmentCompleted { assessments } => {
                let possible = assessments
                    .iter()
                    .filter(|a| {
                        a.verdict == crate::mediator::contract::HoneypotVerdict::PossibleHoneypot
                    })
                    .count();
                let confirmed = assessments
                    .iter()
                    .filter(|a| a.verdict == crate::mediator::contract::HoneypotVerdict::Honeypot)
                    .count();
                self.log_diagnostic(
                    sender,
                    &format!(
                        "Honeypot analysis: {} confirmed, {} possible, {} clean",
                        confirmed,
                        possible,
                        assessments.len().saturating_sub(confirmed + possible)
                    ),
                );
                if confirmed > 0 {
                    self.deception_alerts.push(format!(
                        "HONEYPOT CONFIRMED on {confirmed} port(s); treat target as a deception environment"
                    ));
                } else if possible > 0 {
                    self.deception_alerts.push(format!(
                        "POSSIBLE HONEYPOT on {possible} port(s); corroborate before deeper interaction"
                    ));
                }
                self.honeypot_assessments = assessments;
                self.state = MediatorState::Auditing;

                if confirmed > 0 {
                    MediatorDirective::ConfirmedHoneypotDetected { count: confirmed }
                } else if possible > 0 {
                    MediatorDirective::PossibleHoneypotDetected { count: possible }
                } else {
                    MediatorDirective::Proceed
                }
            }

            ScanEvent::CriticalFindingDetected {
                port,
                service,
                advisory,
            } => {
                let alert = format!("CRITICAL port {port} ({service}): {advisory}");
                self.log_diagnostic(sender, &alert);
                self.critical_alerts.push(alert);
                MediatorDirective::EscalateCriticalAlert { port, service }
            }

            ScanEvent::AuditCompleted {
                audited_results,
                summary,
            } => {
                self.log_diagnostic(
                    sender,
                    &format!(
                        "Audit complete: Open={}, Filtered={}, Grade={} (Score={}/100)",
                        summary.open_count,
                        summary.filtered_count,
                        summary.posture_grade,
                        summary.exposure_score
                    ),
                );
                self.audited_results = audited_results;
                self.summary = Some(summary);
                self.state = MediatorState::Reporting;
                MediatorDirective::Proceed
            }

            ScanEvent::ReportRendered { formatted_report } => {
                self.log_diagnostic(
                    sender,
                    &format!("Rendered final report ({} bytes)", formatted_report.len()),
                );
                self.formatted_report = Some(formatted_report);
                self.state = MediatorState::Completed;
                MediatorDirective::Proceed
            }
        };

        self.event_trace.push(MediatedEventRecord {
            sender,
            event_name,
            resulting_state: self.state,
            directive: directive.clone(),
        });

        directive
    }

    fn mediate_open_stream(&self, port: u16, stream: &mut TcpStream) -> Option<String> {
        if !self.config.grab_banners {
            return None;
        }
        // Mediator delegates banner inspection to FingerprintColleague without ScannerColleague
        // ever importing or knowing about FingerprintColleague.
        let stealth = &self.config.scanner.stealth;
        if stealth.mode == StealthMode::Normal {
            return FingerprintColleague::inspect_live_stream(
                port,
                stream,
                self.config.banner_timeout,
            );
        }

        let host = self
            .target
            .as_ref()
            .map(|target| target.raw_input.as_str())
            .unwrap_or("localhost");
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x51ED_270B_9E37_79B9)
            ^ u64::from(port);
        FingerprintColleague::inspect_live_stream_with_persona(
            port,
            stream,
            self.config.banner_timeout,
            stealth.persona,
            host,
            seed,
        )
    }
}
