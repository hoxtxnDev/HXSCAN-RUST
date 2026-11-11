//! # Concrete Mediator / Controller (`mediator::controller`)
//!
//! Implements [`ScanController`] (the Concrete **Mediator**, **Intermediary**, or **Controller**),
//! which coordinates all 5 Colleague components (`DiscoveryColleague`, `ScannerColleague`,
//! `FingerprintColleague`, `AuditColleague`, `ReportColleague`) without any colleague referencing
//! another colleague directly.
//!
//! ## Key Responsibilities of `ScanController`
//! 1. **Centralized Communication Hub (Star Topology)**: Receives [`ScanEvent`] notifications from
//!    every Colleague and records a verifiable [`MediatedEventRecord`] trace.
//! 2. **Reactive Orchestration & Adaptive Directives**: Issues [`MediatorDirective`] responses when
//!    special network conditions arise (e.g., `PublicTargetHardeningMode`, `FirewallDropDetected`,
//!    `EscalateCriticalAlert`).
//! 3. **Decoupled Stream Mediation**: Implements [`ScanMediator::mediate_open_stream`] so
//!    `ScannerColleague` can hand off an open `TcpStream` to the Mediator without knowing
//!    `FingerprintColleague` exists.

use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::mediator::contract::{
    AuditedPortResult, ComponentId, EnrichedPortResult, MediatedEventRecord, MediatorDirective,
    MediatorState, RawProbeResult, ReportOptions, ScanEvent, ScanMediator, ScannerConfig,
    SecurityPostureSummary, TargetInfo,
};
use crate::stages::stage1_discovery::{DiscoveryColleague, DiscoveryError};
use crate::stages::stage2_scanner::ScannerColleague;
use crate::stages::stage3_fingerprint::FingerprintColleague;
use crate::stages::stage4_audit::AuditColleague;
use crate::stages::stage5_report::ReportColleague;

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
    // Shared blackboard state mediated across Colleagues:
    pub(crate) target: Option<TargetInfo>,
    pub(crate) ports: Vec<u16>,
    pub(crate) raw_results: Vec<RawProbeResult>,
    pub(crate) enriched_results: Vec<EnrichedPortResult>,
    pub(crate) audited_results: Vec<AuditedPortResult>,
    pub(crate) summary: Option<SecurityPostureSummary>,
    pub(crate) formatted_report: Option<String>,
}

impl ScanController {
    /// Construct a new [`ScanController`] Mediator in `MediatorState::Idle`.
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            config,
            state: MediatorState::Idle,
            event_trace: Vec::with_capacity(8),
            critical_alerts: Vec::new(),
            target: None,
            ports: Vec::new(),
            raw_results: Vec::new(),
            enriched_results: Vec::new(),
            audited_results: Vec::new(),
            summary: None,
            formatted_report: None,
        }
    }

    /// Return the current lifecycle state of the Mediator.
    pub fn state(&self) -> MediatorState {
        self.state
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

    /// Execute the full 5-colleague mediated workflow using a custom Stage 2 port prober closure.
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

        // Colleague 4: AuditColleague
        AuditColleague::run(&mut self);

        // Colleague 5: ReportColleague
        let elapsed = start_time.elapsed();
        ReportColleague::run(&mut self, elapsed);

        Ok(self.into_output(elapsed))
    }

    /// Execute the full 5-colleague mediated workflow against the live network stack.
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

        // Colleague 4: AuditColleague
        AuditColleague::run(&mut self);

        // Colleague 5: ReportColleague
        let elapsed = start_time.elapsed();
        ReportColleague::run(&mut self, elapsed);

        Ok(self.into_output(elapsed))
    }

    fn into_output(self, elapsed: Duration) -> PipelineOutput {
        PipelineOutput {
            target: self.target.expect("TargetInfo mediated in Stage 1"),
            audited_ports: self.audited_results,
            summary: self.summary.expect("SecurityPostureSummary mediated in Stage 4"),
            elapsed,
            formatted_report: self.formatted_report.unwrap_or_default(),
            event_trace: self.event_trace,
            critical_alerts: self.critical_alerts,
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
                let is_public =
                    target.scope == crate::mediator::contract::AddressScope::Public;
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
                self.raw_results = raw_results;
                self.state = MediatorState::Fingerprinting;

                if filtered_ports > 0 {
                    MediatorDirective::FirewallDropDetected { filtered_ports }
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
                self.state = MediatorState::Auditing;
                MediatorDirective::Proceed
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
        FingerprintColleague::inspect_live_stream(port, stream, self.config.banner_timeout)
    }
}
