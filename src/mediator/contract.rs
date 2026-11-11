//! # Mediator Pattern Contracts (`mediator::contract`)
//!
//! Defines the **Mediator (Intermediary / Controller)** interfaces, shared domain data structures,
//! [`ComponentId`] identifiers, [`ScanEvent`] notifications, and [`MediatorDirective`] commands.
//!
//! ## Architectural Guarantee (Zero Cross-Stage Coupling)
//! None of the concrete stage modules (`stage1_discovery`, `stage2_scanner`, `stage3_fingerprint`,
//! `stage4_audit`, `stage5_report`) import one another. Every colleague depends **only** on
//! `crate::mediator::contract` and communicates exclusively through the [`ScanMediator`] trait.

use std::fmt;
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

/// Identifies each Colleague component registered with the Mediator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentId {
    /// Stage 0: CLI Parser / User Input Colleague.
    CliColleague,
    /// Stage 1: Target Discovery, DNS & Port Bitmap Colleague.
    DiscoveryColleague,
    /// Stage 2: Concurrent TCP Probing Engine Colleague.
    ScannerColleague,
    /// Stage 3: Service Identification & Banner Grabbing Colleague.
    FingerprintColleague,
    /// Stage 4: Cybersecurity Risk & Posture Audit Colleague.
    AuditColleague,
    /// Stage 5: Telemetry & Multi-Format Reporting Colleague.
    ReportColleague,
}

impl ComponentId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CliColleague => "Stage0::CliColleague",
            Self::DiscoveryColleague => "Stage1::DiscoveryColleague",
            Self::ScannerColleague => "Stage2::ScannerColleague",
            Self::FingerprintColleague => "Stage3::FingerprintColleague",
            Self::AuditColleague => "Stage4::AuditColleague",
            Self::ReportColleague => "Stage5::ReportColleague",
        }
    }
}

impl fmt::Display for ComponentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle state of the [`ScanMediator`] controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediatorState {
    Idle,
    Discovering,
    Probing,
    Fingerprinting,
    Auditing,
    Reporting,
    Completed,
    Failed,
}

/// Classification of the target IP address network scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressScope {
    /// Loopback interface (`127.0.0.0/8`, `::1`).
    Loopback,
    /// RFC 1918 Private network (`10/8`, `172.16/12`, `192.168/16`) or IPv6 ULA (`fc00::/7`).
    Private,
    /// Link-local address (`169.254.0.0/16`, `fe80::/10`).
    LinkLocal,
    /// Globally routable public internet address.
    Public,
}

impl AddressScope {
    /// Classify an [`IpAddr`] into its [`AddressScope`].
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() {
                    Self::Loopback
                } else if v4.is_private() {
                    Self::Private
                } else if v4.is_link_local() {
                    Self::LinkLocal
                } else {
                    Self::Public
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    Self::Loopback
                } else if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                    Self::Private
                } else if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                    Self::LinkLocal
                } else {
                    Self::Public
                }
            }
        }
    }

    /// Human-readable label for reporting.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Private => "private-lan",
            Self::LinkLocal => "link-local",
            Self::Public => "public-internet",
        }
    }
}

impl fmt::Display for AddressScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resolved target metadata produced by `DiscoveryColleague` (Stage 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetInfo {
    /// Original user-supplied target string (hostname or IP).
    pub raw_input: String,
    /// Primary resolved IP address used for probing.
    pub primary_ip: IpAddr,
    /// All IP addresses returned by DNS resolution.
    pub all_ips: Vec<IpAddr>,
    /// Network scope classification of `primary_ip`.
    pub scope: AddressScope,
    /// Optional port extracted if the user passed `host:port` syntax.
    pub inline_port: Option<u16>,
}

/// Precise TCP port state determined by `ScannerColleague` (Stage 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortState {
    /// TCP 3-way handshake succeeded (`SYN` -> `SYN/ACK` -> `ACK`).
    Open,
    /// Target actively rejected connection with TCP `RST` (`ECONNREFUSED`).
    Closed,
    /// Probe timed out or was blocked by a packet filter/firewall (`ETIMEDOUT` / `EHOSTUNREACH`).
    Filtered,
    /// Unexpected socket/OS error occurred.
    Error(String),
}

impl PortState {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Filtered => "filtered",
            Self::Error(_) => "error",
        }
    }

    #[inline]
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Open)
    }
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuration parameters for `ScannerColleague` (Stage 2).
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Maximum concurrent worker threads.
    pub threads: usize,
    /// Per-attempt TCP connection timeout.
    pub timeout: Duration,
    /// Number of additional retries when a probe times out (`Filtered`).
    pub retries: u8,
    /// Optional delay between consecutive probes per worker (stealth / rate-limiting).
    pub delay: Duration,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            threads: 100,
            timeout: Duration::from_millis(1000),
            retries: 0,
            delay: Duration::ZERO,
        }
    }
}

/// Raw probe telemetry emitted by `ScannerColleague` (Stage 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawProbeResult {
    pub port: u16,
    pub state: PortState,
    pub rtt_micros: Option<u64>,
    pub attempts: u8,
    pub inline_banner: Option<String>,
}

impl RawProbeResult {
    pub fn rtt_ms(&self) -> Option<f64> {
        self.rtt_micros.map(|us| (us as f64) / 1000.0)
    }
}

/// Enriched port result produced by `FingerprintColleague` (Stage 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrichedPortResult {
    pub port: u16,
    pub state: PortState,
    pub service: String,
    pub banner: Option<String>,
    pub rtt_micros: Option<u64>,
}

impl EnrichedPortResult {
    pub fn rtt_ms(&self) -> Option<f64> {
        self.rtt_micros.map(|us| (us as f64) / 1000.0)
    }
}

/// Cybersecurity risk severity assigned by `AuditColleague` (Stage 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    None,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    pub fn weight(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Info => 2,
            Self::Low => 5,
            Self::Medium => 12,
            Self::High => 25,
            Self::Critical => 45,
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Complete per-port record after `AuditColleague` (Stage 4) evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditedPortResult {
    pub port: u16,
    pub state: PortState,
    pub service: String,
    pub banner: Option<String>,
    pub rtt_micros: Option<u64>,
    pub risk: RiskLevel,
    pub category: &'static str,
    pub advisory: String,
}

impl AuditedPortResult {
    pub fn rtt_ms(&self) -> Option<f64> {
        self.rtt_micros.map(|us| (us as f64) / 1000.0)
    }
}

/// Aggregate cybersecurity posture summary produced by `AuditColleague` (Stage 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityPostureSummary {
    pub total_scanned: usize,
    pub open_count: usize,
    pub closed_count: usize,
    pub filtered_count: usize,
    pub error_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub exposure_score: u8,
    pub posture_grade: char,
    pub firewall_detected: bool,
}

/// Supported report output formats in `ReportColleague` (Stage 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    Csv,
}

/// Options controlling `ReportColleague` (Stage 5) rendering.
#[derive(Debug, Clone)]
pub struct ReportOptions {
    pub format: OutputFormat,
    pub show_closed: bool,
    pub use_color: bool,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            format: OutputFormat::Human,
            show_closed: false,
            use_color: true,
        }
    }
}

/// Events emitted by Colleague components to the [`ScanMediator`].
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// Emitted by `DiscoveryColleague` when DNS resolution and port bitmap expansion succeed.
    TargetDiscovered {
        target: TargetInfo,
        ports: Vec<u16>,
    },
    /// Emitted by `ScannerColleague` when the concurrent TCP probing batch finishes.
    ProbingCompleted {
        raw_results: Vec<RawProbeResult>,
    },
    /// Emitted by `FingerprintColleague` when service mapping & banner enrichment finish.
    FingerprintingCompleted {
        enriched_results: Vec<EnrichedPortResult>,
    },
    /// Emitted by `AuditColleague` when a `Critical` risk service is identified.
    CriticalFindingDetected {
        port: u16,
        service: String,
        advisory: String,
    },
    /// Emitted by `AuditColleague` when the full attack surface posture evaluation completes.
    AuditCompleted {
        audited_results: Vec<AuditedPortResult>,
        summary: SecurityPostureSummary,
    },
    /// Emitted by `ReportColleague` when the final output string has been rendered.
    ReportRendered {
        formatted_report: String,
    },
}

impl ScanEvent {
    /// Short name of the event for audit trail / telemetry logs.
    pub fn event_name(&self) -> &'static str {
        match self {
            Self::TargetDiscovered { .. } => "TargetDiscovered",
            Self::ProbingCompleted { .. } => "ProbingCompleted",
            Self::FingerprintingCompleted { .. } => "FingerprintingCompleted",
            Self::CriticalFindingDetected { .. } => "CriticalFindingDetected",
            Self::AuditCompleted { .. } => "AuditCompleted",
            Self::ReportRendered { .. } => "ReportRendered",
        }
    }
}

/// Reactive directives issued by the [`ScanMediator`] back to colleagues based on observed events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediatorDirective {
    /// Proceed normally to the next lifecycle phase.
    Proceed,
    /// Target is on the public internet: Mediator advises stricter banner timeout and audit alerts.
    PublicTargetHardeningMode,
    /// High packet filter rate detected: Mediator flags active firewall presence.
    FirewallDropDetected { filtered_ports: usize },
    /// Immediate alert recorded due to critical exposure (`CriticalFindingDetected`).
    EscalateCriticalAlert { port: u16, service: String },
}

/// Record of a single mediated interaction for observability and testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatedEventRecord {
    pub sender: ComponentId,
    pub event_name: &'static str,
    pub resulting_state: MediatorState,
    pub directive: MediatorDirective,
}

/// **The Mediator Interface (`ScanMediator`)** — also known as *Intermediary* or *Controller*.
///
/// Colleague components never call each other directly. Instead:
/// 1. A Colleague finishes its specialized work and calls [`ScanMediator::notify`].
/// 2. Or during socket connection in Stage 2, `ScannerColleague` asks the Mediator to
///    mediate stream inspection via [`ScanMediator::mediate_open_stream`] without knowing
///    anything about `FingerprintColleague`!
pub trait ScanMediator: Sync {
    /// Receive an event from a Colleague, update shared orchestration state, and return a [`MediatorDirective`].
    fn notify(&mut self, sender: ComponentId, event: ScanEvent) -> MediatorDirective;

    /// Mediate live socket inspection when `ScannerColleague` establishes an open TCP connection.
    /// Allows the Mediator to delegate to `FingerprintColleague` (if banner grabbing is enabled)
    /// without `ScannerColleague` knowing `FingerprintColleague` exists.
    fn mediate_open_stream(&self, port: u16, stream: &mut TcpStream) -> Option<String>;
}
