//! # Mediator Pattern Contracts (`mediator::contract`)
//!
//! Defines the **Mediator (Intermediary / Controller)** interfaces, shared domain data structures,
//! [`ComponentId`] identifiers, [`ScanEvent`] notifications, and [`MediatorDirective`] commands.
//!
//! ## Architectural Guarantee (Zero Cross-Stage Coupling)
//! None of the concrete stage modules (`stage1_discovery`, `stage2_scanner`, `stage3_fingerprint`,
//! `stage4_honeypot`, `stage5_audit`, `stage6_report`) import one another. Every colleague depends
//! **only** on `crate::mediator::contract` and communicates exclusively through the
//! [`ScanMediator`] trait.

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
    /// Stage 4: Honeypot & Deception Behavior Analysis Colleague.
    HoneypotColleague,
    /// Stage 5: Cybersecurity Risk & Posture Audit Colleague.
    AuditColleague,
    /// Stage 6: Telemetry & Multi-Format Reporting Colleague.
    ReportColleague,
}

impl ComponentId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CliColleague => "Stage0::CliColleague",
            Self::DiscoveryColleague => "Stage1::DiscoveryColleague",
            Self::ScannerColleague => "Stage2::ScannerColleague",
            Self::FingerprintColleague => "Stage3::FingerprintColleague",
            Self::HoneypotColleague => "Stage4::HoneypotColleague",
            Self::AuditColleague => "Stage5::AuditColleague",
            Self::ReportColleague => "Stage6::ReportColleague",
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
    HoneypotAnalysis,
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

/// Operational stealth posture selected by the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StealthMode {
    /// Standard scanner behavior (fast, explicit `tcpscan` signatures).
    Normal,
    /// Low-noise pacing: shuffled ports, jitter, rate ceiling and no active banners by default.
    Stealth,
    /// Corporate blend mode: human-like bursts, enterprise personas and adaptive pacing.
    Mutable,
}

impl StealthMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Stealth => "stealth",
            Self::Mutable => "mutable",
        }
    }
}

impl fmt::Display for StealthMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Legitimate-looking client identity used by the *mutable* traffic mutation layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficPersona {
    /// Neutral browser-like client.
    Generic,
    /// Managed corporate workstation (Edge/Chrome + enterprise headers).
    CorporateWorkstation,
    /// Common desktop browser (Firefox).
    Browser,
    /// Windows Update / Delivery Optimization background agent.
    MicrosoftUpdate,
    /// Enterprise backup / BITS transfer agent.
    BackupAgent,
}

impl TrafficPersona {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::CorporateWorkstation => "corporate",
            Self::Browser => "browser",
            Self::MicrosoftUpdate => "windows-update",
            Self::BackupAgent => "backup-agent",
        }
    }
}

impl fmt::Display for TrafficPersona {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Anti-fingerprinting / anti-AI legitimacy envelope applied to Stage 2 and Stage 3.
///
/// **Authorized use only**: these controls reduce obvious scanner signatures and keep
/// probe cadence inside normal enterprise traffic envelopes. They do not guarantee
/// evasion of AI/ML, IDS/IPS or EDR products.
#[derive(Debug, Clone)]
pub struct StealthConfig {
    /// Selected stealth posture.
    pub mode: StealthMode,
    /// Client identity used for HTTP banner requests in mutable mode.
    pub persona: TrafficPersona,
    /// Additional uniform random jitter applied to each inter-probe delay.
    pub jitter: Duration,
    /// Global probes-per-second ceiling (`0.0` = unlimited).
    pub max_pps: f64,
    /// Number of probes per burst before a longer pause (`0` = disabled).
    pub burst_size: usize,
    /// Pause inserted after each burst.
    pub burst_pause: Duration,
    /// Increase pacing when filtered/dropped probes suggest defensive feedback.
    pub adaptive_backoff: bool,
    /// Number of decoy probes interleaved against the *same authorized target*.
    pub decoy_probes: usize,
    /// Enable the anti-AI legitimacy envelope bookkeeping/assessment.
    pub ai_filter: bool,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            mode: StealthMode::Normal,
            persona: TrafficPersona::Generic,
            jitter: Duration::ZERO,
            max_pps: 0.0,
            burst_size: 0,
            burst_pause: Duration::ZERO,
            adaptive_backoff: false,
            decoy_probes: 0,
            ai_filter: false,
        }
    }
}

impl StealthConfig {
    /// True when any legitimacy-envelope control is active.
    pub fn is_active(&self) -> bool {
        self.mode != StealthMode::Normal
            || !self.jitter.is_zero()
            || self.max_pps > 0.0
            || self.burst_size > 0
            || self.adaptive_backoff
            || self.ai_filter
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
    /// Stealth, mutable and anti-AI legitimacy envelope settings.
    pub stealth: StealthConfig,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            threads: 100,
            timeout: Duration::from_millis(1000),
            retries: 0,
            delay: Duration::ZERO,
            stealth: StealthConfig::default(),
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

/// X.509 certificate metadata extracted by `FingerprintColleague` (Stage 3) during a
/// TLS 1.2 `ClientHello` exchange. No cryptographic verification is performed: the
/// handshake stops after the server certificate, so this is **reconnaissance metadata**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCertificateInfo {
    /// Subject Common Name (`CN`) from the leaf certificate.
    pub subject_cn: Option<String>,
    /// Issuer Common Name (`CN`).
    pub issuer_cn: Option<String>,
    /// DNS Subject Alternative Names (`SAN`), deduplicated and capped.
    pub sans: Vec<String>,
    /// Raw `notAfter` value as encoded in the certificate.
    pub not_after: Option<String>,
    /// Days remaining until `notAfter` (negative when expired).
    pub days_until_expiry: Option<i64>,
    /// Subject and issuer are identical (strong signal of a self-signed certificate).
    pub self_signed: bool,
    /// The presented identity does not match the SNI hostname.
    pub hostname_mismatch: bool,
    /// Number of certificates advertised in the server chain.
    pub chain_length: usize,
}

impl TlsCertificateInfo {
    /// Compact borrowed identity slice used by reports without heap allocation.
    #[inline]
    pub fn identity(&self) -> &str {
        self.subject_cn
            .as_deref()
            .or_else(|| self.sans.first().map(String::as_str))
            .unwrap_or("<no CN>")
    }

    /// True when the certificate's `notAfter` date is in the past.
    #[inline]
    pub fn is_expired(&self) -> bool {
        self.days_until_expiry.map(|days| days < 0).unwrap_or(false)
    }
}

/// Enriched port result produced by `FingerprintColleague` (Stage 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrichedPortResult {
    pub port: u16,
    pub state: PortState,
    pub service: String,
    /// Protocol version extracted from the banner (e.g. `OpenSSH_9.7p1`, `nginx/1.26.0`).
    pub service_version: Option<String>,
    pub banner: Option<String>,
    pub rtt_micros: Option<u64>,
    /// TLS certificate metadata for TLS-enabled ports.
    pub tls: Option<TlsCertificateInfo>,
}

impl EnrichedPortResult {
    pub fn rtt_ms(&self) -> Option<f64> {
        self.rtt_micros.map(|us| (us as f64) / 1000.0)
    }
}

/// Deception verdict assigned by `HoneypotColleague` (Stage 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HoneypotVerdict {
    /// No deception indicators observed.
    Clean,
    /// Several weak/medium indicators suggest a possible deceptive environment.
    PossibleHoneypot,
    /// Strong indicators: known honeypot signature, contradictory services or mass exposure.
    Honeypot,
}

impl HoneypotVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::PossibleHoneypot => "possible-honeypot",
            Self::Honeypot => "honeypot",
        }
    }

    /// Compact label used by the human report.
    pub fn badge(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::PossibleHoneypot => "POSSIBLE",
            Self::Honeypot => "HONEYPOT",
        }
    }
}

impl fmt::Display for HoneypotVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Observable behaviors that increase the deception confidence score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoneypotBehavior {
    /// Banner matches Cowrie, Kippo, Dionaea, Thinkst Canary, Honeyd, etc.
    KnownHoneypotSignature,
    /// Port is frequently used by honeypot deployments.
    HoneypotPort,
    /// Banner protocol contradicts the port/service identity.
    ServicePortMismatch,
    /// A single banner mixes multiple incompatible protocols.
    ContradictoryBanner,
    /// Abnormally slow handshake, consistent with a tarpit.
    TarpitLatency,
    /// A large fraction/quantity of scanned ports is open.
    MassOpenServices,
    /// Suspiciously uniform RTT across many open ports (synthetic responders).
    UniformRtt,
    /// Multiple services return the exact same banner.
    ClonedBanners,
    /// Interactive credential prompt exposed by an unexpected service.
    DefaultCredentialPrompt,
    /// Legacy/fake version string commonly used by deception frameworks.
    FakeVersionDisclosure,
    /// Interactive service accepted the connection but returned no banner.
    BannerlessInteractiveService,
    /// Service exposed on an ephemeral/high port.
    UnusualEphemeralService,
    /// Multiple known honeypot ports are open on the same target.
    HoneypotPortCluster,
    /// The leaf certificate is self-signed.
    SelfSignedCertificate,
    /// The certificate identity does not match the requested SNI hostname.
    CertificateHostnameMismatch,
    /// The certificate is expired according to its `notAfter` field.
    ExpiredCertificate,
    /// The certificate uses a default/lab identity commonly seen in deception deployments.
    DefaultCertificateIdentity,
}

impl HoneypotBehavior {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KnownHoneypotSignature => "known-honeypot-signature",
            Self::HoneypotPort => "honeypot-port",
            Self::ServicePortMismatch => "service-port-mismatch",
            Self::ContradictoryBanner => "contradictory-banner",
            Self::TarpitLatency => "tarpit-latency",
            Self::MassOpenServices => "mass-open-services",
            Self::UniformRtt => "uniform-rtt",
            Self::ClonedBanners => "cloned-banners",
            Self::DefaultCredentialPrompt => "default-credential-prompt",
            Self::FakeVersionDisclosure => "fake-version-disclosure",
            Self::BannerlessInteractiveService => "bannerless-interactive-service",
            Self::UnusualEphemeralService => "unusual-ephemeral-service",
            Self::HoneypotPortCluster => "honeypot-port-cluster",
            Self::SelfSignedCertificate => "self-signed-certificate",
            Self::CertificateHostnameMismatch => "certificate-hostname-mismatch",
            Self::ExpiredCertificate => "expired-certificate",
            Self::DefaultCertificateIdentity => "default-certificate-identity",
        }
    }

    /// Weight contributed to the 0..=100 deception confidence score.
    pub fn weight(&self) -> u8 {
        match self {
            Self::KnownHoneypotSignature => 80,
            Self::HoneypotPort => 20,
            Self::ServicePortMismatch => 35,
            Self::ContradictoryBanner => 30,
            Self::TarpitLatency => 20,
            Self::MassOpenServices => 45,
            Self::UniformRtt => 20,
            Self::ClonedBanners => 25,
            Self::DefaultCredentialPrompt => 20,
            Self::FakeVersionDisclosure => 15,
            Self::BannerlessInteractiveService => 10,
            Self::UnusualEphemeralService => 10,
            Self::HoneypotPortCluster => 20,
            Self::SelfSignedCertificate => 25,
            Self::CertificateHostnameMismatch => 30,
            Self::ExpiredCertificate => 15,
            Self::DefaultCertificateIdentity => 25,
        }
    }
}

impl fmt::Display for HoneypotBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-port deception assessment produced by `HoneypotColleague` (Stage 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoneypotAssessment {
    pub port: u16,
    pub verdict: HoneypotVerdict,
    pub score: u8,
    pub behaviors: Vec<HoneypotBehavior>,
    pub notes: String,
}

impl HoneypotAssessment {
    /// Neutral assessment for closed/filtered ports or when no signal is present.
    pub fn clean(port: u16) -> Self {
        Self {
            port,
            verdict: HoneypotVerdict::Clean,
            score: 0,
            behaviors: Vec::new(),
            notes: String::new(),
        }
    }

    pub fn is_suspicious(&self) -> bool {
        self.verdict != HoneypotVerdict::Clean
    }

    pub fn behavior_summary(&self) -> String {
        self.behaviors
            .iter()
            .map(HoneypotBehavior::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Cybersecurity risk severity assigned by `AuditColleague` (Stage 5).
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

/// Complete per-port record after `AuditColleague` (Stage 5) evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditedPortResult {
    pub port: u16,
    pub state: PortState,
    pub service: String,
    /// Protocol version extracted from the banner (Stage 3).
    pub service_version: Option<String>,
    /// Standardized NVD CPE 2.3 identifier when product/version is known (Stage 5).
    pub cpe: Option<String>,
    /// High-impact CVE / CWE identifiers correlated with the detected version/exposure (Stage 5).
    pub cves: Vec<String>,
    pub banner: Option<String>,
    pub rtt_micros: Option<u64>,
    pub risk: RiskLevel,
    pub category: &'static str,
    pub advisory: String,
    /// TLS certificate metadata collected by Stage 3.
    pub tls: Option<TlsCertificateInfo>,
    /// Deception/honeypot behavior classification attached by Stage 4.
    pub honeypot: HoneypotAssessment,
}

impl AuditedPortResult {
    pub fn rtt_ms(&self) -> Option<f64> {
        self.rtt_micros.map(|us| (us as f64) / 1000.0)
    }
}

/// Aggregate cybersecurity posture summary produced by `AuditColleague` (Stage 5).
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
    /// Ports classified as `PossibleHoneypot` by Stage 4.
    pub possible_honeypot_count: usize,
    /// Ports classified as confirmed `Honeypot` by Stage 4.
    pub confirmed_honeypot_count: usize,
    /// Passive operating-system hint inferred from service banners and open port profile.
    pub os_hint: Option<String>,
    /// Hybrid multi-port reconnaissance intelligence synthesized by Stage 5.
    pub recon: ReconIntelligence,
}

/// Hybrid Red/Purple-Team Reconnaissance Intelligence synthesized across all open ports
/// on the target host (`Stage 5` -> `Stage 6` via Mediator).
///
/// Combines multi-port architectural role classification, cross-port toxic exposure
/// combinations, RTT micro-variance DNAT/reverse-proxy split detection, and shadow-asset
/// hostname extraction from X.509 SANs and service banners.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconIntelligence {
    /// Inferred architectural role of the host from its open port combination.
    pub host_role: String,
    /// Network proximity tier inferred from minimum clean TCP handshake RTT.
    pub network_topology: String,
    /// Present when clean open ports exhibit >= 4x RTT divergence (>= 15ms delta),
    /// indicating local reverse-proxy termination vs remote DNAT/tunnel port-forwarding.
    pub rtt_split_anomaly: Option<String>,
    /// Unique alternate DNS hostnames / subdomains discovered in TLS SANs, CNs, or banners.
    pub shadow_assets: Vec<String>,
    /// Multi-port attack-path correlations where co-resident services amplify risk.
    pub toxic_combinations: Vec<String>,
}

/// Stealth / anti-AI legitimacy telemetry rendered in the final report.
#[derive(Debug, Clone, PartialEq)]
pub struct StealthTelemetry {
    pub mode: StealthMode,
    pub persona: TrafficPersona,
    pub ai_filter: bool,
    pub max_pps: f64,
    pub jitter_ms: u64,
    pub burst_size: usize,
    pub burst_pause_ms: u64,
    pub decoy_probes: usize,
    pub adaptive_backoff: bool,
    pub filtered_ratio_pct: u8,
    pub legitimacy_score: u8,
    pub legitimacy_grade: char,
}

impl Default for StealthTelemetry {
    fn default() -> Self {
        Self {
            mode: StealthMode::Normal,
            persona: TrafficPersona::Generic,
            ai_filter: false,
            max_pps: 0.0,
            jitter_ms: 0,
            burst_size: 0,
            burst_pause_ms: 0,
            decoy_probes: 0,
            adaptive_backoff: false,
            filtered_ratio_pct: 0,
            legitimacy_score: 50,
            legitimacy_grade: 'D',
        }
    }
}

/// Supported report output formats in `ReportColleague` (Stage 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    Csv,
    /// Nmap-style grepable output (`-oG` / `--grepable`).
    Grepable,
    /// Naabu-style minimal `host:port` output for pipelines (`--silent`).
    Silent,
}

/// Options controlling `ReportColleague` (Stage 6) rendering.
#[derive(Debug, Clone)]
pub struct ReportOptions {
    pub format: OutputFormat,
    pub show_closed: bool,
    pub use_color: bool,
    /// Render the honeypot-filtered Nmap follow-up command (`--nmap-cmd` / `-A`).
    pub show_nmap_cmd: bool,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            format: OutputFormat::Human,
            show_closed: false,
            use_color: true,
            show_nmap_cmd: false,
        }
    }
}

/// Events emitted by Colleague components to the [`ScanMediator`].
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// Emitted by `DiscoveryColleague` when DNS resolution and port bitmap expansion succeed.
    TargetDiscovered { target: TargetInfo, ports: Vec<u16> },
    /// Emitted by `ScannerColleague` when the concurrent TCP probing batch finishes.
    ProbingCompleted { raw_results: Vec<RawProbeResult> },
    /// Emitted by `FingerprintColleague` when service mapping & banner enrichment finish.
    FingerprintingCompleted {
        enriched_results: Vec<EnrichedPortResult>,
    },
    /// Emitted by `HoneypotColleague` when deception behavior analysis finishes.
    HoneypotAssessmentCompleted {
        assessments: Vec<HoneypotAssessment>,
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
    ReportRendered { formatted_report: String },
}

impl ScanEvent {
    /// Short name of the event for audit trail / telemetry logs.
    pub fn event_name(&self) -> &'static str {
        match self {
            Self::TargetDiscovered { .. } => "TargetDiscovered",
            Self::ProbingCompleted { .. } => "ProbingCompleted",
            Self::FingerprintingCompleted { .. } => "FingerprintingCompleted",
            Self::HoneypotAssessmentCompleted { .. } => "HoneypotAssessmentCompleted",
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
    /// Stealth/mutable mode observed defensive feedback and engaged adaptive pacing.
    AdaptivePacingEngaged { filtered_rate_pct: u8 },
    /// Stage 4 found weak/medium deception indicators.
    PossibleHoneypotDetected { count: usize },
    /// Stage 4 found strong deception indicators (known honeypot or contradictory behavior).
    ConfirmedHoneypotDetected { count: usize },
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

    /// Return TLS certificate metadata captured for `port` during Stage 2 stream mediation.
    ///
    /// The default implementation returns `None`, which keeps lightweight test mediators
    /// and alternative engines compatible without implementing TLS collection.
    fn tls_certificate(&self, _port: u16) -> Option<TlsCertificateInfo> {
        None
    }
}
