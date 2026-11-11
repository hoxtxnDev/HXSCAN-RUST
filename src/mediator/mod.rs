//! # Mediator Pattern Module (`src/mediator`)
//!
//! Implements the **Mediator Design Pattern** (also known as *Intermediary* or *Controller*)
//! to decouple all 6 cybersecurity scanning stages into independent Colleagues.

pub mod contract;
pub mod controller;

pub use contract::{
    AddressScope, AuditedPortResult, ComponentId, EnrichedPortResult, HoneypotAssessment,
    HoneypotBehavior, HoneypotVerdict, Language, MediatedEventRecord, MediatorDirective,
    MediatorState, OutputFormat, PortState, RawProbeResult, ReconIntelligence, ReportOptions,
    RiskLevel, ScanEvent, ScanMediator, ScannerConfig, SecurityPostureSummary, StealthConfig,
    StealthMode, StealthTelemetry, TargetInfo, TlsCertificateInfo, TrafficPersona,
};
pub use controller::{PipelineConfig, PipelineOutput, ScanController};
