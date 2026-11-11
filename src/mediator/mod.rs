//! # Mediator Pattern Module (`src/mediator`)
//!
//! Implements the **Mediator Design Pattern** (also known as *Intermediary* or *Controller*)
//! to decouple all 5 cybersecurity scanning stages into independent Colleagues.

pub mod contract;
pub mod controller;

pub use contract::{
    AddressScope, AuditedPortResult, ComponentId, EnrichedPortResult, HoneypotAssessment,
    HoneypotBehavior, HoneypotVerdict, MediatedEventRecord, MediatorDirective, MediatorState,
    OutputFormat, PortState, RawProbeResult, ReportOptions, RiskLevel, ScanEvent, ScanMediator,
    ScannerConfig, SecurityPostureSummary, StealthConfig, StealthMode, StealthTelemetry,
    TargetInfo, TrafficPersona,
};
pub use controller::{PipelineConfig, PipelineOutput, ScanController};
