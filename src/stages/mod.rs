//! # Colleague Stages Module (`src/stages`)
//!
//! Houses the 5 decoupled **Colleague** modules of `tcpscan`:
//! - [`stage1_discovery::DiscoveryColleague`]
//! - [`stage2_scanner::ScannerColleague`]
//! - [`stage3_fingerprint::FingerprintColleague`]
//! - [`stage4_audit::AuditColleague`]
//! - [`stage5_report::ReportColleague`]
//!
//! None of these modules import each other; all coordination happens via [`crate::mediator::ScanController`].

pub mod stage1_discovery;
pub mod stage2_scanner;
pub mod stage3_fingerprint;
pub mod stage4_audit;
pub mod stage5_report;

pub use crate::mediator::{PipelineConfig, PipelineOutput, ScanController};

/// Type alias preserving `ScanPipeline` compatibility over the [`ScanController`] Mediator.
pub type ScanPipeline = ScanController;
