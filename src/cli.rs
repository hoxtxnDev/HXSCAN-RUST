//! # Stage 0: Ergonomic & Hardened CLI Parser for `tcpscan` / `hxscan`
//!
//! Designed for zero-friction simplicity (`tcpscan <target> [ports]`) while maintaining
//! 100% backward compatibility with legacy `hxscan` flags and enforcing **Origin Host Protection**
//! bounds against resource exhaustion (`MAX_SAFE_THREADS`, `MAX_TIMEOUT_SECS`, `MAX_DELAY_MS`,
//! `MAX_RETRIES`, and `--protect-origin`).

use std::time::Duration;

use crate::mediator::{
    OutputFormat, PipelineConfig, ReportOptions, ScannerConfig, StealthConfig, StealthMode,
    TrafficPersona,
};
use crate::stages::stage1_discovery::{DEFAULT_PORTS_SPEC, QUICK_PORTS_SPEC};

/// Hard upper bound on concurrent worker threads to prevent OS thread/FD exhaustion (`EMFILE`) on origin host.
pub const MAX_SAFE_THREADS: usize = 2048;

/// Minimum allowed socket timeout in seconds (`10ms`).
pub const MIN_TIMEOUT_SECS: f64 = 0.01;

/// Maximum allowed socket timeout in seconds (`60s`) to prevent local socket starvation.
pub const MAX_TIMEOUT_SECS: f64 = 60.0;

/// Maximum allowed inter-probe delay in milliseconds (`30s`).
pub const MAX_DELAY_MS: u64 = 30_000;

/// Maximum allowed retries per port (`5`).
pub const MAX_RETRIES: u8 = 5;

/// Maximum inter-probe jitter in milliseconds (`5s`).
pub const MAX_JITTER_MS: u64 = 5_000;

/// Maximum global probe rate in probes per second.
pub const MAX_PPS: f64 = 1_000.0;

/// Maximum probes per burst before a pause.
pub const MAX_BURST_SIZE: usize = 64;

/// Maximum burst pause in milliseconds (`10s`).
pub const MAX_BURST_PAUSE_MS: u64 = 10_000;

/// Maximum number of decoy probes interleaved against the same target.
pub const MAX_DECOY_PROBES: usize = crate::stealth::MAX_DECOY_PROBES;

/// Named scan profiles tailored for different cybersecurity operational scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanProfile {
    /// Default balanced scan (common ports, 100 threads, 1.0s timeout, banner grabbing enabled).
    Default,
    /// Rapid triage (top 20 critical ports, 100 threads, 400ms timeout).
    Quick,
    /// Exhaustive 65,535-port sweep (512 threads, 350ms timeout).
    Full,
    /// Low-noise IDS-evasive scan (shuffled ports, jitter, rate ceiling, no active banners).
    Stealth,
    /// Corporate blend mode: enterprise persona, human-like bursts, adaptive pacing and banners.
    Mutable,
    /// Deep cybersecurity audit (common ports, active banner grabbing, 1 retry on filtered ports).
    Audit,
}

impl ScanProfile {
    pub fn from_str(name: &str) -> Result<Self, String> {
        match name.trim().to_ascii_lowercase().as_str() {
            "default" | "normal" | "standard" => Ok(Self::Default),
            "quick" | "fast" | "top20" => Ok(Self::Quick),
            "full" | "all" => Ok(Self::Full),
            "stealth" | "sneaky" | "quiet" => Ok(Self::Stealth),
            "mutable" | "corporate" | "blend" | "camouflage" => Ok(Self::Mutable),
            "audit" | "sec" | "security" => Ok(Self::Audit),
            other => Err(format!(
                "Unknown scan profile '{other}'. Valid profiles: default, quick, full, stealth, mutable, audit"
            )),
        }
    }
}

/// Parse a legitimate-traffic persona name used by the mutable mode.
pub fn parse_traffic_persona(name: &str) -> Result<TrafficPersona, String> {
    match name.trim().to_ascii_lowercase().as_str() {
        "generic" | "default" => Ok(TrafficPersona::Generic),
        "corporate" | "workstation" | "corporate-workstation" => {
            Ok(TrafficPersona::CorporateWorkstation)
        }
        "browser" | "firefox" => Ok(TrafficPersona::Browser),
        "windows-update" | "windows" | "update" | "delivery-optimization" => {
            Ok(TrafficPersona::MicrosoftUpdate)
        }
        "backup-agent" | "backup" | "bits" => Ok(TrafficPersona::BackupAgent),
        other => Err(format!(
            "Unknown persona '{other}'. Valid personas: generic, corporate, browser, windows-update, backup-agent"
        )),
    }
}

/// Outcome of parsing CLI arguments.
#[derive(Debug, Clone)]
pub enum CliAction {
    Run(PipelineConfig),
    ShowHelp(String),
    ShowVersion(String),
}

/// Return the formatted CLI help text.
pub fn help_text() -> String {
    r#"tcpscan (HXSCAN-RUST v2.1) — Staged Mediator TCP Port Scanner & Cybersecurity Auditor

USAGE:
  tcpscan <target> [ports] [OPTIONS]
  tcpscan -t <target> [-p <ports>] [OPTIONS]

SIMPLICITY EXAMPLES:
  tcpscan 127.0.0.1                        # Quick-start scan on default cybersecurity ports
  tcpscan scanme.nmap.org 22,80,443        # Positional target + ports (no flags needed!)
  tcpscan 192.168.1.10:8080                # Inline host:port syntax
  tcpscan 10.0.0.1 8000-8100 --banner      # Range scan with active banner grabbing
  tcpscan 192.168.1.1 --profile audit      # Full cybersecurity risk & banner audit
  tcpscan 10.0.0.5 --json                  # JSON telemetry output for SIEM / jq
  tcpscan 10.0.0.7 --stealth               # Low-noise jittered scan, no active banners
  tcpscan 10.0.0.7 --mutable               # Corporate blend mode (persona + adaptive pacing)
  tcpscan 10.0.0.7 --mutable --persona corporate --max-pps 5 --burst 4

ARGUMENTS & FLAGS:
  -t, --target <HOST>       Target IPv4, IPv6, hostname, or host:port
  -p, --ports <SPEC>        Ports/ranges (e.g. 22,80,8000-8100) or preset (quick, common, all)
      --profile <NAME>      Scan preset: default | quick | full | stealth | mutable | audit
      --fast, --quick       Shorthand for --profile quick (top 20 ports, 400ms timeout)
      --full                Shorthand for --profile full (ports 1-65535, 512 threads)
      --stealth             Low-noise mode: shuffled ports, jitter, rate ceiling, no banners
      --mutable             Corporate blend mode: enterprise persona, human-like bursts,
                            adaptive backoff and realistic HTTP headers
      --threads <N>         Maximum concurrent worker threads (1..=2048, default: 100)
      --timeout <SEC>       Socket connection timeout in seconds (0.01..=60.0, default: 1.0)
      --retries <N>         Retries for timed-out/filtered ports (0..=5, default: 0)
      --delay-ms <MS>       Base rate-limiting delay in ms between probes (0..=30000)
      --jitter-ms <MS>      Additional uniform random jitter per probe (0..=5000)
      --max-pps <N>         Global probes-per-second ceiling (0 = unlimited, max: 1000)
      --burst <N>           Probes per burst before a longer pause (1..=64)
      --burst-pause-ms <MS> Pause after each burst in ms (0..=10000)
      --decoy-probes <N>    Interleave N decoy probes against the SAME target (0..=128)
      --persona <NAME>      Client identity: generic | corporate | browser |
                            windows-update | backup-agent
      --ai-filter           Enable anti-AI legitimacy envelope (default in stealth/mutable)
      --no-ai-filter        Disable the anti-AI legitimacy envelope bookkeeping
      --adaptive-pacing     Back off on filtered/dropped probes (default in stealth/mutable)
      --no-adaptive-pacing  Disable adaptive pacing
  -b, --banner              Enable active protocol-aware Banner Grabbing (default: true)
      --no-banner           Disable active Banner Grabbing (pure TCP handshake only)
      --shuffle             Randomize port probing order to reduce sequential IDS signature
      --protect-origin      Refuse scanning local origin loopback (127.0.0.0/8, ::1)
      --show-closed, --all  Display closed and filtered ports in the human report table
      --json                Output structured JSON report for SIEM/SOAR automation
      --csv                 Output CSV table (protected against CWE-1236 formula injection)
      --no-color            Disable ANSI color output
  -v, --verbose             Enable stage-by-stage Mediator diagnostic logging to stderr
  -h, --help                Show this help message
  -V, --version             Show version information

ETHICS:
  Stealth/mutable/anti-AI controls are ONLY for authorized security audits.
  They reduce scanner fingerprints; they do not guarantee IDS/IPS or AI evasion.

EXIT CODES:
  0 = Open port(s) found | 1 = Configuration/DNS/Safety error | 2 = No open ports | 130 = Interrupted
"#
    .to_string()
}

#[derive(Debug, Clone, Copy)]
struct ProfileDefaults {
    ports: &'static str,
    threads: usize,
    timeout_ms: u64,
    retries: u8,
    delay_ms: u64,
    banners: bool,
    shuffle: bool,
    mode: StealthMode,
    persona: TrafficPersona,
    jitter_ms: u64,
    max_pps: f64,
    burst_size: usize,
    burst_pause_ms: u64,
    adaptive: bool,
    decoy: usize,
    ai_filter: bool,
}

fn profile_defaults(profile: ScanProfile) -> ProfileDefaults {
    match profile {
        ScanProfile::Default => ProfileDefaults {
            ports: DEFAULT_PORTS_SPEC,
            threads: 100,
            timeout_ms: 1000,
            retries: 0,
            delay_ms: 0,
            banners: true,
            shuffle: false,
            mode: StealthMode::Normal,
            persona: TrafficPersona::Generic,
            jitter_ms: 0,
            max_pps: 0.0,
            burst_size: 0,
            burst_pause_ms: 0,
            adaptive: false,
            decoy: 0,
            ai_filter: false,
        },
        ScanProfile::Quick => ProfileDefaults {
            ports: QUICK_PORTS_SPEC,
            threads: 100,
            timeout_ms: 400,
            retries: 0,
            delay_ms: 0,
            banners: true,
            shuffle: false,
            mode: StealthMode::Normal,
            persona: TrafficPersona::Generic,
            jitter_ms: 0,
            max_pps: 0.0,
            burst_size: 0,
            burst_pause_ms: 0,
            adaptive: false,
            decoy: 0,
            ai_filter: false,
        },
        ScanProfile::Full => ProfileDefaults {
            ports: "1-65535",
            threads: 512,
            timeout_ms: 350,
            retries: 0,
            delay_ms: 0,
            banners: false,
            shuffle: false,
            mode: StealthMode::Normal,
            persona: TrafficPersona::Generic,
            jitter_ms: 0,
            max_pps: 0.0,
            burst_size: 0,
            burst_pause_ms: 0,
            adaptive: false,
            decoy: 0,
            ai_filter: false,
        },
        ScanProfile::Stealth => ProfileDefaults {
            ports: DEFAULT_PORTS_SPEC,
            threads: 10,
            timeout_ms: 1000,
            retries: 0,
            delay_ms: 30,
            banners: false,
            shuffle: true,
            mode: StealthMode::Stealth,
            persona: TrafficPersona::Generic,
            jitter_ms: 120,
            max_pps: 3.0,
            burst_size: 1,
            burst_pause_ms: 900,
            adaptive: true,
            decoy: 0,
            ai_filter: true,
        },
        ScanProfile::Mutable => ProfileDefaults {
            ports: DEFAULT_PORTS_SPEC,
            threads: 4,
            timeout_ms: 1200,
            retries: 0,
            delay_ms: 0,
            banners: true,
            shuffle: true,
            mode: StealthMode::Mutable,
            persona: TrafficPersona::CorporateWorkstation,
            jitter_ms: 80,
            max_pps: 6.0,
            burst_size: 5,
            burst_pause_ms: 500,
            adaptive: true,
            decoy: 0,
            ai_filter: true,
        },
        ScanProfile::Audit => ProfileDefaults {
            ports: DEFAULT_PORTS_SPEC,
            threads: 100,
            timeout_ms: 1000,
            retries: 1,
            delay_ms: 0,
            banners: true,
            shuffle: false,
            mode: StealthMode::Normal,
            persona: TrafficPersona::Generic,
            jitter_ms: 0,
            max_pps: 0.0,
            burst_size: 0,
            burst_pause_ms: 0,
            adaptive: false,
            decoy: 0,
            ai_filter: false,
        },
    }
}

/// Parse command-line arguments (excluding `argv[0]`) into a [`CliAction`].
pub fn parse_cli_args<I, S>(args: I) -> Result<CliAction, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let tokens: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();

    if tokens.is_empty() {
        return Err(
            "Missing target. Usage: tcpscan <target> [ports] (try 'tcpscan --help')".to_string(),
        );
    }

    let mut target: Option<String> = None;
    let mut ports: Option<String> = None;
    let mut profile = ScanProfile::Default;
    let mut threads: Option<usize> = None;
    let mut timeout_secs: Option<f64> = None;
    let mut retries: Option<u8> = None;
    let mut delay_ms: Option<u64> = None;
    let mut grab_banners: Option<bool> = None;
    let mut shuffle: Option<bool> = None;
    let mut persona: Option<TrafficPersona> = None;
    let mut jitter_ms: Option<u64> = None;
    let mut max_pps: Option<f64> = None;
    let mut burst_size: Option<usize> = None;
    let mut burst_pause_ms: Option<u64> = None;
    let mut decoy_probes: Option<usize> = None;
    let mut ai_filter: Option<bool> = None;
    let mut adaptive_pacing: Option<bool> = None;
    let mut protect_origin = false;
    let mut show_closed = false;
    let mut format = OutputFormat::Human;
    let mut use_color = true;
    let mut verbose = false;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 0;
    while i < tokens.len() {
        let arg = tokens[i].as_str();
        match arg {
            "-h" | "--help" => return Ok(CliAction::ShowHelp(help_text())),
            "-V" | "--version" => {
                return Ok(CliAction::ShowVersion(
                    "tcpscan 2.1.0 (HXSCAN-RUST Edition)".to_string(),
                ))
            }
            "-t" | "--target" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("Option '-t/--target' requires a value".to_string());
                }
                target = Some(tokens[i].clone());
            }
            "-p" | "--ports" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("Option '-p/--ports' requires a value".to_string());
                }
                ports = Some(tokens[i].clone());
            }
            "--profile" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("Option '--profile' requires a profile name".to_string());
                }
                profile = ScanProfile::from_str(&tokens[i])?;
            }
            "--fast" | "--quick" => {
                profile = ScanProfile::Quick;
            }
            "--full" => {
                profile = ScanProfile::Full;
            }
            "--stealth" => {
                profile = ScanProfile::Stealth;
            }
            "--mutable" | "--mutable-mode" | "--blend" => {
                profile = ScanProfile::Mutable;
            }
            "--persona" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("Option '--persona' requires a value".to_string());
                }
                persona = Some(parse_traffic_persona(&tokens[i])?);
            }
            "--jitter-ms" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("Option '--jitter-ms' requires milliseconds".to_string());
                }
                let val = tokens[i]
                    .parse::<u64>()
                    .map_err(|_| format!("Invalid '--jitter-ms' value: {}", tokens[i]))?;
                if val > MAX_JITTER_MS {
                    return Err(format!("'--jitter-ms' must be <= {MAX_JITTER_MS}"));
                }
                jitter_ms = Some(val);
            }
            "--max-pps" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("Option '--max-pps' requires a number".to_string());
                }
                let val = tokens[i]
                    .parse::<f64>()
                    .map_err(|_| format!("Invalid '--max-pps' value: {}", tokens[i]))?;
                if !val.is_finite() || !(0.0..=MAX_PPS).contains(&val) || (val > 0.0 && val < 0.1) {
                    return Err(format!(
                        "'--max-pps' must be 0 (unlimited) or between 0.1 and {MAX_PPS}"
                    ));
                }
                max_pps = Some(val);
            }
            "--burst" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("Option '--burst' requires an integer".to_string());
                }
                let val = tokens[i]
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid '--burst' value: {}", tokens[i]))?;
                if !(1..=MAX_BURST_SIZE).contains(&val) {
                    return Err(format!("'--burst' must be between 1 and {MAX_BURST_SIZE}"));
                }
                burst_size = Some(val);
            }
            "--burst-pause-ms" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("Option '--burst-pause-ms' requires milliseconds".to_string());
                }
                let val = tokens[i]
                    .parse::<u64>()
                    .map_err(|_| format!("Invalid '--burst-pause-ms' value: {}", tokens[i]))?;
                if val > MAX_BURST_PAUSE_MS {
                    return Err(format!(
                        "'--burst-pause-ms' must be <= {MAX_BURST_PAUSE_MS}"
                    ));
                }
                burst_pause_ms = Some(val);
            }
            "--decoy-probes" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("Option '--decoy-probes' requires an integer".to_string());
                }
                let val = tokens[i]
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid '--decoy-probes' value: {}", tokens[i]))?;
                if val > MAX_DECOY_PROBES {
                    return Err(format!("'--decoy-probes' must be <= {MAX_DECOY_PROBES}"));
                }
                decoy_probes = Some(val);
            }
            "--ai-filter" => {
                ai_filter = Some(true);
            }
            "--no-ai-filter" => {
                ai_filter = Some(false);
            }
            "--adaptive-pacing" => {
                adaptive_pacing = Some(true);
            }
            "--no-adaptive-pacing" => {
                adaptive_pacing = Some(false);
            }
            "--threads" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("Option '--threads' requires an integer".to_string());
                }
                let val = tokens[i]
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid '--threads' value: {}", tokens[i]))?;
                if !(1..=MAX_SAFE_THREADS).contains(&val) {
                    return Err(format!(
                        "'--threads' must be between 1 and {MAX_SAFE_THREADS} (Origin Host Resource Protection)"
                    ));
                }
                threads = Some(val);
            }
            "--timeout" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("Option '--timeout' requires a number in seconds".to_string());
                }
                let val = tokens[i]
                    .parse::<f64>()
                    .map_err(|_| format!("Invalid '--timeout' value: {}", tokens[i]))?;
                if !val.is_finite() || !(MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&val) {
                    return Err(format!(
                        "'--timeout' must be between {MIN_TIMEOUT_SECS}s and {MAX_TIMEOUT_SECS}s"
                    ));
                }
                timeout_secs = Some(val);
            }
            "--retries" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("Option '--retries' requires a number".to_string());
                }
                let val = tokens[i]
                    .parse::<u8>()
                    .map_err(|_| format!("Invalid '--retries' value: {}", tokens[i]))?;
                if val > MAX_RETRIES {
                    return Err(format!("'--retries' must be <= {MAX_RETRIES}"));
                }
                retries = Some(val);
            }
            "--delay-ms" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("Option '--delay-ms' requires milliseconds".to_string());
                }
                let val = tokens[i]
                    .parse::<u64>()
                    .map_err(|_| format!("Invalid '--delay-ms' value: {}", tokens[i]))?;
                if val > MAX_DELAY_MS {
                    return Err(format!("'--delay-ms' must be <= {MAX_DELAY_MS}"));
                }
                delay_ms = Some(val);
            }
            "-b" | "--banner" => {
                grab_banners = Some(true);
            }
            "--no-banner" => {
                grab_banners = Some(false);
            }
            "--shuffle" => {
                shuffle = Some(true);
            }
            "--protect-origin" | "--no-self-scan" => {
                protect_origin = true;
            }
            "--show-closed" | "--all" => {
                show_closed = true;
            }
            "--json" => {
                format = OutputFormat::Json;
            }
            "--csv" => {
                format = OutputFormat::Csv;
            }
            "--no-color" => {
                use_color = false;
            }
            "-v" | "--verbose" => {
                verbose = true;
            }
            other if other.starts_with('-') => {
                return Err(format!(
                    "Unrecognized option: '{other}' (try 'tcpscan --help')"
                ));
            }
            pos => {
                positional.push(pos.to_string());
            }
        }
        i += 1;
    }

    if target.is_none() && !positional.is_empty() {
        target = Some(positional.remove(0));
    }
    if ports.is_none() && !positional.is_empty() {
        ports = Some(positional.remove(0));
    }
    if !positional.is_empty() {
        return Err(format!(
            "Unexpected positional argument: '{}'",
            positional[0]
        ));
    }

    let target_input = target.ok_or_else(|| {
        "Target is required. Example: 'tcpscan 127.0.0.1' or 'tcpscan -t 127.0.0.1'".to_string()
    })?;

    let defaults = profile_defaults(profile);

    let has_inline_port = crate::stages::stage1_discovery::split_target_inline_port(&target_input)
        .1
        .is_some();

    let resolved_ports = match ports {
        Some(p) => p,
        None if has_inline_port => String::new(),
        None => defaults.ports.to_string(),
    };

    let final_timeout = match timeout_secs {
        Some(secs) => Duration::try_from_secs_f64(secs)
            .map_err(|_| "Timeout value out of valid Duration range".to_string())?,
        None => Duration::from_millis(defaults.timeout_ms),
    };

    let stealth = StealthConfig {
        mode: defaults.mode,
        persona: persona.unwrap_or(defaults.persona),
        jitter: Duration::from_millis(jitter_ms.unwrap_or(defaults.jitter_ms).min(MAX_JITTER_MS)),
        max_pps: max_pps.unwrap_or(defaults.max_pps).clamp(0.0, MAX_PPS),
        burst_size: burst_size
            .unwrap_or(defaults.burst_size)
            .min(MAX_BURST_SIZE),
        burst_pause: Duration::from_millis(
            burst_pause_ms
                .unwrap_or(defaults.burst_pause_ms)
                .min(MAX_BURST_PAUSE_MS),
        ),
        adaptive_backoff: adaptive_pacing.unwrap_or(defaults.adaptive),
        decoy_probes: decoy_probes.unwrap_or(defaults.decoy).min(MAX_DECOY_PROBES),
        ai_filter: ai_filter.unwrap_or(defaults.ai_filter),
    };

    let scanner = ScannerConfig {
        threads: threads
            .unwrap_or(defaults.threads)
            .clamp(1, MAX_SAFE_THREADS),
        timeout: final_timeout,
        retries: retries.unwrap_or(defaults.retries).min(MAX_RETRIES),
        delay: Duration::from_millis(delay_ms.unwrap_or(defaults.delay_ms).min(MAX_DELAY_MS)),
        stealth,
    };

    let banner_timeout = final_timeout
        .min(Duration::from_millis(400))
        .max(Duration::from_millis(120));

    let config = PipelineConfig {
        target_input,
        port_spec: resolved_ports,
        scanner,
        grab_banners: grab_banners.unwrap_or(defaults.banners),
        banner_timeout,
        shuffle: shuffle.unwrap_or(defaults.shuffle),
        protect_origin,
        verbose,
        report_options: ReportOptions {
            format,
            show_closed,
            use_color,
        },
    };

    Ok(CliAction::Run(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_positional_execution() {
        let action = parse_cli_args(["127.0.0.1"]).unwrap();
        match action {
            CliAction::Run(cfg) => {
                assert_eq!(cfg.target_input, "127.0.0.1");
                assert_eq!(cfg.port_spec, DEFAULT_PORTS_SPEC);
            }
            _ => panic!("Expected CliAction::Run"),
        }
    }

    #[test]
    fn test_positional_target_and_ports() {
        let action = parse_cli_args(["10.0.0.1", "22,80,443"]).unwrap();
        match action {
            CliAction::Run(cfg) => {
                assert_eq!(cfg.target_input, "10.0.0.1");
                assert_eq!(cfg.port_spec, "22,80,443");
            }
            _ => panic!("Expected CliAction::Run"),
        }
    }

    #[test]
    fn test_legacy_hxscan_flags_compatibility() {
        let action = parse_cli_args([
            "-t",
            "scanme.nmap.org",
            "-p",
            "80,443,8000-8005",
            "--threads",
            "50",
            "--timeout",
            "0.5",
            "-v",
        ])
        .unwrap();
        match action {
            CliAction::Run(cfg) => {
                assert_eq!(cfg.target_input, "scanme.nmap.org");
                assert_eq!(cfg.port_spec, "80,443,8000-8005");
                assert_eq!(cfg.scanner.threads, 50);
                assert_eq!(cfg.scanner.timeout, Duration::from_millis(500));
                assert!(cfg.verbose);
            }
            _ => panic!("Expected CliAction::Run"),
        }
    }

    #[test]
    fn test_resource_exhaustion_bounds_enforced() {
        // Thread bomb attempt (> 2048) must fail safely
        assert!(parse_cli_args(["127.0.0.1", "--threads", "100000"]).is_err());
        // Overflow timeout (1e30) must not panic and must return Err
        assert!(parse_cli_args(["127.0.0.1", "--timeout", "1e30"]).is_err());
        assert!(parse_cli_args(["127.0.0.1", "--timeout", "0.0001"]).is_err());
        // Excessive retries (> 5) and delay (> 30000ms) must fail safely
        assert!(parse_cli_args(["127.0.0.1", "--retries", "50"]).is_err());
        assert!(parse_cli_args(["127.0.0.1", "--delay-ms", "999999"]).is_err());
    }

    #[test]
    fn test_stealth_and_json_flags() {
        let action = parse_cli_args(["127.0.0.1", "--stealth", "--json"]).unwrap();
        match action {
            CliAction::Run(cfg) => {
                assert!(cfg.shuffle);
                assert!(!cfg.grab_banners);
                assert_eq!(cfg.scanner.threads, 10);
                assert_eq!(cfg.scanner.stealth.mode, StealthMode::Stealth);
                assert!(cfg.scanner.stealth.ai_filter);
                assert!(cfg.scanner.stealth.adaptive_backoff);
                assert_eq!(cfg.report_options.format, OutputFormat::Json);
            }
            _ => panic!("Expected CliAction::Run"),
        }
    }

    #[test]
    fn test_mutable_profile_and_persona_overrides() {
        let action = parse_cli_args([
            "10.0.0.0",
            "--mutable",
            "--persona",
            "browser",
            "--jitter-ms",
            "150",
            "--max-pps",
            "4",
            "--burst",
            "3",
            "--burst-pause-ms",
            "750",
            "--decoy-probes",
            "6",
            "--no-ai-filter",
        ])
        .unwrap();
        match action {
            CliAction::Run(cfg) => {
                assert_eq!(cfg.scanner.stealth.mode, StealthMode::Mutable);
                assert_eq!(cfg.scanner.stealth.persona, TrafficPersona::Browser);
                assert_eq!(cfg.scanner.stealth.jitter, Duration::from_millis(150));
                assert_eq!(cfg.scanner.stealth.max_pps, 4.0);
                assert_eq!(cfg.scanner.stealth.burst_size, 3);
                assert_eq!(cfg.scanner.stealth.burst_pause, Duration::from_millis(750));
                assert_eq!(cfg.scanner.stealth.decoy_probes, 6);
                assert!(!cfg.scanner.stealth.ai_filter);
                assert!(cfg.shuffle);
                assert!(cfg.grab_banners);
            }
            _ => panic!("Expected CliAction::Run"),
        }
    }

    #[test]
    fn test_stealth_bounds_are_enforced() {
        assert!(parse_cli_args(["127.0.0.1", "--jitter-ms", "999999"]).is_err());
        assert!(parse_cli_args(["127.0.0.1", "--max-pps", "5000"]).is_err());
        assert!(parse_cli_args(["127.0.0.1", "--max-pps", "0.01"]).is_err());
        assert!(parse_cli_args(["127.0.0.1", "--burst", "0"]).is_err());
        assert!(parse_cli_args(["127.0.0.1", "--burst", "999"]).is_err());
        assert!(parse_cli_args(["127.0.0.1", "--decoy-probes", "999"]).is_err());
        assert!(parse_cli_args(["127.0.0.1", "--persona", "unknown"]).is_err());
    }
}
