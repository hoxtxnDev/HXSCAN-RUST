//! # Stage 0: Ergonomic & Hardened CLI Parser for `tcpscan` / `hxscan`
//!
//! Designed for zero-friction simplicity (`tcpscan <target> [ports]`) while maintaining
//! 100% backward compatibility with legacy `hxscan` flags and enforcing **Origin Host Protection**
//! bounds against resource exhaustion (`MAX_SAFE_THREADS`, `MAX_TIMEOUT_SECS`, `MAX_DELAY_MS`,
//! `MAX_RETRIES`, and `--protect-origin`).

use std::time::Duration;

use crate::mediator::{OutputFormat, PipelineConfig, ReportOptions, ScannerConfig};
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

/// Named scan profiles tailored for different cybersecurity operational scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanProfile {
    /// Default balanced scan (common ports, 100 threads, 1.0s timeout, banner grabbing enabled).
    Default,
    /// Rapid triage (top 20 critical ports, 100 threads, 400ms timeout).
    Quick,
    /// Exhaustive 65,535-port sweep (512 threads, 350ms timeout).
    Full,
    /// Low-noise IDS-evasive scan (shuffled ports, 10 threads, 30ms inter-probe delay, no active banners).
    Stealth,
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
            "audit" | "sec" | "security" => Ok(Self::Audit),
            other => Err(format!(
                "Unknown scan profile '{other}'. Valid profiles: default, quick, full, stealth, audit"
            )),
        }
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
    r#"tcpscan (HXSCAN-RUST v2.0) — Staged Mediator TCP Port Scanner & Cybersecurity Auditor

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

ARGUMENTS & FLAGS:
  -t, --target <HOST>       Target IPv4, IPv6, hostname, or host:port
  -p, --ports <SPEC>        Ports/ranges (e.g. 22,80,8000-8100) or preset (quick, common, all)
      --profile <NAME>      Scan preset: default | quick | full | stealth | audit
      --fast, --quick       Shorthand for --profile quick (top 20 ports, 400ms timeout)
      --full                Shorthand for --profile full (ports 1-65535, 512 threads)
      --stealth             Shorthand for --profile stealth (shuffled ports, rate-limited)
      --threads <N>         Maximum concurrent worker threads (1..=2048, default: 100)
      --timeout <SEC>       Socket connection timeout in seconds (0.01..=60.0, default: 1.0)
      --retries <N>         Retries for timed-out/filtered ports (0..=5, default: 0)
      --delay-ms <MS>       Rate-limiting delay in ms between probes (0..=30000, default: 0)
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

EXIT CODES:
  0 = Open port(s) found | 1 = Configuration/DNS/Safety error | 2 = No open ports | 130 = Interrupted
"#
    .to_string()
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
                    "tcpscan 2.0.0 (HXSCAN-RUST Edition)".to_string(),
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
                return Err(format!("Unrecognized option: '{other}' (try 'tcpscan --help')"));
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

    let (default_ports, default_threads, default_timeout_ms, default_retries, default_delay_ms, default_banner, default_shuffle) =
        match profile {
            ScanProfile::Default => (DEFAULT_PORTS_SPEC, 100, 1000, 0, 0, true, false),
            ScanProfile::Quick => (QUICK_PORTS_SPEC, 100, 400, 0, 0, true, false),
            ScanProfile::Full => ("1-65535", 512, 350, 0, 0, false, false),
            ScanProfile::Stealth => (DEFAULT_PORTS_SPEC, 10, 1000, 0, 30, false, true),
            ScanProfile::Audit => (DEFAULT_PORTS_SPEC, 100, 1000, 1, 0, true, false),
        };

    let has_inline_port = crate::stages::stage1_discovery::split_target_inline_port(&target_input)
        .1
        .is_some();

    let resolved_ports = match ports {
        Some(p) => p,
        None if has_inline_port => String::new(),
        None => default_ports.to_string(),
    };

    let final_timeout = match timeout_secs {
        Some(secs) => Duration::try_from_secs_f64(secs)
            .map_err(|_| "Timeout value out of valid Duration range".to_string())?,
        None => Duration::from_millis(default_timeout_ms),
    };

    let scanner = ScannerConfig {
        threads: threads.unwrap_or(default_threads).clamp(1, MAX_SAFE_THREADS),
        timeout: final_timeout,
        retries: retries.unwrap_or(default_retries).min(MAX_RETRIES),
        delay: Duration::from_millis(delay_ms.unwrap_or(default_delay_ms).min(MAX_DELAY_MS)),
    };

    let banner_timeout = final_timeout
        .min(Duration::from_millis(400))
        .max(Duration::from_millis(120));

    let config = PipelineConfig {
        target_input,
        port_spec: resolved_ports,
        scanner,
        grab_banners: grab_banners.unwrap_or(default_banner),
        banner_timeout,
        shuffle: shuffle.unwrap_or(default_shuffle),
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
                assert_eq!(cfg.report_options.format, OutputFormat::Json);
            }
            _ => panic!("Expected CliAction::Run"),
        }
    }
}
