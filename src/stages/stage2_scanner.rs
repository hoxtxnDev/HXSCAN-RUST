//! # Stage 2 Colleague: `ScannerColleague` (`stage2_scanner`)
//!
//! Concrete Colleague in the **Mediator Pattern** responsible for:
//! - Lock-free concurrent TCP probing across worker threads (`AtomicUsize` + `std::thread::scope`).
//! - Classifying TCP states (`Open`, `Closed`, `Filtered`, `Error`) and measuring microsecond RTT.
//! - Calling [`ScanMediator::mediate_open_stream`] when a TCP connection opens so the Mediator can
//!   coordinate live socket inspection without `ScannerColleague` knowing `FingerprintColleague` exists.
//! - Emitting [`ScanEvent::ProbingCompleted`] back to the [`ScanController`] Mediator.
//!
//! **Decoupling Guarantee**: Zero imports from `stage1`, `stage3`, `stage4`, or `stage5`.

use std::io::{self, ErrorKind};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::mediator::{
    ComponentId, MediatorDirective, PortState, RawProbeResult, ScanController, ScanEvent,
    ScanMediator, ScannerConfig,
};

/// **Colleague 2 (`ScannerColleague`)**: Lock-free concurrent TCP Probing Colleague.
pub struct ScannerColleague;

impl ScannerColleague {
    /// Execute live TCP probing mediated by [`ScanController`], handing off open sockets via
    /// [`ScanMediator::mediate_open_stream`] and reporting [`ScanEvent::ProbingCompleted`].
    pub fn run_live(mediator: &mut ScanController) -> MediatorDirective {
        let target_ip = mediator
            .target
            .as_ref()
            .expect("Target must be resolved before ScannerColleague runs")
            .primary_ip;
        let ports = mediator.ports.clone();
        let scanner_cfg = mediator.config.scanner.clone();

        // Immutable borrow of `mediator` across scoped worker threads for `mediate_open_stream`
        let raw_results = {
            let mediator_ref: &dyn ScanMediator = mediator;
            let stream_hook = |port: u16, stream: &mut TcpStream| -> Option<String> {
                mediator_ref.mediate_open_stream(port, stream)
            };
            execute_scan_stage(target_ip, &ports, &scanner_cfg, None, Some(&stream_hook))
        };

        mediator.notify(
            ComponentId::ScannerColleague,
            ScanEvent::ProbingCompleted { raw_results },
        )
    }

    /// Execute probing using a custom port prober closure (for deterministic testing / alternative engines)
    /// and notify the [`ScanController`] Mediator.
    pub fn run_with_prober<P>(mediator: &mut ScanController, prober: P) -> MediatorDirective
    where
        P: Fn(u16) -> RawProbeResult + Sync,
    {
        let ports = mediator.ports.clone();
        let scanner_cfg = mediator.config.scanner.clone();
        let raw_results = execute_scan_stage_with_prober(&ports, &scanner_cfg, None, prober);

        mediator.notify(
            ComponentId::ScannerColleague,
            ScanEvent::ProbingCompleted { raw_results },
        )
    }
}

/// Classify a [`std::io::Error`] from `TcpStream::connect_timeout` into `(PortState, should_retry)`.
pub fn classify_connect_error(err: &io::Error) -> (PortState, bool) {
    match err.kind() {
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => (PortState::Closed, false),
        ErrorKind::TimedOut | ErrorKind::WouldBlock => (PortState::Filtered, true),
        default_kind => {
            let is_filtered_os = matches!(
                err.raw_os_error(),
                Some(60) | Some(65) | Some(51) | Some(110) | Some(113)
            );
            if is_filtered_os || format!("{default_kind:?}").contains("Unreachable") {
                (PortState::Filtered, true)
            } else {
                (PortState::Error(err.to_string()), false)
            }
        }
    }
}

/// Probe a single TCP port on `target_ip` with configurable timeout, retries, and optional stream hook.
pub fn probe_single_port<F>(
    target_ip: IpAddr,
    port: u16,
    timeout: Duration,
    retries: u8,
    on_open_stream: Option<&F>,
) -> RawProbeResult
where
    F: Fn(u16, &mut TcpStream) -> Option<String>,
{
    let addr = SocketAddr::new(target_ip, port);
    let max_attempts = retries.saturating_add(1);

    for attempt in 1..=max_attempts {
        let start = Instant::now();
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(mut stream) => {
                let rtt_micros = start.elapsed().as_micros() as u64;
                let inline_banner = on_open_stream.and_then(|hook| hook(port, &mut stream));
                let _ = stream.shutdown(Shutdown::Both);
                return RawProbeResult {
                    port,
                    state: PortState::Open,
                    rtt_micros: Some(rtt_micros),
                    attempts: attempt,
                    inline_banner,
                };
            }
            Err(err) => {
                let elapsed_micros = start.elapsed().as_micros() as u64;
                let (state, retryable) = classify_connect_error(&err);
                if !retryable || attempt == max_attempts {
                    let rtt = if state == PortState::Closed {
                        Some(elapsed_micros)
                    } else {
                        None
                    };
                    return RawProbeResult {
                        port,
                        state,
                        rtt_micros: rtt,
                        attempts: attempt,
                        inline_banner: None,
                    };
                }
            }
        }
    }

    RawProbeResult {
        port,
        state: PortState::Filtered,
        rtt_micros: None,
        attempts: max_attempts,
        inline_banner: None,
    }
}

/// Core lock-free concurrent work distributor over `ports` using a custom port prober closure.
pub fn execute_scan_stage_with_prober<P>(
    ports: &[u16],
    config: &ScannerConfig,
    cancel_flag: Option<&AtomicBool>,
    prober: P,
) -> Vec<RawProbeResult>
where
    P: Fn(u16) -> RawProbeResult + Sync,
{
    if ports.is_empty() {
        return Vec::new();
    }

    let max_threads = ports.len().min(2048);
    let worker_count = config.threads.clamp(1, max_threads);
    let cursor = AtomicUsize::new(0);
    let per_worker_cap = (ports.len() / worker_count) + 2;

    let mut all_results: Vec<RawProbeResult> = Vec::with_capacity(ports.len());

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        let prober_ref = &prober;

        for _ in 0..worker_count {
            let cursor_ref = &cursor;
            let handle = scope.spawn(move || {
                let mut local_results = Vec::with_capacity(per_worker_cap);

                loop {
                    if let Some(cancel) = cancel_flag {
                        if cancel.load(Ordering::Relaxed) {
                            break;
                        }
                    }

                    let idx = cursor_ref.fetch_add(1, Ordering::Relaxed);
                    if idx >= ports.len() {
                        break;
                    }

                    let port = ports[idx];
                    let res = prober_ref(port);
                    local_results.push(res);

                    if !config.delay.is_zero() {
                        thread::sleep(config.delay);
                    }
                }

                local_results
            });
            handles.push(handle);
        }

        for handle in handles {
            if let Ok(mut worker_vec) = handle.join() {
                all_results.append(&mut worker_vec);
            }
        }
    });

    all_results.sort_unstable_by_key(|r| r.port);
    all_results
}

/// Execute Stage 2 concurrent TCP scanning across `ports` using lock-free atomic work distribution.
pub fn execute_scan_stage<F>(
    target_ip: IpAddr,
    ports: &[u16],
    config: &ScannerConfig,
    cancel_flag: Option<&AtomicBool>,
    on_open_stream: Option<&F>,
) -> Vec<RawProbeResult>
where
    F: Fn(u16, &mut TcpStream) -> Option<String> + Sync,
{
    execute_scan_stage_with_prober(ports, config, cancel_flag, |port| {
        probe_single_port(
            target_ip,
            port,
            config.timeout,
            config.retries,
            on_open_stream,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{Ipv4Addr, TcpListener};

    #[test]
    fn test_classify_connect_errors() {
        let refused = io::Error::new(ErrorKind::ConnectionRefused, "Connection refused");
        assert_eq!(classify_connect_error(&refused), (PortState::Closed, false));

        let timed_out = io::Error::new(ErrorKind::TimedOut, "Operation timed out");
        assert_eq!(
            classify_connect_error(&timed_out),
            (PortState::Filtered, true)
        );

        let perm = io::Error::new(ErrorKind::PermissionDenied, "Operation not permitted");
        assert_eq!(
            classify_connect_error(&perm),
            (PortState::Error("Operation not permitted".to_string()), false)
        );
    }

    #[test]
    fn test_lock_free_work_distribution_across_threads() {
        let ports: Vec<u16> = (1..=500).rev().collect();
        let config = ScannerConfig {
            threads: 16,
            timeout: Duration::from_millis(50),
            retries: 0,
            delay: Duration::ZERO,
        };

        let results = execute_scan_stage_with_prober(&ports, &config, None, |port| {
            let state = match port {
                22 | 80 | 443 => PortState::Open,
                135 | 445 => PortState::Filtered,
                _ => PortState::Closed,
            };
            RawProbeResult {
                port,
                state,
                rtt_micros: Some(120),
                attempts: 1,
                inline_banner: if port == 22 {
                    Some("SSH-2.0-OpenSSH_9.7".to_string())
                } else {
                    None
                },
            }
        });

        assert_eq!(results.len(), 500);
        for (i, r) in results.iter().enumerate() {
            assert_eq!(r.port, (i + 1) as u16);
        }
        assert_eq!(results[21].state, PortState::Open);
        assert_eq!(
            results[21].inline_banner.as_deref(),
            Some("SSH-2.0-OpenSSH_9.7")
        );
        assert_eq!(results[134].state, PortState::Filtered);
        assert_eq!(results[0].state, PortState::Closed);
    }

    #[test]
    fn test_probe_localhost_nonblocking_listener() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let open_port = listener.local_addr().unwrap().port();

        let server_handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(250);
            while Instant::now() < deadline {
                if let Ok((mut stream, _)) = listener.accept() {
                    let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.6\r\n");
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
        });

        let config = ScannerConfig {
            threads: 2,
            timeout: Duration::from_millis(150),
            retries: 0,
            delay: Duration::ZERO,
        };

        let ports = vec![open_port];
        let results = execute_scan_stage::<fn(u16, &mut TcpStream) -> Option<String>>(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &ports,
            &config,
            None,
            None,
        );

        let _ = server_handle.join();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].port, open_port);
        assert!(matches!(
            results[0].state,
            PortState::Open | PortState::Error(_)
        ));
    }

    #[test]
    fn test_cancel_flag_stops_scan_early() {
        let cancel = AtomicBool::new(true);
        let config = ScannerConfig::default();
        let ports: Vec<u16> = (1..=100).collect();
        let results = execute_scan_stage::<fn(u16, &mut TcpStream) -> Option<String>>(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &ports,
            &config,
            Some(&cancel),
            None,
        );
        assert!(results.is_empty());
    }
}
