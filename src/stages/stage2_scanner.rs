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

use std::io::{self, BufRead, ErrorKind, IsTerminal};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::mediator::{
    ComponentId, MediatorDirective, PortState, RawProbeResult, ScanController, ScanEvent,
    ScanMediator, ScannerConfig,
};
use crate::stealth::{build_work_plan, PacingController};

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
#[inline]
pub fn classify_connect_error(err: &io::Error) -> (PortState, bool) {
    match err.kind() {
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => (PortState::Closed, false),
        ErrorKind::TimedOut
        | ErrorKind::WouldBlock
        | ErrorKind::HostUnreachable
        | ErrorKind::NetworkUnreachable => (PortState::Filtered, true),
        _ => {
            let is_filtered_os = matches!(
                err.raw_os_error(),
                Some(51 | 60 | 65 | 110 | 113 | 10051 | 10060 | 10065)
            );
            if is_filtered_os {
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

/// Shared non-blocking line channel over `stdin` so both interactive console mode (`tcpscan>`)
/// and live scan Enter-key progress queries can read `stdin` without thread contention.
pub fn global_stdin_receiver() -> &'static Mutex<mpsc::Receiver<String>> {
    static STDIN_RX: OnceLock<Mutex<mpsc::Receiver<String>>> = OnceLock::new();
    STDIN_RX.get_or_init(|| {
        let (tx, rx) = mpsc::channel();
        let _ = thread::Builder::new()
            .name("tcpscan-stdin-listener".to_string())
            .spawn(move || {
                let stdin = io::stdin();
                let mut reader = stdin.lock();
                let mut buf = String::new();
                loop {
                    buf.clear();
                    match reader.read_line(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            if tx.send(buf.clone()).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        Mutex::new(rx)
    })
}

/// Format an Nmap-style real-time scan progress line when the operator presses `[ENTER]`
/// during a running scan.
pub fn format_scan_progress(
    completed: usize,
    total: usize,
    open_found: usize,
    filtered_found: usize,
    elapsed: Duration,
) -> String {
    let safe_total = total.max(1);
    let clamped_done = completed.min(safe_total);
    let pct = ((clamped_done as f64) / (safe_total as f64)) * 100.0;
    let bar_width = 20usize;
    let filled = (((pct / 100.0) * (bar_width as f64)).round() as usize).min(bar_width);
    let bar = format!(
        "[{}{}]",
        "#".repeat(filled),
        "-".repeat(bar_width.saturating_sub(filled))
    );

    let elapsed_secs = elapsed.as_secs_f64();
    let rate = if elapsed_secs > 0.001 {
        (clamped_done as f64) / elapsed_secs
    } else {
        clamped_done as f64
    };
    let remaining = safe_total.saturating_sub(clamped_done);
    let eta_secs = if rate > 0.0 {
        (remaining as f64) / rate
    } else {
        0.0
    };

    format!(
        "[Avance] {:>5.1}% {} {}/{} puertos | Abiertos: {} | Filtrados: {} | {:.0} puertos/s | {:.1}s | ETA: ~{:.1}s",
        pct,
        bar,
        clamped_done,
        safe_total,
        open_found,
        filtered_found,
        rate,
        elapsed_secs,
        eta_secs
    )
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

    let total_real_ports = ports.len();
    let max_threads = total_real_ports.min(2048);
    let worker_count = config.threads.clamp(1, max_threads);
    let cursor = AtomicUsize::new(0);
    let completed_probes = AtomicUsize::new(0);
    let open_found = AtomicUsize::new(0);
    let filtered_found = AtomicUsize::new(0);
    let scan_done = AtomicBool::new(false);
    let per_worker_cap = (total_real_ports / worker_count) + 2;
    let stage_start = Instant::now();

    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xA5A5_5A5A_F0F0_0F0F);
    // Decoys are interleaved against the same primary target and discarded afterwards.
    let work_plan = build_work_plan(ports, config.stealth.decoy_probes, seed);

    let mut all_results: Vec<RawProbeResult> = Vec::with_capacity(total_real_ports);
    let enable_enter_progress = io::stdin().is_terminal() && total_real_ports > 1;

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        let prober_ref = &prober;
        let plan_ref = &work_plan;
        let completed_ref = &completed_probes;
        let open_ref = &open_found;
        let filtered_ref = &filtered_found;
        let done_ref = &scan_done;

        let progress_handle = if enable_enter_progress {
            Some(scope.spawn(move || {
                // Only activate interactive Enter listener if the scan takes longer than 350ms
                for _ in 0..14 {
                    if done_ref.load(Ordering::Relaxed) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(25));
                }
                if done_ref.load(Ordering::Relaxed) {
                    return;
                }

                eprintln!(
                    "[i] Escaneo en progreso ({total_real_ports} puertos)... presiona [ENTER] para ver el % de avance y ETA."
                );

                let rx_mutex = global_stdin_receiver();
                while !done_ref.load(Ordering::Relaxed) {
                    let pressed_enter = rx_mutex
                        .lock()
                        .ok()
                        .and_then(|rx| rx.recv_timeout(Duration::from_millis(40)).ok())
                        .is_some();
                    if pressed_enter && !done_ref.load(Ordering::Relaxed) {
                        let status = format_scan_progress(
                            completed_ref.load(Ordering::Relaxed),
                            total_real_ports,
                            open_ref.load(Ordering::Relaxed),
                            filtered_ref.load(Ordering::Relaxed),
                            stage_start.elapsed(),
                        );
                        eprintln!("{status}");
                    }
                }
            }))
        } else {
            None
        };

        for worker_idx in 0..worker_count {
            let cursor_ref = &cursor;
            let worker_seed = seed ^ (worker_idx as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let handle = scope.spawn(move || {
                let mut local_results = Vec::with_capacity(per_worker_cap);
                let mut pacer = PacingController::new(config, worker_count, worker_seed);

                loop {
                    if let Some(cancel) = cancel_flag {
                        if cancel.load(Ordering::Relaxed) {
                            break;
                        }
                    }

                    let idx = cursor_ref.fetch_add(1, Ordering::Relaxed);
                    if idx >= plan_ref.len() {
                        break;
                    }

                    let (port, is_decoy) = plan_ref[idx];
                    let res = prober_ref(port);
                    let next_delay = pacer.on_probe_complete(&res.state);

                    // Decoy results never reach the Mediator or the audit.
                    if !is_decoy {
                        match res.state {
                            PortState::Open => {
                                open_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            PortState::Filtered => {
                                filtered_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {}
                        }
                        completed_ref.fetch_add(1, Ordering::Relaxed);
                        local_results.push(res);
                    }

                    if !next_delay.is_zero() {
                        thread::sleep(next_delay);
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
        done_ref.store(true, Ordering::Relaxed);
        if let Some(mon) = progress_handle {
            let _ = mon.join();
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
            (
                PortState::Error("Operation not permitted".to_string()),
                false
            )
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
            stealth: crate::mediator::StealthConfig::default(),
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
            stealth: crate::mediator::StealthConfig::default(),
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

    #[test]
    fn test_format_scan_progress_percentage_bar_and_eta() {
        let status = format_scan_progress(450, 1000, 3, 12, Duration::from_secs(3));
        assert!(status.contains("45.0%"));
        assert!(status.contains("[#########-----------]"));
        assert!(status.contains("450/1000 puertos"));
        assert!(status.contains("Abiertos: 3"));
        assert!(status.contains("Filtrados: 12"));
        assert!(status.contains("150 puertos/s"));
        assert!(status.contains("ETA: ~3.7s"));
    }
}
