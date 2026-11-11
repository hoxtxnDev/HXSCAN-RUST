//! Comprehensive End-to-End, Stage, Mediator Pattern & Origin-Protection Tests for `tcpscan` (HXSCAN-RUST v2.2).

use std::io::Write;
use std::net::{Ipv4Addr, TcpListener};
use std::thread;
use std::time::{Duration, Instant};

use tcpscan::{
    parse_cli_args, parse_port_spec, run_from_args, sanitize_csv_cell, AddressScope, CliAction,
    ComponentId, EnrichedPortResult, HoneypotVerdict, MediatorDirective, MediatorState, PortState,
    RawProbeResult, RiskLevel, ScanController, ScanPipeline, StealthMode, TrafficPersona,
    SERVICE_TABLE,
};

#[test]
fn test_mediator_pattern_event_trace_and_reactive_directives() {
    let action = parse_cli_args(["8.8.8.8", "22,80,6379,9999", "--no-color"]).unwrap();
    let config = match action {
        CliAction::Run(cfg) => cfg,
        _ => panic!("Expected CliAction::Run"),
    };

    let controller = ScanController::new(config);
    assert_eq!(controller.state(), MediatorState::Idle);

    let output = controller
        .execute_with_prober(|port| match port {
            22 => RawProbeResult {
                port: 22,
                state: PortState::Open,
                rtt_micros: Some(450),
                attempts: 1,
                inline_banner: Some("SSH-2.0-OpenSSH_9.7p1".to_string()),
            },
            6379 => RawProbeResult {
                port: 6379,
                state: PortState::Open,
                rtt_micros: Some(310),
                attempts: 1,
                inline_banner: Some("+PONG".to_string()),
            },
            80 => RawProbeResult {
                port: 80,
                state: PortState::Closed,
                rtt_micros: Some(150),
                attempts: 1,
                inline_banner: None,
            },
            _ => RawProbeResult {
                port,
                state: PortState::Filtered,
                rtt_micros: None,
                attempts: 1,
                inline_banner: None,
            },
        })
        .unwrap();

    assert_eq!(output.event_trace.len(), 7);
    assert_eq!(
        output.event_trace[0].sender,
        ComponentId::DiscoveryColleague
    );
    assert_eq!(
        output.event_trace[0].directive,
        MediatorDirective::PublicTargetHardeningMode
    );
    assert_eq!(output.event_trace[1].sender, ComponentId::ScannerColleague);
    assert_eq!(
        output.event_trace[1].directive,
        MediatorDirective::FirewallDropDetected { filtered_ports: 1 }
    );
    assert_eq!(
        output.event_trace[2].sender,
        ComponentId::FingerprintColleague
    );
    assert_eq!(output.event_trace[3].sender, ComponentId::HoneypotColleague);
    assert_eq!(output.event_trace[3].directive, MediatorDirective::Proceed);
    assert_eq!(output.event_trace[4].sender, ComponentId::AuditColleague);
    assert_eq!(
        output.event_trace[4].directive,
        MediatorDirective::EscalateCriticalAlert {
            port: 6379,
            service: "Redis".to_string()
        }
    );
    assert_eq!(output.event_trace[5].sender, ComponentId::AuditColleague);
    assert_eq!(output.event_trace[6].sender, ComponentId::ReportColleague);
    assert_eq!(
        output.event_trace[6].resulting_state,
        MediatorState::Completed
    );

    assert_eq!(output.critical_alerts.len(), 1);
    assert!(output.critical_alerts[0].contains("CRITICAL port 6379 (Redis)"));
}

#[test]
fn test_full_5_stage_pipeline_open_ssh_and_redis_and_closed_ports() {
    let action = parse_cli_args(["127.0.0.1", "22,80,6379,9999", "--no-color"]).unwrap();
    let config = match action {
        CliAction::Run(cfg) => cfg,
        _ => panic!("Expected CliAction::Run"),
    };

    let pipeline = ScanPipeline::new(config);
    let output = pipeline
        .execute_with_prober(|port| match port {
            22 => RawProbeResult {
                port: 22,
                state: PortState::Open,
                rtt_micros: Some(450),
                attempts: 1,
                inline_banner: Some("SSH-2.0-OpenSSH_9.7p1".to_string()),
            },
            6379 => RawProbeResult {
                port: 6379,
                state: PortState::Open,
                rtt_micros: Some(310),
                attempts: 1,
                inline_banner: Some("+PONG".to_string()),
            },
            80 => RawProbeResult {
                port: 80,
                state: PortState::Closed,
                rtt_micros: Some(150),
                attempts: 1,
                inline_banner: None,
            },
            _ => RawProbeResult {
                port,
                state: PortState::Filtered,
                rtt_micros: None,
                attempts: 1,
                inline_banner: None,
            },
        })
        .unwrap();

    assert_eq!(output.exit_code(), 0);
    assert_eq!(output.summary.total_scanned, 4);
    assert_eq!(output.summary.open_count, 2);
    assert_eq!(output.summary.closed_count, 1);
    assert_eq!(output.summary.filtered_count, 1);
    assert_eq!(output.summary.critical_count, 1);
    assert!(output.summary.firewall_detected);
    assert_eq!(output.summary.posture_grade, 'F');

    let report = &output.formatted_report;
    assert!(report.contains("SSH-2.0-OpenSSH_9.7p1"));
    assert!(report.contains("Unauthenticated Redis"));
    assert!(report.contains("Scanned: 4 port(s) | Open: 2 | Closed: 1 | Filtered: 1"));
    assert!(!report.contains("80       closed"));
}

#[test]
fn test_full_pipeline_json_and_csv_reporting_with_formula_injection_shield() {
    let action_json = parse_cli_args(["127.0.0.1:8080", "--json"]).unwrap();
    let cfg_json = match action_json {
        CliAction::Run(c) => c,
        _ => panic!("Expected Run"),
    };
    let out_json = ScanPipeline::new(cfg_json)
        .execute_with_prober(|port| RawProbeResult {
            port,
            state: PortState::Open,
            rtt_micros: Some(800),
            attempts: 1,
            inline_banner: Some("HTTP/1.1 200 OK (nginx/1.26.2)".to_string()),
        })
        .unwrap();

    assert_eq!(out_json.exit_code(), 0);
    assert!(out_json
        .formatted_report
        .contains("\"scanner\": \"tcpscan-rs\""));
    assert!(out_json
        .formatted_report
        .contains("\"pattern\": \"Mediator\""));
    assert!(out_json.formatted_report.contains("\"port\": 8080"));
    assert!(out_json
        .formatted_report
        .contains("\"service_version\": \"nginx/1.26.2\""));
    assert!(out_json.formatted_report.contains("\"tls\": null"));

    // CSV mode with malicious formula-injection banner (=cmd|' /C calc'!A0)
    let action_csv = parse_cli_args(["127.0.0.1", "22,443", "--csv"]).unwrap();
    let cfg_csv = match action_csv {
        CliAction::Run(c) => c,
        _ => panic!("Expected Run"),
    };
    let out_csv = ScanPipeline::new(cfg_csv)
        .execute_with_prober(|port| RawProbeResult {
            port,
            state: PortState::Open,
            rtt_micros: Some(500),
            attempts: 1,
            inline_banner: if port == 22 {
                Some("=cmd|' /C calc'!A0".to_string())
            } else {
                None
            },
        })
        .unwrap();

    assert!(out_csv.formatted_report.starts_with(
        "target,ip,port,state,service,service_version,risk,category,rtt_ms,banner,advisory,tls_subject_cn,tls_issuer_cn,tls_self_signed,tls_hostname_mismatch,tls_days_until_expiry,tls_not_after,tls_sans,honeypot_verdict,honeypot_score,honeypot_behaviors,cpe,cves\n"
    ));
    assert!(out_csv
        .formatted_report
        .contains("\"127.0.0.1\",127.0.0.1,22,open,\"SSH\""));
    // Verify CWE-1236 formula payload is neutralized with leading single quote
    assert!(out_csv.formatted_report.contains("\"'=cmd|' /C calc'!A0\""));
    assert_eq!(sanitize_csv_cell("@SUM(1+1)*cmd"), "\"'@SUM(1+1)*cmd\"");
}

#[test]
fn test_origin_host_protection_flags_and_unsafe_addresses() {
    // 1. --protect-origin blocks scanning 127.0.0.1
    let (code_loopback, _, stderr_loopback) =
        run_from_args(["127.0.0.1", "80", "--protect-origin"]);
    assert_eq!(code_loopback, 1);
    assert!(stderr_loopback.contains("Origin Protection active"));

    // 2. 0.0.0.0 and 255.255.255.255 and multicast 224.0.0.1 are always blocked
    let (code_zero, _, stderr_zero) = run_from_args(["0.0.0.0", "80"]);
    assert_eq!(code_zero, 1);
    assert!(stderr_zero.contains("Origin Protection blocked unsafe target address"));

    let (code_bcast, _, stderr_bcast) = run_from_args(["255.255.255.255", "80"]);
    assert_eq!(code_bcast, 1);
    assert!(stderr_bcast.contains("Origin Protection blocked unsafe target address"));
}

#[test]
fn test_exit_code_2_when_all_ports_closed() {
    let action = parse_cli_args(["127.0.0.1", "80,443", "--no-color"]).unwrap();
    let cfg = match action {
        CliAction::Run(c) => c,
        _ => panic!("Expected Run"),
    };
    let out = ScanPipeline::new(cfg)
        .execute_with_prober(|port| RawProbeResult {
            port,
            state: PortState::Closed,
            rtt_micros: Some(100),
            attempts: 1,
            inline_banner: None,
        })
        .unwrap();

    assert_eq!(out.exit_code(), 2);
    assert!(out.formatted_report.contains("No open ports found."));
}

#[test]
fn test_e2e_live_loopback_nonblocking_socket() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_thread = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(250);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.7p1\r\n");
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    let target_with_port = format!("127.0.0.1:{port}");
    let (exit_code, stdout, _stderr) =
        run_from_args([&target_with_port, "--timeout", "0.15", "--no-color"]);

    let _ = server_thread.join();

    assert!(exit_code == 0 || exit_code == 2);
    assert!(stdout.contains("TCPSCAN / HXSCAN v3.0 Audit Report"));
}

#[test]
fn test_e2e_live_tls_certificate_capture_and_json_report() {
    // TLS-like ports are the only ones where the Mediator starts the exchange.
    let listener = [8443u16, 9443, 8883, 6443, 5986, 2376]
        .iter()
        .find_map(|port| TcpListener::bind((Ipv4Addr::LOCALHOST, *port)).ok())
        .expect("no free TLS-like loopback port available for the TLS test");
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_thread = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut hello = [0u8; 2048];
                let _ = std::io::Read::read(&mut stream, &mut hello);
                let _ = stream.write_all(&tls_server_response());
                let _ = stream.flush();
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    let target_with_port = format!("127.0.0.1:{port}");
    let (exit_code, stdout, _stderr) = run_from_args([
        &target_with_port,
        "--timeout",
        "0.5",
        "--json",
        "--no-color",
    ]);

    let _ = server_thread.join();

    assert_eq!(exit_code, 0, "stdout:\n{stdout}\nstderr:\n{_stderr}");
    assert!(
        stdout.contains("\"service_version\": null"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("\"subject_cn\": \"tls.test\""),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("\"issuer_cn\": \"Test CA\""));
    assert!(stdout.contains("\"self_signed\": false"));
    assert!(stdout.contains("\"chain_length\": 2"));
}

fn test_der(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else {
        let mut length = value.len();
        let mut bytes = Vec::new();
        while length > 0 {
            bytes.push((length & 0xFF) as u8);
            length >>= 8;
        }
        out.push(0x80 | bytes.len() as u8);
        for byte in bytes.iter().rev() {
            out.push(*byte);
        }
    }
    out.extend_from_slice(value);
    out
}

fn test_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    test_der(0x30, &parts.concat())
}

fn test_common_name(value: &str) -> Vec<u8> {
    test_sequence(&[test_der(
        0x31,
        &test_sequence(&[
            test_der(0x06, &[0x55, 0x04, 0x03]),
            test_der(0x0C, value.as_bytes()),
        ]),
    )])
}

fn tls_test_certificate() -> Vec<u8> {
    let signature_algorithm = test_sequence(&[
        test_der(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]),
        test_der(0x05, &[]),
    ]);
    let validity = test_sequence(&[
        test_der(0x17, b"250101000000Z"),
        test_der(0x17, b"301231235959Z"),
    ]);
    let subject_public_key_info = test_sequence(&[
        test_sequence(&[
            test_der(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]),
            test_der(0x03, &[0x00, 0x01, 0x02]),
        ]),
        test_der(0x03, &[0x00, 0xAA]),
    ]);
    let san_extension = test_sequence(&[
        test_der(0x06, &[0x55, 0x1D, 0x11]),
        test_der(0x04, &test_sequence(&[test_der(0x82, b"tls.test")])),
    ]);
    let extensions = test_der(0xA3, &test_sequence(&[san_extension]));
    let tbs = test_sequence(&[
        test_der(0xA0, &test_der(0x02, &[0x02])),
        test_der(0x02, &[0x01]),
        signature_algorithm.clone(),
        test_common_name("Test CA"),
        validity,
        test_common_name("tls.test"),
        subject_public_key_info,
        extensions,
    ]);
    test_sequence(&[tbs, signature_algorithm, test_der(0x03, &[0x00, 0xAA])])
}

fn tls_server_response() -> Vec<u8> {
    let der = tls_test_certificate();

    // Two identical entries exercise chain-length accounting.
    let mut certificate_body = Vec::new();
    let list_length = (der.len() + 3) * 2;
    certificate_body.push((list_length >> 16) as u8);
    certificate_body.push((list_length >> 8) as u8);
    certificate_body.push(list_length as u8);
    for _ in 0..2 {
        certificate_body.push((der.len() >> 16) as u8);
        certificate_body.push((der.len() >> 8) as u8);
        certificate_body.push(der.len() as u8);
        certificate_body.extend_from_slice(&der);
    }

    let mut certificate_message = vec![0x0B];
    let body_length = certificate_body.len();
    certificate_message.push((body_length >> 16) as u8);
    certificate_message.push((body_length >> 8) as u8);
    certificate_message.push(body_length as u8);
    certificate_message.extend_from_slice(&certificate_body);

    let server_hello = [0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00];

    let mut handshake = Vec::new();
    handshake.extend_from_slice(&server_hello);
    handshake.extend_from_slice(&certificate_message);

    let mut record = vec![0x16, 0x03, 0x03];
    record.push((handshake.len() >> 8) as u8);
    record.push(handshake.len() as u8);
    record.extend_from_slice(&handshake);
    record
}

#[test]
fn test_e2e_exit_code_1_on_invalid_arguments_and_ports() {
    let (code_empty, _, stderr_empty) = run_from_args(Vec::<&str>::new());
    assert_eq!(code_empty, 1);
    assert!(stderr_empty.contains("Missing target"));

    let (code_bad_port, _, stderr_bad_port) = run_from_args(["127.0.0.1", "9000-8000"]);
    assert_eq!(code_bad_port, 1);
    assert!(stderr_bad_port.contains("Port specification error"));

    let (code_oor, _, _) = run_from_args(["127.0.0.1", "70000"]);
    assert_eq!(code_oor, 1);

    let (code_help, stdout_help, _) = run_from_args(["--help"]);
    assert_eq!(code_help, 0);
    assert!(stdout_help.contains("USAGE:"));

    let (code_ver, stdout_ver, _) = run_from_args(["--version"]);
    assert_eq!(code_ver, 0);
    assert!(stdout_ver.contains("tcpscan 3.0.0"));
}

#[test]
fn test_cybersecurity_audit_stage_risk_classifications() {
    let mut ftp = EnrichedPortResult::new(21, PortState::Open, None);
    ftp.banner = Some("220 (vsFTPd 2.3.4)".to_string());
    let audited = tcpscan::evaluate_port_security(ftp, AddressScope::Private);
    assert_eq!(audited.risk, RiskLevel::Critical);
    assert!(audited.advisory.contains("CVE-2011-2523"));

    for &(port, name) in SERVICE_TABLE {
        assert!(port >= 1);
        assert!(!name.is_empty());
    }

    assert_eq!(
        parse_port_spec("22, 80, 8000-8002, 22").unwrap(),
        vec![22, 80, 8000, 8001, 8002]
    );
}

#[test]
fn test_honeypot_behavior_classification_and_confirmed_directive() {
    let action = parse_cli_args(["8.8.8.8", "22,2222,8080", "--no-color"]).unwrap();
    let config = match action {
        CliAction::Run(cfg) => cfg,
        _ => panic!("Expected CliAction::Run"),
    };

    let output = ScanController::new(config)
        .execute_with_prober(|port| match port {
            2222 => RawProbeResult {
                port,
                state: PortState::Open,
                rtt_micros: Some(900),
                attempts: 1,
                inline_banner: Some("SSH-2.0-Cowrie-1.0".to_string()),
            },
            22 => RawProbeResult {
                port,
                state: PortState::Open,
                rtt_micros: Some(700),
                attempts: 1,
                inline_banner: Some("SSH-2.0-OpenSSH_9.7p1".to_string()),
            },
            _ => RawProbeResult {
                port,
                state: PortState::Open,
                rtt_micros: Some(1_000),
                attempts: 1,
                inline_banner: Some("HTTP/1.1 200 OK (nginx/1.26.0)".to_string()),
            },
        })
        .unwrap();

    assert_eq!(output.summary.confirmed_honeypot_count, 1);
    assert_eq!(output.summary.possible_honeypot_count, 0);
    assert_eq!(output.deception_alerts.len(), 1);
    assert!(output.deception_alerts[0].contains("HONEYPOT CONFIRMED"));

    let cowrie = output
        .honeypot_assessments
        .iter()
        .find(|assessment| assessment.port == 2222)
        .unwrap();
    assert_eq!(cowrie.verdict, HoneypotVerdict::Honeypot);
    assert!(cowrie
        .behaviors
        .iter()
        .any(|behavior| behavior.as_str() == "known-honeypot-signature"));

    let honeypot_event = output
        .event_trace
        .iter()
        .find(|record| record.sender == ComponentId::HoneypotColleague)
        .unwrap();
    assert_eq!(
        honeypot_event.directive,
        MediatorDirective::ConfirmedHoneypotDetected { count: 1 }
    );
    assert!(output.formatted_report.contains("HONEYPOT"));
    assert!(output.formatted_report.contains("known-honeypot-signature"));
}

#[test]
fn test_mutable_mode_telemetry_and_persona() {
    let action = parse_cli_args(["127.0.0.1", "22,80", "--mutable", "--no-color"]).unwrap();
    let config = match action {
        CliAction::Run(cfg) => cfg,
        _ => panic!("Expected CliAction::Run"),
    };

    let output = ScanController::new(config)
        .execute_with_prober(|port| RawProbeResult {
            port,
            state: PortState::Open,
            rtt_micros: Some(800),
            attempts: 1,
            inline_banner: if port == 22 {
                Some("SSH-2.0-OpenSSH_9.7p1".to_string())
            } else {
                Some("HTTP/1.1 200 OK (Caddy)".to_string())
            },
        })
        .unwrap();

    assert_eq!(output.stealth_telemetry.mode, StealthMode::Mutable);
    assert_eq!(
        output.stealth_telemetry.persona,
        TrafficPersona::CorporateWorkstation
    );
    assert!(output.stealth_telemetry.ai_filter);
    assert!(output.stealth_telemetry.legitimacy_score >= 85);
    assert_eq!(output.stealth_telemetry.legitimacy_grade, 'A');

    let report = &output.formatted_report;
    assert!(report.contains("Mode: mutable"));
    assert!(report.contains("Persona: corporate"));
    assert!(report.contains("AI-Filter: on"));
    assert!(report.contains("Legitimacy:"));
}

#[test]
fn test_stealth_mode_engages_adaptive_pacing_on_filtered_feedback() {
    let action = parse_cli_args([
        "8.8.8.8",
        "1-10",
        "--stealth",
        "--max-pps",
        "1000",
        "--delay-ms",
        "0",
        "--jitter-ms",
        "0",
        "--burst-pause-ms",
        "0",
        "--no-color",
    ])
    .unwrap();
    let config = match action {
        CliAction::Run(cfg) => cfg,
        _ => panic!("Expected CliAction::Run"),
    };

    let output = ScanController::new(config)
        .execute_with_prober(|port| RawProbeResult {
            port,
            state: if port <= 3 {
                PortState::Filtered
            } else {
                PortState::Closed
            },
            rtt_micros: Some(200),
            attempts: 1,
            inline_banner: None,
        })
        .unwrap();

    let scanner_event = output
        .event_trace
        .iter()
        .find(|record| record.sender == ComponentId::ScannerColleague)
        .unwrap();
    assert_eq!(
        scanner_event.directive,
        MediatorDirective::AdaptivePacingEngaged {
            filtered_rate_pct: 30
        }
    );
    assert_eq!(output.stealth_telemetry.mode, StealthMode::Stealth);
    assert_eq!(output.stealth_telemetry.filtered_ratio_pct, 30);
}

#[test]
fn test_v3_aggressive_audit_cpe_cve_os_hint_and_honeypot_filtered_nmap_cmd() {
    let action = parse_cli_args([
        "10.0.0.5",
        "-p22,80,2222,8080",
        "--exclude-ports",
        "8080",
        "-A",
        "--no-color",
    ])
    .unwrap();
    let config = match action {
        CliAction::Run(cfg) => cfg,
        _ => panic!("Expected CliAction::Run"),
    };

    let output = ScanController::new(config)
        .execute_with_prober(|port| match port {
            22 => RawProbeResult {
                port,
                state: PortState::Open,
                rtt_micros: Some(450),
                attempts: 1,
                inline_banner: Some("SSH-2.0-OpenSSH_9.2p1 Debian-2".to_string()),
            },
            80 => RawProbeResult {
                port,
                state: PortState::Open,
                rtt_micros: Some(550),
                attempts: 1,
                inline_banner: Some("HTTP/1.1 200 OK (Apache/2.4.49 (Ubuntu))".to_string()),
            },
            2222 => RawProbeResult {
                port,
                state: PortState::Open,
                rtt_micros: Some(900),
                attempts: 1,
                inline_banner: Some("SSH-2.0-Cowrie-1.0".to_string()),
            },
            _ => unreachable!("Port 8080 should have been excluded by --exclude-ports"),
        })
        .unwrap();

    // Port 8080 was excluded, leaving 3 ports (22, 80, 2222)
    assert_eq!(output.summary.total_scanned, 3);
    assert_eq!(output.summary.os_hint.as_deref(), Some("Linux (Debian)"));

    let report = &output.formatted_report;
    assert!(report.contains("TCPSCAN / HXSCAN v3.0 Audit Report"));
    assert!(report.contains("OS Hint: Linux (Debian)"));
    assert!(report.contains("[CPE & Vulnerability Intelligence (CVE)]"));
    assert!(report.contains("cpe:2.3:a:openbsd:openssh:9.2p1:*:*:*:*:*:*:*"));
    assert!(report.contains("CVE-2024-6387"));
    assert!(report.contains("CVE-2021-41773"));
    // Honeypot port 2222 (Cowrie) MUST be excluded from the Nmap handoff command
    assert!(report.contains("[Honeypot-Filtered Nmap Handoff Command]"));
    assert!(report.contains("nmap -sV -sC -p 22,80 10.0.0.5"));
    assert!(!report.contains("nmap -sV -sC -p 22,80,2222"));
}

#[test]
fn test_v3_hybrid_recon_dnat_split_shadow_assets_and_attack_paths() {
    let action = parse_cli_args(["10.0.0.15", "-p25,443,3306", "--no-color"]).unwrap();
    let config = match action {
        CliAction::Run(cfg) => cfg,
        _ => panic!("Expected CliAction::Run"),
    };

    let output = ScanController::new(config)
        .execute_with_prober(|port| match port {
            25 => RawProbeResult {
                port,
                state: PortState::Open,
                rtt_micros: Some(2_200), // 2.2ms
                attempts: 1,
                inline_banner: Some("220 smtp-relay.internal.corp ESMTP Postfix".to_string()),
            },
            443 => RawProbeResult {
                port,
                state: PortState::Open,
                rtt_micros: Some(2_000), // 2.0ms (edge proxy)
                attempts: 1,
                inline_banner: Some("HTTP/1.1 200 OK (nginx/1.26.2)".to_string()),
            },
            3306 => RawProbeResult {
                port,
                state: PortState::Open,
                rtt_micros: Some(46_000), // 46.0ms (remote DNAT database)
                attempts: 1,
                inline_banner: Some("8.0.36-MySQL".to_string()),
            },
            _ => unreachable!(),
        })
        .unwrap();

    assert_eq!(
        output.summary.recon.host_role,
        "Web + Database Monolith (Co-Resident Stack)"
    );
    assert!(output.summary.recon.rtt_split_anomaly.is_some());
    assert_eq!(
        output.summary.recon.shadow_assets,
        vec!["smtp-relay.internal.corp".to_string()]
    );
    assert!(output
        .summary
        .recon
        .toxic_combinations
        .iter()
        .any(|c| c.contains("Web + Data Store Co-Residency")));

    let report = &output.formatted_report;
    assert!(report.contains("[Hybrid Recon & Attack Path Synthesis]"));
    assert!(report.contains("Host Role: Web + Database Monolith (Co-Resident Stack)"));
    assert!(report.contains("Proxy / DNAT Split: Port 443 (2.00ms) vs Port 3306 (46.00ms)"));
    assert!(report.contains("Shadow Assets / Pivot FQDNs: smtp-relay.internal.corp"));
    assert!(report.contains("Attack Path Chain: Web + Data Store Co-Residency"));
}
