//! Comprehensive End-to-End, Stage, Mediator Pattern & Origin-Protection Tests for `tcpscan` (HXSCAN-RUST v2.0).

use std::io::Write;
use std::net::{Ipv4Addr, TcpListener};
use std::thread;
use std::time::{Duration, Instant};

use tcpscan::{
    parse_cli_args, parse_port_spec, run_from_args, sanitize_csv_cell, AddressScope, CliAction,
    ComponentId, EnrichedPortResult, MediatorDirective, MediatorState, PortState, RawProbeResult,
    RiskLevel, ScanController, ScanPipeline, SERVICE_TABLE,
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

    assert_eq!(output.event_trace.len(), 6);
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
    assert_eq!(output.event_trace[3].sender, ComponentId::AuditColleague);
    assert_eq!(
        output.event_trace[3].directive,
        MediatorDirective::EscalateCriticalAlert {
            port: 6379,
            service: "Redis".to_string()
        }
    );
    assert_eq!(output.event_trace[4].sender, ComponentId::AuditColleague);
    assert_eq!(output.event_trace[5].sender, ComponentId::ReportColleague);
    assert_eq!(
        output.event_trace[5].resulting_state,
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
    assert!(out_json.formatted_report.contains("\"scanner\": \"tcpscan-rs\""));
    assert!(out_json.formatted_report.contains("\"pattern\": \"Mediator\""));
    assert!(out_json.formatted_report.contains("\"port\": 8080"));

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

    assert!(out_csv
        .formatted_report
        .starts_with("target,ip,port,state,service,risk,category,rtt_ms,banner,advisory\n"));
    assert!(out_csv
        .formatted_report
        .contains("\"127.0.0.1\",127.0.0.1,22,open,\"SSH\""));
    // Verify CWE-1236 formula payload is neutralized with leading single quote
    assert!(out_csv.formatted_report.contains("\"'=cmd|' /C calc'!A0\""));
    assert_eq!(
        sanitize_csv_cell("@SUM(1+1)*cmd"),
        "\"'@SUM(1+1)*cmd\""
    );
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
    assert!(stdout.contains("TCPSCAN / HXSCAN v2.0 Audit Report"));
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
    assert!(stdout_ver.contains("tcpscan 2.0.0"));
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
