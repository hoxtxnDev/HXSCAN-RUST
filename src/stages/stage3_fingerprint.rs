//! # Stage 3 Colleague: `FingerprintColleague` (`stage3_fingerprint`)
//!
//! Concrete Colleague in the **Mediator Pattern** responsible for:
//! 1. Resolving well-known service names via a compile-time sorted table (`SERVICE_TABLE`) using binary search.
//! 2. Performing protocol-aware active **Banner Grabbing** when invoked by the Mediator's [`ScanMediator::mediate_open_stream`].
//! 3. Dynamically inferring the true protocol (`SSH`, `HTTP`, `FTP`, `SMTP`, `Redis`, `MySQL`, etc.) from banners.
//! 4. Sanitizing captured banners against ANSI/terminal control-character injection.
//! 5. Emitting [`ScanEvent::FingerprintingCompleted`] back to the [`ScanController`] Mediator.
//!
//! **Decoupling Guarantee**: Zero imports from `stage1`, `stage2`, `stage4`, or `stage5`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::mediator::{
    ComponentId, EnrichedPortResult, MediatorDirective, PortState, RawProbeResult, ScanController,
    ScanEvent, ScanMediator, TrafficPersona,
};
use crate::stealth::build_http_probe;

/// Compile-time sorted `(port, service_name)` table covering all original `hxscan` services
/// plus key enterprise, cloud, and cybersecurity infrastructure ports.
pub const SERVICE_TABLE: &[(u16, &str)] = &[
    (20, "FTP-data"),
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (67, "DHCP-server"),
    (68, "DHCP-client"),
    (69, "TFTP"),
    (80, "HTTP"),
    (88, "Kerberos"),
    (110, "POP3"),
    (111, "RPC"),
    (123, "NTP"),
    (135, "MS-RPC"),
    (137, "NetBIOS-ns"),
    (138, "NetBIOS-dgm"),
    (139, "NetBIOS-ssn"),
    (143, "IMAP"),
    (161, "SNMP"),
    (162, "SNMP-trap"),
    (389, "LDAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (465, "SMTPS"),
    (500, "IKE"),
    (514, "Syslog"),
    (587, "SMTP-submission"),
    (636, "LDAPS"),
    (853, "DNS-over-TLS"),
    (873, "Rsync"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1080, "SOCKS"),
    (1194, "OpenVPN"),
    (1433, "MSSQL"),
    (1521, "Oracle-DB"),
    (1883, "MQTT"),
    (2049, "NFS"),
    (2181, "ZooKeeper"),
    (2375, "Docker-API"),
    (2376, "Docker-TLS"),
    (2379, "Etcd"),
    (3000, "HTTP-dev"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5000, "UPnP"),
    (5432, "PostgreSQL"),
    (5601, "Kibana"),
    (5672, "AMQP"),
    (5900, "VNC"),
    (5901, "VNC-1"),
    (5985, "WinRM-HTTP"),
    (5986, "WinRM-HTTPS"),
    (6379, "Redis"),
    (6443, "Kubernetes-API"),
    (8000, "HTTP-alt3"),
    (8080, "HTTP-alt"),
    (8443, "HTTPS-alt"),
    (8883, "MQTTS"),
    (8888, "HTTP-proxy"),
    (9000, "FastCGI"),
    (9042, "Cassandra"),
    (9090, "HTTP-alt2"),
    (9092, "Kafka"),
    (9200, "Elasticsearch"),
    (9418, "Git"),
    (9443, "HTTPS-mgmt"),
    (10250, "Kubelet"),
    (11211, "Memcached"),
    (27017, "MongoDB"),
];

/// **Colleague 3 (`FingerprintColleague`)**: Service Identification & Banner Grabbing Colleague.
pub struct FingerprintColleague;

impl FingerprintColleague {
    /// Called by [`ScanController::mediate_open_stream`] to inspect a live open TCP socket.
    pub fn inspect_live_stream(
        port: u16,
        stream: &mut TcpStream,
        banner_timeout: Duration,
    ) -> Option<String> {
        grab_banner_from_stream(port, stream, banner_timeout)
    }

    /// Persona-aware variant used by the Mediator in `stealth`/`mutable` modes.
    /// Mutates HTTP headers so the active probe resembles ordinary enterprise traffic.
    pub fn inspect_live_stream_with_persona(
        port: u16,
        stream: &mut TcpStream,
        banner_timeout: Duration,
        persona: TrafficPersona,
        host: &str,
        seed: u64,
    ) -> Option<String> {
        let _ = stream.set_read_timeout(Some(banner_timeout));
        let _ = stream.set_write_timeout(Some(banner_timeout));
        grab_banner_from_rw_with_persona(port, stream, persona, host, seed)
    }

    /// Enrich all raw probe results stored in the Mediator and emit [`ScanEvent::FingerprintingCompleted`].
    ///
    /// TLS certificates captured during Stage 2 stream mediation are attached here,
    /// keeping `ScannerColleague` unaware of certificate parsing.
    pub fn run(mediator: &mut ScanController) -> MediatorDirective {
        let raw = std::mem::take(&mut mediator.raw_results);
        let mut enriched_results = enrich_probe_results(raw);
        for item in &mut enriched_results {
            if item.state == PortState::Open {
                item.tls = mediator.tls_certificate(item.port);
            }
        }
        mediator.notify(
            ComponentId::FingerprintColleague,
            ScanEvent::FingerprintingCompleted { enriched_results },
        )
    }
}

impl EnrichedPortResult {
    /// Construct a result compatible with `hxscan`'s `ScanResult` semantics:
    /// if `state == Open` and `service == "unknown"`, resolves the well-known service name.
    pub fn new(port: u16, state: PortState, service: Option<&str>) -> Self {
        let resolved_service = match (&state, service) {
            (PortState::Open, None | Some("unknown") | Some("")) => {
                get_service_name(port).to_string()
            }
            (_, Some(s)) if !s.is_empty() => s.to_string(),
            (PortState::Error(err_msg), None) => err_msg.clone(),
            _ => "unknown".to_string(),
        };

        Self {
            port,
            state,
            service: resolved_service,
            service_version: None,
            banner: None,
            rtt_micros: None,
            tls: None,
        }
    }
}

/// Look up the well-known service name for `port` in $O(\log N)$ via binary search.
pub fn get_service_name(port: u16) -> &'static str {
    match SERVICE_TABLE.binary_search_by_key(&port, |&(p, _)| p) {
        Ok(idx) => SERVICE_TABLE[idx].1,
        Err(_) => "unknown",
    }
}

/// Check whether `port` typically speaks HTTP in cleartext and expects a client request first.
#[inline]
pub fn is_http_like_port(port: u16) -> bool {
    matches!(
        port,
        80 | 2375 | 3000 | 5000 | 5601 | 5985 | 8000 | 8080 | 8888 | 9090 | 9200
    )
}

/// Strip ANSI CSI (`\x1b[...X`) and OSC (`\x1b]...\x07`) terminal escape sequences completely
/// before filtering printable ASCII characters, protecting the origin host's terminal emulator.
fn strip_ansi_sequences(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    // CSI sequence: consume '[' and parameters until final byte (0x40..=0x7E)
                    let _ = chars.next();
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // OSC sequence: consume until BEL (\x07) or ST (\x1b\\)
                    let _ = chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\x07' {
                            break;
                        }
                        if c == '\x1b' && chars.peek().copied() == Some('\\') {
                            let _ = chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            }
        } else if ch.is_ascii_graphic() || ch == ' ' {
            out.push(ch);
        }
    }
    out
}

/// Sanitize raw bytes read from a network socket into a clean, single-line printable banner.
pub fn sanitize_banner(raw: &[u8]) -> Option<String> {
    if raw.is_empty() {
        return None;
    }

    let lossy = String::from_utf8_lossy(raw);
    let mut lines = lossy
        .lines()
        .map(strip_ansi_sequences)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let first_line = lines.next()?;

    if first_line.starts_with("HTTP/") {
        for line in lines {
            if line.len() > 7 && line[..7].eq_ignore_ascii_case("server:") {
                let srv = line[7..].trim();
                if !srv.is_empty() {
                    let combined = format!("{first_line} ({srv})");
                    return Some(truncate_str(&combined, 96));
                }
            }
        }
    }

    Some(truncate_str(&first_line, 96))
}

#[inline]
fn truncate_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max_chars.saturating_sub(3)).collect();
        out.push_str("...");
        out
    }
}

/// Infer the underlying protocol name from a captured banner when running on a non-standard port.
pub fn infer_service_from_banner(banner: &str) -> Option<&'static str> {
    let upper = banner.to_ascii_uppercase();
    if upper.starts_with("SSH-") {
        Some("SSH")
    } else if upper.starts_with("HTTP/") {
        Some("HTTP")
    } else if upper.starts_with("220 ") && (upper.contains("SMTP") || upper.contains("ESMTP")) {
        Some("SMTP")
    } else if upper.starts_with("220 ") && upper.contains("FTP") {
        Some("FTP")
    } else if upper.starts_with("+PONG") || upper.starts_with("-NOAUTH") || upper.contains("REDIS")
    {
        Some("Redis")
    } else if upper.starts_with("+OK") {
        Some("POP3")
    } else if upper.starts_with("* OK") && upper.contains("IMAP") {
        Some("IMAP")
    } else if upper.contains("MARIADB") || upper.contains("MYSQL") {
        Some("MySQL")
    } else if upper.starts_with("RFB ") {
        Some("VNC")
    } else {
        None
    }
}

/// Extract a human-readable product version from a sanitized banner.
///
/// The function is intentionally conservative: it only recognizes well-known
/// protocol greetings and HTTP `Server` products, avoiding speculative matches
/// that would pollute the report with random tokens.
pub fn extract_service_version(service: &str, banner: Option<&str>) -> Option<String> {
    let banner = banner?;
    let first = banner.lines().next()?.trim();
    if first.is_empty() {
        return None;
    }

    for prefix in ["SSH-2.0-", "SSH-1.99-", "SSH-1.5-"] {
        if let Some(rest) = first.strip_prefix(prefix) {
            let version = rest.split_whitespace().next()?.trim();
            if !version.is_empty() {
                return Some(truncate_version(version));
            }
        }
    }

    let lower = service.to_ascii_lowercase();
    if lower.contains("http")
        || lower.contains("winrm")
        || lower.contains("kubernetes")
        || lower.contains("docker")
        || lower.contains("elastic")
        || lower.contains("kibana")
    {
        if let Some(start) = first.rfind('(') {
            if let Some(rest) = first.get(start + 1..) {
                if let Some(end) = rest.rfind(')') {
                    let product = rest[..end].trim();
                    if !product.is_empty() {
                        return Some(truncate_version(product));
                    }
                }
            }
        }
    }

    if lower.contains("ftp")
        || lower.contains("smtp")
        || lower.contains("mail")
        || lower.contains("pop3")
        || lower.contains("imap")
    {
        let greeting = first.strip_prefix("220").unwrap_or(first).trim();
        for marker in [
            "vsFTPd",
            "ProFTPD",
            "Pure-FTPd",
            "FileZilla",
            "Postfix",
            "Exim",
            "Sendmail",
            "Microsoft",
            "Dovecot",
            "Courier",
        ] {
            if let Some(position) = find_ignore_ascii_case(greeting, marker) {
                let product = greeting[position..]
                    .trim()
                    .trim_end_matches(&[')', ']'][..]);
                if !product.is_empty() {
                    return Some(truncate_version(product));
                }
            }
        }
    }

    if lower.contains("mysql") || lower.contains("maria") {
        for token in banner.split(|ch: char| ch.is_whitespace() || ch.is_control()) {
            let candidate = token.trim_matches(|ch: char| !ch.is_ascii_graphic());
            if candidate.contains('.') && candidate.chars().any(|ch| ch.is_ascii_digit()) {
                return Some(truncate_version(candidate));
            }
        }
    }

    if lower.contains("redis") {
        if let Some(position) = find_ignore_ascii_case(banner, "redis_version:") {
            let rest = &banner[position + "redis_version:".len()..];
            let version = rest
                .split(|ch: char| ch.is_whitespace() || ch == '\r' || ch == '\n')
                .next()?
                .trim();
            if !version.is_empty() {
                return Some(truncate_version(version));
            }
        }
    }

    None
}

#[inline]
fn find_ignore_ascii_case(haystack: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let needle_bytes = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle_bytes.len())
        .position(|window| window.eq_ignore_ascii_case(needle_bytes))
}

fn truncate_version(value: &str) -> String {
    value.trim().chars().take(48).collect()
}

/// Protocol-aware banner reader operating on any `Read + Write` stream.
pub fn grab_banner_from_rw<S: Read + Write>(port: u16, stream: &mut S) -> Option<String> {
    let mut buf = [0u8; 512];

    if is_http_like_port(port) {
        let _ = stream
            .write_all(b"HEAD / HTTP/1.0\r\nUser-Agent: tcpscan/2.2\r\nConnection: close\r\n\r\n");
        if let Ok(n) = stream.read(&mut buf) {
            if n > 0 {
                return sanitize_banner(&buf[..n]);
            }
        }
        return None;
    }

    if port == 6379 {
        let _ = stream.write_all(b"PING\r\n");
    }

    if let Ok(n) = stream.read(&mut buf) {
        if n > 0 {
            return sanitize_banner(&buf[..n]);
        }
    }

    if get_service_name(port) == "unknown" {
        let _ = stream.write_all(b"HEAD / HTTP/1.0\r\nConnection: close\r\n\r\n");
        if let Ok(n) = stream.read(&mut buf) {
            if n > 0 {
                return sanitize_banner(&buf[..n]);
            }
        }
    }

    None
}

/// Protocol-aware banner reader with enterprise persona mutation.
///
/// HTTP-like probes use realistic browser/update-agent headers instead of the
/// explicit `tcpscan` User-Agent. Non-HTTP protocols preserve their original probe.
pub fn grab_banner_from_rw_with_persona<S: Read + Write>(
    port: u16,
    stream: &mut S,
    persona: TrafficPersona,
    host: &str,
    seed: u64,
) -> Option<String> {
    let mut buf = [0u8; 512];

    if is_http_like_port(port) {
        let request = build_http_probe(persona, host, seed);
        let _ = stream.write_all(&request);
        if let Ok(n) = stream.read(&mut buf) {
            if n > 0 {
                return sanitize_banner(&buf[..n]);
            }
        }
        return None;
    }

    if port == 6379 {
        let _ = stream.write_all(b"PING\r\n");
    }

    if let Ok(n) = stream.read(&mut buf) {
        if n > 0 {
            return sanitize_banner(&buf[..n]);
        }
    }

    if get_service_name(port) == "unknown" {
        let request = build_http_probe(persona, host, seed);
        let _ = stream.write_all(&request);
        if let Ok(n) = stream.read(&mut buf) {
            if n > 0 {
                return sanitize_banner(&buf[..n]);
            }
        }
    }

    None
}

/// Attempt to grab a service banner from an already-connected [`TcpStream`].
pub fn grab_banner_from_stream(
    port: u16,
    stream: &mut TcpStream,
    banner_timeout: Duration,
) -> Option<String> {
    let _ = stream.set_read_timeout(Some(banner_timeout));
    let _ = stream.set_write_timeout(Some(banner_timeout));
    grab_banner_from_rw(port, stream)
}

/// Execute Stage 3 enrichment across a batch of [`RawProbeResult`] items.
pub fn enrich_probe_results(raw_results: Vec<RawProbeResult>) -> Vec<EnrichedPortResult> {
    raw_results
        .into_iter()
        .map(|raw| {
            let mut service = if raw.state == PortState::Open {
                get_service_name(raw.port).to_string()
            } else if let PortState::Error(ref msg) = raw.state {
                msg.clone()
            } else {
                "unknown".to_string()
            };

            if raw.state == PortState::Open {
                if let Some(ref banner) = raw.inline_banner {
                    if let Some(inferred) = infer_service_from_banner(banner) {
                        if service == "unknown" {
                            service = inferred.to_string();
                        }
                    }
                }
            }

            let service_version = if raw.state == PortState::Open {
                extract_service_version(&service, raw.inline_banner.as_deref())
            } else {
                None
            };

            EnrichedPortResult {
                port: raw.port,
                state: raw.state,
                service,
                service_version,
                banner: raw.inline_banner,
                rtt_micros: raw.rtt_micros,
                tls: None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct MockStream {
        read_data: Vec<u8>,
        read_pos: usize,
        written_data: Vec<u8>,
    }

    impl MockStream {
        fn new(response: &[u8]) -> Self {
            Self {
                read_data: response.to_vec(),
                read_pos: 0,
                written_data: Vec::new(),
            }
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let remaining = &self.read_data[self.read_pos..];
            let to_copy = remaining.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            Ok(to_copy)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written_data.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_service_table_is_strictly_sorted() {
        for window in SERVICE_TABLE.windows(2) {
            assert!(
                window[0].0 < window[1].0,
                "SERVICE_TABLE must be strictly sorted by port: {} >= {}",
                window[0].0,
                window[1].0
            );
            assert!(window[0].0 >= 1);
        }
    }

    #[test]
    fn test_known_ports_lookup() {
        assert_eq!(get_service_name(22), "SSH");
        assert_eq!(get_service_name(80), "HTTP");
        assert_eq!(get_service_name(443), "HTTPS");
        assert_eq!(get_service_name(3306), "MySQL");
        assert_eq!(get_service_name(3389), "RDP");
        assert_eq!(get_service_name(6379), "Redis");
        assert_eq!(get_service_name(27017), "MongoDB");
    }

    #[test]
    fn test_unknown_port_lookup() {
        assert_eq!(get_service_name(9999), "unknown");
        assert_eq!(get_service_name(42424), "unknown");
    }

    #[test]
    fn test_enriched_port_result_semantics() {
        let open_ssh = EnrichedPortResult::new(22, PortState::Open, None);
        assert_eq!(open_ssh.service, "SSH");

        let closed_unknown = EnrichedPortResult::new(9999, PortState::Closed, None);
        assert_eq!(closed_unknown.service, "unknown");

        let open_unknown = EnrichedPortResult::new(9999, PortState::Open, None);
        assert_eq!(open_unknown.service, "unknown");

        let err_res = EnrichedPortResult::new(80, PortState::Error("timeout".into()), None);
        assert_eq!(err_res.service, "timeout");
    }

    #[test]
    fn test_sanitize_banner_strips_control_chars_and_parses_http_server() {
        let raw_http = b"HTTP/1.1 200 OK\r\nDate: Wed\r\nServer: nginx/1.26.0\r\n\r\n";
        assert_eq!(
            sanitize_banner(raw_http).as_deref(),
            Some("HTTP/1.1 200 OK (nginx/1.26.0)")
        );

        let raw_ansi = b"\x1b]0;pwned\x07SSH-2.0-OpenSSH_9.6\x1b[31m\r\n";
        assert_eq!(
            sanitize_banner(raw_ansi).as_deref(),
            Some("SSH-2.0-OpenSSH_9.6")
        );
    }

    #[test]
    fn test_grab_banner_from_rw_http_and_redis_and_ssh() {
        let mut http_mock = MockStream::new(b"HTTP/1.0 200 OK\r\nServer: Caddy\r\n\r\n");
        let banner = grab_banner_from_rw(80, &mut http_mock).unwrap();
        assert_eq!(banner, "HTTP/1.0 200 OK (Caddy)");
        assert!(String::from_utf8_lossy(&http_mock.written_data).starts_with("HEAD / HTTP/1.0"));

        let mut redis_mock = MockStream::new(b"+PONG\r\n");
        let r_banner = grab_banner_from_rw(6379, &mut redis_mock).unwrap();
        assert_eq!(r_banner, "+PONG");
        assert_eq!(&redis_mock.written_data, b"PING\r\n");

        let mut ssh_mock = MockStream::new(b"SSH-2.0-OpenSSH_9.8\r\n");
        let s_banner = grab_banner_from_rw(22, &mut ssh_mock).unwrap();
        assert_eq!(s_banner, "SSH-2.0-OpenSSH_9.8");
        assert!(ssh_mock.written_data.is_empty());
    }

    #[test]
    fn test_grab_banner_with_persona_mutates_http_headers() {
        let mut mock = MockStream::new(b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n");
        let banner = grab_banner_from_rw_with_persona(
            80,
            &mut mock,
            TrafficPersona::CorporateWorkstation,
            "portal.example.test",
            7,
        )
        .unwrap();
        assert!(banner.contains("HTTP/1.1 200 OK"));
        let written = String::from_utf8_lossy(&mock.written_data);
        assert!(written.starts_with("GET / HTTP/1.1"));
        assert!(written.contains("Host: portal.example.test"));
        assert!(!written.to_ascii_lowercase().contains("tcpscan"));
    }

    #[test]
    fn test_infer_service_from_banner() {
        assert_eq!(
            infer_service_from_banner("SSH-2.0-OpenSSH_9.7"),
            Some("SSH")
        );
        assert_eq!(
            infer_service_from_banner("HTTP/1.1 403 Forbidden"),
            Some("HTTP")
        );
        assert_eq!(
            infer_service_from_banner("220 mail.example.com ESMTP Postfix"),
            Some("SMTP")
        );
        assert_eq!(
            infer_service_from_banner("-NOAUTH Authentication required."),
            Some("Redis")
        );
    }

    #[test]
    fn test_extract_service_version_from_common_banners() {
        assert_eq!(
            extract_service_version("SSH", Some("SSH-2.0-OpenSSH_9.7p1 Ubuntu-3")),
            Some("OpenSSH_9.7p1".to_string())
        );
        assert_eq!(
            extract_service_version("HTTP", Some("HTTP/1.1 200 OK (nginx/1.26.0)")),
            Some("nginx/1.26.0".to_string())
        );
        assert_eq!(
            extract_service_version("FTP", Some("220 (vsFTPd 3.0.5)")),
            Some("vsFTPd 3.0.5".to_string())
        );
        assert_eq!(
            extract_service_version("SMTP", Some("220 mail.example.test ESMTP Postfix")),
            Some("Postfix".to_string())
        );
        assert_eq!(extract_service_version("Redis", Some("+PONG")), None);
        assert_eq!(extract_service_version("unknown", Some("READY")), None);
    }

    #[test]
    fn test_enrich_probe_results_populates_service_version() {
        let raw = vec![RawProbeResult {
            port: 22,
            state: PortState::Open,
            rtt_micros: Some(900),
            attempts: 1,
            inline_banner: Some("SSH-2.0-OpenSSH_9.7p1".to_string()),
        }];
        let enriched = enrich_probe_results(raw);
        assert_eq!(enriched.len(), 1);
        assert_eq!(
            enriched[0].service_version.as_deref(),
            Some("OpenSSH_9.7p1")
        );
        assert!(enriched[0].tls.is_none());
    }
}
