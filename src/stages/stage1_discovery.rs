//! # Stage 1 Colleague: `DiscoveryColleague` (`stage1_discovery`)
//!
//! Concrete Colleague in the **Mediator Pattern** responsible for:
//! 1. Parsing and validating target strings (IPv4, IPv6, domain names, or `host:port` shorthand).
//! 2. Performing DNS resolution and classifying the network exposure scope (`Loopback`, `Private`, `LinkLocal`, `Public`).
//! 3. **Origin Host Protection (Anti-DNS-Rebinding & Unsafe IP Shield)**:
//!    - Blocks `Unspecified` (`0.0.0.0`, `::`), `Broadcast` (`255.255.255.255`), and `Multicast` (`224.0.0.0/4`, `ff00::/8`)
//!      addresses so the scanner never triggers local self-connects via `0.0.0.0` or LAN broadcast storms.
//!    - Detects and blocks **DNS Rebinding attacks** where an external domain name resolves to `127.0.0.0/8`,
//!      `::1`, or Link-Local (`169.254.0.0/16`), protecting the originating machine from unintended self-scanning.
//! 4. Expanding port specifications (`22,80,8000-8100` or presets) using a stack-allocated 8 KiB `PortBitmap`.
//! 5. Reporting [`ScanEvent::TargetDiscovered`] to the [`ScanMediator`] (`ScanController`).
//!
//! **Decoupling Guarantee**: This module has zero imports from `stage2`, `stage3`, `stage4`, or `stage5`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};

use crate::mediator::{
    AddressScope, ComponentId, MediatorDirective, ScanController, ScanEvent, ScanMediator,
    TargetInfo,
};

/// Default well-known cybersecurity audit ports.
pub const DEFAULT_PORTS_SPEC: &str =
    "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,2375,3306,3389,5432,5900,5985,6379,6443,8080,8443,9090,9200,27017";

/// Quick top-20 high-value ports for fast triage.
pub const QUICK_PORTS_SPEC: &str =
    "21,22,23,25,53,80,135,139,443,445,1433,3306,3389,5432,5900,6379,8080,8443,9200,27017";

/// Errors that can occur during Stage 1 (Discovery, Validation & Origin Host Protection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    EmptyTarget,
    DnsResolutionFailed(String),
    InvalidPortSpec(String),
    EmptyPortList,
    /// Target IP is unspecified (`0.0.0.0`/`::`), broadcast (`255.255.255.255`), or multicast.
    UnsafeTargetAddress(String),
    /// External domain resolved to loopback or link-local IP (DNS Rebinding against origin host).
    DnsRebindingDetected {
        domain: String,
        resolved_ip: IpAddr,
    },
    /// User enabled `--protect-origin` (`--no-loopback`) and attempted to scan the local origin machine.
    OriginHostProtected(IpAddr),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTarget => write!(f, "Target host cannot be empty"),
            Self::DnsResolutionFailed(msg) => write!(f, "DNS resolution failed: {msg}"),
            Self::InvalidPortSpec(msg) => write!(f, "Port specification error: {msg}"),
            Self::EmptyPortList => write!(f, "No valid ports to scan"),
            Self::UnsafeTargetAddress(msg) => {
                write!(f, "Origin Protection blocked unsafe target address: {msg}")
            }
            Self::DnsRebindingDetected {
                domain,
                resolved_ip,
            } => write!(
                f,
                "Origin Protection blocked potential DNS Rebinding: external domain '{domain}' resolved to local/reserved address {resolved_ip}"
            ),
            Self::OriginHostProtected(ip) => write!(
                f,
                "Origin Protection active (--protect-origin): refusing to scan local host address {ip}"
            ),
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// **Colleague 1 (`DiscoveryColleague`)**: Interacts exclusively with the [`ScanController`] Mediator.
pub struct DiscoveryColleague;

impl DiscoveryColleague {
    /// Execute Stage 1 discovery and notify the [`ScanController`] Mediator via [`ScanEvent::TargetDiscovered`].
    pub fn run(
        mediator: &mut ScanController,
        seed: u64,
    ) -> Result<MediatorDirective, DiscoveryError> {
        let target = resolve_target(&mediator.config.target_input)?;

        if mediator.config.protect_origin && target.scope == AddressScope::Loopback {
            return Err(DiscoveryError::OriginHostProtected(target.primary_ip));
        }

        let effective_port_spec = if let Some(inline_p) = target.inline_port {
            if mediator.config.port_spec.is_empty() {
                inline_p.to_string()
            } else {
                mediator.config.port_spec.clone()
            }
        } else {
            mediator.config.port_spec.clone()
        };

        let mut ports = parse_port_spec(&effective_port_spec)?;
        if mediator.config.shuffle {
            shuffle_ports(&mut ports, seed);
        }

        let directive = mediator.notify(
            ComponentId::DiscoveryColleague,
            ScanEvent::TargetDiscovered { target, ports },
        );
        Ok(directive)
    }
}

/// Validate that an IP address does not endanger the originating host (e.g. `0.0.0.0` self-connect,
/// broadcast storm, multicast, or DNS Rebinding from an external hostname to `127.0.0.1` / `169.254.x.x`).
pub fn validate_ip_safety(
    ip: IpAddr,
    raw_host: &str,
    was_dns_resolved: bool,
) -> Result<(), DiscoveryError> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                return Err(DiscoveryError::UnsafeTargetAddress(
                    "0.0.0.0 (unspecified address redirects to local origin host)".to_string(),
                ));
            }
            if v4.is_broadcast() {
                return Err(DiscoveryError::UnsafeTargetAddress(
                    "255.255.255.255 (broadcast address)".to_string(),
                ));
            }
            if v4.is_multicast() {
                return Err(DiscoveryError::UnsafeTargetAddress(format!(
                    "{v4} (multicast address range 224.0.0.0/4)"
                )));
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                return Err(DiscoveryError::UnsafeTargetAddress(
                    ":: (unspecified IPv6 address redirects to local origin host)".to_string(),
                ));
            }
            if v6.is_multicast() {
                return Err(DiscoveryError::UnsafeTargetAddress(format!(
                    "{v6} (IPv6 multicast address)"
                )));
            }
        }
    }

    // Anti-DNS Rebinding protection: if the user supplied a domain name (not "localhost"),
    // it must NOT resolve to Loopback (127.0.0.0/8, ::1) or Link-Local (169.254.0.0/16, fe80::/10).
    if was_dns_resolved {
        let lower = raw_host.to_ascii_lowercase();
        let is_explicit_localhost = lower == "localhost"
            || lower == "localhost.localdomain"
            || lower.ends_with(".localhost");

        if !is_explicit_localhost {
            let scope = AddressScope::from_ip(ip);
            if matches!(scope, AddressScope::Loopback | AddressScope::LinkLocal) {
                return Err(DiscoveryError::DnsRebindingDetected {
                    domain: raw_host.to_string(),
                    resolved_ip: ip,
                });
            }
        }
    }

    Ok(())
}

/// Split an input string into `(host, Optional<inline_port>)` if it uses `host:port` or `[ipv6]:port` syntax.
pub fn split_target_inline_port(input: &str) -> (&str, Option<u16>) {
    let trimmed = input.trim();
    if trimmed.starts_with('[') {
        if let Some(end_bracket) = trimmed.find(']') {
            let host = &trimmed[1..end_bracket];
            let rest = &trimmed[end_bracket + 1..];
            if let Some(port_str) = rest.strip_prefix(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    if port >= 1 {
                        return (host, Some(port));
                    }
                }
            }
            return (host, None);
        }
    }

    if trimmed.matches(':').count() == 1 {
        if let Some((host, port_str)) = trimmed.rsplit_once(':') {
            if !host.is_empty() {
                if let Ok(port) = port_str.parse::<u16>() {
                    if port >= 1 {
                        return (host, Some(port));
                    }
                }
            }
        }
    }

    (trimmed, None)
}

/// Resolve a hostname or IP string into a [`TargetInfo`] with Origin Host Protection checks.
pub fn resolve_target(target: &str) -> Result<TargetInfo, DiscoveryError> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err(DiscoveryError::EmptyTarget);
    }

    let (host, inline_port) = split_target_inline_port(trimmed);
    if host.is_empty() {
        return Err(DiscoveryError::EmptyTarget);
    }

    // Fast path: direct IP literal
    if let Ok(ip) = host.parse::<IpAddr>() {
        validate_ip_safety(ip, host, false)?;
        return Ok(TargetInfo {
            raw_input: host.to_string(),
            primary_ip: ip,
            all_ips: vec![ip],
            scope: AddressScope::from_ip(ip),
            inline_port,
        });
    }

    let addrs_iter = (host, 0u16)
        .to_socket_addrs()
        .map_err(|e| DiscoveryError::DnsResolutionFailed(format!("{host} ({e})")))?;

    let mut all_ips: Vec<IpAddr> = Vec::new();
    for sock_addr in addrs_iter {
        let ip = sock_addr.ip();
        validate_ip_safety(ip, host, true)?;
        if !all_ips.contains(&ip) {
            all_ips.push(ip);
        }
    }

    if all_ips.is_empty() {
        return Err(DiscoveryError::DnsResolutionFailed(format!(
            "No IP addresses found for {host}"
        )));
    }

    let primary_ip = all_ips
        .iter()
        .copied()
        .find(|ip| ip.is_ipv4())
        .unwrap_or(all_ips[0]);

    Ok(TargetInfo {
        raw_input: host.to_string(),
        primary_ip,
        all_ips,
        scope: AddressScope::from_ip(primary_ip),
        inline_port,
    })
}

/// Resolve a hostname to a primary IP string.
pub fn resolve_target_ip_string(target: &str) -> Result<String, DiscoveryError> {
    Ok(resolve_target(target)?.primary_ip.to_string())
}

/// Stack-allocated 65,536-bit bitmap (`[u64; 1024]` = 8 KiB) for O(1) port deduplication and sorting.
struct PortBitmap {
    bits: [u64; 1024],
    count: usize,
}

impl PortBitmap {
    #[inline]
    const fn new() -> Self {
        Self {
            bits: [0u64; 1024],
            count: 0,
        }
    }

    #[inline]
    fn insert(&mut self, port: u16) {
        let idx = (port as usize) >> 6;
        let mask = 1u64 << ((port as usize) & 63);
        if (self.bits[idx] & mask) == 0 {
            self.bits[idx] |= mask;
            self.count += 1;
        }
    }

    #[inline]
    fn insert_range(&mut self, start: u16, end: u16) {
        for p in start..=end {
            self.insert(p);
        }
    }

    fn into_sorted_vec(self) -> Vec<u16> {
        let mut out = Vec::with_capacity(self.count);
        for (word_idx, &word) in self.bits.iter().enumerate() {
            if word == 0 {
                continue;
            }
            let mut w = word;
            while w != 0 {
                let bit = w.trailing_zeros() as usize;
                let port = ((word_idx << 6) | bit) as u16;
                if port >= 1 {
                    out.push(port);
                }
                w &= w - 1;
            }
        }
        out
    }
}

/// Parse a port specification string into a deduplicated, sorted `Vec<u16>`.
pub fn parse_port_spec(spec: &str) -> Result<Vec<u16>, DiscoveryError> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(DiscoveryError::EmptyPortList);
    }

    let expanded = match trimmed.to_ascii_lowercase().as_str() {
        "default" | "common" => DEFAULT_PORTS_SPEC,
        "quick" | "fast" | "top20" => QUICK_PORTS_SPEC,
        "all" | "full" | "-" => "1-65535",
        _ => trimmed,
    };

    let mut bitmap = PortBitmap::new();

    for raw_token in expanded.split(',') {
        let token = raw_token.trim();
        if token.is_empty() {
            continue;
        }

        if let Some((start_str, end_str)) = token.split_once('-') {
            let start_val = start_str.trim().parse::<u32>().map_err(|_| {
                DiscoveryError::InvalidPortSpec(format!("Invalid port range: {token}"))
            })?;
            let end_val = end_str.trim().parse::<u32>().map_err(|_| {
                DiscoveryError::InvalidPortSpec(format!("Invalid port range: {token}"))
            })?;

            if start_val < 1 || end_val > 65535 || start_val > end_val {
                return Err(DiscoveryError::InvalidPortSpec(format!(
                    "Invalid port range: {token}"
                )));
            }
            bitmap.insert_range(start_val as u16, end_val as u16);
        } else {
            let port_val = token.parse::<u32>().map_err(|_| {
                DiscoveryError::InvalidPortSpec(format!("Invalid port number: {token}"))
            })?;
            if !(1..=65535).contains(&port_val) {
                return Err(DiscoveryError::InvalidPortSpec(format!(
                    "Port out of range (1-65535): {port_val}"
                )));
            }
            bitmap.insert(port_val as u16);
        }
    }

    let ports = bitmap.into_sorted_vec();
    if ports.is_empty() {
        return Err(DiscoveryError::EmptyPortList);
    }

    Ok(ports)
}

/// Deterministically or pseudo-randomly shuffle a port slice in-place using Fisher-Yates + Xorshift64.
pub fn shuffle_ports(ports: &mut [u16], seed: u64) {
    if ports.len() <= 1 {
        return;
    }
    let mut state = if seed == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        seed
    };
    for i in (1..ports.len()).rev() {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let rnd = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        let j = (rnd as usize) % (i + 1);
        ports.swap(i, j);
    }
}

/// Helper to build a [`SocketAddr`] from an [`IpAddr`] and port.
#[inline]
pub const fn make_socket_addr(ip: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(ip, port)
}

/// Helper to construct a loopback IPv4 address for testing.
#[inline]
pub const fn loopback_v4() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_port() {
        assert_eq!(parse_port_spec("80").unwrap(), vec![80]);
    }

    #[test]
    fn test_multiple_ports_sorted() {
        assert_eq!(parse_port_spec("443,22,80").unwrap(), vec![22, 80, 443]);
    }

    #[test]
    fn test_range() {
        assert_eq!(
            parse_port_spec("8000-8003").unwrap(),
            vec![8000, 8001, 8002, 8003]
        );
    }

    #[test]
    fn test_mixed_ports_and_ranges() {
        assert_eq!(
            parse_port_spec("22,80,8000-8002").unwrap(),
            vec![22, 80, 8000, 8001, 8002]
        );
    }

    #[test]
    fn test_deduplication_via_bitmap() {
        assert_eq!(parse_port_spec("80,80,80,79-81").unwrap(), vec![79, 80, 81]);
    }

    #[test]
    fn test_full_65535_range_performance_and_accuracy() {
        let all = parse_port_spec("all").unwrap();
        assert_eq!(all.len(), 65535);
        assert_eq!(all.first().copied(), Some(1));
        assert_eq!(all.last().copied(), Some(65535));
    }

    #[test]
    fn test_named_presets() {
        let quick = parse_port_spec("quick").unwrap();
        assert!(quick.contains(&22));
        assert!(quick.contains(&80));
        assert!(quick.contains(&443));

        let common = parse_port_spec("common").unwrap();
        assert!(common.len() >= quick.len());
    }

    #[test]
    fn test_invalid_range_inverted_fails() {
        assert!(parse_port_spec("8000-7999").is_err());
    }

    #[test]
    fn test_out_of_range_ports_fail() {
        assert!(parse_port_spec("0").is_err());
        assert!(parse_port_spec("70000").is_err());
        assert!(parse_port_spec("0-80").is_err());
        assert!(parse_port_spec("100-65536").is_err());
    }

    #[test]
    fn test_empty_tokens_ignored_unless_all_empty() {
        assert_eq!(parse_port_spec("22,,80,").unwrap(), vec![22, 80]);
        assert!(parse_port_spec(",,,").is_err());
        assert!(parse_port_spec("   ").is_err());
    }

    #[test]
    fn test_address_scope_classification() {
        assert_eq!(
            AddressScope::from_ip("127.0.0.1".parse().unwrap()),
            AddressScope::Loopback
        );
        assert_eq!(
            AddressScope::from_ip("192.168.1.50".parse().unwrap()),
            AddressScope::Private
        );
        assert_eq!(
            AddressScope::from_ip("10.0.0.1".parse().unwrap()),
            AddressScope::Private
        );
        assert_eq!(
            AddressScope::from_ip("169.254.10.20".parse().unwrap()),
            AddressScope::LinkLocal
        );
        assert_eq!(
            AddressScope::from_ip("8.8.8.8".parse().unwrap()),
            AddressScope::Public
        );
        assert_eq!(
            AddressScope::from_ip("::1".parse().unwrap()),
            AddressScope::Loopback
        );
    }

    #[test]
    fn test_resolve_target_ip_and_inline_port() {
        let info = resolve_target("127.0.0.1:8080").unwrap();
        assert_eq!(info.primary_ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(info.inline_port, Some(8080));
        assert_eq!(info.scope, AddressScope::Loopback);

        let v6_info = resolve_target("[::1]:9000").unwrap();
        assert_eq!(v6_info.primary_ip, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(v6_info.inline_port, Some(9000));
    }

    #[test]
    fn test_origin_protection_blocks_unspecified_broadcast_multicast_and_dns_rebinding() {
        // 0.0.0.0 redirects to origin host on macOS/Linux — must be blocked
        assert!(matches!(
            resolve_target("0.0.0.0"),
            Err(DiscoveryError::UnsafeTargetAddress(_))
        ));
        assert!(matches!(
            resolve_target("::"),
            Err(DiscoveryError::UnsafeTargetAddress(_))
        ));
        // Broadcast & Multicast must be blocked
        assert!(matches!(
            resolve_target("255.255.255.255"),
            Err(DiscoveryError::UnsafeTargetAddress(_))
        ));
        assert!(matches!(
            resolve_target("224.0.0.1"),
            Err(DiscoveryError::UnsafeTargetAddress(_))
        ));

        // DNS Rebinding: external domain resolving to 127.0.0.1 or 169.254.169.254 must be blocked
        let loopback_ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(matches!(
            validate_ip_safety(loopback_ip, "evil-rebind.attacker.com", true),
            Err(DiscoveryError::DnsRebindingDetected { .. })
        ));
        let metadata_ip: IpAddr = "169.254.169.254".parse().unwrap();
        assert!(matches!(
            validate_ip_safety(metadata_ip, "ssrf.attacker.com", true),
            Err(DiscoveryError::DnsRebindingDetected { .. })
        ));
        // Explicit "localhost" is allowed
        assert!(validate_ip_safety(loopback_ip, "localhost", true).is_ok());
    }

    #[test]
    fn test_shuffle_ports_preserves_elements() {
        let mut ports: Vec<u16> = (1..=50).collect();
        let original = ports.clone();
        shuffle_ports(&mut ports, 42);
        assert_ne!(ports, original);
        ports.sort_unstable();
        assert_eq!(ports, original);
    }
}
