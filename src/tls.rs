//! # TLS Certificate Reconnaissance (`tls`)
//!
//! Shared, dependency-free infrastructure used by the Mediator during **Stage 2**
//! stream mediation. It performs a deliberately minimal TLS 1.2 `ClientHello`
//! exchange to retrieve the server certificate and extract reconnaissance metadata:
//!
//! - Subject / issuer Common Name (`CN`).
//! - DNS Subject Alternative Names (`SAN`).
//! - `notAfter` and remaining days.
//! - Self-signed heuristic (subject == issuer).
//! - Hostname mismatch against the requested SNI.
//! - Advertised chain length.
//!
//! ## Important limits
//! This module **does not complete a TLS handshake**, does not verify signatures,
//! does not derive session keys and does not send application data. It stops after
//! the server certificate, so it cannot be used to intercept, decrypt or modify TLS
//! traffic. Certificate metadata is passive reconnaissance and may be spoofed by a
//! deceptive endpoint; it is a signal, not a proof.

use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::mediator::contract::TlsCertificateInfo;

const MAX_TLS_RECORDS: usize = 32;
const MAX_HANDSHAKE_BYTES: usize = 256 * 1024;
const MAX_TLS_RECORD_BYTES: usize = 18_432;

/// Ports that normally require a TLS handshake before any application banner.
pub fn is_tls_like_port(port: u16) -> bool {
    matches!(
        port,
        443 | 465 | 636 | 853 | 993 | 995 | 2376 | 5986 | 6443 | 8443 | 8883 | 9443
    )
}

/// Extract a DNS name suitable for SNI from the user-supplied target.
///
/// IP literals (including IPv6) return `None` because SNI must contain a hostname.
pub fn server_name_from_input(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }

    let host = if let Some(rest) = trimmed.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else if trimmed.matches(':').count() == 1 {
        match trimmed.rsplit_once(':') {
            Some((head, tail)) if tail.parse::<u16>().is_ok() => head,
            _ => trimmed,
        }
    } else {
        trimmed
    };

    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    if host.len() > 253
        || !host
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_')
    {
        return None;
    }

    Some(host.to_ascii_lowercase())
}

/// Perform the minimal TLS exchange on an already-connected socket with a strict total deadline.
///
/// Enforces an absolute wall-clock `deadline = Instant::now() + timeout` across the entire
/// handshake read loop so a "slowloris" TLS tarpit dripping 1 byte at a time cannot hold a
/// worker thread beyond `timeout`.
pub fn inspect_tls_certificate(
    stream: &mut TcpStream,
    server_name: Option<&str>,
    timeout: Duration,
) -> Option<TlsCertificateInfo> {
    let deadline = Instant::now() + timeout;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let hello = build_tls_client_hello(server_name);
    stream.write_all(&hello).ok()?;
    stream.flush().ok()?;
    let (certificate, chain_length) = read_server_certificate_tcp(stream, deadline)?;
    parse_certificate_der(&certificate, server_name, chain_length)
}

/// Generic, testable TLS certificate negotiation over any `Read + Write` stream.
pub fn negotiate_tls_certificate<S: Read + Write>(
    stream: &mut S,
    server_name: Option<&str>,
) -> Option<TlsCertificateInfo> {
    negotiate_tls_certificate_with_timeout(stream, server_name, Duration::from_secs(5))
}

/// Generic, testable TLS certificate negotiation with an explicit wall-clock timeout ceiling.
pub fn negotiate_tls_certificate_with_timeout<S: Read + Write>(
    stream: &mut S,
    server_name: Option<&str>,
    timeout: Duration,
) -> Option<TlsCertificateInfo> {
    let deadline = Instant::now() + timeout;
    let hello = build_tls_client_hello(server_name);
    stream.write_all(&hello).ok()?;
    stream.flush().ok()?;
    let (certificate, chain_length) = read_server_certificate(stream, deadline)?;
    parse_certificate_der(&certificate, server_name, chain_length)
}

/// Build a TLS 1.2 `ClientHello` record with optional SNI and modern ECDSA + RSA cipher suites.
///
/// The offered cipher suites cover both `ECDHE_ECDSA` and `ECDHE_RSA` (including ChaCha20-Poly1305,
/// AES-GCM, and AES-CBC) so servers with either ECDSA (P-256/P-384) or RSA certificates return
/// their certificate in cleartext (TLS 1.2 `Certificate` message).
pub fn build_tls_client_hello(server_name: Option<&str>) -> Vec<u8> {
    let random = client_random(server_name);

    let mut extensions = Vec::new();
    if let Some(name) = server_name {
        let mut sni_entry = Vec::new();
        push_u16(&mut sni_entry, name.len());
        sni_entry.extend_from_slice(name.as_bytes());
        let mut sni_data = Vec::new();
        push_u16(&mut sni_data, sni_entry.len());
        sni_data.extend_from_slice(&sni_entry);
        push_extension(&mut extensions, 0x0000, &sni_data);
    }
    // supported_groups: x25519 (0x001D), secp256r1 (0x0017), secp384r1 (0x0018)
    push_extension(
        &mut extensions,
        0x000A,
        &[0x00, 0x06, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x18],
    );
    // ec_point_formats: uncompressed
    push_extension(&mut extensions, 0x000B, &[0x01, 0x00]);
    // signature_algorithms: ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ed25519,
    // rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pkcs1_sha512
    push_extension(
        &mut extensions,
        0x000D,
        &[
            0x00, 0x10, 0x04, 0x03, 0x05, 0x03, 0x08, 0x07, 0x08, 0x04, 0x08, 0x05, 0x04, 0x01,
            0x05, 0x01, 0x06, 0x01,
        ],
    );
    // extended_master_secret
    push_extension(&mut extensions, 0x0017, &[]);

    let mut body = Vec::with_capacity(160);
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    body.extend_from_slice(&random);
    body.push(0x00); // empty session id

    let cipher_suites: [u16; 14] = [
        0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        0xC009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0xC00A, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
        0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384
        0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
    ];
    push_u16(&mut body, cipher_suites.len() * 2);
    for suite in cipher_suites {
        body.extend_from_slice(&suite.to_be_bytes());
    }
    body.extend_from_slice(&[0x01, 0x00]); // one compression method: null
    push_u16(&mut body, extensions.len());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(0x01); // ClientHello
    push_u24(&mut handshake, body.len());
    handshake.extend_from_slice(&body);

    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.extend_from_slice(&[0x16, 0x03, 0x01]); // handshake, TLS 1.0 record for compatibility
    push_u16(&mut record, handshake.len());
    record.extend_from_slice(&handshake);
    record
}

fn client_random(server_name: Option<&str>) -> [u8; 32] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0x51ED_270B_9E37_79B9);
    let mut state = now
        ^ 0x9E37_79B9_7F4A_7C15
        ^ ((server_name.map(|name| name.len() as u64).unwrap_or(0)) << 32);
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let value = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    out
}

/// Read exact bytes while enforcing an overall wall-clock `deadline`.
/// If `on_chunk` is provided (for `TcpStream`), updates the OS socket read timeout before each syscall.
fn read_exact_until<S, F>(
    stream: &mut S,
    mut buf: &mut [u8],
    deadline: Instant,
    mut update_timeout: F,
) -> Option<()>
where
    S: Read,
    F: FnMut(&mut S, Duration),
{
    while !buf.is_empty() {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        if remaining.is_zero() {
            return None;
        }
        update_timeout(stream, remaining);
        match stream.read(buf) {
            Ok(0) => return None,
            Ok(n) => {
                buf = &mut buf[n..];
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(())
}

/// Read TLS records from a live `TcpStream` with per-chunk remaining deadline updates.
fn read_server_certificate_tcp(
    stream: &mut TcpStream,
    deadline: Instant,
) -> Option<(Vec<u8>, usize)> {
    read_server_certificate_with_hook(stream, deadline, |s, rem| {
        let _ = s.set_read_timeout(Some(rem));
    })
}

/// Read TLS records until a `Certificate` handshake message is found or `deadline` expires.
fn read_server_certificate<S: Read + Write>(
    stream: &mut S,
    deadline: Instant,
) -> Option<(Vec<u8>, usize)> {
    read_server_certificate_with_hook(stream, deadline, |_, _| {})
}

fn read_server_certificate_with_hook<S, F>(
    stream: &mut S,
    deadline: Instant,
    mut update_timeout: F,
) -> Option<(Vec<u8>, usize)>
where
    S: Read + Write,
    F: FnMut(&mut S, Duration),
{
    let mut handshake = Vec::with_capacity(4096);
    let mut cursor = 0usize;
    let mut records = 0usize;
    let mut record_buf = [0u8; MAX_TLS_RECORD_BYTES];

    loop {
        records += 1;
        if records > MAX_TLS_RECORDS {
            return None;
        }

        let mut header = [0u8; 5];
        read_exact_until(stream, &mut header, deadline, &mut update_timeout)?;
        let content_type = header[0];
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        if length == 0 || length > MAX_TLS_RECORD_BYTES {
            return None;
        }

        let payload = &mut record_buf[..length];
        read_exact_until(stream, payload, deadline, &mut update_timeout)?;

        match content_type {
            22 => {
                if handshake.len() + payload.len() > MAX_HANDSHAKE_BYTES {
                    return None;
                }
                handshake.extend_from_slice(payload);
                while let Some((message_type, body, consumed)) =
                    next_handshake_message(&handshake[cursor..])
                {
                    if message_type == 11 {
                        let (certificate, chain_length) = parse_certificate_message(body)?;
                        return Some((certificate, chain_length));
                    }
                    if message_type == 14 {
                        // ServerHelloDone reached without a certificate.
                        return None;
                    }
                    cursor += consumed;
                }
            }
            21 => return None, // alert
            _ => {}
        }
    }
}

fn next_handshake_message(buffer: &[u8]) -> Option<(u8, &[u8], usize)> {
    if buffer.len() < 4 {
        return None;
    }
    let length = ((buffer[1] as usize) << 16) | ((buffer[2] as usize) << 8) | buffer[3] as usize;
    if length > MAX_HANDSHAKE_BYTES || buffer.len() < 4 + length {
        return None;
    }
    Some((buffer[0], &buffer[4..4 + length], 4 + length))
}

/// Parse a TLS 1.2 `Certificate` message body and return the leaf DER plus chain length.
fn parse_certificate_message(body: &[u8]) -> Option<(Vec<u8>, usize)> {
    if body.len() < 3 {
        return None;
    }
    let list_length = u24(&body[0..3])?;
    if list_length == 0 || body.len() < 3 + list_length {
        return None;
    }

    let end = 3 + list_length;
    let mut offset = 3usize;
    let mut first = None;
    let mut count = 0usize;
    while offset + 3 <= end {
        let certificate_length = u24(&body[offset..offset + 3])?;
        offset += 3;
        if certificate_length == 0 || offset + certificate_length > body.len() {
            return None;
        }
        if first.is_none() {
            first = Some(body[offset..offset + certificate_length].to_vec());
        }
        count += 1;
        offset += certificate_length;
    }

    if count == 0 {
        return None;
    }
    Some((first?, count))
}

#[derive(Clone, Copy)]
struct DerNode<'a> {
    tag: u8,
    value: &'a [u8],
    raw: &'a [u8],
}

fn parse_der(input: &[u8]) -> Option<(DerNode<'_>, usize)> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    let first = input[1];
    let (length, header_length) = if first < 0x80 {
        (first as usize, 2usize)
    } else {
        let bytes = (first & 0x7F) as usize;
        if bytes == 0 || bytes > 4 || input.len() < 2 + bytes {
            return None;
        }
        let mut length = 0usize;
        for byte in &input[2..2 + bytes] {
            length = (length << 8) | *byte as usize;
        }
        (length, 2 + bytes)
    };

    let total = header_length + length;
    if input.len() < total {
        return None;
    }
    Some((
        DerNode {
            tag,
            value: &input[header_length..total],
            raw: &input[..total],
        },
        total,
    ))
}

fn der_children(node: DerNode<'_>) -> Option<Vec<DerNode<'_>>> {
    let mut children = Vec::new();
    let mut rest = node.value;
    while !rest.is_empty() {
        let (child, consumed) = parse_der(rest)?;
        children.push(child);
        rest = &rest[consumed..];
    }
    Some(children)
}

/// Parse the leaf certificate DER and compute reconnaissance metadata.
fn parse_certificate_der(
    der: &[u8],
    server_name: Option<&str>,
    chain_length: usize,
) -> Option<TlsCertificateInfo> {
    let (certificate, _) = parse_der(der)?;
    if certificate.tag != 0x30 {
        return None;
    }
    let certificate_fields = der_children(certificate)?;
    let tbs = *certificate_fields.first()?;
    if tbs.tag != 0x30 {
        return None;
    }
    let fields = der_children(tbs)?;

    let mut index = 0usize;
    if fields.first().map(|node| node.tag) == Some(0xA0) {
        index += 1; // explicit version
    }
    if fields.get(index)?.tag != 0x02 {
        return None; // serialNumber
    }
    index += 1;
    if fields.get(index)?.tag != 0x30 {
        return None; // signature algorithm
    }
    index += 1;
    let issuer = *fields.get(index)?;
    index += 1;
    let validity = *fields.get(index)?;
    index += 1;
    let subject = *fields.get(index)?;
    index += 1;
    if fields.get(index)?.tag != 0x30 {
        return None; // subjectPublicKeyInfo
    }
    let extension_fields = &fields[index + 1..];

    let subject_cn = extract_common_name(subject);
    let issuer_cn = extract_common_name(issuer);
    let sans = extract_sans(extension_fields);
    let not_after = extract_not_after(validity);
    let days_until_expiry = not_after.as_ref().and_then(|(_, day)| days_until(*day));
    let self_signed = issuer.raw == subject.raw;
    let hostname_mismatch = server_name
        .map(|host| !certificate_matches_host(subject_cn.as_deref(), &sans, host))
        .unwrap_or(false);

    Some(TlsCertificateInfo {
        subject_cn,
        issuer_cn,
        sans,
        not_after: not_after.map(|(value, _)| value),
        days_until_expiry,
        self_signed,
        hostname_mismatch,
        chain_length,
    })
}

fn extract_common_name(name: DerNode<'_>) -> Option<String> {
    for rdn in der_children(name)? {
        if rdn.tag != 0x31 {
            continue;
        }
        for attribute in der_children(rdn)? {
            if attribute.tag != 0x30 {
                continue;
            }
            let parts = der_children(attribute)?;
            if parts.len() >= 2 && parts[0].tag == 0x06 && parts[0].value == [0x55, 0x04, 0x03] {
                return der_string(parts[1]);
            }
        }
    }
    None
}

fn extract_sans(extension_fields: &[DerNode<'_>]) -> Vec<String> {
    let Some(extensions) = extension_fields.iter().find(|node| node.tag == 0xA3) else {
        return Vec::new();
    };
    let Some(sequence) = der_children(*extensions).and_then(|children| children.into_iter().next())
    else {
        return Vec::new();
    };
    if sequence.tag != 0x30 {
        return Vec::new();
    }
    let Some(entries) = der_children(sequence) else {
        return Vec::new();
    };

    for entry in entries {
        if entry.tag != 0x30 {
            continue;
        }
        let Some(parts) = der_children(entry) else {
            continue;
        };
        let is_san = parts
            .first()
            .map(|part| part.tag == 0x06 && part.value == [0x55, 0x1D, 0x11])
            .unwrap_or(false);
        if !is_san {
            continue;
        }
        let Some(octet) = parts.iter().find(|part| part.tag == 0x04) else {
            continue;
        };
        let Some((san_sequence, _)) = parse_der(octet.value) else {
            continue;
        };
        if san_sequence.tag != 0x30 {
            continue;
        }
        let Some(names) = der_children(san_sequence) else {
            continue;
        };
        let mut sans = Vec::new();
        for name in names {
            if name.tag == 0x82 {
                if let Some(value) = der_string(name) {
                    if !sans.contains(&value) {
                        sans.push(value);
                    }
                }
            }
            if sans.len() >= 16 {
                break;
            }
        }
        return sans;
    }
    Vec::new()
}

fn extract_not_after(validity: DerNode<'_>) -> Option<(String, i64)> {
    let fields = der_children(validity)?;
    let not_after = *fields.get(1)?;
    let (year, month, day) = parse_asn1_time(not_after)?;
    let raw = String::from_utf8_lossy(not_after.value).trim().to_string();
    Some((raw, days_from_civil(year, month, day)))
}

fn parse_asn1_time(node: DerNode<'_>) -> Option<(i64, u32, u32)> {
    let text = std::str::from_utf8(node.value).ok()?.trim();
    let digits = text.strip_suffix('Z')?;
    let (year, rest) = match node.tag {
        0x17 if digits.len() >= 10 => {
            let short: i64 = digits.get(0..2)?.parse().ok()?;
            (
                if short >= 70 {
                    1900 + short
                } else {
                    2000 + short
                },
                &digits[2..],
            )
        }
        0x18 if digits.len() >= 12 => {
            let full: i64 = digits.get(0..4)?.parse().ok()?;
            (full, &digits[4..])
        }
        _ => return None,
    };
    let month: u32 = rest.get(0..2)?.parse().ok()?;
    let day: u32 = rest.get(2..4)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((year, month, day))
}

/// Days since 1970-01-01 (Howard Hinnant's civil calendar algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = (month as i64 + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn days_until(epoch_day: i64) -> Option<i64> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    Some(epoch_day - now / 86_400)
}

fn certificate_matches_host(subject_cn: Option<&str>, sans: &[String], host: &str) -> bool {
    if sans.is_empty() {
        subject_cn
            .map(|cn| hostname_matches(cn, host))
            .unwrap_or(false)
    } else {
        sans.iter().any(|name| hostname_matches(name, host))
    }
}

fn hostname_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.');
    let host = host.trim().trim_end_matches('.');
    if pattern.eq_ignore_ascii_case(host) {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if host.len() > suffix.len() {
            let split_at = host.len() - suffix.len();
            if host.is_char_boundary(split_at) && host[split_at..].eq_ignore_ascii_case(suffix) {
                let prefix = &host[..split_at];
                return prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.');
            }
        }
    }
    false
}

/// Filter out control characters AND Unicode Bidirectional / zero-width formatting characters
/// (`U+202A..=U+202E`, `U+2066..=U+2069`, `U+200B..=U+200F`, `U+061C`, `U+FEFF`) to prevent
/// terminal/report RLO spoofing (Trojan Source / Bidi override attacks).
#[inline]
fn is_safe_cert_char(ch: char) -> bool {
    if ch.is_control() {
        return false;
    }
    !matches!(
        ch,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
    )
}

fn der_string(node: DerNode<'_>) -> Option<String> {
    match node.tag {
        0x0C | 0x13 | 0x16 | 0x82 => {
            let cleaned: String = String::from_utf8_lossy(node.value)
                .trim()
                .chars()
                .filter(|&ch| is_safe_cert_char(ch))
                .take(128)
                .collect();
            if cleaned.is_empty() {
                None
            } else {
                Some(cleaned)
            }
        }
        _ => None,
    }
}

fn push_u16(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u16).to_be_bytes());
}

fn push_u24(out: &mut Vec<u8>, value: usize) {
    out.push((value >> 16) as u8);
    out.push((value >> 8) as u8);
    out.push(value as u8);
}

fn push_extension(out: &mut Vec<u8>, extension_type: u16, data: &[u8]) {
    out.extend_from_slice(&extension_type.to_be_bytes());
    push_u16(out, data.len());
    out.extend_from_slice(data);
}

fn u24(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 3 {
        return None;
    }
    Some(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct MockStream {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
    }

    impl MockStream {
        fn new(response: &[u8]) -> Self {
            Self {
                read_data: response.to_vec(),
                read_pos: 0,
                written: Vec::new(),
            }
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let remaining = &self.read_data[self.read_pos..];
            let copied = remaining.len().min(buf.len());
            buf[..copied].copy_from_slice(&remaining[..copied]);
            self.read_pos += copied;
            Ok(copied)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if value.len() < 0x80 {
            out.push(value.len() as u8);
        } else {
            let bytes = value.len().to_be_bytes();
            let first = bytes
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(bytes.len() - 1);
            out.push(0x80 | (bytes.len() - first) as u8);
            out.extend_from_slice(&bytes[first..]);
        }
        out.extend_from_slice(value);
        out
    }

    fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
        der(0x30, &parts.concat())
    }

    fn set(parts: &[Vec<u8>]) -> Vec<u8> {
        der(0x31, &parts.concat())
    }

    fn oid(bytes: &[u8]) -> Vec<u8> {
        der(0x06, bytes)
    }

    fn utf8(value: &str) -> Vec<u8> {
        der(0x0C, value.as_bytes())
    }

    fn common_name(value: &str) -> Vec<u8> {
        sequence(&[set(&[sequence(&[oid(&[0x55, 0x04, 0x03]), utf8(value)])])])
    }

    fn certificate_der(subject: &str, issuer: &str, not_after: &str, san: &[&str]) -> Vec<u8> {
        let signature_algorithm = sequence(&[
            oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]),
            der(0x05, &[]),
        ]);
        let validity = sequence(&[der(0x17, b"250101000000Z"), der(0x17, not_after.as_bytes())]);
        let subject_public_key_info = sequence(&[
            sequence(&[
                oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]),
                der(0x03, &[0x00, 0x01, 0x02]),
            ]),
            der(0x03, &[0x00, 0xAA]),
        ]);
        let mut extensions = Vec::new();
        if !san.is_empty() {
            let names: Vec<Vec<u8>> = san.iter().map(|name| der(0x82, name.as_bytes())).collect();
            let san_extension = sequence(&[oid(&[0x55, 0x1D, 0x11]), der(0x04, &sequence(&names))]);
            extensions = der(0xA3, &sequence(&[san_extension]));
        }
        let tbs = sequence(&[
            der(0xA0, &der(0x02, &[0x02])),
            der(0x02, &[0x01]),
            signature_algorithm.clone(),
            common_name(issuer),
            validity,
            common_name(subject),
            subject_public_key_info,
            extensions,
        ]);
        sequence(&[tbs, signature_algorithm, der(0x03, &[0x00, 0xAA])])
    }

    #[test]
    fn test_server_name_from_input() {
        assert_eq!(
            server_name_from_input("example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            server_name_from_input("example.com:443"),
            Some("example.com".to_string())
        );
        assert_eq!(server_name_from_input("127.0.0.1"), None);
        assert_eq!(server_name_from_input("[::1]:443"), None);
        assert_eq!(server_name_from_input("bad host"), None);
    }

    #[test]
    fn test_client_hello_is_tls12_with_sni() {
        let hello = build_tls_client_hello(Some("example.com"));
        assert_eq!(hello[0], 0x16);
        assert_eq!(&hello[1..3], &[0x03, 0x01]);
        assert_eq!(hello[5], 0x01); // ClientHello
        let text = String::from_utf8_lossy(&hello);
        assert!(text.contains("example.com"));
        assert_eq!(&hello[9..11], &[0x03, 0x03]); // TLS 1.2
    }

    #[test]
    fn test_parse_certificate_extracts_identity_and_sans() {
        let der = certificate_der(
            "test.local",
            "Test CA",
            "301231235959Z",
            &["test.local", "www.test.local"],
        );
        let info =
            parse_certificate_der(&der, Some("test.local"), 2).expect("certificate should parse");
        assert_eq!(info.subject_cn.as_deref(), Some("test.local"));
        assert_eq!(info.issuer_cn.as_deref(), Some("Test CA"));
        assert_eq!(info.sans, vec!["test.local", "www.test.local"]);
        assert_eq!(info.chain_length, 2);
        assert!(!info.self_signed);
        assert!(!info.hostname_mismatch);
        assert!(info.days_until_expiry.unwrap_or_default() > 0);
    }

    #[test]
    fn test_parse_certificate_detects_self_signed_and_mismatch() {
        let der = certificate_der("localhost", "localhost", "200101000000Z", &["localhost"]);
        let info =
            parse_certificate_der(&der, Some("example.com"), 1).expect("certificate should parse");
        assert!(info.self_signed);
        assert!(info.hostname_mismatch);
        assert!(info.days_until_expiry.unwrap_or_default() < 0);
    }

    #[test]
    fn test_wildcard_hostname_matching() {
        assert!(hostname_matches("*.example.com", "app.example.com"));
        assert!(!hostname_matches("*.example.com", "a.b.example.com"));
        assert!(!hostname_matches("*.example.com", "example.com"));
        assert!(hostname_matches("example.com", "example.com"));
    }

    #[test]
    fn test_negotiate_certificate_over_mock_stream() {
        let der = certificate_der("mock.local", "Mock CA", "301231235959Z", &["mock.local"]);
        let mut certificate_body = Vec::new();
        push_u24(&mut certificate_body, der.len() + 3);
        push_u24(&mut certificate_body, der.len());
        certificate_body.extend_from_slice(&der);
        let mut certificate_message = Vec::new();
        certificate_message.push(0x0B);
        push_u24(&mut certificate_message, certificate_body.len());
        certificate_message.extend_from_slice(&certificate_body);

        let server_hello = [0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00];
        let mut handshake = Vec::new();
        handshake.extend_from_slice(&server_hello);
        handshake.extend_from_slice(&certificate_message);
        let mut record = vec![0x16, 0x03, 0x03];
        push_u16(&mut record, handshake.len());
        record.extend_from_slice(&handshake);

        let mut stream = MockStream::new(&record);
        let info = negotiate_tls_certificate(&mut stream, Some("mock.local"))
            .expect("mock TLS handshake should yield a certificate");
        assert_eq!(info.subject_cn.as_deref(), Some("mock.local"));
        assert_eq!(info.issuer_cn.as_deref(), Some("Mock CA"));
        assert!(!stream.written.is_empty());
    }

    #[test]
    fn test_truncated_certificate_is_rejected() {
        let der = certificate_der("test.local", "Test CA", "301231235959Z", &[]);
        let truncated = &der[..der.len() / 2];
        assert!(parse_certificate_der(truncated, None, 1).is_none());
    }

    struct DripStream {
        data: Vec<u8>,
        pos: usize,
        drip_delay: Duration,
    }

    impl Read for DripStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            std::thread::sleep(self.drip_delay);
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    impl Write for DripStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_slowloris_tls_drip_stream_aborts_at_total_deadline() {
        // Advertise a 10,000-byte TLS handshake record, dripping 1 byte every 20ms.
        // Without a total deadline, read_exact would block for 200 seconds.
        // With a 70ms total timeout, it must abort in well under 250ms.
        let mut fake_record = vec![0x16, 0x03, 0x03, 0x27, 0x10];
        fake_record.extend(std::iter::repeat_n(0x41u8, 100));
        let mut drip = DripStream {
            data: fake_record,
            pos: 0,
            drip_delay: Duration::from_millis(20),
        };
        let start = Instant::now();
        let res = negotiate_tls_certificate_with_timeout(
            &mut drip,
            Some("slowloris.test"),
            Duration::from_millis(70),
        );
        assert!(res.is_none());
        assert!(start.elapsed() < Duration::from_millis(350));
    }

    #[test]
    fn test_bidi_override_characters_stripped_from_cn_and_san() {
        let der = certificate_der(
            "portal\u{202E}live.test",
            "Test\u{2066}CA",
            "301231235959Z",
            &["sub\u{202E}.example.com"],
        );
        let info = parse_certificate_der(&der, None, 1).expect("certificate should parse");
        assert_eq!(info.subject_cn.as_deref(), Some("portallive.test"));
        assert_eq!(info.issuer_cn.as_deref(), Some("TestCA"));
        assert_eq!(info.sans, vec!["sub.example.com"]);
    }

    #[test]
    fn test_client_hello_includes_ecdsa_and_chacha20_suites() {
        let hello = build_tls_client_hello(Some("ecdsa.example.com"));
        // Verify ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B) and CHACHA20 (0xCCA9) are offered
        assert!(hello.windows(2).any(|w| w == [0xC0, 0x2B]));
        assert!(hello.windows(2).any(|w| w == [0xCC, 0xA9]));
    }
}
