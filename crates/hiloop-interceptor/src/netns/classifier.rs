//! Incremental, non-consuming TCP protocol classification.

use std::collections::{BTreeMap, BTreeSet};

/// Maximum prefix inspected before classification fails closed.
pub(super) const MAX_CLASSIFICATION_BYTES: usize = 64 * 1024;

const MAX_TLS_RECORD_BYTES: usize = 18 * 1024;
const MAX_HTTP_METHOD_BYTES: usize = 32;
const ECH_EXTENSION: u16 = 0xfe0d;

/// More bytes are needed or a protocol has been classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassificationProgress {
    /// Classification cannot yet be decided from the available prefix.
    NeedMore,
    /// Enough bytes were available to classify the flow.
    Classified(TcpProtocol),
}

/// Application protocol visible before an upstream connection is opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpProtocol {
    /// A complete cleartext HTTP/1 request head.
    CleartextHttp(HttpIdentity),
    /// A complete TLS `ClientHello`.
    TlsClientHello(ClientHelloIdentity),
    /// A TCP protocol without an implemented application classifier.
    OtherTcp,
}

/// Routing metadata from a cleartext HTTP request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpIdentity {
    authority: Option<String>,
}

impl HttpIdentity {
    /// HTTP Host authority, when the request supplied one.
    pub fn authority(&self) -> Option<&str> {
        self.authority.as_deref()
    }
}

/// Routing and retry identity parsed from a TLS `ClientHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloIdentity {
    server_name: Option<String>,
    fingerprint: String,
    encrypted_client_hello: bool,
}

impl ClientHelloIdentity {
    /// Visible SNI from the `ClientHello`, when present.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Versioned, normalized fingerprint for run-scoped retry matching.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Whether the `ClientHello` carried the encrypted-client-hello extension.
    pub fn encrypted_client_hello(&self) -> bool {
        self.encrypted_client_hello
    }
}

/// A prefix looked like HTTP or TLS but violated that protocol's framing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClassificationError {
    /// A recognized HTTP request line had malformed headers.
    #[error("malformed cleartext HTTP request head")]
    MalformedHttp,
    /// A TLS handshake prefix did not contain one valid `ClientHello`.
    #[error("malformed TLS ClientHello")]
    MalformedTls,
    /// Classification exceeded the bounded prefix budget.
    #[error("TCP classification exceeded {MAX_CLASSIFICATION_BYTES} bytes")]
    PrefixTooLarge,
}

/// Classify the currently available, unconsumed TCP prefix.
pub fn classify_tcp_prefix(prefix: &[u8]) -> Result<ClassificationProgress, ClassificationError> {
    let bounded = prefix.get(..MAX_CLASSIFICATION_BYTES).unwrap_or(prefix);
    let progress = if bounded.first() == Some(&22) {
        classify_tls(bounded)?
    } else {
        classify_http_or_other(bounded)?
    };
    if progress == ClassificationProgress::NeedMore && prefix.len() >= MAX_CLASSIFICATION_BYTES {
        Err(ClassificationError::PrefixTooLarge)
    } else {
        Ok(progress)
    }
}

fn classify_http_or_other(prefix: &[u8]) -> Result<ClassificationProgress, ClassificationError> {
    let Some(first) = prefix.first() else {
        return Ok(ClassificationProgress::NeedMore);
    };
    if !first.is_ascii_uppercase() {
        return Ok(ClassificationProgress::Classified(TcpProtocol::OtherTcp));
    }

    let Some(method_end) = prefix.iter().position(|byte| *byte == b' ') else {
        return if prefix.len() <= MAX_HTTP_METHOD_BYTES
            && prefix.iter().all(|byte| is_token_byte(*byte))
        {
            Ok(ClassificationProgress::NeedMore)
        } else {
            Ok(ClassificationProgress::Classified(TcpProtocol::OtherTcp))
        };
    };
    if method_end == 0
        || method_end > MAX_HTTP_METHOD_BYTES
        || !prefix[..method_end].iter().all(|byte| is_token_byte(*byte))
    {
        return Ok(ClassificationProgress::Classified(TcpProtocol::OtherTcp));
    }

    let Some(request_line_end) = find_bytes(prefix, b"\r\n") else {
        return Ok(ClassificationProgress::NeedMore);
    };
    let mut request_line = prefix[..request_line_end].split(|byte| *byte == b' ');
    let method = request_line.next();
    let target = request_line.next();
    let version = request_line.next();
    if method.is_none()
        || target.is_none_or(<[u8]>::is_empty)
        || !matches!(version, Some(b"HTTP/1.0" | b"HTTP/1.1"))
        || request_line.next().is_some()
    {
        return Ok(ClassificationProgress::Classified(TcpProtocol::OtherTcp));
    }

    let Some(head_end) = find_bytes(prefix, b"\r\n\r\n") else {
        return Ok(ClassificationProgress::NeedMore);
    };
    let headers = prefix
        .get(request_line_end + 2..head_end + 2)
        .ok_or(ClassificationError::MalformedHttp)?;
    let authority = parse_http_host(headers)?;
    Ok(ClassificationProgress::Classified(
        TcpProtocol::CleartextHttp(HttpIdentity { authority }),
    ))
}

fn parse_http_host(headers: &[u8]) -> Result<Option<String>, ClassificationError> {
    let mut authority = None;
    for line in headers.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let line = line
            .strip_suffix(b"\r")
            .ok_or(ClassificationError::MalformedHttp)?;
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err(ClassificationError::MalformedHttp);
        };
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|byte| is_token_byte(*byte)) {
            return Err(ClassificationError::MalformedHttp);
        }
        if name.eq_ignore_ascii_case(b"host") {
            if authority.is_some() {
                return Err(ClassificationError::MalformedHttp);
            }
            let value = trim_ascii_whitespace(&line[colon + 1..]);
            if value.is_empty() {
                return Err(ClassificationError::MalformedHttp);
            }
            authority = Some(
                std::str::from_utf8(value)
                    .map_err(|_| ClassificationError::MalformedHttp)?
                    .to_owned(),
            );
        }
    }
    Ok(authority)
}

fn classify_tls(prefix: &[u8]) -> Result<ClassificationProgress, ClassificationError> {
    let mut offset = 0;
    let mut handshake = Vec::new();
    loop {
        let Some(header) = prefix.get(offset..offset + 5) else {
            return Ok(ClassificationProgress::NeedMore);
        };
        if header[0] != 22 || header[1] != 3 || header[2] > 4 {
            return Err(ClassificationError::MalformedTls);
        }
        let record_length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if record_length == 0 || record_length > MAX_TLS_RECORD_BYTES {
            return Err(ClassificationError::MalformedTls);
        }
        let record_end = offset
            .checked_add(5 + record_length)
            .ok_or(ClassificationError::PrefixTooLarge)?;
        let Some(fragment) = prefix.get(offset + 5..record_end) else {
            return Ok(ClassificationProgress::NeedMore);
        };
        handshake.extend_from_slice(fragment);
        if handshake.len() > MAX_CLASSIFICATION_BYTES {
            return Err(ClassificationError::PrefixTooLarge);
        }
        if let Some(header) = handshake.get(..4) {
            if header[0] != 1 {
                return Err(ClassificationError::MalformedTls);
            }
            let body_length =
                usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
            let handshake_end = 4_usize
                .checked_add(body_length)
                .ok_or(ClassificationError::PrefixTooLarge)?;
            if handshake_end > MAX_CLASSIFICATION_BYTES {
                return Err(ClassificationError::PrefixTooLarge);
            }
            if let Some(body) = handshake.get(4..handshake_end) {
                return parse_client_hello(body).map(|identity| {
                    ClassificationProgress::Classified(TcpProtocol::TlsClientHello(identity))
                });
            }
        }
        offset = record_end;
    }
}

fn parse_client_hello(body: &[u8]) -> Result<ClientHelloIdentity, ClassificationError> {
    let mut reader = TlsReader::new(body);
    let legacy_version = reader.u16()?;
    reader.take(32)?;
    reader.vector_u8()?;
    let cipher_suites = parse_u16_values(reader.vector_u16()?)?;
    let mut compression = reader.vector_u8()?.to_vec();
    if cipher_suites.is_empty() || compression.is_empty() {
        return Err(ClassificationError::MalformedTls);
    }
    let extensions = if reader.is_empty() {
        &[][..]
    } else {
        reader.vector_u16()?
    };
    reader.finish()?;

    let extensions = parse_extensions(extensions)?;
    let server_name = extensions
        .get(&0)
        .map(|payload| parse_server_name(payload))
        .transpose()?
        .flatten();
    let encrypted_client_hello = extensions.contains_key(&ECH_EXTENSION);

    let mut suites = normalize_u16_values(cipher_suites);
    let mut extension_types = normalize_u16_values(extensions.keys().copied().collect());
    let mut groups = parse_optional_u16_extension(&extensions, 10)?;
    let mut signatures = parse_optional_u16_extension(&extensions, 13)?;
    let mut versions = parse_supported_versions(&extensions)?;
    let mut alpn = parse_alpn(&extensions)?;
    compression.sort_unstable();
    compression.dedup();
    suites.sort_unstable();
    extension_types.sort_unstable();
    groups.sort_unstable();
    signatures.sort_unstable();
    versions.sort_unstable();
    alpn.sort_unstable();

    let mut normalized = Vec::new();
    normalized.extend_from_slice(b"hiloop-client-hello-v1\0");
    normalized.extend_from_slice(&legacy_version.to_be_bytes());
    append_u16_set(&mut normalized, 1, &suites);
    append_u8_set(&mut normalized, 2, &compression);
    append_u16_set(&mut normalized, 3, &extension_types);
    append_u16_set(&mut normalized, 4, &groups);
    append_u16_set(&mut normalized, 5, &signatures);
    append_u16_set(&mut normalized, 6, &versions);
    append_byte_strings(&mut normalized, 7, &alpn);
    let fingerprint = format!("ch1:{}", blake3::hash(&normalized).to_hex());

    Ok(ClientHelloIdentity {
        server_name,
        fingerprint,
        encrypted_client_hello,
    })
}

fn parse_extensions(bytes: &[u8]) -> Result<BTreeMap<u16, &[u8]>, ClassificationError> {
    let mut reader = TlsReader::new(bytes);
    let mut extensions = BTreeMap::new();
    while !reader.is_empty() {
        let kind = reader.u16()?;
        let length = usize::from(reader.u16()?);
        let payload = reader.take(length)?;
        if extensions.insert(kind, payload).is_some() {
            return Err(ClassificationError::MalformedTls);
        }
    }
    Ok(extensions)
}

fn parse_server_name(payload: &[u8]) -> Result<Option<String>, ClassificationError> {
    let mut extension = TlsReader::new(payload);
    let names = extension.vector_u16()?;
    extension.finish()?;
    let mut names = TlsReader::new(names);
    let mut server_name = None;
    while !names.is_empty() {
        let name_type = names.u8()?;
        let name = names.vector_u16()?;
        if name_type == 0 {
            if name.is_empty() || server_name.is_some() {
                return Err(ClassificationError::MalformedTls);
            }
            server_name = Some(
                std::str::from_utf8(name)
                    .map_err(|_| ClassificationError::MalformedTls)?
                    .to_owned(),
            );
        }
    }
    Ok(server_name)
}

fn parse_optional_u16_extension(
    extensions: &BTreeMap<u16, &[u8]>,
    kind: u16,
) -> Result<Vec<u16>, ClassificationError> {
    extensions.get(&kind).map_or_else(
        || Ok(Vec::new()),
        |payload| {
            let mut reader = TlsReader::new(payload);
            let values = parse_u16_values(reader.vector_u16()?)?;
            reader.finish()?;
            Ok(normalize_u16_values(values))
        },
    )
}

fn parse_supported_versions(
    extensions: &BTreeMap<u16, &[u8]>,
) -> Result<Vec<u16>, ClassificationError> {
    extensions.get(&43).map_or_else(
        || Ok(Vec::new()),
        |payload| {
            let mut reader = TlsReader::new(payload);
            let values = parse_u16_values(reader.vector_u8()?)?;
            reader.finish()?;
            Ok(normalize_u16_values(values))
        },
    )
}

fn parse_alpn(extensions: &BTreeMap<u16, &[u8]>) -> Result<Vec<Vec<u8>>, ClassificationError> {
    extensions.get(&16).map_or_else(
        || Ok(Vec::new()),
        |payload| {
            let mut extension = TlsReader::new(payload);
            let protocols = extension.vector_u16()?;
            extension.finish()?;
            let mut protocols = TlsReader::new(protocols);
            let mut values = Vec::new();
            while !protocols.is_empty() {
                let value = protocols.vector_u8()?;
                if value.is_empty() {
                    return Err(ClassificationError::MalformedTls);
                }
                values.push(value.to_vec());
            }
            Ok(values)
        },
    )
}

fn parse_u16_values(bytes: &[u8]) -> Result<Vec<u16>, ClassificationError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(ClassificationError::MalformedTls);
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|value| u16::from_be_bytes([value[0], value[1]]))
        .collect())
}

fn normalize_u16_values(values: Vec<u16>) -> Vec<u16> {
    values
        .into_iter()
        .filter(|value| !is_grease(*value))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a
}

fn append_u16_set(bytes: &mut Vec<u8>, tag: u8, values: &[u16]) {
    bytes.push(tag);
    bytes.extend_from_slice(&usize_u32(values.len()).to_be_bytes());
    for value in values {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
}

fn append_u8_set(bytes: &mut Vec<u8>, tag: u8, values: &[u8]) {
    bytes.push(tag);
    bytes.extend_from_slice(&usize_u32(values.len()).to_be_bytes());
    bytes.extend_from_slice(values);
}

fn append_byte_strings(bytes: &mut Vec<u8>, tag: u8, values: &[Vec<u8>]) {
    bytes.push(tag);
    bytes.extend_from_slice(&usize_u32(values.len()).to_be_bytes());
    for value in values {
        bytes.extend_from_slice(&usize_u32(value.len()).to_be_bytes());
        bytes.extend_from_slice(value);
    }
}

fn usize_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

struct TlsReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> TlsReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ClassificationError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ClassificationError::MalformedTls)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ClassificationError::MalformedTls)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ClassificationError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ClassificationError> {
        let value = self.take(2)?;
        Ok(u16::from_be_bytes([value[0], value[1]]))
    }

    fn vector_u8(&mut self) -> Result<&'a [u8], ClassificationError> {
        let length = usize::from(self.u8()?);
        self.take(length)
    }

    fn vector_u16(&mut self) -> Result<&'a [u8], ClassificationError> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }

    fn finish(self) -> Result<(), ClassificationError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(ClassificationError::MalformedTls)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ECH_EXTENSION: u16 = 0xfe0d;

    #[test]
    fn cleartext_http_waits_for_the_head_and_preserves_host() {
        for prefix in [
            b"G".as_slice(),
            b"GET / HTTP/1.1\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: ExAmPle.COM:8080\r\n".as_slice(),
        ] {
            assert_eq!(
                classify_tcp_prefix(prefix).expect("partial HTTP"),
                ClassificationProgress::NeedMore
            );
        }

        let classified = classify_tcp_prefix(
            b"GET / HTTP/1.1\r\nHost: ExAmPle.COM:8080\r\nUser-Agent: fixture\r\n\r\nbody",
        )
        .expect("complete HTTP");
        let ClassificationProgress::Classified(TcpProtocol::CleartextHttp(identity)) = classified
        else {
            panic!("expected HTTP classification: {classified:?}");
        };
        assert_eq!(identity.authority(), Some("ExAmPle.COM:8080"));
    }

    #[test]
    fn fragmented_client_hello_is_incremental() {
        let handshake = client_hello(
            "api.example.com",
            &[0x1301, 0x1302],
            vec![
                extension(0, server_name("api.example.com")),
                extension(10, u16_vector(&[29, 23])),
                extension(13, u16_vector(&[0x0403, 0x0804])),
            ],
        );
        let records = tls_records(&handshake, 9);

        for end in 1..records.len() {
            assert_eq!(
                classify_tcp_prefix(&records[..end]).expect("partial ClientHello"),
                ClassificationProgress::NeedMore,
                "prefix length {end}"
            );
        }
        let classified = classify_tcp_prefix(&records).expect("complete ClientHello");
        let ClassificationProgress::Classified(TcpProtocol::TlsClientHello(identity)) = classified
        else {
            panic!("expected TLS classification: {classified:?}");
        };
        assert_eq!(identity.server_name(), Some("api.example.com"));
        assert!(identity.fingerprint().starts_with("ch1:"));
        assert!(!identity.encrypted_client_hello());
    }

    #[test]
    fn fingerprint_ignores_grease_and_unstable_ordering() {
        let first = tls_record(&client_hello(
            "api.example.com",
            &[0x0a0a, 0x1302, 0x1301],
            vec![
                extension(0x1a1a, vec![1, 2]),
                extension(13, u16_vector(&[0x0a0a, 0x0804, 0x0403])),
                extension(10, u16_vector(&[0x1a1a, 23, 29])),
                extension(0, server_name("api.example.com")),
            ],
        ));
        let second = tls_record(&client_hello(
            "api.example.com",
            &[0x1301, 0x1302, 0x2a2a],
            vec![
                extension(0, server_name("api.example.com")),
                extension(10, u16_vector(&[29, 23, 0x3a3a])),
                extension(13, u16_vector(&[0x0403, 0x0804, 0x4a4a])),
                extension(0x5a5a, vec![9]),
            ],
        ));

        assert_eq!(fingerprint(&first), fingerprint(&second));
    }

    #[test]
    fn materially_different_clients_have_different_fingerprints() {
        let first = tls_record(&client_hello(
            "api.example.com",
            &[0x1301],
            vec![extension(0, server_name("api.example.com"))],
        ));
        let second = tls_record(&client_hello(
            "api.example.com",
            &[0x1302],
            vec![extension(0, server_name("api.example.com"))],
        ));

        assert_ne!(fingerprint(&first), fingerprint(&second));
    }

    #[test]
    fn ech_presence_is_reported_without_parsing_encrypted_identity() {
        let bytes = tls_record(&client_hello(
            "public.example.com",
            &[0x1301],
            vec![
                extension(0, server_name("public.example.com")),
                extension(ECH_EXTENSION, vec![0, 1, 2, 3]),
            ],
        ));
        let classified = classify_tcp_prefix(&bytes).expect("ECH ClientHello");
        let ClassificationProgress::Classified(TcpProtocol::TlsClientHello(identity)) = classified
        else {
            panic!("expected TLS classification: {classified:?}");
        };
        assert!(identity.encrypted_client_hello());
    }

    #[test]
    fn malformed_tls_is_not_reclassified_as_opaque_tcp() {
        let malformed = [22, 3, 3, 0, 4, 2, 0, 0, 0];
        assert_eq!(
            classify_tcp_prefix(&malformed),
            Err(ClassificationError::MalformedTls)
        );
    }

    #[test]
    fn unsupported_protocols_classify_as_other_tcp() {
        for prefix in [b"SSH-2.0-fixture\r\n".as_slice(), &[1, 2, 3, 4][..]] {
            assert_eq!(
                classify_tcp_prefix(prefix).expect("opaque TCP"),
                ClassificationProgress::Classified(TcpProtocol::OtherTcp)
            );
        }
    }

    fn fingerprint(bytes: &[u8]) -> String {
        let classified = classify_tcp_prefix(bytes).expect("ClientHello");
        let ClassificationProgress::Classified(TcpProtocol::TlsClientHello(identity)) = classified
        else {
            panic!("expected TLS classification: {classified:?}");
        };
        identity.fingerprint().to_owned()
    }

    fn client_hello(
        _server_name: &str,
        cipher_suites: &[u16],
        extensions: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[3, 3]);
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        push_u16(&mut body, cipher_suites.len() * 2);
        for suite in cipher_suites {
            body.extend_from_slice(&suite.to_be_bytes());
        }
        body.extend_from_slice(&[1, 0]);
        let extensions = extensions.into_iter().flatten().collect::<Vec<_>>();
        push_u16(&mut body, extensions.len());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![1];
        push_u24(&mut handshake, body.len());
        handshake.extend_from_slice(&body);
        handshake
    }

    fn server_name(name: &str) -> Vec<u8> {
        let mut entry = vec![0];
        push_u16(&mut entry, name.len());
        entry.extend_from_slice(name.as_bytes());
        let mut list = Vec::new();
        push_u16(&mut list, entry.len());
        list.extend_from_slice(&entry);
        list
    }

    fn u16_vector(values: &[u16]) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_u16(&mut bytes, values.len() * 2);
        for value in values {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes
    }

    fn extension(kind: u16, payload: Vec<u8>) -> Vec<u8> {
        let mut bytes = kind.to_be_bytes().to_vec();
        push_u16(&mut bytes, payload.len());
        bytes.extend(payload);
        bytes
    }

    fn tls_record(handshake: &[u8]) -> Vec<u8> {
        tls_records(handshake, handshake.len())
    }

    fn tls_records(handshake: &[u8], split: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for fragment in [&handshake[..split], &handshake[split..]] {
            if fragment.is_empty() {
                continue;
            }
            bytes.extend_from_slice(&[22, 3, 3]);
            push_u16(&mut bytes, fragment.len());
            bytes.extend_from_slice(fragment);
        }
        bytes
    }

    fn push_u16(bytes: &mut Vec<u8>, value: usize) {
        bytes.extend_from_slice(
            &u16::try_from(value)
                .expect("test length fits u16")
                .to_be_bytes(),
        );
    }

    fn push_u24(bytes: &mut Vec<u8>, value: usize) {
        let value = u32::try_from(value)
            .expect("test length fits u24")
            .to_be_bytes();
        bytes.extend_from_slice(&value[1..]);
    }
}
