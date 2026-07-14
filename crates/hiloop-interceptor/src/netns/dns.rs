use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

use super::DnsAnswerEvidence;

const DNS_HEADER_LENGTH: usize = 12;
const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_RESPONSE: u16 = 0x8000;
const DNS_COMPRESSION_POINTER: u8 = 0xc0;

/// Per-run evidence containing only exact A and AAAA answers returned to the workload.
#[derive(Debug, Default)]
pub struct DnsAnswerTracker {
    answers: Mutex<HashMap<(String, IpAddr), Instant>>,
}

impl DnsAnswerTracker {
    /// Record one response after it has been returned successfully to the workload.
    ///
    /// Malformed, mismatched, and non-answer messages add no evidence; DNS forwarding remains
    /// independent because missing evidence can never authorize a route.
    pub fn record_response(&self, query: &[u8], response: &[u8]) {
        self.record_response_at(query, response, Instant::now());
    }

    fn record_response_at(&self, query: &[u8], response: &[u8], now: Instant) {
        let Some((query_id, questions)) = parse_questions(query) else {
            return;
        };
        let Some(message) = parse_response(response) else {
            return;
        };
        if message.id != query_id || message.questions != questions {
            return;
        }

        let mut correlated = Vec::new();
        for answer in &message.addresses {
            correlated.push((answer.name.clone(), answer.address, answer.ttl));
        }
        for question in questions {
            correlate_question(
                &question.name,
                None,
                &message.addresses,
                &message.cnames,
                &mut HashSet::new(),
                &mut correlated,
            );
        }

        let mut answers = self
            .answers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        answers.retain(|_, expiry| *expiry > now);
        for (name, address, ttl) in correlated {
            if ttl == 0 {
                continue;
            }
            if let Some(expiry) = now.checked_add(Duration::from_secs(u64::from(ttl))) {
                answers.insert((name, address), expiry);
            }
        }
    }

    fn contains_at(&self, hostname: &str, address: IpAddr, now: Instant) -> bool {
        let Some(hostname) = canonical_dns_name(hostname.as_bytes()) else {
            return false;
        };
        let mut answers = self
            .answers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        answers.retain(|_, expiry| *expiry > now);
        answers
            .get(&(hostname, address))
            .is_some_and(|expiry| *expiry > now)
    }
}

impl DnsAnswerEvidence for DnsAnswerTracker {
    fn contains_unexpired(&self, hostname: &str, address: IpAddr) -> bool {
        self.contains_at(hostname, address, Instant::now())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Question {
    name: String,
    kind: u16,
    class: u16,
}

#[derive(Debug)]
struct AddressAnswer {
    name: String,
    address: IpAddr,
    ttl: u32,
}

#[derive(Debug)]
struct CnameAnswer {
    name: String,
    target: String,
    ttl: u32,
}

#[derive(Debug)]
struct ParsedResponse {
    id: u16,
    questions: Vec<Question>,
    addresses: Vec<AddressAnswer>,
    cnames: Vec<CnameAnswer>,
}

fn parse_questions(packet: &[u8]) -> Option<(u16, Vec<Question>)> {
    let header = Header::parse(packet)?;
    let (questions, _) = questions(packet, header.question_count)?;
    Some((header.id, questions))
}

fn parse_response(packet: &[u8]) -> Option<ParsedResponse> {
    let header = Header::parse(packet)?;
    if header.flags & DNS_RESPONSE == 0 {
        return None;
    }
    let (questions, mut offset) = questions(packet, header.question_count)?;
    let mut addresses = Vec::new();
    let mut cnames = Vec::new();
    for _ in 0..header.answer_count {
        let (name, next) = read_name(packet, offset)?;
        offset = next;
        let kind = read_u16(packet, offset)?;
        let class = read_u16(packet, offset.checked_add(2)?)?;
        let ttl = read_u32(packet, offset.checked_add(4)?)?;
        let data_length = usize::from(read_u16(packet, offset.checked_add(8)?)?);
        let data_offset = offset.checked_add(10)?;
        let data_end = data_offset.checked_add(data_length)?;
        let data = packet.get(data_offset..data_end)?;
        offset = data_end;
        if class != DNS_CLASS_IN {
            continue;
        }
        match kind {
            DNS_TYPE_A if data.len() == 4 => addresses.push(AddressAnswer {
                name,
                address: IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                ttl,
            }),
            DNS_TYPE_AAAA if data.len() == 16 => {
                let octets: [u8; 16] = data.try_into().ok()?;
                addresses.push(AddressAnswer {
                    name,
                    address: IpAddr::V6(Ipv6Addr::from(octets)),
                    ttl,
                });
            }
            DNS_TYPE_CNAME => {
                let (target, name_end) = read_name(packet, data_offset)?;
                if name_end > data_end {
                    return None;
                }
                cnames.push(CnameAnswer { name, target, ttl });
            }
            _ => {}
        }
    }
    Some(ParsedResponse {
        id: header.id,
        questions,
        addresses,
        cnames,
    })
}

fn questions(packet: &[u8], count: u16) -> Option<(Vec<Question>, usize)> {
    let mut offset = DNS_HEADER_LENGTH;
    let mut questions = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let (name, next) = read_name(packet, offset)?;
        let kind = read_u16(packet, next)?;
        let class = read_u16(packet, next.checked_add(2)?)?;
        offset = next.checked_add(4)?;
        questions.push(Question { name, kind, class });
    }
    Some((questions, offset))
}

#[derive(Debug, Clone, Copy)]
struct Header {
    id: u16,
    flags: u16,
    question_count: u16,
    answer_count: u16,
}

impl Header {
    fn parse(packet: &[u8]) -> Option<Self> {
        (packet.len() >= DNS_HEADER_LENGTH).then_some(Self {
            id: read_u16(packet, 0)?,
            flags: read_u16(packet, 2)?,
            question_count: read_u16(packet, 4)?,
            answer_count: read_u16(packet, 6)?,
        })
    }
}

fn correlate_question(
    name: &str,
    ttl_limit: Option<u32>,
    addresses: &[AddressAnswer],
    cnames: &[CnameAnswer],
    visited: &mut HashSet<String>,
    correlated: &mut Vec<(String, IpAddr, u32)>,
) {
    if !visited.insert(name.to_owned()) {
        return;
    }
    for answer in addresses.iter().filter(|answer| answer.name == name) {
        correlated.push((
            name.to_owned(),
            answer.address,
            ttl_limit.map_or(answer.ttl, |limit| limit.min(answer.ttl)),
        ));
    }
    for cname in cnames.iter().filter(|cname| cname.name == name) {
        let limit = ttl_limit.map_or(cname.ttl, |limit| limit.min(cname.ttl));
        let before = correlated.len();
        correlate_question(
            &cname.target,
            Some(limit),
            addresses,
            cnames,
            visited,
            correlated,
        );
        for answer in &mut correlated[before..] {
            answer.0.clone_from(&name.to_owned());
        }
    }
    visited.remove(name);
}

fn read_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut next = None;
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(offset) {
            return None;
        }
        let length = *packet.get(offset)?;
        if length & DNS_COMPRESSION_POINTER == DNS_COMPRESSION_POINTER {
            let low = usize::from(*packet.get(offset.checked_add(1)?)?);
            let pointer = (usize::from(length & !DNS_COMPRESSION_POINTER) << 8) | low;
            next.get_or_insert(offset.checked_add(2)?);
            offset = pointer;
            continue;
        }
        if length & DNS_COMPRESSION_POINTER != 0 {
            return None;
        }
        offset = offset.checked_add(1)?;
        if length == 0 {
            let next = next.unwrap_or(offset);
            let name = labels.join(".");
            return (!name.is_empty()).then_some((name, next));
        }
        let end = offset.checked_add(usize::from(length))?;
        let label = packet.get(offset..end)?;
        if length > 63 || !label.is_ascii() || label.contains(&b'.') {
            return None;
        }
        labels.push(String::from_utf8(label.to_ascii_lowercase()).ok()?);
        if labels.iter().map(String::len).sum::<usize>() + labels.len() > 255 {
            return None;
        }
        offset = end;
    }
}

fn canonical_dns_name(name: &[u8]) -> Option<String> {
    let name = name.strip_suffix(b".").unwrap_or(name);
    if name.is_empty() || !name.is_ascii() {
        return None;
    }
    let canonical = name.to_ascii_lowercase();
    canonical
        .split(|byte| *byte == b'.')
        .all(|label| !label.is_empty() && label.len() <= 63)
        .then(|| String::from_utf8(canonical).ok())
        .flatten()
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = packet
        .get(offset..offset.checked_add(2)?)?
        .try_into()
        .ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn read_u32(packet: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = packet
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()?;
    Some(u32::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        time::{Duration, Instant},
    };

    use super::DnsAnswerTracker;
    use crate::netns::DnsAnswerEvidence as _;

    #[test]
    fn exact_answers_expire_at_their_own_ttls() {
        let now = Instant::now();
        let tracker = DnsAnswerTracker::default();
        let query = query("api.example.com", 1);
        let response = response(
            &query,
            &[
                answer_a("api.example.com", 2, Ipv4Addr::new(192, 0, 2, 10)),
                answer_aaaa(
                    "api.example.com",
                    5,
                    "2001:db8::10".parse().expect("test IPv6"),
                ),
            ],
        );

        tracker.record_response_at(&query, &response, now);

        assert!(tracker.contains_at(
            "api.example.com",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            now + Duration::from_secs(1),
        ));
        assert!(!tracker.contains_at(
            "api.example.com",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            now + Duration::from_secs(2),
        ));
        assert!(tracker.contains_at(
            "api.example.com",
            IpAddr::V6("2001:db8::10".parse().expect("test IPv6")),
            now + Duration::from_secs(4),
        ));
        assert!(!tracker.contains_at(
            "api.example.com",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
            now,
        ));
    }

    #[test]
    fn cname_correlation_uses_the_shortest_chain_ttl() {
        let now = Instant::now();
        let tracker = DnsAnswerTracker::default();
        let query = query("api.example.com", 1);
        let response = response(
            &query,
            &[
                answer_cname("api.example.com", 3, "edge.example.net"),
                answer_a("edge.example.net", 30, Ipv4Addr::new(198, 51, 100, 7)),
            ],
        );

        tracker.record_response_at(&query, &response, now);

        let address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        assert!(tracker.contains_at("api.example.com", address, now + Duration::from_secs(2)));
        assert!(!tracker.contains_at("api.example.com", address, now + Duration::from_secs(3)));
        assert!(tracker.contains_at("edge.example.net", address, now + Duration::from_secs(29)));
    }

    #[test]
    fn zero_ttl_and_malformed_responses_add_no_evidence() {
        let now = Instant::now();
        let tracker = DnsAnswerTracker::default();
        let query = query("api.example.com", 1);
        let zero_ttl = response(
            &query,
            &[answer_a(
                "api.example.com",
                0,
                Ipv4Addr::new(203, 0, 113, 9),
            )],
        );

        tracker.record_response_at(&query, &zero_ttl, now);
        tracker.record_response_at(&query, &[0, 1, 2], now);

        assert!(
            !tracker
                .contains_unexpired("api.example.com", IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)))
        );
    }

    fn query(name: &str, kind: u16) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234_u16.to_be_bytes());
        packet.extend_from_slice(&0x0100_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&[0; 6]);
        encode_name(&mut packet, name);
        packet.extend_from_slice(&kind.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet
    }

    fn response(query: &[u8], answers: &[Vec<u8>]) -> Vec<u8> {
        let mut packet = query.to_vec();
        packet[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        packet[6..8].copy_from_slice(
            &u16::try_from(answers.len())
                .expect("test answer count")
                .to_be_bytes(),
        );
        for answer in answers {
            packet.extend_from_slice(answer);
        }
        packet
    }

    fn answer_a(name: &str, ttl: u32, address: Ipv4Addr) -> Vec<u8> {
        answer(name, 1, ttl, &address.octets())
    }

    fn answer_aaaa(name: &str, ttl: u32, address: Ipv6Addr) -> Vec<u8> {
        answer(name, 28, ttl, &address.octets())
    }

    fn answer_cname(name: &str, ttl: u32, target: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        encode_name(&mut encoded, target);
        answer(name, 5, ttl, &encoded)
    }

    fn answer(name: &str, kind: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        encode_name(&mut record, name);
        record.extend_from_slice(&kind.to_be_bytes());
        record.extend_from_slice(&1_u16.to_be_bytes());
        record.extend_from_slice(&ttl.to_be_bytes());
        record.extend_from_slice(
            &u16::try_from(data.len())
                .expect("test RDATA length")
                .to_be_bytes(),
        );
        record.extend_from_slice(data);
        record
    }

    fn encode_name(packet: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            packet.push(u8::try_from(label.len()).expect("test label length"));
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
    }
}
