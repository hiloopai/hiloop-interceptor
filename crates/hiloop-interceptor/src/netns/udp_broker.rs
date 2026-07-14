use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::UdpFlowKey;

pub(super) const BROKER_VERSION: u8 = 1;
pub(super) const BROKER_STATUS_OK: u8 = 0;
pub(super) const BROKER_STATUS_ERROR: u8 = 1;
pub(super) const BROKER_REQUEST_LENGTH: usize = 38;

pub(super) fn encode_request(key: UdpFlowKey) -> [u8; BROKER_REQUEST_LENGTH] {
    let mut request = [0_u8; BROKER_REQUEST_LENGTH];
    request[0] = BROKER_VERSION;
    request[1] = if key.destination().is_ipv4() { 4 } else { 6 };
    encode_address(key.client(), &mut request[2..20]);
    encode_address(key.destination(), &mut request[20..38]);
    request
}

pub(super) fn decode_request(request: &[u8]) -> Option<UdpFlowKey> {
    if request.len() != BROKER_REQUEST_LENGTH || request[0] != BROKER_VERSION {
        return None;
    }
    let family = request[1];
    let client = decode_address(family, &request[2..20])?;
    let destination = decode_address(family, &request[20..38])?;
    UdpFlowKey::new(client, destination).ok()
}

fn encode_address(address: SocketAddr, output: &mut [u8]) {
    match address.ip() {
        IpAddr::V4(ipv4) => output[12..16].copy_from_slice(&ipv4.octets()),
        IpAddr::V6(ipv6) => output[..16].copy_from_slice(&ipv6.octets()),
    }
    output[16..18].copy_from_slice(&address.port().to_be_bytes());
}

fn decode_address(family: u8, input: &[u8]) -> Option<SocketAddr> {
    let port = u16::from_be_bytes(input.get(16..18)?.try_into().ok()?);
    let ip = match family {
        4 if input.get(..12)?.iter().all(|byte| *byte == 0) => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(input.get(12..16)?).ok()?,
        )),
        6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(input.get(..16)?).ok()?)),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_request_round_trips_both_address_families() {
        for key in [
            UdpFlowKey::new(
                "169.254.254.2:40000".parse().expect("client IPv4"),
                "192.0.2.8:443".parse().expect("destination IPv4"),
            )
            .expect("IPv4 flow"),
            UdpFlowKey::new(
                "[fd00:6869:6c6f:6f70::2]:40000"
                    .parse()
                    .expect("client IPv6"),
                "[2001:db8::8]:443".parse().expect("destination IPv6"),
            )
            .expect("IPv6 flow"),
        ] {
            assert_eq!(decode_request(&encode_request(key)), Some(key));
        }
    }

    #[test]
    fn broker_request_rejects_malformed_or_mixed_family_data() {
        let key = UdpFlowKey::new(
            "169.254.254.2:40000".parse().expect("client"),
            "192.0.2.8:443".parse().expect("destination"),
        )
        .expect("flow");
        let mut request = encode_request(key);
        request[0] = 2;
        assert_eq!(decode_request(&request), None);
        request = encode_request(key);
        request[2] = 1;
        assert_eq!(decode_request(&request), None);
        assert_eq!(decode_request(&request[..10]), None);
    }
}
