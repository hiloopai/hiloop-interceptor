//! Pure command and packet-size policy generation for the private network substrate.

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU16,
};

pub(super) const WORKLOAD_INTERFACE: &str = "hlwork0";
pub(super) const GATEWAY_INTERFACE: &str = "hlgate0";
pub(super) const LINK_MTU: u16 = 65_520;
pub(super) const TPROXY_MARK: u32 = 0x1;
pub(super) const TPROXY_TABLE: u32 = 100;
pub(super) const TPROXY_RULE_PRIORITY: u32 = 100;
pub(super) const WORKLOAD_IPV4: Ipv4Addr = Ipv4Addr::new(169, 254, 254, 2);
pub(super) const GATEWAY_IPV4: Ipv4Addr = Ipv4Addr::new(169, 254, 254, 1);
pub(super) const WORKLOAD_IPV6: Ipv6Addr =
    Ipv6Addr::new(0xfd00, 0x6869, 0x6c6f, 0x6f70, 0, 0, 0, 2);
pub(super) const GATEWAY_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x6869, 0x6c6f, 0x6f70, 0, 0, 0, 1);

const IPV4_PREFIX_LENGTH: u8 = 30;
const IPV6_PREFIX_LENGTH: u8 = 64;
pub(super) const NFT_TABLE: &str = "hiloop_capture";
pub(super) const IPV4_FRAGMENT_COUNTER: &str = "udp_fragments_v4";
pub(super) const IPV6_FRAGMENT_COUNTER: &str = "udp_fragments_v6";
const IPV4_HEADER_LENGTH: usize = 20;
const IPV6_HEADER_LENGTH: usize = 40;
const UDP_HEADER_LENGTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NetworkNamespace {
    Gateway,
    Workload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Command {
    program: &'static str,
    args: Vec<String>,
}

impl Command {
    fn new(program: &'static str, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            program,
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub(super) fn program(&self) -> &'static str {
        self.program
    }

    pub(super) fn arguments(&self) -> &[String] {
        &self.args
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NamespacedCommand {
    namespace: NetworkNamespace,
    command: Command,
}

impl NamespacedCommand {
    fn new(
        namespace: NetworkNamespace,
        program: &'static str,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            namespace,
            command: Command::new(program, args),
        }
    }

    pub(super) fn namespace(&self) -> NetworkNamespace {
        self.namespace
    }

    pub(super) fn command(&self) -> &Command {
        &self.command
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RoutingPlan {
    setup: Vec<NamespacedCommand>,
    teardown: Vec<NamespacedCommand>,
    nft_script: String,
}

impl RoutingPlan {
    pub(super) fn new(workload_pid: u32, intercept_port: NonZeroU16) -> Self {
        Self {
            setup: setup_commands(workload_pid),
            teardown: teardown_commands(),
            nft_script: nft_script(intercept_port),
        }
    }

    pub(super) fn setup_commands(&self) -> &[NamespacedCommand] {
        &self.setup
    }

    pub(super) fn teardown_commands(&self) -> &[NamespacedCommand] {
        &self.teardown
    }

    pub(super) fn nft_script(&self) -> &str {
        &self.nft_script
    }
}

fn setup_commands(workload_pid: u32) -> Vec<NamespacedCommand> {
    let gateway_ipv4 = GATEWAY_IPV4.to_string();
    let gateway_ipv6 = GATEWAY_IPV6.to_string();
    let gateway_ipv4_cidr = format!("{GATEWAY_IPV4}/{IPV4_PREFIX_LENGTH}");
    let workload_ipv4_cidr = format!("{WORKLOAD_IPV4}/{IPV4_PREFIX_LENGTH}");
    let gateway_ipv6_cidr = format!("{GATEWAY_IPV6}/{IPV6_PREFIX_LENGTH}");
    let workload_ipv6_cidr = format!("{WORKLOAD_IPV6}/{IPV6_PREFIX_LENGTH}");
    let mtu = LINK_MTU.to_string();
    let workload_pid = workload_pid.to_string();
    let mark = format!("{TPROXY_MARK:#x}");
    let table = TPROXY_TABLE.to_string();
    let priority = TPROXY_RULE_PRIORITY.to_string();

    vec![
        gateway_command(
            "ip",
            [
                "link",
                "add",
                GATEWAY_INTERFACE,
                "type",
                "veth",
                "peer",
                "name",
                WORKLOAD_INTERFACE,
            ],
        ),
        gateway_command(
            "ip",
            ["link", "set", "dev", GATEWAY_INTERFACE, "mtu", mtu.as_str()],
        ),
        gateway_command(
            "ip",
            [
                "link",
                "set",
                "dev",
                WORKLOAD_INTERFACE,
                "mtu",
                mtu.as_str(),
            ],
        ),
        gateway_command(
            "ip",
            [
                "link",
                "set",
                "dev",
                WORKLOAD_INTERFACE,
                "netns",
                workload_pid.as_str(),
            ],
        ),
        gateway_command("ip", ["link", "set", "dev", "lo", "up"]),
        gateway_command(
            "ip",
            [
                "-4",
                "address",
                "add",
                gateway_ipv4_cidr.as_str(),
                "dev",
                GATEWAY_INTERFACE,
            ],
        ),
        gateway_command(
            "ip",
            [
                "-6",
                "address",
                "add",
                gateway_ipv6_cidr.as_str(),
                "dev",
                GATEWAY_INTERFACE,
                "nodad",
            ],
        ),
        gateway_command("ip", ["link", "set", "dev", GATEWAY_INTERFACE, "up"]),
        workload_command("ip", ["link", "set", "dev", "lo", "up"]),
        workload_command(
            "ip",
            [
                "-4",
                "address",
                "add",
                workload_ipv4_cidr.as_str(),
                "dev",
                WORKLOAD_INTERFACE,
            ],
        ),
        workload_command(
            "ip",
            [
                "-6",
                "address",
                "add",
                workload_ipv6_cidr.as_str(),
                "dev",
                WORKLOAD_INTERFACE,
                "nodad",
            ],
        ),
        workload_command("ip", ["link", "set", "dev", WORKLOAD_INTERFACE, "up"]),
        workload_command(
            "ip",
            [
                "-4",
                "route",
                "add",
                "default",
                "via",
                gateway_ipv4.as_str(),
                "dev",
                WORKLOAD_INTERFACE,
            ],
        ),
        workload_command(
            "ip",
            [
                "-6",
                "route",
                "add",
                "default",
                "via",
                gateway_ipv6.as_str(),
                "dev",
                WORKLOAD_INTERFACE,
            ],
        ),
        gateway_command(
            "ip",
            [
                "-4",
                "route",
                "add",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                table.as_str(),
            ],
        ),
        gateway_command(
            "ip",
            [
                "-4",
                "rule",
                "add",
                "fwmark",
                mark.as_str(),
                "lookup",
                table.as_str(),
                "priority",
                priority.as_str(),
            ],
        ),
        gateway_command(
            "ip",
            [
                "-6",
                "route",
                "add",
                "local",
                "::/0",
                "dev",
                "lo",
                "table",
                table.as_str(),
            ],
        ),
        gateway_command(
            "ip",
            [
                "-6",
                "rule",
                "add",
                "fwmark",
                mark.as_str(),
                "lookup",
                table.as_str(),
                "priority",
                priority.as_str(),
            ],
        ),
        gateway_command("nft", ["-f", "-"]),
    ]
}

fn teardown_commands() -> Vec<NamespacedCommand> {
    let mark = format!("{TPROXY_MARK:#x}");
    let table = TPROXY_TABLE.to_string();
    let priority = TPROXY_RULE_PRIORITY.to_string();

    vec![
        gateway_command("ip", ["link", "delete", "dev", GATEWAY_INTERFACE]),
        gateway_command("nft", ["delete", "table", "inet", NFT_TABLE]),
        gateway_command(
            "ip",
            [
                "-6",
                "rule",
                "del",
                "fwmark",
                mark.as_str(),
                "lookup",
                table.as_str(),
                "priority",
                priority.as_str(),
            ],
        ),
        gateway_command(
            "ip",
            [
                "-6",
                "route",
                "del",
                "local",
                "::/0",
                "dev",
                "lo",
                "table",
                table.as_str(),
            ],
        ),
        gateway_command(
            "ip",
            [
                "-4",
                "rule",
                "del",
                "fwmark",
                mark.as_str(),
                "lookup",
                table.as_str(),
                "priority",
                priority.as_str(),
            ],
        ),
        gateway_command(
            "ip",
            [
                "-4",
                "route",
                "del",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                table.as_str(),
            ],
        ),
    ]
}

fn nft_script(intercept_port: NonZeroU16) -> String {
    // TPROXY enables netfilter defragmentation at priority -400. The fragment chain must run
    // earlier so every fragmented UDP datagram, including DNS, is rejected before reassembly;
    // protocol exceptions apply only after this carrier boundary.
    format!(
        r#"table inet {NFT_TABLE} {{
    counter {IPV4_FRAGMENT_COUNTER} {{
    }}
    counter {IPV6_FRAGMENT_COUNTER} {{
    }}
    chain fragments {{
        type filter hook prerouting priority -450; policy accept;
        iifname "{GATEWAY_INTERFACE}" meta nfproto ipv4 meta l4proto udp ip frag-off & 0x3fff != 0 counter name {IPV4_FRAGMENT_COUNTER} drop
        iifname "{GATEWAY_INTERFACE}" meta nfproto ipv6 meta l4proto udp exthdr frag exists counter name {IPV6_FRAGMENT_COUNTER} drop
    }}
    chain prerouting {{
        type filter hook prerouting priority mangle; policy accept;
        iifname "{GATEWAY_INTERFACE}" ip daddr {GATEWAY_IPV4} tcp dport 53 accept
        iifname "{GATEWAY_INTERFACE}" ip6 daddr {GATEWAY_IPV6} tcp dport 53 accept
        iifname "{GATEWAY_INTERFACE}" ip daddr {GATEWAY_IPV4} udp dport 53 accept
        iifname "{GATEWAY_INTERFACE}" ip6 daddr {GATEWAY_IPV6} udp dport 53 accept
        iifname "{GATEWAY_INTERFACE}" meta l4proto udp drop
        iifname "{GATEWAY_INTERFACE}" meta l4proto tcp socket transparent 1 meta mark set {TPROXY_MARK:#x} accept
        iifname "{GATEWAY_INTERFACE}" meta l4proto tcp tproxy to :{intercept_port} meta mark set {TPROXY_MARK:#x} accept
    }}
}}
"#
    )
}

pub(super) fn parse_counter_packets(output: &str) -> io::Result<u64> {
    let mut packets = None;
    let mut tokens = output.split_ascii_whitespace();
    while let Some(token) = tokens.next() {
        if token != "packets" {
            continue;
        }
        if packets.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "nft counter output contains duplicate packet counts",
            ));
        }
        let value = tokens.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "nft counter output omits the packet count",
            )
        })?;
        packets = Some(value.parse::<u64>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid nft counter packet count `{value}`: {error}"),
            )
        })?);
    }
    packets.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "nft counter output contains no packet count",
        )
    })
}

fn gateway_command(
    program: &'static str,
    args: impl IntoIterator<Item = impl Into<String>>,
) -> NamespacedCommand {
    NamespacedCommand::new(NetworkNamespace::Gateway, program, args)
}

fn workload_command(
    program: &'static str,
    args: impl IntoIterator<Item = impl Into<String>>,
) -> NamespacedCommand {
    NamespacedCommand::new(NetworkNamespace::Workload, program, args)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IpFamily {
    Ipv4,
    Ipv6,
}

impl IpFamily {
    pub(super) fn max_udp_payload(self) -> usize {
        let network_header_length = match self {
            Self::Ipv4 => IPV4_HEADER_LENGTH,
            Self::Ipv6 => IPV6_HEADER_LENGTH,
        };
        usize::from(LINK_MTU) - network_header_length - UDP_HEADER_LENGTH
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use super::*;

    fn command_lines(commands: &[NamespacedCommand]) -> Vec<String> {
        commands
            .iter()
            .map(|command| {
                format!(
                    "{:?}: {} {}",
                    command.namespace(),
                    command.command().program(),
                    command.command().arguments().join(" ")
                )
            })
            .collect()
    }

    #[test]
    fn routing_constants_are_stable() {
        assert_eq!(WORKLOAD_INTERFACE, "hlwork0");
        assert_eq!(GATEWAY_INTERFACE, "hlgate0");
        assert_eq!(LINK_MTU, 65_520);
        assert_eq!(TPROXY_MARK, 0x1);
        assert_eq!(TPROXY_TABLE, 100);
        assert_eq!(TPROXY_RULE_PRIORITY, 100);
        assert_eq!(WORKLOAD_IPV4.to_string(), "169.254.254.2");
        assert_eq!(GATEWAY_IPV4.to_string(), "169.254.254.1");
        assert_eq!(WORKLOAD_IPV6.to_string(), "fd00:6869:6c6f:6f70::2");
        assert_eq!(GATEWAY_IPV6.to_string(), "fd00:6869:6c6f:6f70::1");
        assert_eq!(NFT_TABLE, "hiloop_capture");
        assert_eq!(IPV4_FRAGMENT_COUNTER, "udp_fragments_v4");
        assert_eq!(IPV6_FRAGMENT_COUNTER, "udp_fragments_v6");
    }

    #[test]
    fn setup_plan_is_deterministic_and_namespaced() {
        let plan = RoutingPlan::new(
            4_242,
            NonZeroU16::new(15_001).expect("test port is nonzero"),
        );

        assert_eq!(
            command_lines(plan.setup_commands()),
            [
                "Gateway: ip link add hlgate0 type veth peer name hlwork0",
                "Gateway: ip link set dev hlgate0 mtu 65520",
                "Gateway: ip link set dev hlwork0 mtu 65520",
                "Gateway: ip link set dev hlwork0 netns 4242",
                "Gateway: ip link set dev lo up",
                "Gateway: ip -4 address add 169.254.254.1/30 dev hlgate0",
                "Gateway: ip -6 address add fd00:6869:6c6f:6f70::1/64 dev hlgate0 nodad",
                "Gateway: ip link set dev hlgate0 up",
                "Workload: ip link set dev lo up",
                "Workload: ip -4 address add 169.254.254.2/30 dev hlwork0",
                "Workload: ip -6 address add fd00:6869:6c6f:6f70::2/64 dev hlwork0 nodad",
                "Workload: ip link set dev hlwork0 up",
                "Workload: ip -4 route add default via 169.254.254.1 dev hlwork0",
                "Workload: ip -6 route add default via fd00:6869:6c6f:6f70::1 dev hlwork0",
                "Gateway: ip -4 route add local 0.0.0.0/0 dev lo table 100",
                "Gateway: ip -4 rule add fwmark 0x1 lookup 100 priority 100",
                "Gateway: ip -6 route add local ::/0 dev lo table 100",
                "Gateway: ip -6 rule add fwmark 0x1 lookup 100 priority 100",
                "Gateway: nft -f -",
            ]
        );
    }

    #[test]
    fn teardown_closes_veth_before_gateway_policy_cleanup() {
        let plan = RoutingPlan::new(
            4_242,
            NonZeroU16::new(15_001).expect("test port is nonzero"),
        );

        assert_eq!(
            command_lines(plan.teardown_commands()),
            [
                "Gateway: ip link delete dev hlgate0",
                "Gateway: nft delete table inet hiloop_capture",
                "Gateway: ip -6 rule del fwmark 0x1 lookup 100 priority 100",
                "Gateway: ip -6 route del local ::/0 dev lo table 100",
                "Gateway: ip -4 rule del fwmark 0x1 lookup 100 priority 100",
                "Gateway: ip -4 route del local 0.0.0.0/0 dev lo table 100",
            ]
        );
        assert!(
            plan.teardown_commands()
                .iter()
                .all(|command| command.namespace() == NetworkNamespace::Gateway)
        );
    }

    #[test]
    fn nft_script_is_an_exact_dual_stack_snapshot() {
        let plan = RoutingPlan::new(
            4_242,
            NonZeroU16::new(15_001).expect("test port is nonzero"),
        );

        assert_eq!(
            plan.nft_script(),
            r#"table inet hiloop_capture {
    counter udp_fragments_v4 {
    }
    counter udp_fragments_v6 {
    }
    chain fragments {
        type filter hook prerouting priority -450; policy accept;
        iifname "hlgate0" meta nfproto ipv4 meta l4proto udp ip frag-off & 0x3fff != 0 counter name udp_fragments_v4 drop
        iifname "hlgate0" meta nfproto ipv6 meta l4proto udp exthdr frag exists counter name udp_fragments_v6 drop
    }
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        iifname "hlgate0" ip daddr 169.254.254.1 tcp dport 53 accept
        iifname "hlgate0" ip6 daddr fd00:6869:6c6f:6f70::1 tcp dport 53 accept
        iifname "hlgate0" ip daddr 169.254.254.1 udp dport 53 accept
        iifname "hlgate0" ip6 daddr fd00:6869:6c6f:6f70::1 udp dport 53 accept
        iifname "hlgate0" meta l4proto udp drop
        iifname "hlgate0" meta l4proto tcp socket transparent 1 meta mark set 0x1 accept
        iifname "hlgate0" meta l4proto tcp tproxy to :15001 meta mark set 0x1 accept
    }
}
"#
        );
    }

    #[test]
    fn nft_scope_and_fragment_order_cannot_silently_widen() {
        let plan = RoutingPlan::new(9, NonZeroU16::new(32_000).expect("test port is nonzero"));
        let script = plan.nft_script();

        assert_eq!(script.matches("iifname \"hlgate0\"").count(), 9);
        assert_eq!(script.matches(IPV4_FRAGMENT_COUNTER).count(), 2);
        assert_eq!(script.matches(IPV6_FRAGMENT_COUNTER).count(), 2);
        assert!(!script.contains("hlwork0"));
        assert!(script.contains("tproxy to :32000"));
        let ipv4_frag = script.find("ip frag-off").expect("IPv4 fragment rule");
        let ipv6_frag = script.find("exthdr frag").expect("IPv6 fragment rule");
        let early_priority = script.find("priority -450").expect("pre-defrag priority");
        let tproxy_priority = script.find("priority mangle").expect("TPROXY priority");
        let ipv4_tcp_dns = script
            .find("ip daddr 169.254.254.1 tcp dport 53 accept")
            .expect("IPv4 TCP DNS exception");
        let ipv6_tcp_dns = script
            .find("ip6 daddr fd00:6869:6c6f:6f70::1 tcp dport 53 accept")
            .expect("IPv6 TCP DNS exception");
        let ipv4_udp_dns = script
            .find("ip daddr 169.254.254.1 udp dport 53 accept")
            .expect("IPv4 UDP DNS exception");
        let ipv6_udp_dns = script
            .find("ip6 daddr fd00:6869:6c6f:6f70::1 udp dport 53 accept")
            .expect("IPv6 UDP DNS exception");
        let udp_drop = script
            .find("meta l4proto udp drop")
            .expect("non-DNS UDP fail-closed rule");
        let divert = script
            .find("socket transparent")
            .expect("socket divert rule");
        let tproxy = script.find("tproxy to").expect("TPROXY rule");
        for fragment_rule in [ipv4_frag, ipv6_frag] {
            for dns_exception in [ipv4_tcp_dns, ipv6_tcp_dns, ipv4_udp_dns, ipv6_udp_dns] {
                assert!(fragment_rule < dns_exception);
            }
        }
        assert!(early_priority < tproxy_priority);
        for dns_exception in [ipv4_tcp_dns, ipv6_tcp_dns, ipv4_udp_dns, ipv6_udp_dns] {
            assert!(dns_exception < udp_drop);
        }
        assert!(udp_drop < divert);
        assert!(divert < tproxy);
    }

    #[test]
    fn nft_counter_packet_count_is_parsed() {
        let output = r"table inet hiloop_capture {
    counter udp_fragments_v4 {
        packets 17 bytes 1115200
    }
}";

        assert_eq!(parse_counter_packets(output).expect("valid nft output"), 17);
        assert_eq!(
            parse_counter_packets("packets 0 bytes 0").expect("valid zero counter"),
            0
        );
    }

    #[test]
    fn malformed_nft_counter_output_is_rejected() {
        for output in [
            "counter udp_fragments_v4 { bytes 0 }",
            "counter udp_fragments_v4 { packets }",
            "counter udp_fragments_v4 { packets invalid bytes 0 }",
            "packets 1 bytes 64 packets 2 bytes 128",
        ] {
            let error = parse_counter_packets(output).expect_err("malformed output must fail");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn nonzero_port_type_excludes_an_invalid_tproxy_target() {
        assert_eq!(NonZeroU16::new(0), None);
    }

    #[test]
    fn udp_payload_policy_prevents_carrier_fragmentation() {
        assert_eq!(IpFamily::Ipv4.max_udp_payload(), 65_492);
        assert_eq!(IpFamily::Ipv6.max_udp_payload(), 65_472);
    }
}
