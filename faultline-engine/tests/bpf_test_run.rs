use std::net::{Ipv4Addr, Ipv6Addr};

use aya::{
    maps::{
        ArrayOfMaps, MapData,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{SchedClassifier, TestRun, TestRunOptions},
};
use faultline_common::{
    ADDRESS_FAMILY_IPV4, ADDRESS_FAMILY_IPV6, FaultRule, LOSS_ALGORITHM_HASH, PROTOCOL_TCP,
    RULE_NAMESPACE_SOURCE_V4, RULE_NAMESPACE_SOURCE_V6, RULE_NODE_DESTINATION, RULE_NODE_SOURCE,
    RuleNode,
};

const TC_ACT_PIPE: u32 = 3;
const TC_ACT_SHOT: u32 = 2;

#[test]
#[ignore = "requires root or CAP_BPF and a kernel with BPF_PROG_TEST_RUN support"]
fn classifier_matches_ipv4_ipv6_vlan_and_fragments() -> anyhow::Result<()> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/faultline"
    )))?;
    let mut outer: ArrayOfMaps<_, LpmTrie<MapData, [u8; 24], RuleNode>> =
        ArrayOfMaps::try_from(ebpf.take_map("RULES").expect("RULES map"))?;
    let mut rules = LpmTrie::<MapData, [u8; 24], RuleNode>::create(2048, 1)?;
    let ipv4_specific = FaultRule {
        id: 0,
        seed: 42,
        drop_permyriad: 10_000,
        source_network: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        source_mask: [255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ge_enter_permyriad: 0,
        ge_recover_permyriad: 0,
        ge_good_loss_permyriad: 0,
        ge_bad_loss_permyriad: 0,
        ge_idle_reset_secs: 0,
        duplicate_permyriad: 0,
        reorder_permyriad: 0,
        delay_ns: 0,
        jitter_ns: 0,
        bandwidth_bps: 0,
        protocol: PROTOCOL_TCP,
        loss_algorithm: LOSS_ALGORITHM_HASH,
        destination_port: 443,
        source_prefix_len: 32,
        address_family: ADDRESS_FAMILY_IPV4,
        _rule_padding: [0; 2],
    };
    let ipv4_catch_all = FaultRule {
        id: 1,
        seed: 42,
        drop_permyriad: 0,
        source_network: [0; 16],
        source_mask: [0; 16],
        ge_enter_permyriad: 0,
        ge_recover_permyriad: 0,
        ge_good_loss_permyriad: 0,
        ge_bad_loss_permyriad: 0,
        ge_idle_reset_secs: 0,
        duplicate_permyriad: 0,
        reorder_permyriad: 0,
        delay_ns: 0,
        jitter_ns: 0,
        bandwidth_bps: 0,
        protocol: PROTOCOL_TCP,
        loss_algorithm: LOSS_ALGORITHM_HASH,
        destination_port: 443,
        source_prefix_len: 0,
        address_family: ADDRESS_FAMILY_IPV4,
        _rule_padding: [0; 2],
    };
    insert_destination(
        &mut rules,
        ADDRESS_FAMILY_IPV4,
        &Ipv4Addr::new(10, 20, 0, 0).octets(),
        16,
        0,
    )?;
    insert_source(
        &mut rules,
        RULE_NAMESPACE_SOURCE_V4,
        0,
        &[192, 0, 2, 1],
        32,
        ipv4_specific,
    )?;
    insert_source(
        &mut rules,
        RULE_NAMESPACE_SOURCE_V4,
        0,
        &[],
        0,
        ipv4_catch_all,
    )?;
    let destination_v6: Ipv6Addr = "2001:db8:20::".parse()?;
    let ipv6_rule = FaultRule {
        id: 2,
        seed: 42,
        drop_permyriad: 10_000,
        source_network: "2001:db8:10::".parse::<Ipv6Addr>()?.octets(),
        source_mask: Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0, 0, 0, 0, 0).octets(),
        ge_enter_permyriad: 0,
        ge_recover_permyriad: 0,
        ge_good_loss_permyriad: 0,
        ge_bad_loss_permyriad: 0,
        ge_idle_reset_secs: 0,
        duplicate_permyriad: 0,
        reorder_permyriad: 0,
        delay_ns: 0,
        jitter_ns: 0,
        bandwidth_bps: 0,
        protocol: PROTOCOL_TCP,
        loss_algorithm: LOSS_ALGORITHM_HASH,
        destination_port: 443,
        source_prefix_len: 48,
        address_family: ADDRESS_FAMILY_IPV6,
        _rule_padding: [0; 2],
    };
    insert_destination(
        &mut rules,
        ADDRESS_FAMILY_IPV6,
        &destination_v6.octets(),
        48,
        1,
    )?;
    insert_source(
        &mut rules,
        RULE_NAMESPACE_SOURCE_V6,
        1,
        &"2001:db8:10::".parse::<Ipv6Addr>()?.octets(),
        48,
        ipv6_rule,
    )?;
    outer.set(0, &rules, 0)?;
    let program: &mut SchedClassifier = ebpf
        .program_mut("faultline_classifier")
        .expect("faultline_classifier program")
        .try_into()?;
    program.load()?;

    let matching = ipv4_tcp_packet(
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(10, 20, 1, 2),
        40_000,
        443,
    );
    let wrong_port = ipv4_tcp_packet(
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(10, 20, 1, 2),
        40_000,
        80,
    );
    let wrong_source = ipv4_tcp_packet(
        Ipv4Addr::new(192, 0, 2, 2),
        Ipv4Addr::new(10, 20, 1, 2),
        40_000,
        443,
    );
    let outside_cidr = ipv4_tcp_packet(
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(10, 21, 1, 2),
        40_000,
        443,
    );
    let dot1q = ipv4_tcp_packet_with_vlans(
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(10, 20, 1, 2),
        40_000,
        443,
        &[0x8100],
    );
    let qinq = ipv4_tcp_packet_with_vlans(
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(10, 20, 1, 2),
        40_000,
        443,
        &[0x88a8, 0x8100],
    );
    let too_many_vlan_tags = ipv4_tcp_packet_with_vlans(
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(10, 20, 1, 2),
        40_000,
        443,
        &[0x88a8, 0x8100, 0x8100],
    );
    let ipv6 = ipv6_tcp_packet(
        "2001:db8:10::1".parse()?,
        "2001:db8:20::2".parse()?,
        40_000,
        443,
        false,
    );
    let ipv6_hop_by_hop = ipv6_tcp_packet(
        "2001:db8:10::1".parse()?,
        "2001:db8:20::2".parse()?,
        40_000,
        443,
        true,
    );
    let ipv4_first_fragment = ipv4_tcp_fragment(
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(10, 20, 1, 2),
        0x1234,
        0,
        true,
        Some((40_000, 443)),
    );
    let ipv4_later_fragment = ipv4_tcp_fragment(
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(10, 20, 1, 2),
        0x1234,
        1,
        false,
        None,
    );
    let ipv4_unknown_fragment = ipv4_tcp_fragment(
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(10, 20, 1, 2),
        0x4321,
        1,
        false,
        None,
    );
    let ipv6_first_fragment = ipv6_tcp_fragment(
        "2001:db8:10::1".parse()?,
        "2001:db8:20::2".parse()?,
        0x1234_5678,
        0,
        true,
        Some((40_000, 443)),
    );
    let ipv6_later_fragment = ipv6_tcp_fragment(
        "2001:db8:10::1".parse()?,
        "2001:db8:20::2".parse()?,
        0x1234_5678,
        1,
        false,
        None,
    );
    let ipv6_unknown_fragment = ipv6_tcp_fragment(
        "2001:db8:10::1".parse()?,
        "2001:db8:20::2".parse()?,
        0x8765_4321,
        1,
        false,
        None,
    );

    assert_eq!(run(program, &matching)?, TC_ACT_SHOT);
    assert_eq!(run(program, &wrong_port)?, TC_ACT_PIPE);
    assert_eq!(run(program, &wrong_source)?, TC_ACT_PIPE);
    assert_eq!(run(program, &outside_cidr)?, TC_ACT_PIPE);
    assert_eq!(run(program, &dot1q)?, TC_ACT_SHOT);
    assert_eq!(run(program, &qinq)?, TC_ACT_SHOT);
    assert_eq!(run(program, &too_many_vlan_tags)?, TC_ACT_PIPE);
    assert_eq!(run(program, &ipv6)?, TC_ACT_SHOT);
    assert_eq!(run(program, &ipv6_hop_by_hop)?, TC_ACT_SHOT);
    assert_eq!(run(program, &ipv4_unknown_fragment)?, TC_ACT_PIPE);
    assert_eq!(run(program, &ipv4_first_fragment)?, TC_ACT_SHOT);
    assert_eq!(run(program, &ipv4_later_fragment)?, TC_ACT_SHOT);
    assert_eq!(run(program, &ipv6_unknown_fragment)?, TC_ACT_PIPE);
    assert_eq!(run(program, &ipv6_first_fragment)?, TC_ACT_SHOT);
    assert_eq!(run(program, &ipv6_later_fragment)?, TC_ACT_SHOT);
    Ok(())
}

fn insert_destination(
    rules: &mut LpmTrie<MapData, [u8; 24], RuleNode>,
    family: u8,
    address: &[u8],
    prefix_len: u32,
    destination_id: u32,
) -> anyhow::Result<()> {
    let mut data = [0u8; 24];
    data[0] = family;
    data[1..1 + address.len()].copy_from_slice(address);
    rules.insert(
        &Key::new(8 + prefix_len, data),
        RuleNode {
            kind: RULE_NODE_DESTINATION,
            destination_id,
            generation: 1,
            _padding: 0,
            rule: FaultRule::default(),
        },
        0,
    )?;
    Ok(())
}

fn insert_source(
    rules: &mut LpmTrie<MapData, [u8; 24], RuleNode>,
    namespace: u8,
    destination_id: u32,
    address: &[u8],
    prefix_len: u32,
    rule: FaultRule,
) -> anyhow::Result<()> {
    let mut data = [0u8; 24];
    data[0] = namespace;
    data[1..5].copy_from_slice(&destination_id.to_be_bytes());
    data[5..5 + address.len()].copy_from_slice(address);
    rules.insert(
        &Key::new(40 + prefix_len, data),
        RuleNode {
            kind: RULE_NODE_SOURCE,
            destination_id,
            generation: 1,
            _padding: 0,
            rule,
        },
        0,
    )?;
    Ok(())
}

fn ipv4_tcp_fragment(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    identification: u16,
    fragment_offset: u16,
    more_fragments: bool,
    ports: Option<(u16, u16)>,
) -> Vec<u8> {
    // Every non-final fragment payload must be a multiple of eight bytes.
    let payload_len = if ports.is_some() { 24 } else { 8 };
    let mut packet = vec![0u8; 14 + 20 + payload_len];
    packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    packet[14] = 0x45;
    packet[16..18].copy_from_slice(&((20 + payload_len) as u16).to_be_bytes());
    packet[18..20].copy_from_slice(&identification.to_be_bytes());
    let fragment = fragment_offset | if more_fragments { 0x2000 } else { 0 };
    packet[20..22].copy_from_slice(&fragment.to_be_bytes());
    packet[22] = 64;
    packet[23] = PROTOCOL_TCP;
    packet[26..30].copy_from_slice(&source.octets());
    packet[30..34].copy_from_slice(&destination.octets());
    if let Some((source_port, destination_port)) = ports {
        packet[34..36].copy_from_slice(&source_port.to_be_bytes());
        packet[36..38].copy_from_slice(&destination_port.to_be_bytes());
        packet[46] = 0x50;
    }
    packet
}

fn ipv6_tcp_fragment(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    identification: u32,
    fragment_offset: u16,
    more_fragments: bool,
    ports: Option<(u16, u16)>,
) -> Vec<u8> {
    let fragment_payload_len = if ports.is_some() { 24 } else { 8 };
    let mut packet = vec![0u8; 14 + 40 + 8 + fragment_payload_len];
    packet[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    packet[14] = 0x60;
    packet[18..20].copy_from_slice(&((8 + fragment_payload_len) as u16).to_be_bytes());
    packet[20] = 44;
    packet[21] = 64;
    packet[22..38].copy_from_slice(&source.octets());
    packet[38..54].copy_from_slice(&destination.octets());
    packet[54] = PROTOCOL_TCP;
    let fragment = (fragment_offset << 3) | u16::from(more_fragments);
    packet[56..58].copy_from_slice(&fragment.to_be_bytes());
    packet[58..62].copy_from_slice(&identification.to_be_bytes());
    if let Some((source_port, destination_port)) = ports {
        packet[62..64].copy_from_slice(&source_port.to_be_bytes());
        packet[64..66].copy_from_slice(&destination_port.to_be_bytes());
        packet[74] = 0x50;
    }
    packet
}

fn ipv6_tcp_packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    hop_by_hop: bool,
) -> Vec<u8> {
    let extension_len = if hop_by_hop { 8 } else { 0 };
    let mut packet = vec![0u8; 14 + 40 + extension_len + 20];
    packet[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    packet[14] = 0x60;
    packet[18..20].copy_from_slice(&((extension_len + 20) as u16).to_be_bytes());
    packet[20] = if hop_by_hop { 0 } else { PROTOCOL_TCP };
    packet[21] = 64;
    packet[22..38].copy_from_slice(&source.octets());
    packet[38..54].copy_from_slice(&destination.octets());
    let transport = 54 + extension_len;
    if hop_by_hop {
        packet[54] = PROTOCOL_TCP;
        packet[55] = 0;
    }
    packet[transport..transport + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[transport + 2..transport + 4].copy_from_slice(&destination_port.to_be_bytes());
    packet[transport + 12] = 0x50;
    packet
}

fn run(program: &SchedClassifier, packet: &[u8]) -> anyhow::Result<u32> {
    let result = program.test_run(TestRunOptions {
        data_in: Some(packet),
        ..Default::default()
    })?;
    Ok(result.return_value)
}

fn ipv4_tcp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    ipv4_tcp_packet_with_vlans(source, destination, source_port, destination_port, &[])
}

fn ipv4_tcp_packet_with_vlans(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    vlan_ethertypes: &[u16],
) -> Vec<u8> {
    let mut packet = vec![0u8; 54 + vlan_ethertypes.len() * 4];

    packet[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    packet[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    packet[12..14].copy_from_slice(
        &vlan_ethertypes
            .first()
            .copied()
            .unwrap_or(0x0800)
            .to_be_bytes(),
    );
    let mut network_offset = 14;
    for (index, _) in vlan_ethertypes.iter().enumerate() {
        packet[network_offset..network_offset + 2].copy_from_slice(&0u16.to_be_bytes());
        let next = vlan_ethertypes.get(index + 1).copied().unwrap_or(0x0800);
        packet[network_offset + 2..network_offset + 4].copy_from_slice(&next.to_be_bytes());
        network_offset += 4;
    }

    packet[network_offset] = 0x45;
    packet[network_offset + 2..network_offset + 4].copy_from_slice(&40u16.to_be_bytes());
    packet[network_offset + 8] = 64;
    packet[network_offset + 9] = PROTOCOL_TCP;
    packet[network_offset + 12..network_offset + 16].copy_from_slice(&source.octets());
    packet[network_offset + 16..network_offset + 20].copy_from_slice(&destination.octets());

    let transport_offset = network_offset + 20;
    packet[transport_offset..transport_offset + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[transport_offset + 2..transport_offset + 4]
        .copy_from_slice(&destination_port.to_be_bytes());
    packet[transport_offset + 12] = 0x50;
    packet
}
