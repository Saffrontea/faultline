use std::{
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::Context as _;
use aya::{
    maps::{
        ArrayOfMaps, HashMap, MapData, PerCpuArray,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{SchedClassifier, TestRun, TestRunOptions},
};
use faultline_common::{
    ADDRESS_FAMILY_IPV4, ADDRESS_FAMILY_IPV6, FaultRule, FlowKey, LOSS_ALGORITHM_GILBERT_ELLIOTT,
    LOSS_ALGORITHM_HASH, LOSS_ALGORITHM_RANDOM, PROTOCOL_TCP, RULE_NAMESPACE_SOURCE_V4,
    RULE_NAMESPACE_SOURCE_V6, RULE_NODE_DESTINATION, RULE_NODE_SOURCE, RuleNode, RuleStats,
    gilbert_elliott_step, should_drop_hash,
};

const TC_ACT_PIPE: u32 = 3;
const TC_ACT_SHOT: u32 = 2;
const DEFAULT_SEED: u64 = 0x7062_745f_6773_6f00;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SkbContext {
    len: u32,
    pkt_type: u32,
    mark: u32,
    queue_mapping: u32,
    protocol: u32,
    vlan_present: u32,
    vlan_tci: u32,
    vlan_proto: u32,
    priority: u32,
    ingress_ifindex: u32,
    ifindex: u32,
    tc_index: u32,
    cb: [u32; 5],
    hash: u32,
    tc_classid: u32,
    data: u32,
    data_end: u32,
    napi_id: u32,
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [u32; 4],
    local_ip6: [u32; 4],
    remote_port: u32,
    local_port: u32,
    data_meta: u32,
    flow_keys: u64,
    tstamp: u64,
    wire_len: u32,
    gso_segs: u32,
    sk: u64,
    gso_size: u32,
    tstamp_type_and_padding: u32,
    hwtstamp: u64,
}

const _: () = assert!(size_of::<SkbContext>() == 192);

impl SkbContext {
    fn as_bytes(&self) -> &[u8] {
        // `SkbContext` mirrors the kernel's fixed `__sk_buff` test-run ABI.
        // `repr(C)` fixes field layout and every byte belongs to initialized
        // integer fields, so exposing that representation is sound.
        unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref(self).cast::<u8>(), size_of::<Self>())
        }
    }

    fn read_from(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bytes.len() >= size_of::<Self>(),
            "kernel returned a short skb context: {}",
            bytes.len()
        );
        // The byte buffer has no `SkbContext` alignment guarantee; the size
        // check above and the fixed POD layout make an unaligned copy valid.
        Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<Self>()) })
    }
}

#[derive(Debug, Default)]
struct Totals {
    skbs: u64,
    dropped_skbs: u64,
    segments: u64,
    dropped_segments: u64,
    bytes: u64,
    dropped_bytes: u64,
    gso_skbs: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct TestFlowStateKey {
    flow: FlowKey,
    rule_id: u32,
    generation: u32,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct TestFlowState {
    packet_index: u64,
    ge_state: u64,
}

unsafe impl aya::Pod for TestFlowStateKey {}
unsafe impl aya::Pod for TestFlowState {}

#[test]
#[ignore = "requires root or CAP_BPF and BPF_PROG_TEST_RUN context support"]
fn generated_gso_skb_sequences_match_the_skb_reference_model() -> anyhow::Result<()> {
    let seed = std::env::var("FAULTLINE_PBT_SEED")
        .ok()
        .and_then(|value| parse_seed(&value))
        .unwrap_or(DEFAULT_SEED);
    let cases = std::env::var("FAULTLINE_PBT_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(256u32);
    let only_case = std::env::var("FAULTLINE_PBT_CASE")
        .ok()
        .and_then(|value| value.parse::<u32>().ok());

    let (mut ebpf, _rules_guard, flow_state, stats, rule) = load_ruleset()?;
    let program: &mut SchedClassifier = ebpf
        .program_mut("faultline_classifier")
        .expect("faultline_classifier program")
        .try_into()?;
    program.load()?;

    let mut totals = Totals::default();
    for case in 0..cases {
        if only_case.is_some_and(|selected| selected != case) {
            continue;
        }
        run_case(program, &flow_state, &rule, seed, case, &mut totals)
            .map_err(|error| anyhow::anyhow!("seed=0x{seed:016x} case={case}: {error:#}"))?;
    }

    let kernel_stats =
        stats
            .get(&rule.id, 0)?
            .iter()
            .fold(RuleStats::default(), |mut total, value| {
                total.matched += value.matched;
                total.dropped += value.dropped;
                total.matched_segments += value.matched_segments;
                total.dropped_segments += value.dropped_segments;
                total.matched_bytes += value.matched_bytes;
                total.dropped_bytes += value.dropped_bytes;
                total.gso_skbs += value.gso_skbs;
                total
            });
    anyhow::ensure!(
        kernel_stats.matched == totals.skbs
            && kernel_stats.dropped == totals.dropped_skbs
            && kernel_stats.matched_segments == totals.segments
            && kernel_stats.dropped_segments == totals.dropped_segments
            && kernel_stats.matched_bytes == totals.bytes
            && kernel_stats.dropped_bytes == totals.dropped_bytes
            && kernel_stats.gso_skbs == totals.gso_skbs,
        "kernel stats differ from model: kernel={kernel_stats:?} model={totals:?}"
    );

    println!(
        "PBT seed=0x{seed:016x} cases={cases} skb_loss={:.2}% segment_loss={:.2}% byte_loss={:.2}% skbs={} segments={} bytes={}",
        percent(totals.dropped_skbs, totals.skbs),
        percent(totals.dropped_segments, totals.segments),
        percent(totals.dropped_bytes, totals.bytes),
        totals.skbs,
        totals.segments,
        totals.bytes,
    );
    Ok(())
}

#[test]
#[ignore = "requires root or CAP_BPF and BPF_PROG_TEST_RUN context support"]
fn generation_swap_restarts_flow_state_without_changing_the_hash_model() -> anyhow::Result<()> {
    let (mut ebpf, mut rules_guard, flow_state, _stats, rule) = load_ruleset()?;
    let program: &mut SchedClassifier = ebpf
        .program_mut("faultline_classifier")
        .expect("faultline_classifier program")
        .try_into()?;
    program.load()?;

    let source = Ipv4Addr::new(192, 0, 2, 1);
    let destination = Ipv4Addr::new(10, 20, 1, 1);
    let source_port = 20_001;
    let packet = ipv4_tcp_packet(source, destination, source_port, 443, 512);
    let context = SkbContext {
        ifindex: 1,
        wire_len: packet.len() as u32,
        gso_segs: 1,
        gso_size: 512,
        ..Default::default()
    };
    let flow = FlowKey {
        source_address: ipv4_bytes(source),
        destination_address: ipv4_bytes(destination),
        source_port,
        destination_port: 443,
        protocol: PROTOCOL_TCP,
        address_family: ADDRESS_FAMILY_IPV4,
        _padding: [0; 2],
    };

    let first = run_sequence(program, &packet, &context, &flow, &rule, 8)?;
    let next = build_inner_ruleset(rule, 2)?;
    rules_guard.set(0, &next, 0)?;
    let second = run_sequence(program, &packet, &context, &flow, &rule, 8)?;

    assert_eq!(
        first, second,
        "a new generation must restart the hash sequence"
    );
    for generation in [1, 2] {
        let state = flow_state.get(
            &TestFlowStateKey {
                flow,
                rule_id: rule.id,
                generation,
            },
            0,
        )?;
        assert_eq!(state.packet_index, 8);
    }
    Ok(())
}

#[test]
#[ignore = "requires root or CAP_BPF and BPF_PROG_TEST_RUN context support"]
fn pass_through_rule_preserves_tstamp_and_skips_flow_state() -> anyhow::Result<()> {
    let (mut ebpf, mut rules_guard, flow_state, _stats, _) = load_ruleset()?;
    let program: &mut SchedClassifier = ebpf
        .program_mut("faultline_classifier")
        .expect("faultline_classifier program")
        .try_into()?;
    program.load()?;

    let rule = FaultRule {
        id: 0,
        seed: 42,
        protocol: PROTOCOL_TCP,
        loss_algorithm: LOSS_ALGORITHM_RANDOM,
        destination_port: 443,
        address_family: ADDRESS_FAMILY_IPV4,
        ..Default::default()
    };
    let generation = 7;
    let next = build_inner_ruleset(rule, generation)?;
    rules_guard.set(0, &next, 0)?;

    let source = Ipv4Addr::new(192, 0, 2, 1);
    let destination = Ipv4Addr::new(10, 20, 1, 1);
    let source_port = 20_001;
    let packet = ipv4_tcp_packet(source, destination, source_port, 443, 64);
    let context = SkbContext {
        ifindex: 1,
        wire_len: packet.len() as u32,
        gso_segs: 1,
        tstamp: 123_456,
        ..Default::default()
    };
    let (action, output) = run_with_context(program, &packet, &context)?;
    assert_eq!(action, TC_ACT_PIPE);
    assert_eq!(output.tstamp, context.tstamp);

    let flow = FlowKey {
        source_address: ipv4_bytes(source),
        destination_address: ipv4_bytes(destination),
        source_port,
        destination_port: 443,
        protocol: PROTOCOL_TCP,
        address_family: ADDRESS_FAMILY_IPV4,
        _padding: [0; 2],
    };
    assert!(
        flow_state
            .get(
                &TestFlowStateKey {
                    flow,
                    rule_id: rule.id,
                    generation,
                },
                0,
            )
            .is_err(),
        "a pass-through random rule must not allocate FLOW_STATE"
    );
    Ok(())
}

#[test]
#[ignore = "requires root or CAP_BPF and BPF_PROG_TEST_RUN context support"]
fn generated_gilbert_elliott_sequences_match_the_reference_model() -> anyhow::Result<()> {
    let seed = pbt_seed();
    let cases = pbt_cases();
    let only_case = pbt_only_case();
    let (mut ebpf, mut rules_guard, flow_state, _stats, _) = load_ruleset()?;
    let program: &mut SchedClassifier = ebpf
        .program_mut("faultline_classifier")
        .expect("faultline_classifier program")
        .try_into()?;
    program.load()?;

    let rates = [0, 1, 2_500, 5_000, 9_999, 10_000];
    let mut packets = 0u64;
    for case in 0..cases {
        if only_case.is_some_and(|selected| selected != case) {
            continue;
        }
        let mut random = SplitMix64(seed ^ 0x6765_5f70_6274_0000 ^ case as u64);
        let rule = FaultRule {
            id: 0,
            seed: random.next() as u32,
            loss_algorithm: LOSS_ALGORITHM_GILBERT_ELLIOTT,
            ge_enter_permyriad: rates[random.bounded(rates.len() as u64) as usize],
            ge_recover_permyriad: rates[random.bounded(rates.len() as u64) as usize],
            ge_good_loss_permyriad: rates[random.bounded(rates.len() as u64) as usize],
            ge_bad_loss_permyriad: rates[random.bounded(rates.len() as u64) as usize],
            protocol: PROTOCOL_TCP,
            destination_port: 443,
            address_family: ADDRESS_FAMILY_IPV4,
            ..Default::default()
        };
        let generation = case.checked_add(1).context("generation overflow")?;
        let next = build_inner_ruleset(rule, generation)?;
        rules_guard.set(0, &next, 0)?;

        let source = Ipv4Addr::new(192, 0, 2, 1);
        let destination = Ipv4Addr::new(10, 20, (case >> 8) as u8, case as u8);
        let source_port = 1024 + (case % 50_000) as u16;
        let flow = FlowKey {
            source_address: ipv4_bytes(source),
            destination_address: ipv4_bytes(destination),
            source_port,
            destination_port: 443,
            protocol: PROTOCOL_TCP,
            address_family: ADDRESS_FAMILY_IPV4,
            _padding: [0; 2],
        };
        let packet = ipv4_tcp_packet(source, destination, source_port, 443, 64);
        let context = SkbContext {
            ifindex: 1,
            wire_len: packet.len() as u32,
            gso_segs: 1,
            ..Default::default()
        };
        let count = 1 + random.bounded(64);
        let mut bad = false;
        for packet_index in 0..count {
            let (next_bad, expected_drop) = gilbert_elliott_step(&flow, packet_index, bad, &rule);
            let actual_drop = run(program, &packet, &context)? == TC_ACT_SHOT;
            anyhow::ensure!(
                actual_drop == expected_drop,
                "seed=0x{seed:016x} case={case} packet={packet_index} rule={rule:?} previous_bad={bad} next_bad={next_bad}: expected drop={expected_drop}, got {actual_drop}"
            );
            bad = next_bad;
            packets += 1;
        }
        let state = flow_state.get(
            &TestFlowStateKey {
                flow,
                rule_id: rule.id,
                generation,
            },
            0,
        )?;
        // A pure GE rule advances only the sequence packed into ge_state.
        // packet_index is reserved for hash loss and seeded impairments.
        anyhow::ensure!(
            state.packet_index == 0 && state.ge_state & ((1 << 31) - 1) == count,
            "case={case}: kernel state counters differ: state={state:?} count={count}"
        );
    }
    println!("GE PBT seed=0x{seed:016x} cases={cases} packets={packets}");
    Ok(())
}

#[test]
#[ignore = "requires root or CAP_BPF and BPF_PROG_TEST_RUN context support"]
fn generated_ipv4_parser_and_rule_boundaries_match_the_model() -> anyhow::Result<()> {
    let seed = pbt_seed();
    let cases = pbt_cases();
    let only_case = pbt_only_case();
    let (mut ebpf, mut rules_guard, _flow_state, _stats, mut rule) = load_ruleset()?;
    rule.drop_permyriad = 10_000;
    let next = build_inner_ruleset(rule, 2)?;
    rules_guard.set(0, &next, 0)?;
    let program: &mut SchedClassifier = ebpf
        .program_mut("faultline_classifier")
        .expect("faultline_classifier program")
        .try_into()?;
    program.load()?;

    let mut matched = 0u64;
    for case in 0..cases {
        if only_case.is_some_and(|selected| selected != case) {
            continue;
        }
        let mut random = SplitMix64(seed ^ 0x7061_7273_6572_0000 ^ case as u64);
        let vlan_depth = random.bounded(4) as usize;
        let ihl_words = 5 + random.bounded(11) as u8;
        let tcp = random.bounded(2) == 0;
        let port_matches = random.bounded(2) == 0;
        let destination_matches = random.bounded(2) == 0;
        let declared_transport = random.bounded(4) != 0;
        let source = Ipv4Addr::new(192, 0, random.next() as u8, random.next() as u8);
        let destination = if destination_matches {
            Ipv4Addr::new(10, 20, random.next() as u8, random.next() as u8)
        } else {
            Ipv4Addr::new(10, 21, random.next() as u8, random.next() as u8)
        };
        let destination_port = if port_matches { 443 } else { 80 };
        let protocol = if tcp { PROTOCOL_TCP } else { 17 };
        let packet = GeneratedIpv4Packet {
            source,
            destination,
            source_port: 20_000 + case as u16,
            destination_port,
            protocol,
            ihl_words,
            vlan_depth,
            declared_transport,
        }
        .build();
        let context = SkbContext {
            ifindex: 1,
            wire_len: packet.len() as u32,
            ..Default::default()
        };
        let expected_drop =
            vlan_depth <= 2 && tcp && port_matches && destination_matches && declared_transport;
        let actual_drop = run(program, &packet, &context)? == TC_ACT_SHOT;
        anyhow::ensure!(
            actual_drop == expected_drop,
            "seed=0x{seed:016x} case={case}: vlan_depth={vlan_depth} ihl={ihl_words} declared_transport={declared_transport} protocol={protocol} destination={destination}:{destination_port}: expected drop={expected_drop}, got {actual_drop}"
        );
        matched += expected_drop as u64;
    }
    println!("parser PBT seed=0x{seed:016x} cases={cases} matched={matched}");
    Ok(())
}

#[test]
#[ignore = "requires root or CAP_BPF and BPF_PROG_TEST_RUN context support"]
fn generated_ipv6_extensions_and_payload_length_match_the_model() -> anyhow::Result<()> {
    let seed = pbt_seed();
    let cases = pbt_cases();
    let only_case = pbt_only_case();
    let (mut ebpf, mut rules_guard, _flow_state, _stats, _) = load_ruleset()?;
    let rule = FaultRule {
        id: 0,
        drop_permyriad: 10_000,
        protocol: PROTOCOL_TCP,
        loss_algorithm: LOSS_ALGORITHM_HASH,
        destination_port: 443,
        address_family: ADDRESS_FAMILY_IPV6,
        ..Default::default()
    };
    let next = build_ipv6_inner_ruleset(rule, 2)?;
    rules_guard.set(0, &next, 0)?;
    let program: &mut SchedClassifier = ebpf
        .program_mut("faultline_classifier")
        .expect("faultline_classifier program")
        .try_into()?;
    program.load()?;

    let mut matched = 0u64;
    for case in 0..cases {
        if only_case.is_some_and(|selected| selected != case) {
            continue;
        }
        let mut random = SplitMix64(seed ^ 0x6970_7636_5f70_6274 ^ case as u64);
        let extension_count = random.bounded(8) as usize;
        let tcp = random.bounded(2) == 0;
        let port_matches = random.bounded(2) == 0;
        let destination_matches = random.bounded(2) == 0;
        let declared_transport = random.bounded(4) != 0;
        let source = Ipv6Addr::new(0x2001, 0xdb8, 0x10, case as u16, 0, 0, 0, 1);
        let destination = if destination_matches {
            Ipv6Addr::new(0x2001, 0xdb8, 0x20, case as u16, 0, 0, 0, 2)
        } else {
            Ipv6Addr::new(0x2001, 0xdb8, 0x21, case as u16, 0, 0, 0, 2)
        };
        let destination_port = if port_matches { 443 } else { 80 };
        let protocol = if tcp { PROTOCOL_TCP } else { 17 };
        let packet = generated_ipv6_packet(
            source,
            destination,
            30_000u16.wrapping_add(case as u16),
            destination_port,
            protocol,
            extension_count,
            declared_transport,
        );
        let context = SkbContext {
            ifindex: 1,
            wire_len: packet.len() as u32,
            ..Default::default()
        };
        let expected_drop = extension_count <= 6
            && tcp
            && port_matches
            && destination_matches
            && declared_transport;
        let actual_drop = run(program, &packet, &context)? == TC_ACT_SHOT;
        anyhow::ensure!(
            actual_drop == expected_drop,
            "seed=0x{seed:016x} case={case}: extensions={extension_count} declared_transport={declared_transport} protocol={protocol} destination={destination}:{destination_port}: expected drop={expected_drop}, got {actual_drop}"
        );
        matched += expected_drop as u64;
    }
    println!("IPv6 PBT seed=0x{seed:016x} cases={cases} matched={matched}");
    Ok(())
}

#[test]
#[ignore = "requires root or CAP_BPF and BPF_PROG_TEST_RUN context support"]
fn more_than_sixteen_source_rules_can_share_one_destination() -> anyhow::Result<()> {
    let (mut ebpf, mut rules_guard, _flow_state, _stats, _rule) = load_ruleset()?;
    let mut rules = LpmTrie::<MapData, [u8; 24], RuleNode>::create(2048, 1)?;
    let mut destination_key = [0u8; 24];
    destination_key[0] = ADDRESS_FAMILY_IPV4;
    destination_key[1..3].copy_from_slice(&[10, 20]);
    rules.insert(
        &Key::new(24, destination_key),
        RuleNode {
            kind: RULE_NODE_DESTINATION,
            destination_id: 0,
            generation: 2,
            rule: FaultRule::default(),
            ..Default::default()
        },
        0,
    )?;
    for host in 1..=17u8 {
        let mut source_key = [0u8; 24];
        source_key[0] = RULE_NAMESPACE_SOURCE_V4;
        source_key[5..9].copy_from_slice(&[192, 0, 2, host]);
        let rule = FaultRule {
            id: host as u32 - 1,
            seed: 42,
            drop_permyriad: if host == 17 { 10_000 } else { 0 },
            source_network: ipv4_bytes(Ipv4Addr::new(192, 0, 2, host)),
            source_mask: ipv4_bytes(Ipv4Addr::new(255, 255, 255, 255)),
            protocol: PROTOCOL_TCP,
            loss_algorithm: LOSS_ALGORITHM_HASH,
            destination_port: 443,
            source_prefix_len: 32,
            address_family: ADDRESS_FAMILY_IPV4,
            ..Default::default()
        };
        rules.insert(
            &Key::new(72, source_key),
            RuleNode {
                kind: RULE_NODE_SOURCE,
                destination_id: 0,
                generation: 2,
                rule,
                ..Default::default()
            },
            0,
        )?;
    }
    rules_guard.set(0, &rules, 0)?;

    let program: &mut SchedClassifier = ebpf
        .program_mut("faultline_classifier")
        .expect("faultline_classifier program")
        .try_into()?;
    program.load()?;
    let matching = ipv4_tcp_packet(
        Ipv4Addr::new(192, 0, 2, 17),
        Ipv4Addr::new(10, 20, 1, 1),
        20_017,
        443,
        64,
    );
    let missing = ipv4_tcp_packet(
        Ipv4Addr::new(192, 0, 2, 18),
        Ipv4Addr::new(10, 20, 1, 1),
        20_018,
        443,
        64,
    );
    let context = SkbContext {
        ifindex: 1,
        wire_len: matching.len() as u32,
        gso_segs: 1,
        gso_size: 64,
        ..Default::default()
    };
    assert_eq!(run(program, &matching, &context)?, TC_ACT_SHOT);
    assert_eq!(run(program, &missing, &context)?, TC_ACT_PIPE);
    Ok(())
}

fn run_sequence(
    program: &SchedClassifier,
    packet: &[u8],
    context: &SkbContext,
    flow: &FlowKey,
    rule: &FaultRule,
    count: u64,
) -> anyhow::Result<Vec<bool>> {
    let mut decisions = Vec::with_capacity(count as usize);
    for packet_index in 0..count {
        let actual = run(program, packet, context)? == TC_ACT_SHOT;
        let expected = should_drop_hash(flow, packet_index, rule);
        anyhow::ensure!(
            actual == expected,
            "packet={packet_index}: expected drop={expected}, got {actual}"
        );
        decisions.push(actual);
    }
    Ok(decisions)
}

fn run_case(
    program: &SchedClassifier,
    flow_state: &HashMap<MapData, TestFlowStateKey, TestFlowState>,
    rule: &FaultRule,
    seed: u64,
    case: u32,
    totals: &mut Totals,
) -> anyhow::Result<()> {
    let mut random = SplitMix64(seed ^ case as u64);
    let source = Ipv4Addr::new(192, 0, 2, 1);
    let destination = Ipv4Addr::new(10, 20, (case >> 8) as u8, case as u8);
    let source_port = 1024 + (case % 50_000) as u16;
    let packet_count = 1 + random.bounded(32);
    let flow = FlowKey {
        source_address: ipv4_bytes(source),
        destination_address: ipv4_bytes(destination),
        source_port,
        destination_port: 443,
        protocol: PROTOCOL_TCP,
        address_family: ADDRESS_FAMILY_IPV4,
        _padding: [0; 2],
    };
    let mut actual_sequence = Vec::with_capacity(packet_count as usize);
    let mut model_sequence = Vec::with_capacity(packet_count as usize);

    for packet_index in 0..packet_count {
        let gso_segs_raw = match random.bounded(8) {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 16,
            _ => 1 + random.bounded(64) as u32,
        };
        let gso_segs = gso_segs_raw.max(1);
        let gso_size = match random.bounded(8) {
            0 => 0,
            1 => 1,
            2 => 63,
            3 => 64,
            4 => 1_400,
            5 => u16::MAX as u32,
            _ => 64 + random.bounded(1400) as u32,
        };
        let logical_payload_len = ((gso_segs as u64) * (gso_size as u64)).min(60_000) as u32;
        // SCHED_CLS test-run keeps data_in in one page. A real GSO skb carries
        // most data non-linearly, so keep the synthetic linear area bounded
        // and describe its logical size through wire_len and GSO metadata.
        let payload_len = logical_payload_len.min(3_000) as usize;
        let packet = ipv4_tcp_packet(source, destination, source_port, 443, payload_len);
        let described_wire_len = 14 + 20 + 20 + logical_payload_len;
        let context_wire_len = if random.bounded(4) == 0 {
            0
        } else {
            described_wire_len
        };
        let context = SkbContext {
            ifindex: 1,
            wire_len: context_wire_len,
            gso_segs: gso_segs_raw,
            gso_size,
            ..Default::default()
        };
        let actual = run(program, &packet, &context).map_err(|error| {
            anyhow::anyhow!(
                "packet={packet_index} data_len={} wire_len={context_wire_len} gso_segs_raw={gso_segs_raw} gso_size={gso_size}: {error:#}",
                packet.len()
            )
        })?;
        let expected_drop = should_drop_hash(&flow, packet_index, rule);
        let expected = if expected_drop {
            TC_ACT_SHOT
        } else {
            TC_ACT_PIPE
        };
        actual_sequence.push(actual == TC_ACT_SHOT);
        model_sequence.push(expected == TC_ACT_SHOT);

        let bytes = if context_wire_len == 0 {
            packet.len() as u64
        } else {
            context_wire_len as u64
        };
        totals.skbs += 1;
        totals.segments += gso_segs as u64;
        totals.bytes += bytes;
        if gso_segs > 1 {
            totals.gso_skbs += 1;
        }
        if expected_drop {
            totals.dropped_skbs += 1;
            totals.dropped_segments += gso_segs as u64;
            totals.dropped_bytes += bytes;
        }
    }
    anyhow::ensure!(
        actual_sequence == model_sequence,
        "skb decision sequence differs: kernel_state={:?} actual_drop={actual_sequence:?} model_drop={model_sequence:?} model_shifted_by_one={:?}",
        flow_state
            .get(
                &TestFlowStateKey {
                    flow,
                    rule_id: rule.id,
                    generation: 1
                },
                0
            )
            .ok(),
        (1..=packet_count)
            .map(|index| should_drop_hash(&flow, index, rule))
            .collect::<Vec<_>>()
    );
    Ok(())
}

fn pbt_seed() -> u64 {
    std::env::var("FAULTLINE_PBT_SEED")
        .ok()
        .and_then(|value| parse_seed(&value))
        .unwrap_or(DEFAULT_SEED)
}

fn pbt_cases() -> u32 {
    std::env::var("FAULTLINE_PBT_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(256)
}

fn pbt_only_case() -> Option<u32> {
    std::env::var("FAULTLINE_PBT_CASE")
        .ok()
        .and_then(|value| value.parse().ok())
}

type RulesGuard = ArrayOfMaps<MapData, LpmTrie<MapData, [u8; 24], RuleNode>>;
type FlowStateGuard = HashMap<MapData, TestFlowStateKey, TestFlowState>;
type StatsGuard = PerCpuArray<MapData, RuleStats>;

fn load_ruleset() -> anyhow::Result<(aya::Ebpf, RulesGuard, FlowStateGuard, StatsGuard, FaultRule)>
{
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/faultline"
    )))?;
    let mut outer: ArrayOfMaps<_, LpmTrie<MapData, [u8; 24], RuleNode>> =
        ArrayOfMaps::try_from(ebpf.take_map("RULES").expect("RULES map"))?;
    let flow_state = HashMap::try_from(ebpf.take_map("FLOW_STATE").expect("FLOW_STATE map"))?;
    let stats = PerCpuArray::try_from(ebpf.take_map("STATS").expect("STATS map"))?;
    let rule = FaultRule {
        id: 0,
        seed: 42,
        drop_permyriad: 5_000,
        source_network: [0; 16],
        source_mask: [0; 16],
        protocol: PROTOCOL_TCP,
        loss_algorithm: LOSS_ALGORITHM_HASH,
        destination_port: 443,
        source_prefix_len: 0,
        address_family: ADDRESS_FAMILY_IPV4,
        ..Default::default()
    };
    let rules = build_inner_ruleset(rule, 1)?;
    outer.set(0, &rules, 0)?;
    Ok((ebpf, outer, flow_state, stats, rule))
}

fn build_inner_ruleset(
    rule: FaultRule,
    generation: u32,
) -> anyhow::Result<LpmTrie<MapData, [u8; 24], RuleNode>> {
    let mut rules = LpmTrie::<MapData, [u8; 24], RuleNode>::create(2048, 1)?;
    let mut destination = [0u8; 24];
    destination[0] = ADDRESS_FAMILY_IPV4;
    destination[1..3].copy_from_slice(&[10, 20]);
    rules.insert(
        &Key::new(8 + 16, destination),
        RuleNode {
            kind: RULE_NODE_DESTINATION,
            destination_id: 0,
            generation,
            rule: FaultRule::default(),
            ..Default::default()
        },
        0,
    )?;
    let mut source = [0u8; 24];
    source[0] = RULE_NAMESPACE_SOURCE_V4;
    rules.insert(
        &Key::new(40, source),
        RuleNode {
            kind: RULE_NODE_SOURCE,
            destination_id: 0,
            generation,
            rule,
            ..Default::default()
        },
        0,
    )?;
    Ok(rules)
}

fn build_ipv6_inner_ruleset(
    rule: FaultRule,
    generation: u32,
) -> anyhow::Result<LpmTrie<MapData, [u8; 24], RuleNode>> {
    let mut rules = LpmTrie::<MapData, [u8; 24], RuleNode>::create(2048, 1)?;
    let mut destination = [0u8; 24];
    destination[0] = ADDRESS_FAMILY_IPV6;
    destination[1..7].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x20]);
    rules.insert(
        &Key::new(8 + 48, destination),
        RuleNode {
            kind: RULE_NODE_DESTINATION,
            destination_id: 0,
            generation,
            rule: FaultRule::default(),
            ..Default::default()
        },
        0,
    )?;
    let mut source = [0u8; 24];
    source[0] = RULE_NAMESPACE_SOURCE_V6;
    rules.insert(
        &Key::new(40, source),
        RuleNode {
            kind: RULE_NODE_SOURCE,
            destination_id: 0,
            generation,
            rule,
            ..Default::default()
        },
        0,
    )?;
    Ok(rules)
}

fn run(program: &SchedClassifier, packet: &[u8], context: &SkbContext) -> anyhow::Result<u32> {
    Ok(program
        .test_run(TestRunOptions {
            data_in: Some(packet),
            ctx_in: Some(context.as_bytes()),
            ..Default::default()
        })?
        .return_value)
}

fn run_with_context(
    program: &SchedClassifier,
    packet: &[u8],
    context: &SkbContext,
) -> anyhow::Result<(u32, SkbContext)> {
    let mut context_out = vec![0u8; size_of::<SkbContext>()];
    let result = program.test_run(TestRunOptions {
        data_in: Some(packet),
        ctx_in: Some(context.as_bytes()),
        ctx_out: Some(&mut context_out),
        ..Default::default()
    })?;
    let returned = usize::try_from(result.ctx_size_out)
        .unwrap_or(usize::MAX)
        .min(context_out.len());
    let output = SkbContext::read_from(&context_out[..returned])?;
    Ok((result.return_value, output))
}

fn ipv4_tcp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload_len: usize,
) -> Vec<u8> {
    let mut packet = vec![0u8; 14 + 20 + 20 + payload_len];
    packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    packet[14] = 0x45;
    packet[16..18].copy_from_slice(&((40 + payload_len) as u16).to_be_bytes());
    packet[22] = 64;
    packet[23] = PROTOCOL_TCP;
    packet[26..30].copy_from_slice(&source.octets());
    packet[30..34].copy_from_slice(&destination.octets());
    packet[34..36].copy_from_slice(&source_port.to_be_bytes());
    packet[36..38].copy_from_slice(&destination_port.to_be_bytes());
    packet[46] = 0x50;
    packet
}

struct GeneratedIpv4Packet {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    protocol: u8,
    ihl_words: u8,
    vlan_depth: usize,
    declared_transport: bool,
}

impl GeneratedIpv4Packet {
    fn build(self) -> Vec<u8> {
        let network_offset = 14 + self.vlan_depth * 4;
        let ip_header_len = self.ihl_words as usize * 4;
        let mut packet = vec![0u8; network_offset + ip_header_len + 20];
        if self.vlan_depth == 0 {
            packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        } else {
            packet[12..14].copy_from_slice(&0x88a8u16.to_be_bytes());
            for tag in 0..self.vlan_depth {
                let offset = 14 + tag * 4;
                let next = if tag + 1 == self.vlan_depth {
                    0x0800
                } else {
                    0x8100
                };
                packet[offset + 2..offset + 4].copy_from_slice(&u16::to_be_bytes(next));
            }
        }
        packet[network_offset] = 0x40 | self.ihl_words;
        let declared_ip_len = ip_header_len + if self.declared_transport { 20 } else { 0 };
        packet[network_offset + 2..network_offset + 4]
            .copy_from_slice(&(declared_ip_len as u16).to_be_bytes());
        packet[network_offset + 8] = 64;
        packet[network_offset + 9] = self.protocol;
        packet[network_offset + 12..network_offset + 16].copy_from_slice(&self.source.octets());
        packet[network_offset + 16..network_offset + 20]
            .copy_from_slice(&self.destination.octets());
        let transport_offset = network_offset + ip_header_len;
        packet[transport_offset..transport_offset + 2]
            .copy_from_slice(&self.source_port.to_be_bytes());
        packet[transport_offset + 2..transport_offset + 4]
            .copy_from_slice(&self.destination_port.to_be_bytes());
        packet
    }
}

fn generated_ipv6_packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    protocol: u8,
    extension_count: usize,
    declared_transport: bool,
) -> Vec<u8> {
    let extension_len = extension_count * 8;
    let mut packet = vec![0u8; 14 + 40 + extension_len + 20];
    packet[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    packet[14] = 0x60;
    let declared_payload_len = extension_len + if declared_transport { 20 } else { 0 };
    packet[18..20].copy_from_slice(&(declared_payload_len as u16).to_be_bytes());
    packet[20] = if extension_count == 0 { protocol } else { 0 };
    packet[21] = 64;
    packet[22..38].copy_from_slice(&source.octets());
    packet[38..54].copy_from_slice(&destination.octets());
    for extension in 0..extension_count {
        let offset = 54 + extension * 8;
        packet[offset] = if extension + 1 == extension_count {
            protocol
        } else {
            0
        };
        packet[offset + 1] = 0;
    }
    let transport_offset = 54 + extension_len;
    packet[transport_offset..transport_offset + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[transport_offset + 2..transport_offset + 4]
        .copy_from_slice(&destination_port.to_be_bytes());
    packet
}

fn ipv4_bytes(address: Ipv4Addr) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&address.octets());
    bytes
}

fn parse_seed(value: &str) -> Option<u64> {
    value.strip_prefix("0x").map_or_else(
        || value.parse().ok(),
        |hex| u64::from_str_radix(hex, 16).ok(),
    )
}

fn percent(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 * 100.0 / total as f64
    }
}

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn bounded(&mut self, upper: u64) -> u64 {
        self.next() % upper
    }
}
