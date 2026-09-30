use std::{mem::size_of, net::Ipv4Addr};

use aya::{
    maps::{
        ArrayOfMaps, HashMap, Map, MapData, MapType,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{SchedClassifier, TestRun, TestRunOptions},
};
use faultline_common::{
    ADDRESS_FAMILY_IPV4, FaultRule, FlowKey, FlowState, FlowStateKey, LOSS_ALGORITHM_HASH,
    PROTOCOL_TCP, PaceKey, PaceState, RULE_NAMESPACE_SOURCE_V4, RULE_NODE_DESTINATION,
    RULE_NODE_SOURCE, RuleNode, serialization_delay_ns, should_drop_hash,
};

const TC_ACT_PIPE: u32 = 3;
const TC_ACT_SHOT: u32 = 2;
const BPF_F_NO_PREALLOC: u32 = 1;

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
        // SAFETY: SkbContext is the initialized, fixed-layout __sk_buff test
        // ABI, and the returned slice cannot outlive this shared reference.
        unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref(self).cast::<u8>(), size_of::<Self>())
        }
    }

    fn read_from(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(bytes.len() >= size_of::<Self>(), "short skb context");
        // SAFETY: the size check guarantees a complete SkbContext, every bit
        // pattern is valid for its integer fields, and read_unaligned removes
        // any alignment requirement on the byte buffer.
        Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<Self>()) })
    }
}

type TestFlowStateKey = FlowStateKey;
type TestFlowState = FlowState;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TestFragmentKey {
    source_address: [u8; 16],
    destination_address: [u8; 16],
    fragment_id: u32,
    protocol: u8,
    address_family: u8,
    padding: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TestFragmentPorts {
    seen_ns: u64,
    source_port: u16,
    destination_port: u16,
    padding: [u8; 4],
}

// SAFETY: the C-layout key contains only integer arrays and integer fields.
unsafe impl aya::Pod for TestFragmentKey {}
// SAFETY: the C-layout value contains integer fields and explicit padding.
unsafe impl aya::Pod for TestFragmentPorts {}

type Rules = ArrayOfMaps<MapData, LpmTrie<MapData, [u8; 24], RuleNode>>;
type FlowStates = HashMap<MapData, TestFlowStateKey, TestFlowState>;
type FragmentPorts = HashMap<MapData, TestFragmentKey, TestFragmentPorts>;
type PaceStates = HashMap<MapData, PaceKey, PaceState>;

struct Maps {
    rules: Rules,
    flows: FlowStates,
    fragments: FragmentPorts,
    pace: PaceStates,
}

#[test]
#[ignore = "requires root or CAP_BPF and BPF_PROG_TEST_RUN context support"]
fn flow_state_full_map_does_not_evict_or_alias_another_flow() -> anyhow::Result<()> {
    for capacity in [1, 2] {
        let (mut ebpf, mut maps) = load(capacity, 4, 4)?;
        let rule = hash_rule();
        maps.rules.set(0, &build_rules(rule, 1)?, 0)?;
        let program = load_program(&mut ebpf)?;

        let original: Vec<_> = (0..capacity)
            .map(|index| flow_and_packet(20_000 + index as u16, 0x1000 + index as u16))
            .collect();
        for (flow, packet) in &original {
            run(program, packet, &SkbContext::default())?;
            assert_eq!(flow_state(&maps.flows, *flow, 1)?.packet_index, 1);
        }
        assert_eq!(map_len(&maps.flows)?, capacity as usize);

        let (overflow_flow, overflow_packet) =
            flow_and_packet(30_000 + capacity as u16, 0x2000 + capacity as u16);
        let action = run(program, &overflow_packet, &SkbContext::default())?;
        let expected = if should_drop_hash(&overflow_flow, 0, &rule) {
            TC_ACT_SHOT
        } else {
            TC_ACT_PIPE
        };
        assert_eq!(
            action, expected,
            "an untracked flow still uses sequence zero"
        );
        assert_eq!(map_len(&maps.flows)?, capacity as usize);
        assert!(
            flow_state(&maps.flows, overflow_flow, 1).is_err(),
            "a full non-preallocated map must not recycle an existing slot"
        );

        run(program, &original[0].1, &SkbContext::default())?;
        assert_eq!(map_len(&maps.flows)?, capacity as usize);
        assert_eq!(
            flow_state(&maps.flows, original[0].0, 1)?.packet_index,
            2,
            "overflow must not replace or modify the existing flow's state"
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires root or CAP_BPF and BPF_PROG_TEST_RUN context support"]
fn flow_sequence_wraps_at_u64_boundary() -> anyhow::Result<()> {
    let (mut ebpf, mut maps) = load(1, 1, 1)?;
    let rule = hash_rule();
    maps.rules.set(0, &build_rules(rule, 1)?, 0)?;
    let (flow, packet) = flow_and_packet(20_000, 0x1234);
    maps.flows.insert(
        TestFlowStateKey {
            flow,
            rule_id: rule.id,
            generation: 1,
        },
        TestFlowState {
            packet_index: u64::MAX,
            ge_state: 0,
        },
        0,
    )?;
    let program = load_program(&mut ebpf)?;

    let action = run(program, &packet, &SkbContext::default())?;
    let expected = if should_drop_hash(&flow, u64::MAX, &rule) {
        TC_ACT_SHOT
    } else {
        TC_ACT_PIPE
    };
    assert_eq!(action, expected);
    assert_eq!(flow_state(&maps.flows, flow, 1)?.packet_index, 0);
    Ok(())
}

#[test]
#[ignore = "requires root or CAP_BPF and BPF_PROG_TEST_RUN context support"]
fn fragment_full_map_does_not_reuse_another_datagrams_ports() -> anyhow::Result<()> {
    let (mut ebpf, mut maps) = load(4, 1, 1)?;
    let rule = FaultRule {
        drop_permyriad: 10_000,
        ..hash_rule()
    };
    maps.rules.set(0, &build_rules(rule, 1)?, 0)?;
    let program = load_program(&mut ebpf)?;
    let source = Ipv4Addr::new(192, 0, 2, 1);
    let destination = Ipv4Addr::new(10, 20, 1, 2);

    let first_a = ipv4_tcp_fragment(source, destination, 0x1000, 0, true, Some((40_000, 443)));
    let later_a = ipv4_tcp_fragment(source, destination, 0x1000, 1, false, None);
    let first_b = ipv4_tcp_fragment(source, destination, 0x1001, 0, true, Some((40_001, 443)));
    let later_b = ipv4_tcp_fragment(source, destination, 0x1001, 1, false, None);

    assert_eq!(run(program, &first_a, &SkbContext::default())?, TC_ACT_SHOT);
    assert_eq!(map_len(&maps.fragments)?, 1);
    assert_eq!(run(program, &first_b, &SkbContext::default())?, TC_ACT_SHOT);
    assert_eq!(map_len(&maps.fragments)?, 1);
    assert_eq!(
        run(program, &later_a, &SkbContext::default())?,
        TC_ACT_SHOT,
        "overflow must not evict the existing fragment entry"
    );
    assert_eq!(
        run(program, &later_b, &SkbContext::default())?,
        TC_ACT_PIPE,
        "an unrecorded fragment must not inherit another datagram's ports"
    );
    assert_eq!(map_len(&maps.fragments)?, 1);
    Ok(())
}

#[test]
#[ignore = "requires root or CAP_BPF and BPF_PROG_TEST_RUN context support"]
fn pacing_full_map_fails_closed_without_reusing_another_generation() -> anyhow::Result<()> {
    let (mut ebpf, mut maps) = load(8, 1, 1)?;
    let rule = FaultRule {
        drop_permyriad: 0,
        bandwidth_bps: 1_000_000_000,
        ..hash_rule()
    };
    maps.rules.set(0, &build_rules(rule, 1)?, 0)?;
    let (_, packet) = flow_and_packet(20_000, 0x1234);
    let requested = u64::MAX - 1_000_000;
    let context = SkbContext {
        tstamp: requested,
        wire_len: packet.len() as u32,
        gso_segs: 1,
        ..Default::default()
    };
    let serialization = serialization_delay_ns(packet.len() as u32, rule.bandwidth_bps);
    let program = load_program(&mut ebpf)?;

    assert_eq!(
        run_with_context(program, &packet, &context)?.1.tstamp,
        requested
    );
    assert_eq!(
        run_with_context(program, &packet, &context)?.1.tstamp,
        requested + serialization
    );
    assert_eq!(map_len(&maps.pace)?, 1);

    maps.rules.set(0, &build_rules(rule, 2)?, 0)?;
    assert_eq!(
        run_with_context(program, &packet, &context)?.0,
        TC_ACT_SHOT,
        "a full pacing map must fail closed rather than update another generation"
    );
    assert_eq!(
        maps.pace
            .get(
                &PaceKey {
                    rule_id: rule.id,
                    generation: 1,
                },
                0,
            )?
            .next_ns,
        requested + serialization * 2,
        "the existing generation's clock must remain unchanged"
    );
    assert!(
        maps.pace
            .get(
                &PaceKey {
                    rule_id: rule.id,
                    generation: 2,
                },
                0,
            )
            .is_err(),
        "the overflowing generation must not be inserted"
    );
    assert_eq!(map_len(&maps.pace)?, 1);

    maps.rules.set(0, &build_rules(rule, 1)?, 0)?;
    assert_eq!(
        run_with_context(program, &packet, &context)?.1.tstamp,
        requested + serialization * 2,
        "overflow must not replace or reset the existing generation's clock"
    );
    assert_eq!(map_len(&maps.pace)?, 1);
    Ok(())
}

fn load(
    flow_entries: u32,
    fragment_entries: u32,
    pace_entries: u32,
) -> anyhow::Result<(aya::Ebpf, Maps)> {
    let mut loader = aya::EbpfLoader::new();
    loader
        .map_max_entries("FLOW_STATE", flow_entries)
        .map_max_entries("FRAGMENT_PORTS", fragment_entries)
        .map_max_entries("PACE_STATE", pace_entries);
    let mut ebpf = loader.load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/faultline"
    )))?;
    for name in ["FLOW_STATE", "FRAGMENT_PORTS", "PACE_STATE"] {
        let Map::HashMap(data) = ebpf.map(name).expect("state map") else {
            panic!("{name} must be a hash map");
        };
        let info = data.info()?;
        assert_eq!(info.map_type()?, MapType::Hash, "{name} must not be LRU");
        assert_ne!(
            info.map_flags() & BPF_F_NO_PREALLOC,
            0,
            "{name} must set BPF_F_NO_PREALLOC"
        );
    }
    let maps = Maps {
        rules: ArrayOfMaps::try_from(ebpf.take_map("RULES").expect("RULES map"))?,
        flows: HashMap::try_from(ebpf.take_map("FLOW_STATE").expect("FLOW_STATE map"))?,
        fragments: HashMap::try_from(ebpf.take_map("FRAGMENT_PORTS").expect("FRAGMENT_PORTS map"))?,
        pace: HashMap::try_from(ebpf.take_map("PACE_STATE").expect("PACE_STATE map"))?,
    };
    Ok((ebpf, maps))
}

fn load_program(ebpf: &mut aya::Ebpf) -> anyhow::Result<&mut SchedClassifier> {
    let program: &mut SchedClassifier = ebpf
        .program_mut("faultline_classifier")
        .expect("faultline_classifier program")
        .try_into()?;
    program.load()?;
    Ok(program)
}

fn hash_rule() -> FaultRule {
    FaultRule {
        id: 0,
        seed: 42,
        drop_permyriad: 5_000,
        protocol: PROTOCOL_TCP,
        loss_algorithm: LOSS_ALGORITHM_HASH,
        destination_port: 443,
        address_family: ADDRESS_FAMILY_IPV4,
        ..Default::default()
    }
}

fn build_rules(
    rule: FaultRule,
    generation: u32,
) -> anyhow::Result<LpmTrie<MapData, [u8; 24], RuleNode>> {
    let mut rules = LpmTrie::<MapData, [u8; 24], RuleNode>::create(4, 1)?;
    let mut destination = [0u8; 24];
    destination[0] = ADDRESS_FAMILY_IPV4;
    destination[1..3].copy_from_slice(&[10, 20]);
    rules.insert(
        &Key::new(24, destination),
        RuleNode {
            kind: RULE_NODE_DESTINATION,
            destination_id: 0,
            generation,
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

fn flow_and_packet(source_port: u16, identification: u16) -> (FlowKey, Vec<u8>) {
    let source = Ipv4Addr::new(192, 0, 2, 1);
    let destination = Ipv4Addr::new(10, 20, 1, 2);
    (
        FlowKey {
            source_address: ipv4_bytes(source),
            destination_address: ipv4_bytes(destination),
            source_port,
            destination_port: 443,
            protocol: PROTOCOL_TCP,
            address_family: ADDRESS_FAMILY_IPV4,
            _padding: [0; 2],
        },
        ipv4_tcp_packet(source, destination, source_port, 443, identification),
    )
}

fn flow_state(
    states: &FlowStates,
    flow: FlowKey,
    generation: u32,
) -> anyhow::Result<TestFlowState> {
    Ok(states.get(
        &TestFlowStateKey {
            flow,
            rule_id: 0,
            generation,
        },
        0,
    )?)
}

fn map_len<K: aya::Pod, V: aya::Pod>(map: &HashMap<MapData, K, V>) -> anyhow::Result<usize> {
    map.keys().try_fold(0usize, |count, key| {
        key.map(|_| count + 1).map_err(anyhow::Error::from)
    })
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
    let mut output = vec![0u8; size_of::<SkbContext>()];
    let result = program.test_run(TestRunOptions {
        data_in: Some(packet),
        ctx_in: Some(context.as_bytes()),
        ctx_out: Some(&mut output),
        ..Default::default()
    })?;
    let returned = usize::try_from(result.ctx_size_out)
        .unwrap_or(usize::MAX)
        .min(output.len());
    Ok((
        result.return_value,
        SkbContext::read_from(&output[..returned])?,
    ))
}

fn ipv4_tcp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    identification: u16,
) -> Vec<u8> {
    let mut packet = vec![0u8; 54];
    packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    packet[14] = 0x45;
    packet[16..18].copy_from_slice(&40u16.to_be_bytes());
    packet[18..20].copy_from_slice(&identification.to_be_bytes());
    packet[22] = 64;
    packet[23] = PROTOCOL_TCP;
    packet[26..30].copy_from_slice(&source.octets());
    packet[30..34].copy_from_slice(&destination.octets());
    packet[34..36].copy_from_slice(&source_port.to_be_bytes());
    packet[36..38].copy_from_slice(&destination_port.to_be_bytes());
    packet[46] = 0x50;
    packet
}

fn ipv4_tcp_fragment(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    identification: u16,
    fragment_offset: u16,
    more_fragments: bool,
    ports: Option<(u16, u16)>,
) -> Vec<u8> {
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

fn ipv4_bytes(address: Ipv4Addr) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(&address.octets());
    bytes
}
