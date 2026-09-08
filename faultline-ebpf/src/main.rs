#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]

use aya_ebpf::{
    EbpfContext,
    bindings::{__sk_buff, BPF_ANY, BPF_NOEXIST, TC_ACT_PIPE, TC_ACT_SHOT},
    btf_maps::{ArrayOfMaps, LpmTrie as BtfLpmTrie},
    helpers::{bpf_get_prandom_u32, bpf_ktime_get_ns},
    macros::{btf_map, classifier, map},
    maps::{LruHashMap, PerCpuArray, lpm_trie::Key},
    programs::TcContext,
};
use faultline_common::{
    ADDRESS_FAMILY_IPV4, ADDRESS_FAMILY_IPV6, DiagnosticStats, FaultRule, FlowKey,
    LOSS_ALGORITHM_GILBERT_ELLIOTT, LOSS_ALGORITHM_HASH, LOSS_ALGORITHM_RANDOM,
    MAX_RULE_MAP_ENTRIES, MAX_RULES, PROTOCOL_ANY, PROTOCOL_TCP, PROTOCOL_UDP, PaceKey, PaceState,
    RULE_NAMESPACE_SOURCE_V4, RULE_NAMESPACE_SOURCE_V6, RULE_NODE_DESTINATION, RULE_NODE_SOURCE,
    RuleNode, RuleStats, edt_base_ns, gilbert_elliott_step, seeded_delay_ns, seeded_hit,
    serialization_delay_ns, should_drop_hash, should_drop_random_sample,
};

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_8021Q: u16 = 0x8100;
const ETHERTYPE_8021AD: u16 = 0x88a8;
const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_HEADER_LEN: usize = 4;
const MAX_VLAN_DEPTH: usize = 2;
const CAS_RETRIES: usize = 2;

// This value lives in a shared (not per-CPU) map. Keeping the state global makes
// hash and Gilbert-Elliott sequences deterministic even when one flow moves
// between CPUs. Both words are updated atomically by their respective paths.
#[repr(C)]
struct AtomicFlowState {
    packet_index: u64,
    ge_state: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct FlowStateKey {
    flow: FlowKey,
    rule_id: u32,
    generation: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct FragmentKey {
    source_address: [u8; 16],
    destination_address: [u8; 16],
    fragment_id: u32,
    protocol: u8,
    address_family: u8,
    _padding: [u8; 2],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct FragmentPorts {
    seen_ns: u64,
    source_port: u16,
    destination_port: u16,
    _padding: [u8; 4],
}

// A complete ruleset lives in one inner LPM. Userspace builds a fresh inner map
// and atomically replaces slot zero, so packets see either generation in full.
// The first key byte is the address family; destination bytes follow it. The
// trailing padding keeps the inner LPM value naturally aligned.
type RuleLpm = BtfLpmTrie<[u8; 24], RuleNode, { MAX_RULE_MAP_ENTRIES as usize }>;

#[btf_map]
static RULES: ArrayOfMaps<RuleLpm, 1> = ArrayOfMaps::new();

// Flow state is keyed by five-tuple, rule ID and generation, bounded, and automatically
// evicted. Eviction only restarts the deterministic sequence for that flow and
// rule; it never allows this map to grow without limit.
#[map]
static FLOW_STATE: LruHashMap<FlowStateKey, AtomicFlowState> =
    LruHashMap::with_max_entries(65_536, 0);

// IP fragments are associated only long enough to carry the first fragment's
// transport ports to later fragments. LRU bounds memory under hostile IDs;
// timestamp validation prevents an old ID collision from living indefinitely.
#[map]
static FRAGMENT_PORTS: LruHashMap<FragmentKey, FragmentPorts> =
    LruHashMap::with_max_entries(32_768, 0);

// Statistics do not need a cross-CPU atomic operation. Each CPU updates its own
// slot and userspace sums all slots when it emits a snapshot.
#[map]
static STATS: PerCpuArray<RuleStats> = PerCpuArray::with_max_entries(MAX_RULES, 0);

#[map]
static DIAGNOSTICS: PerCpuArray<DiagnosticStats> = PerCpuArray::with_max_entries(1, 0);

// One aggregate virtual clock per rule generation implements bandwidth pacing.
// LRU retires old generations without invalidating in-flight packets.
#[map]
static PACE_STATE: LruHashMap<PaceKey, PaceState> = LruHashMap::with_max_entries(MAX_RULES * 4, 0);

const DUPLICATE_MARK: u32 = 1 << 31;
const DIAG_SEEN: u32 = 0;
const DIAG_DUPLICATE_BYPASS: u32 = 1;
const DIAG_NON_IP: u32 = 2;
const DIAG_MALFORMED: u32 = 3;
const DIAG_NO_RULES: u32 = 4;
const DIAG_DESTINATION_MISS: u32 = 5;
const DIAG_SOURCE_MISS: u32 = 6;
const DIAG_PROTOCOL_MISS: u32 = 7;
const DIAG_FRAGMENT_PORT_MISS: u32 = 8;
const DIAG_PORT_MISS: u32 = 9;
const DIAG_INVALID_RULE: u32 = 10;

#[classifier]
pub fn faultline_classifier(ctx: TcContext) -> i32 {
    update_diagnostic(DIAG_SEEN);
    match try_faultline_classifier(&ctx) {
        Ok(action) => action,
        Err(_) => {
            update_diagnostic(DIAG_MALFORMED);
            TC_ACT_PIPE
        }
    }
}

fn try_faultline_classifier(ctx: &TcContext) -> Result<i32, i64> {
    let skb = ctx.as_ptr() as *mut __sk_buff;
    let mark = unsafe { (*skb).mark };
    if mark & DUPLICATE_MARK != 0 {
        // A same-interface clone traverses TC again. Clear our private marker
        // and bypass classification so it is neither cloned nor impaired twice.
        ctx.set_mark(mark & !DUPLICATE_MARK);
        update_diagnostic(DIAG_DUPLICATE_BYPASS);
        return Ok(TC_ACT_PIPE);
    }
    // Hardware-offloaded VLAN tags may already be represented as skb metadata;
    // inline 802.1Q/802.1ad headers are peeled here up to QinQ depth.
    let Some((ether_type, network_offset)) = network_header(ctx)? else {
        update_diagnostic(DIAG_NON_IP);
        return Ok(TC_ACT_PIPE);
    };
    // The lookup key is the only place the addresses need to live. parse_ip
    // fills it in directly so the five-tuple is not copied between a parse
    // result, a fragment key and a flow key on a 512-byte stack.
    let mut state_key = FlowStateKey {
        flow: FlowKey::default(),
        rule_id: 0,
        generation: 0,
    };
    let Some(packet) = parse_ip(ctx, ether_type, network_offset, &mut state_key.flow)? else {
        update_diagnostic(DIAG_MALFORMED);
        return Ok(TC_ACT_PIPE);
    };
    let mut destination = [0u8; 24];
    destination[0] = state_key.flow.address_family;
    destination[1..17].copy_from_slice(&state_key.flow.destination_address);
    let key = Key::new(
        8 + if state_key.flow.address_family == ADDRESS_FAMILY_IPV4 {
            32
        } else {
            128
        },
        destination,
    );
    let Some(rules) = RULES.get(0) else {
        update_diagnostic(DIAG_NO_RULES);
        return Ok(TC_ACT_PIPE);
    };
    let destination_id = {
        let Some(node) = rules.get(&key) else {
            update_diagnostic(DIAG_DESTINATION_MISS);
            return Ok(TC_ACT_PIPE);
        };
        if node.kind != RULE_NODE_DESTINATION {
            update_diagnostic(DIAG_INVALID_RULE);
            return Ok(TC_ACT_PIPE);
        }
        node.destination_id
    };
    let mut source = [0u8; 24];
    source[0] = if state_key.flow.address_family == ADDRESS_FAMILY_IPV4 {
        RULE_NAMESPACE_SOURCE_V4
    } else {
        RULE_NAMESPACE_SOURCE_V6
    };
    let destination_id_bytes = destination_id.to_be_bytes();
    source[1..5].copy_from_slice(&destination_id_bytes);
    source[5..21].copy_from_slice(&state_key.flow.source_address);
    let source_key = Key::new(
        40 + if state_key.flow.address_family == ADDRESS_FAMILY_IPV4 {
            32
        } else {
            128
        },
        source,
    );
    let Some(source_node) = rules.get(&source_key) else {
        update_diagnostic(DIAG_SOURCE_MISS);
        return Ok(TC_ACT_PIPE);
    };
    if source_node.kind != RULE_NODE_SOURCE || source_node.destination_id != destination_id {
        update_diagnostic(DIAG_INVALID_RULE);
        return Ok(TC_ACT_PIPE);
    }
    let rule = source_node.rule;
    let generation = source_node.generation;
    if generation == 0 || rule.address_family != state_key.flow.address_family {
        update_diagnostic(DIAG_INVALID_RULE);
        return Ok(TC_ACT_PIPE);
    }
    if rule.protocol != PROTOCOL_ANY && rule.protocol != state_key.flow.protocol {
        update_diagnostic(DIAG_PROTOCOL_MISS);
        return Ok(TC_ACT_PIPE);
    }

    let (source_port, destination_port) =
        if state_key.flow.protocol == PROTOCOL_TCP || state_key.flow.protocol == PROTOCOL_UDP {
            if packet.non_initial_fragment {
                match fragment_ports(&state_key.flow, &packet) {
                    Some(ports) => ports,
                    None if rule.destination_port != 0 => {
                        update_diagnostic(DIAG_FRAGMENT_PORT_MISS);
                        return Ok(TC_ACT_PIPE);
                    }
                    None => (0, 0),
                }
            } else {
                let ports = (
                    u16::from_be(ctx.load::<u16>(packet.transport_offset)?),
                    u16::from_be(ctx.load::<u16>(packet.transport_offset + 2)?),
                );
                if packet.fragmented {
                    remember_fragment_ports(&state_key.flow, &packet, ports);
                }
                ports
            }
        } else {
            (0, 0)
        };

    if rule.destination_port != 0 && rule.destination_port != destination_port {
        update_diagnostic(DIAG_PORT_MISS);
        return Ok(TC_ACT_PIPE);
    }
    if rule.id >= MAX_RULES {
        update_diagnostic(DIAG_INVALID_RULE);
        return Ok(TC_ACT_PIPE);
    }

    state_key.flow.source_port = source_port;
    state_key.flow.destination_port = destination_port;
    state_key.rule_id = rule.id;
    state_key.generation = generation;
    let flow = &state_key.flow;
    let has_impairments = rule.has_impairments();
    // Hash loss and seeded impairments consume the shared flow sequence.
    // Random loss and Gilbert-Elliott have their own decision state, so a
    // pure rule in either mode does not need an otherwise unused map update.
    let packet_index = if has_impairments
        || (rule.loss_algorithm == LOSS_ALGORITHM_HASH && rule.drop_permyriad != 0)
    {
        next_packet_index(&state_key)
    } else {
        0
    };
    let gso_segs = unsafe { (*ctx.skb.skb).gso_segs }.max(1);
    let context_wire_len = unsafe { (*ctx.skb.skb).wire_len };
    let wire_len = if context_wire_len == 0 {
        ctx.len()
    } else {
        context_wire_len
    };

    // Random mode makes a fresh decision for every packet. Hash mode includes
    // a monotonically increasing per-flow index, giving a repeatable sequence
    // for the same five-tuple, rule and seed.
    let drop = match rule.loss_algorithm {
        LOSS_ALGORITHM_RANDOM => {
            should_drop_random_sample(rule.drop_permyriad, unsafe { bpf_get_prandom_u32() })
        }
        LOSS_ALGORITHM_HASH => should_drop_hash(flow, packet_index, &rule),
        LOSS_ALGORITHM_GILBERT_ELLIOTT => next_gilbert_elliott_decision(&state_key, &rule),
        _ => false,
    };
    if drop {
        update_stats(
            rule.id, gso_segs, wire_len, true, false, false, false, false,
        );
        Ok(TC_ACT_SHOT)
    } else if !has_impairments {
        update_stats(
            rule.id, gso_segs, wire_len, false, false, false, false, false,
        );
        Ok(TC_ACT_PIPE)
    } else {
        let (duplicated, reordered, delayed, pacing_dropped) =
            apply_impairments(ctx, flow, packet_index, &rule, generation);
        update_stats(
            rule.id,
            gso_segs,
            wire_len,
            false,
            duplicated,
            reordered,
            delayed,
            pacing_dropped,
        );
        Ok(if pacing_dropped {
            TC_ACT_SHOT
        } else {
            TC_ACT_PIPE
        })
    }
}

#[inline(always)]
fn network_header(ctx: &TcContext) -> Result<Option<(u16, usize)>, i64> {
    let mut ether_type = u16::from_be(ctx.load::<u16>(12)?);
    let mut network_offset = ETHERNET_HEADER_LEN;
    for _ in 0..MAX_VLAN_DEPTH {
        if ether_type != ETHERTYPE_8021Q && ether_type != ETHERTYPE_8021AD {
            break;
        }
        // At network_offset the VLAN header contains TCI followed by the next
        // encapsulated EtherType. Advancing four bytes lands on its payload.
        ether_type = u16::from_be(ctx.load::<u16>(network_offset + 2)?);
        network_offset += VLAN_HEADER_LEN;
    }
    if ether_type == ETHERTYPE_IPV4 || ether_type == ETHERTYPE_IPV6 {
        Ok(Some((ether_type, network_offset)))
    } else {
        Ok(None)
    }
}

#[derive(Clone, Copy)]
/// Everything about a parsed packet that is not already recorded in FlowKey.
struct ParsedPacket {
    transport_offset: usize,
    non_initial_fragment: bool,
    fragmented: bool,
    fragment_id: u32,
}

#[inline(always)]
fn parse_ip(
    ctx: &TcContext,
    ether_type: u16,
    offset: usize,
    flow: &mut FlowKey,
) -> Result<Option<ParsedPacket>, i64> {
    if ether_type == ETHERTYPE_IPV4 {
        let version_ihl = ctx.load::<u8>(offset)?;
        let header_len = ((version_ihl & 0x0f) as usize) * 4;
        if version_ihl >> 4 != 4 || header_len < 20 {
            return Ok(None);
        }
        let total_len = u16::from_be(ctx.load::<u16>(offset + 2)?) as usize;
        if total_len < header_len || offset.saturating_add(total_len) > ctx.len() as usize {
            return Ok(None);
        }
        let fragment = u16::from_be(ctx.load::<u16>(offset + 6)?);
        let fragment_offset = fragment & 0x1fff;
        let more_fragments = fragment & 0x2000 != 0;
        // The caller zeroed the key, so only the leading four bytes are written
        // and the remaining twelve stay zero for an IPv4 address.
        flow.source_address[..4].copy_from_slice(&ctx.load::<[u8; 4]>(offset + 12)?);
        flow.destination_address[..4].copy_from_slice(&ctx.load::<[u8; 4]>(offset + 16)?);
        flow.protocol = ctx.load::<u8>(offset + 9)?;
        flow.address_family = ADDRESS_FAMILY_IPV4;
        if fragment_offset == 0
            && (flow.protocol == PROTOCOL_TCP || flow.protocol == PROTOCOL_UDP)
            && total_len < header_len + 4
        {
            return Ok(None);
        }
        return Ok(Some(ParsedPacket {
            transport_offset: offset + header_len,
            non_initial_fragment: fragment_offset != 0,
            fragmented: fragment_offset != 0 || more_fragments,
            fragment_id: u16::from_be(ctx.load::<u16>(offset + 4)?) as u32,
        }));
    }
    if ctx.load::<u8>(offset)? >> 4 != 6 {
        return Ok(None);
    }
    let payload_len = u16::from_be(ctx.load::<u16>(offset + 4)?) as usize;
    let packet_end = offset.saturating_add(40).saturating_add(payload_len);
    if packet_end > ctx.len() as usize {
        return Ok(None);
    }
    let mut next = ctx.load::<u8>(offset + 6)?;
    let mut transport_offset = offset + 40;
    let mut non_initial_fragment = false;
    let mut fragmented = false;
    let mut fragment_id = 0;
    // IPv6 extension chains are attacker-controlled. Six bounded iterations
    // cover normal chains while keeping verifier cost and packet reads finite.
    for _ in 0..6 {
        match next {
            0 | 43 | 60 => {
                if transport_offset.saturating_add(2) > packet_end {
                    return Ok(None);
                }
                next = ctx.load::<u8>(transport_offset)?;
                let len = ctx.load::<u8>(transport_offset + 1)? as usize;
                let next_offset = transport_offset.saturating_add((len + 1) * 8);
                if next_offset > packet_end {
                    return Ok(None);
                }
                transport_offset = next_offset;
            }
            44 => {
                if transport_offset.saturating_add(8) > packet_end {
                    return Ok(None);
                }
                next = ctx.load::<u8>(transport_offset)?;
                let fragment = u16::from_be(ctx.load::<u16>(transport_offset + 2)?);
                non_initial_fragment = fragment & 0xfff8 != 0;
                fragmented = non_initial_fragment || fragment & 1 != 0;
                fragment_id = u32::from_be(ctx.load::<u32>(transport_offset + 4)?);
                transport_offset += 8;
            }
            51 => {
                if transport_offset.saturating_add(2) > packet_end {
                    return Ok(None);
                }
                next = ctx.load::<u8>(transport_offset)?;
                let len = ctx.load::<u8>(transport_offset + 1)? as usize;
                let next_offset = transport_offset.saturating_add((len + 2) * 4);
                if next_offset > packet_end {
                    return Ok(None);
                }
                transport_offset = next_offset;
            }
            _ => break,
        }
    }
    if matches!(next, 0 | 43 | 44 | 51 | 60) {
        return Ok(None);
    }
    flow.source_address = ctx.load::<[u8; 16]>(offset + 8)?;
    flow.destination_address = ctx.load::<[u8; 16]>(offset + 24)?;
    flow.protocol = next;
    flow.address_family = ADDRESS_FAMILY_IPV6;
    if !non_initial_fragment
        && (flow.protocol == PROTOCOL_TCP || flow.protocol == PROTOCOL_UDP)
        && transport_offset.saturating_add(4) > packet_end
    {
        return Ok(None);
    }
    Ok(Some(ParsedPacket {
        transport_offset,
        non_initial_fragment,
        fragmented,
        fragment_id,
    }))
}

const FRAGMENT_CACHE_TTL_NS: u64 = 30_000_000_000;

#[inline(always)]
fn fragment_key(flow: &FlowKey, packet: &ParsedPacket) -> FragmentKey {
    FragmentKey {
        source_address: flow.source_address,
        destination_address: flow.destination_address,
        fragment_id: packet.fragment_id,
        protocol: flow.protocol,
        address_family: flow.address_family,
        _padding: [0; 2],
    }
}

#[inline(always)]
fn remember_fragment_ports(flow: &FlowKey, packet: &ParsedPacket, ports: (u16, u16)) {
    let value = FragmentPorts {
        seen_ns: unsafe { bpf_ktime_get_ns() },
        source_port: ports.0,
        destination_port: ports.1,
        _padding: [0; 4],
    };
    let _ = FRAGMENT_PORTS.insert(fragment_key(flow, packet), value, BPF_ANY as u64);
}

#[inline(always)]
fn fragment_ports(flow: &FlowKey, packet: &ParsedPacket) -> Option<(u16, u16)> {
    let key = fragment_key(flow, packet);
    let value = *unsafe { FRAGMENT_PORTS.get(key) }?;
    let now = unsafe { bpf_ktime_get_ns() };
    if now.saturating_sub(value.seen_ns) > FRAGMENT_CACHE_TTL_NS {
        let _ = FRAGMENT_PORTS.remove(key);
        return None;
    }
    Some((value.source_port, value.destination_port))
}

#[inline(always)]
fn apply_impairments(
    ctx: &TcContext,
    flow: &FlowKey,
    packet_index: u64,
    rule: &FaultRule,
    generation: u32,
) -> (bool, bool, bool, bool) {
    let now = unsafe { bpf_ktime_get_ns() };
    let existing_tstamp = unsafe { (*(ctx.as_ptr() as *mut __sk_buff)).tstamp };
    let reordered = seeded_hit(
        flow,
        packet_index,
        rule,
        0x7265_6f72_6465_7200,
        rule.reorder_permyriad,
    );
    let delay = seeded_delay_ns(flow, packet_index, rule, reordered);
    let base = edt_base_ns(now, existing_tstamp);
    let requested = base.saturating_add(delay);
    let duplicate_selected = seeded_hit(
        flow,
        packet_index,
        rule,
        0x6475_706c_6963_6174,
        rule.duplicate_permyriad,
    );
    let Some(delivery) = reserve_delivery_time(
        rule.id,
        generation,
        requested,
        ctx.len(),
        rule.bandwidth_bps,
    ) else {
        return (false, reordered, false, true);
    };
    // A clone consumes the same wire bytes as the original. Reserve its slot
    // before cloning so aggregate bandwidth includes both packets.
    let duplicate_delivery = if duplicate_selected {
        let Some(value) = reserve_delivery_time(
            rule.id,
            generation,
            requested,
            ctx.len(),
            rule.bandwidth_bps,
        ) else {
            return (false, reordered, delivery > base, true);
        };
        value
    } else {
        delivery
    };
    if delivery > existing_tstamp {
        unsafe {
            // On TC egress __sk_buff.tstamp is the fq delivery time. Direct
            // context writes are supported before the newer set_tstamp helper
            // and keep the base classifier compatible with Linux 5.12.
            (*(ctx.as_ptr() as *mut __sk_buff)).tstamp = delivery;
        }
    }

    let mut duplicated = false;
    if duplicate_selected {
        let skb = ctx.as_ptr() as *mut __sk_buff;
        let mark = unsafe { (*skb).mark };
        let ifindex = unsafe { (*skb).ifindex };
        ctx.set_mark(mark | DUPLICATE_MARK);
        unsafe { (*skb).tstamp = duplicate_delivery };
        duplicated = ctx.clone_redirect(ifindex, 0).is_ok();
        ctx.set_mark(mark);
        unsafe { (*skb).tstamp = delivery };
    }
    // Do not attribute a timestamp supplied by the application/TCP stack to
    // this chaos rule. Only time added beyond the incoming EDT is ours.
    (
        duplicated,
        reordered,
        delivery > base || (duplicated && duplicate_delivery > base),
        false,
    )
}

#[inline(always)]
fn reserve_delivery_time(
    rule_id: u32,
    generation: u32,
    requested: u64,
    packet_len: u32,
    bps: u64,
) -> Option<u64> {
    if bps == 0 {
        return Some(requested);
    }
    let key = PaceKey {
        rule_id,
        generation,
    };
    if PACE_STATE.get_ptr_mut(key).is_none() {
        let _ = PACE_STATE.insert(key, PaceState::default(), BPF_NOEXIST as u64);
    }
    let state = PACE_STATE.get_ptr_mut(key)?;
    let address = unsafe { core::ptr::addr_of_mut!((*state).next_ns) };
    let mut observed = unsafe {
        core::intrinsics::atomic_xadd::<u64, u64, { core::intrinsics::AtomicOrdering::Relaxed }>(
            address, 0,
        )
    };
    let serialization = serialization_delay_ns(packet_len, bps);
    // Keep retries low so older verifiers do not multiply this loop with the
    // surrounding classifier branches. Failure conservatively drops instead
    // of releasing a burst beyond the configured rate.
    for _ in 0..CAS_RETRIES {
        let delivery = if observed > requested {
            observed
        } else {
            requested
        };
        let next = delivery.saturating_add(serialization);
        let (actual, exchanged) = unsafe {
            core::intrinsics::atomic_cxchg::<
                u64,
                { core::intrinsics::AtomicOrdering::Relaxed },
                { core::intrinsics::AtomicOrdering::Relaxed },
            >(address, observed, next)
        };
        if exchanged {
            return Some(delivery);
        }
        observed = actual;
    }
    None
}

#[inline(always)]
fn next_packet_index(flow: &FlowStateKey) -> u64 {
    // BPF_NOEXIST makes initialization race-safe: when two CPUs observe a new
    // flow, one insert wins and the other proceeds with the winning entry.
    if FLOW_STATE.get_ptr_mut(flow).is_none() {
        let state = AtomicFlowState {
            packet_index: 0,
            ge_state: 0,
        };
        let _ = FLOW_STATE.insert(flow, &state, BPF_NOEXIST as u64);
    }
    if let Some(state) = FLOW_STATE.get_ptr_mut(flow) {
        let address = unsafe { core::ptr::addr_of_mut!((*state).packet_index) };
        // atomic_xadd updates the BPF map correctly but its Rust intrinsic
        // result is not the fetched value on every supported toolchain. Use a
        // zero-add only as an initial hint, then obtain the authoritative old
        // value from cmpxchg. A successful exchange returns a unique index.
        let mut observed = unsafe {
            core::intrinsics::atomic_xadd::<u64, u64, { core::intrinsics::AtomicOrdering::Relaxed }>(
                address, 0,
            )
        };
        for _ in 0..CAS_RETRIES {
            let next = observed.wrapping_add(1);
            let (actual, exchanged) = unsafe {
                core::intrinsics::atomic_cxchg::<
                    u64,
                    { core::intrinsics::AtomicOrdering::Relaxed },
                    { core::intrinsics::AtomicOrdering::Relaxed },
                >(address, observed, next)
            };
            if exchanged {
                return observed;
            }
            observed = actual;
        }
        // Extreme contention may exhaust the verifier-bounded loop. Advance
        // the counter anyway; reusing the last observed index is safer than
        // skipping the configured rule entirely.
        unsafe {
            core::intrinsics::atomic_xadd::<u64, u64, { core::intrinsics::AtomicOrdering::Relaxed }>(
                address, 1,
            );
        }
        observed
    } else {
        // A concurrent LRU eviction can remove the entry between lookup and
        // update. Falling back to zero is preferable to passing the packet
        // without applying the configured loss rule.
        0
    }
}

const GE_BAD_BIT: u64 = 1 << 63;
const GE_SEQUENCE_MASK: u64 = (1 << 31) - 1;
const GE_TIME_MASK: u64 = u32::MAX as u64;

#[inline(always)]
fn next_gilbert_elliott_decision(key: &FlowStateKey, rule: &FaultRule) -> bool {
    if FLOW_STATE.get_ptr_mut(key).is_none() {
        let state = AtomicFlowState {
            packet_index: 0,
            ge_state: 0,
        };
        let _ = FLOW_STATE.insert(key, &state, BPF_NOEXIST as u64);
    }
    let Some(state) = FLOW_STATE.get_ptr_mut(key) else {
        return false;
    };

    // One CAS word keeps the state bit, sequence and timestamp consistent.
    // Seconds are sufficient for idle reset and leave 31 bits for the packet
    // sequence. Both counters intentionally wrap; wrapping subtraction keeps
    // idle comparisons valid for intervals shorter than half their range.
    let now_secs = unsafe { bpf_ktime_get_ns() / 1_000_000_000 } & GE_TIME_MASK;
    let address = unsafe { core::ptr::addr_of_mut!((*state).ge_state) };
    let mut observed = unsafe {
        core::intrinsics::atomic_xadd::<u64, u64, { core::intrinsics::AtomicOrdering::Relaxed }>(
            address, 0,
        )
    };

    // Contention is local to a single flow and rule. Bound the retries so the
    // verifier can prove termination and a hot flow cannot monopolize the hook.
    for _ in 0..CAS_RETRIES {
        let previous_bad = (observed & GE_BAD_BIT) != 0;
        let previous_time = (observed >> 31) & GE_TIME_MASK;
        let sequence = observed & GE_SEQUENCE_MASK;
        let idle = rule.ge_idle_reset_secs != 0
            && previous_time != 0
            && now_secs.wrapping_sub(previous_time) >= rule.ge_idle_reset_secs as u64;
        let (next_bad, drop) = gilbert_elliott_step(
            &key.flow,
            sequence,
            if idle { false } else { previous_bad },
            rule,
        );
        let next = ((next_bad as u64) << 63)
            | ((now_secs & GE_TIME_MASK) << 31)
            | (sequence.wrapping_add(1) & GE_SEQUENCE_MASK);
        let (actual, exchanged) = unsafe {
            core::intrinsics::atomic_cxchg::<
                u64,
                { core::intrinsics::AtomicOrdering::Relaxed },
                { core::intrinsics::AtomicOrdering::Relaxed },
            >(address, observed, next)
        };
        if exchanged {
            return drop;
        }
        observed = actual;
    }
    false
}

#[inline(always)]
// Keeping these scalar arguments avoids materializing another aggregate on the
// verifier-constrained 512-byte BPF stack.
#[allow(clippy::too_many_arguments)]
fn update_stats(
    rule_id: u32,
    segments: u32,
    bytes: u32,
    dropped: bool,
    duplicated: bool,
    reordered: bool,
    delayed: bool,
    pacing_dropped: bool,
) {
    if let Some(stats) = STATS.get_ptr_mut(rule_id) {
        unsafe {
            // STATS is per-CPU, so these non-atomic writes cannot race with an
            // update performed by the same program on another CPU.
            (*stats).matched = (*stats).matched.wrapping_add(1);
            (*stats).matched_segments = (*stats).matched_segments.wrapping_add(segments as u64);
            (*stats).matched_bytes = (*stats).matched_bytes.wrapping_add(bytes as u64);
            if segments > 1 {
                (*stats).gso_skbs = (*stats).gso_skbs.wrapping_add(1);
            }
            if dropped {
                (*stats).dropped = (*stats).dropped.wrapping_add(1);
                (*stats).dropped_segments = (*stats).dropped_segments.wrapping_add(segments as u64);
                (*stats).dropped_bytes = (*stats).dropped_bytes.wrapping_add(bytes as u64);
            }
            if duplicated {
                (*stats).duplicated = (*stats).duplicated.wrapping_add(1);
            }
            if reordered {
                (*stats).reordered = (*stats).reordered.wrapping_add(1);
            }
            if delayed {
                (*stats).delayed = (*stats).delayed.wrapping_add(1);
            }
            if pacing_dropped {
                (*stats).pacing_dropped = (*stats).pacing_dropped.wrapping_add(1);
            }
        }
    }
}

#[inline(always)]
fn update_diagnostic(reason: u32) {
    if let Some(stats) = DIAGNOSTICS.get_ptr_mut(0) {
        unsafe {
            match reason {
                DIAG_SEEN => (*stats).seen = (*stats).seen.wrapping_add(1),
                DIAG_DUPLICATE_BYPASS => {
                    (*stats).duplicate_bypass = (*stats).duplicate_bypass.wrapping_add(1)
                }
                DIAG_NON_IP => (*stats).non_ip = (*stats).non_ip.wrapping_add(1),
                DIAG_MALFORMED => (*stats).malformed = (*stats).malformed.wrapping_add(1),
                DIAG_NO_RULES => (*stats).no_rules = (*stats).no_rules.wrapping_add(1),
                DIAG_DESTINATION_MISS => {
                    (*stats).destination_miss = (*stats).destination_miss.wrapping_add(1)
                }
                DIAG_SOURCE_MISS => (*stats).source_miss = (*stats).source_miss.wrapping_add(1),
                DIAG_PROTOCOL_MISS => {
                    (*stats).protocol_miss = (*stats).protocol_miss.wrapping_add(1)
                }
                DIAG_FRAGMENT_PORT_MISS => {
                    (*stats).fragment_port_miss = (*stats).fragment_port_miss.wrapping_add(1)
                }
                DIAG_PORT_MISS => (*stats).port_miss = (*stats).port_miss.wrapping_add(1),
                DIAG_INVALID_RULE => (*stats).invalid_rule = (*stats).invalid_rule.wrapping_add(1),
                _ => {}
            }
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
