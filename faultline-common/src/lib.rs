#![no_std]

pub const FAULTLINE_AGENT_APPLICATION: &str = "faultline-agent";
pub const FAULTLINE_ENGINE_APPLICATION: &str = "faultline-engine";
pub const FLT_APPLICATION: &str = "flt";
pub const FAULTLINE_LAB_APPLICATION: &str = "faultline-lab";
pub const DEFAULT_AGENT_IMAGE: &str = "faultline-agent:latest";

pub const MAX_RULES: u32 = 1024;
pub const MAX_RULE_MAP_ENTRIES: u32 = MAX_RULES * 2;
pub const RULE_NODE_DESTINATION: u32 = 1;
pub const RULE_NODE_SOURCE: u32 = 2;
pub const RULE_NAMESPACE_SOURCE_V4: u8 = 0x84;
pub const RULE_NAMESPACE_SOURCE_V6: u8 = 0x86;
pub const PROTOCOL_ANY: u8 = 0;
pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;
pub const ADDRESS_FAMILY_IPV4: u8 = 4;
pub const ADDRESS_FAMILY_IPV6: u8 = 6;
pub const LOSS_ALGORITHM_HASH: u8 = 0;
pub const LOSS_ALGORITHM_RANDOM: u8 = 1;
pub const LOSS_ALGORITHM_GILBERT_ELLIOTT: u8 = 2;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct FaultRule {
    pub id: u32,
    pub seed: u32,
    pub drop_permyriad: u32,
    /// Source network and mask in the same byte order as packet addresses.
    /// A zero mask disables source filtering.
    pub source_network: [u8; 16],
    pub source_mask: [u8; 16],
    pub ge_enter_permyriad: u32,
    pub ge_recover_permyriad: u32,
    pub ge_good_loss_permyriad: u32,
    pub ge_bad_loss_permyriad: u32,
    pub ge_idle_reset_secs: u32,
    pub duplicate_permyriad: u32,
    pub reorder_permyriad: u32,
    pub delay_ns: u64,
    pub jitter_ns: u64,
    pub bandwidth_bps: u64,
    pub protocol: u8,
    pub loss_algorithm: u8,
    pub destination_port: u16,
    pub source_prefix_len: u8,
    pub address_family: u8,
    pub _rule_padding: [u8; 2],
}

impl FaultRule {
    /// Whether this rule needs the queue/clone impairment path after its loss
    /// decision. Pure loss and pass-through rules must not rewrite skb timing.
    #[inline(always)]
    pub const fn has_impairments(&self) -> bool {
        self.duplicate_permyriad != 0
            || self.reorder_permyriad != 0
            || self.delay_ns != 0
            || self.jitter_ns != 0
            || self.bandwidth_bps != 0
    }
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct RuleNode {
    pub kind: u32,
    pub destination_id: u32,
    pub generation: u32,
    pub _padding: u32,
    pub rule: FaultRule,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct PaceKey {
    pub rule_id: u32,
    pub generation: u32,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct PaceState {
    pub next_ns: u64,
}

/// Composes chaos delay with an EDT timestamp already supplied by a socket or
/// an earlier classifier. Moving an existing deadline backwards would defeat
/// application pacing, so artificial delay starts at the later clock.
#[inline(always)]
pub fn edt_base_ns(now: u64, existing_tstamp: u64) -> u64 {
    if existing_tstamp > now {
        existing_tstamp
    } else {
        now
    }
}

/// Returns a reproducible pseudo-random value for one flow packet and purpose.
/// Callers use different domain constants to keep independent decisions from
/// becoming correlated while retaining seed reproducibility.
// This hash is shared by several impairment decisions. Keeping it out of line
// avoids combining its bounded-loop states with every caller's control flow.
#[inline(never)]
pub fn seeded_value(flow: &FlowKey, packet_index: u64, rule: &FaultRule, domain: u64) -> u64 {
    let mut hash = domain ^ ((rule.seed as u64) << 32 | rule.id as u64);
    for index in 0..16 {
        hash = mix(hash ^ flow.source_address[index] as u64);
        hash = mix(hash ^ ((flow.destination_address[index] as u64) << 1));
    }
    hash ^= ((flow.source_port as u64) << 48) | ((flow.destination_port as u64) << 32);
    hash ^= (flow.protocol as u64) << 24;
    mix(hash ^ packet_index)
}

#[inline(always)]
pub fn seeded_hit(
    flow: &FlowKey,
    packet_index: u64,
    rule: &FaultRule,
    domain: u64,
    permyriad: u32,
) -> bool {
    seeded_value(flow, packet_index, rule, domain) % 10_000 < permyriad.min(10_000) as u64
}

/// Computes the BPF-owned EDT offset for one packet. Reordered packets receive
/// no artificial delay, allowing them to overtake packets already queued by fq.
#[inline(always)]
pub fn seeded_delay_ns(
    flow: &FlowKey,
    packet_index: u64,
    rule: &FaultRule,
    reordered: bool,
) -> u64 {
    if reordered {
        return 0;
    }
    if rule.jitter_ns == 0 {
        return rule.delay_ns;
    }
    let sample = seeded_value(flow, packet_index, rule, 0x6a69_7474_6572_0000);
    let variation = sample % rule.jitter_ns.saturating_add(1);
    if sample & 1 == 0 {
        rule.delay_ns.saturating_add(variation)
    } else {
        rule.delay_ns.saturating_sub(variation)
    }
}

#[inline(always)]
pub fn serialization_delay_ns(packet_len: u32, bandwidth_bps: u64) -> u64 {
    if bandwidth_bps == 0 {
        return 0;
    }
    // Keep this a native 64-bit multiply. saturating_mul lowers to the
    // compiler-rt __multi3 helper on BPF, which cannot be relocated by Aya.
    // A one-gigabyte skb is already far beyond practical Linux skb sizes and
    // bounds bits * nanoseconds-per-second below u64::MAX.
    let bounded_len = packet_len.min(1_000_000_000) as u64;
    let bits = bounded_len * 8;
    (bits * 1_000_000_000) / bandwidth_bps
}

/// Advances one packet of a deterministic Gilbert-Elliott process.
///
/// `bad` is the flow's state before this packet. Separate hash domains are
/// used for state transition and packet loss so the two decisions do not
/// accidentally correlate.
#[inline(always)]
pub fn gilbert_elliott_step(
    flow: &FlowKey,
    packet_index: u64,
    bad: bool,
    rule: &FaultRule,
) -> (bool, bool) {
    let transition_rate = if bad {
        rule.ge_recover_permyriad
    } else {
        rule.ge_enter_permyriad
    };
    let transition = deterministic_bucket(flow, packet_index, rule, 0x7472_616e_7369_7469)
        < transition_rate.min(10_000) as u64;
    let next_bad = bad ^ transition;
    let loss_rate = if next_bad {
        rule.ge_bad_loss_permyriad
    } else {
        rule.ge_good_loss_permyriad
    };
    let drop = deterministic_bucket(flow, packet_index, rule, 0x6c6f_7373_5f67_6500)
        < loss_rate.min(10_000) as u64;
    (next_bad, drop)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct RuleStats {
    pub matched: u64,
    pub dropped: u64,
    pub matched_segments: u64,
    pub dropped_segments: u64,
    pub matched_bytes: u64,
    pub dropped_bytes: u64,
    pub gso_skbs: u64,
    pub duplicated: u64,
    pub reordered: u64,
    pub delayed: u64,
    pub pacing_dropped: u64,
}

/// Global classifier diagnostics for packets that do not reach a RuleStats
/// slot. Kept separate because most misses have no rule id to attribute to.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct DiagnosticStats {
    pub seen: u64,
    pub duplicate_bypass: u64,
    pub non_ip: u64,
    pub malformed: u64,
    pub no_rules: u64,
    pub destination_miss: u64,
    pub source_miss: u64,
    pub protocol_miss: u64,
    pub fragment_port_miss: u64,
    pub port_miss: u64,
    pub invalid_rule: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FlowKey {
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
    pub address_family: u8,
    pub _padding: [u8; 2],
}

/// Returns whether a packet should be dropped for a rule.
///
/// The result depends only on the flow, packet index, and rule, making an
/// experiment repeatable without relying on the kernel's random helper.
// Keep this as a BPF subprogram. Inlining the bounded address hash loop into
// the classifier combines its verifier states with the surrounding packet,
// rule, and atomic-update branches on older kernels.
#[inline(never)]
pub fn should_drop_hash(flow: &FlowKey, packet_index: u64, rule: &FaultRule) -> bool {
    if rule.drop_permyriad == 0 {
        return false;
    }
    if rule.drop_permyriad >= 10_000 {
        return true;
    }

    let mut hash = (rule.seed as u64) << 32 | rule.id as u64;
    for index in 0..16 {
        hash = mix(hash ^ flow.source_address[index] as u64);
        hash = mix(hash ^ ((flow.destination_address[index] as u64) << 1));
    }
    hash ^= ((flow.source_port as u64) << 48) | ((flow.destination_port as u64) << 32);
    hash ^= (flow.protocol as u64) << 24;
    hash = mix(hash ^ packet_index);
    (hash % 10_000) < rule.drop_permyriad as u64
}

/// Applies a uniformly distributed 32-bit random sample to a loss rate.
///
/// The eBPF program supplies samples from `bpf_get_prandom_u32`; accepting the
/// sample as an argument keeps the probability boundary testable in userspace.
#[inline(always)]
pub fn should_drop_random_sample(drop_permyriad: u32, sample: u32) -> bool {
    if drop_permyriad == 0 {
        return false;
    }
    if drop_permyriad >= 10_000 {
        return true;
    }
    let bucket = ((sample as u64) * 10_000) >> 32;
    bucket < drop_permyriad as u64
}

#[inline(always)]
fn mix(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[inline(always)]
fn deterministic_bucket(flow: &FlowKey, packet_index: u64, rule: &FaultRule, domain: u64) -> u64 {
    seeded_value(flow, packet_index, rule, domain) % 10_000
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FaultRule {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleStats {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for DiagnosticStats {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleNode {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PaceState {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PaceKey {}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow() -> FlowKey {
        FlowKey {
            source_address: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            destination_address: [10, 20, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            source_port: 40_000,
            destination_port: 443,
            protocol: PROTOCOL_TCP,
            address_family: ADDRESS_FAMILY_IPV4,
            _padding: [0; 2],
        }
    }

    fn rule(drop_permyriad: u32, seed: u32) -> FaultRule {
        FaultRule {
            id: 7,
            seed,
            drop_permyriad,
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
        }
    }

    #[test]
    fn zero_percent_never_drops() {
        for packet_index in 0..100_000 {
            assert!(!should_drop_hash(&flow(), packet_index, &rule(0, 42)));
        }
    }

    #[test]
    fn one_hundred_percent_always_drops() {
        for packet_index in 0..100_000 {
            assert!(should_drop_hash(&flow(), packet_index, &rule(10_000, 42)));
        }
    }

    #[test]
    fn the_same_seed_repeats_the_same_pattern() {
        for packet_index in 0..10_000 {
            let first = should_drop_hash(&flow(), packet_index, &rule(500, 42));
            let second = should_drop_hash(&flow(), packet_index, &rule(500, 42));
            assert_eq!(first, second);
        }
    }

    #[test]
    fn a_different_seed_changes_the_pattern() {
        let differences = (0..10_000)
            .filter(|packet_index| {
                should_drop_hash(&flow(), *packet_index, &rule(500, 42))
                    != should_drop_hash(&flow(), *packet_index, &rule(500, 43))
            })
            .count();
        assert!(differences > 500);
    }

    #[test]
    fn observed_loss_is_close_to_the_requested_rate() {
        let dropped = (0..100_000)
            .filter(|packet_index| should_drop_hash(&flow(), *packet_index, &rule(500, 42)))
            .count();
        assert!((4_700..=5_300).contains(&dropped), "dropped={dropped}");
    }

    #[test]
    fn random_sample_respects_zero_and_one_hundred_percent() {
        for sample in [0, 1, u32::MAX / 2, u32::MAX] {
            assert!(!should_drop_random_sample(0, sample));
            assert!(should_drop_random_sample(10_000, sample));
        }
    }

    #[test]
    fn random_sample_maps_the_lower_half_to_fifty_percent_loss() {
        assert!(should_drop_random_sample(5_000, 0));
        assert!(should_drop_random_sample(5_000, u32::MAX / 2));
        assert!(!should_drop_random_sample(5_000, u32::MAX / 2 + 1));
        assert!(!should_drop_random_sample(5_000, u32::MAX));
    }

    #[test]
    fn fault_rule_abi_remains_compact_and_stable() {
        assert_eq!(core::mem::size_of::<FaultRule>(), 104);
        assert_eq!(core::mem::align_of::<FaultRule>(), 8);
        assert_eq!(core::mem::size_of::<RuleNode>(), 120);
        assert_eq!(core::mem::align_of::<RuleNode>(), 8);
    }

    #[test]
    fn pure_loss_is_not_a_queue_or_clone_impairment() {
        let loss = FaultRule {
            drop_permyriad: 5_000,
            ..Default::default()
        };
        assert!(!loss.has_impairments());
        assert!(
            FaultRule {
                delay_ns: 1,
                ..loss
            }
            .has_impairments()
        );
        assert!(
            FaultRule {
                duplicate_permyriad: 1,
                ..loss
            }
            .has_impairments()
        );
    }

    #[test]
    fn diagnostic_stats_abi_is_a_dense_counter_block() {
        assert_eq!(core::mem::size_of::<DiagnosticStats>(), 11 * 8);
        assert_eq!(core::mem::align_of::<DiagnosticStats>(), 8);
    }

    #[test]
    fn gilbert_elliott_is_repeatable_and_bursty() {
        let mut rule = rule(0, 42);
        rule.ge_enter_permyriad = 500;
        rule.ge_recover_permyriad = 1_000;
        rule.ge_good_loss_permyriad = 0;
        rule.ge_bad_loss_permyriad = 10_000;

        let run = || {
            let mut bad = false;
            let mut pattern = [false; 1_000];
            for (packet_index, dropped) in pattern.iter_mut().enumerate() {
                let result = gilbert_elliott_step(&flow(), packet_index as u64, bad, &rule);
                bad = result.0;
                *dropped = result.1;
            }
            pattern
        };
        let first = run();
        assert_eq!(first, run());
        assert!(
            first
                .windows(4)
                .any(|window| window.iter().all(|dropped| *dropped))
        );
        assert!(first.iter().any(|dropped| !dropped));
    }

    #[test]
    fn seeded_impairment_timing_is_repeatable() {
        let mut rule = rule(0, 42);
        rule.delay_ns = 20_000_000;
        rule.jitter_ns = 5_000_000;
        rule.reorder_permyriad = 2_500;
        let first: [u64; 64] = core::array::from_fn(|index| {
            let reordered = seeded_hit(
                &flow(),
                index as u64,
                &rule,
                0x7265_6f72_6465_7200,
                rule.reorder_permyriad,
            );
            seeded_delay_ns(&flow(), index as u64, &rule, reordered)
        });
        let second: [u64; 64] = core::array::from_fn(|index| {
            let reordered = seeded_hit(
                &flow(),
                index as u64,
                &rule,
                0x7265_6f72_6465_7200,
                rule.reorder_permyriad,
            );
            seeded_delay_ns(&flow(), index as u64, &rule, reordered)
        });

        assert_eq!(first, second);
        assert!(first.contains(&0));
        assert!(first.iter().any(|delay| *delay >= 15_000_000));

        rule.seed = 43;
        let different: [u64; 64] = core::array::from_fn(|index| {
            let reordered = seeded_hit(
                &flow(),
                index as u64,
                &rule,
                0x7265_6f72_6465_7200,
                rule.reorder_permyriad,
            );
            seeded_delay_ns(&flow(), index as u64, &rule, reordered)
        });
        assert_ne!(first, different);
    }

    #[test]
    fn delay_uses_the_callers_single_reorder_decision() {
        let mut rule = rule(0, 42);
        rule.delay_ns = 20_000_000;
        rule.jitter_ns = 5_000_000;
        rule.reorder_permyriad = 10_000;

        assert_eq!(seeded_delay_ns(&flow(), 0, &rule, true), 0);
        assert!(seeded_delay_ns(&flow(), 0, &rule, false) >= 15_000_000);
    }

    #[test]
    fn seeded_duplication_pattern_is_repeatable_and_seeded() {
        let mut rule = rule(0, 42);
        rule.duplicate_permyriad = 2_000;
        let pattern = |rule: &FaultRule| -> [bool; 128] {
            core::array::from_fn(|index| {
                seeded_hit(
                    &flow(),
                    index as u64,
                    rule,
                    0x6475_706c_6963_6174,
                    rule.duplicate_permyriad,
                )
            })
        };
        let first = pattern(&rule);
        assert_eq!(first, pattern(&rule));
        assert!(first.iter().any(|selected| *selected));
        assert!(first.iter().any(|selected| !selected));

        rule.seed = 43;
        assert_ne!(first, pattern(&rule));
    }

    #[test]
    fn bandwidth_is_converted_to_wire_serialization_time() {
        assert_eq!(serialization_delay_ns(125_000, 1_000_000), 1_000_000_000);
        assert_eq!(serialization_delay_ns(1_500, 0), 0);
    }

    #[test]
    fn edt_never_moves_an_existing_deadline_backwards() {
        assert_eq!(edt_base_ns(1_000, 0), 1_000);
        assert_eq!(edt_base_ns(1_000, 900), 1_000);
        assert_eq!(edt_base_ns(1_000, 1_500), 1_500);
    }
}
