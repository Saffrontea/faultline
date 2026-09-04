use std::collections::{BTreeMap, HashSet};

use anyhow::{Context as _, bail};
use aya::maps::{
    ArrayOfMaps, HashMap, Map, MapData,
    lpm_trie::{Key, LpmTrie},
};
use faultline_common::{
    ADDRESS_FAMILY_IPV4, ADDRESS_FAMILY_IPV6, FaultRule, MAX_RULE_MAP_ENTRIES, MAX_RULES, PaceKey,
    PaceState, RULE_NAMESPACE_SOURCE_V4, RULE_NAMESPACE_SOURCE_V6, RULE_NODE_DESTINATION,
    RULE_NODE_SOURCE, RuleNode,
};
use faultline_protocol::RuleSpec;
use ipnet::IpNet;

use crate::control::ControlCommand;

type GroupedRules = BTreeMap<IpNet, Vec<(Option<IpNet>, FaultRule)>>;

pub struct RuleStore {
    rules: ArrayOfMaps<MapData, LpmTrie<MapData, [u8; 24], RuleNode>>,
    pace_state: HashMap<MapData, PaceKey, PaceState>,
    active_rule_ids: Vec<u32>,
    generation: u32,
}

impl RuleStore {
    pub fn new(rules: Map, pace_state: Map) -> anyhow::Result<Self> {
        Ok(Self {
            rules: ArrayOfMaps::try_from(rules)?,
            pace_state: HashMap::try_from(pace_state)?,
            active_rule_ids: Vec::new(),
            generation: 0,
        })
    }

    pub fn active_rule_ids(&self) -> &[u32] {
        &self.active_rule_ids
    }

    /// Applies one transport-independent control command.
    ///
    /// A replacement is built in a detached inner LPM and published with one
    /// outer-map update, so packet lookups see one complete generation.
    pub fn apply(&mut self, command: ControlCommand) -> anyhow::Result<bool> {
        match command {
            ControlCommand::ReplaceRules(rules) => {
                self.replace(rules)?;
                Ok(true)
            }
            ControlCommand::Stop => Ok(false),
        }
    }

    fn replace(&mut self, specs: Vec<RuleSpec>) -> anyhow::Result<()> {
        let (rule_ids, grouped) = group_rules(specs)?;

        let mut next = LpmTrie::<MapData, [u8; 24], RuleNode>::create(MAX_RULE_MAP_ENTRIES, 1)
            .context("creating the next BPF rule generation")?;
        let generation = self.generation.wrapping_add(1).max(1);
        // Populate generation-specific clocks before publishing the rules.
        // Packets still using the old inner map retain their old clocks.
        for &rule_id in &rule_ids {
            self.pace_state
                .insert(
                    PaceKey {
                        rule_id,
                        generation,
                    },
                    PaceState::default(),
                    0,
                )
                .context("resetting the BPF pacing clock")?;
        }
        for (destination_id, (network, source_rules)) in grouped.into_iter().enumerate() {
            let destination_id = destination_id as u32;
            let (prefix_len, data) = destination_key(network);
            let destination_node = RuleNode {
                kind: RULE_NODE_DESTINATION,
                destination_id,
                generation,
                _padding: 0,
                rule: FaultRule::default(),
            };
            next.insert(&Key::new(prefix_len, data), destination_node, 0)
                .context("inserting a BPF destination rule")?;
            for (source, rule) in source_rules {
                let (prefix_len, data) = source_key(destination_id, network, source);
                let source_node = RuleNode {
                    kind: RULE_NODE_SOURCE,
                    destination_id,
                    generation,
                    _padding: 0,
                    rule,
                };
                next.insert(&Key::new(prefix_len, data), source_node, 0)
                    .context("inserting a BPF source rule")?;
            }
        }
        self.rules
            .set(0, &next, 0)
            .context("publishing the BPF rule generation")?;
        self.generation = generation;
        self.active_rule_ids = rule_ids.into_iter().collect();
        self.active_rule_ids.sort_unstable();
        Ok(())
    }
}

fn group_rules(specs: Vec<RuleSpec>) -> anyhow::Result<(HashSet<u32>, GroupedRules)> {
    if specs.is_empty() {
        bail!("a scenario must contain at least one rule");
    }
    if specs.len() > MAX_RULES as usize {
        bail!("a scenario may contain at most {MAX_RULES} rules");
    }
    let capacity = specs.len();

    specs.into_iter().try_fold(
        (HashSet::with_capacity(capacity), GroupedRules::new()),
        |(mut rule_ids, mut grouped), spec| {
            spec.validate().map_err(anyhow::Error::msg)?;
            if !rule_ids.insert(spec.id) {
                bail!("duplicate rule id: {}", spec.id);
            }

            let candidate = fault_rule_from_spec(&spec);
            let bucket = grouped.entry(spec.destination.trunc()).or_default();
            if bucket.iter().any(|(_, existing)| {
                existing.source_network == candidate.source_network
                    && existing.source_mask == candidate.source_mask
            }) {
                bail!(
                    "duplicate source prefix {:?} for destination {}",
                    spec.source,
                    spec.destination
                );
            }
            bucket.push((spec.source, candidate));
            Ok((rule_ids, grouped))
        },
    )
}

fn fault_rule_from_spec(spec: &RuleSpec) -> FaultRule {
    let (source_network, source_mask) = spec.source_network_and_mask();
    FaultRule {
        id: spec.id,
        seed: spec.seed,
        drop_permyriad: spec.drop_permyriad,
        source_network,
        source_mask,
        ge_enter_permyriad: spec.ge_enter_permyriad,
        ge_recover_permyriad: spec.ge_recover_permyriad,
        ge_good_loss_permyriad: spec.ge_good_loss_permyriad,
        ge_bad_loss_permyriad: spec.ge_bad_loss_permyriad,
        ge_idle_reset_secs: spec.ge_idle_reset_secs,
        duplicate_permyriad: spec.duplicate_permyriad,
        reorder_permyriad: spec.reorder_permyriad,
        delay_ns: spec.delay_ns,
        jitter_ns: spec.jitter_ns,
        bandwidth_bps: spec.bandwidth_bps,
        protocol: spec.protocol,
        loss_algorithm: spec.loss_algorithm,
        destination_port: spec.destination_port,
        source_prefix_len: spec.source.map(|source| source.prefix_len()).unwrap_or(0),
        address_family: if spec.destination.addr().is_ipv4() {
            ADDRESS_FAMILY_IPV4
        } else {
            ADDRESS_FAMILY_IPV6
        },
        _rule_padding: [0; 2],
    }
}

fn source_key(destination_id: u32, destination: IpNet, source: Option<IpNet>) -> (u32, [u8; 24]) {
    let mut data = [0u8; 24];
    data[1..5].copy_from_slice(&destination_id.to_be_bytes());
    match (destination, source) {
        (IpNet::V4(_), Some(IpNet::V4(value))) => {
            data[0] = RULE_NAMESPACE_SOURCE_V4;
            data[5..9].copy_from_slice(&value.network().octets());
            (40 + value.prefix_len() as u32, data)
        }
        (IpNet::V6(_), Some(IpNet::V6(value))) => {
            data[0] = RULE_NAMESPACE_SOURCE_V6;
            data[5..21].copy_from_slice(&value.network().octets());
            (40 + value.prefix_len() as u32, data)
        }
        (IpNet::V4(_), None) => {
            data[0] = RULE_NAMESPACE_SOURCE_V4;
            (40, data)
        }
        (IpNet::V6(_), None) => {
            data[0] = RULE_NAMESPACE_SOURCE_V6;
            (40, data)
        }
        _ => unreachable!("RuleSpec validation rejects mixed address families"),
    }
}

fn destination_key(network: IpNet) -> (u32, [u8; 24]) {
    let mut data = [0u8; 24];
    match network {
        IpNet::V4(value) => {
            data[0] = ADDRESS_FAMILY_IPV4;
            data[1..5].copy_from_slice(&value.network().octets());
            (8 + value.prefix_len() as u32, data)
        }
        IpNet::V6(value) => {
            data[0] = ADDRESS_FAMILY_IPV6;
            data[1..17].copy_from_slice(&value.network().octets());
            (8 + value.prefix_len() as u32, data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_keys_partition_destinations_and_preserve_prefix_length() {
        let destination = "10.0.0.0/8".parse().unwrap();
        let source = Some("192.0.2.0/24".parse().unwrap());
        let (prefix, first) = source_key(7, destination, source);
        let (_, second) = source_key(8, destination, source);

        assert_eq!(prefix, 40 + 24);
        assert_eq!(first[0], RULE_NAMESPACE_SOURCE_V4);
        assert_eq!(&first[1..5], &7u32.to_be_bytes());
        assert_eq!(&first[5..9], &[192, 0, 2, 0]);
        assert_ne!(first, second);
    }

    #[test]
    fn catch_all_source_stops_after_the_namespace_and_destination_id() {
        let destination = "2001:db8::/32".parse().unwrap();
        let (prefix, key) = source_key(11, destination, None);

        assert_eq!(prefix, 40);
        assert_eq!(key[0], RULE_NAMESPACE_SOURCE_V6);
        assert_eq!(&key[1..5], &11u32.to_be_bytes());
        assert_eq!(&key[5..], &[0; 19]);
    }
}
