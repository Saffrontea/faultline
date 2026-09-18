//! User-facing experiment model and its compilation into a Linux-neutral plan.
//!
//! Workloads and convenient destination names stop at this boundary. The
//! privileged agent consumes only [`AttachSpec`] and concrete `RuleSpec`s.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, ToSocketAddrs},
};

use faultline_common::{LOSS_ALGORITHM_HASH, MAX_RULES, PROTOCOL_TCP, PROTOCOL_UDP};
use faultline_protocol::{RuleSpec, TIMELINE_VERSION, Timeline, TimelineEvent, TimelineKind};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const EXPERIMENT_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentSpec {
    pub version: u32,
    pub name: String,
    pub source: WorkloadSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<DestinationSpec>,
    /// Named L3/L4 selectors. This is the full form used when an experiment
    /// needs more than one communication relation or a source CIDR.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<CommunicationSelector>,
    pub profile: FaultProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic: Option<TrafficSpec>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrafficSpec {
    Http {
        url: String,
        #[serde(default = "default_traffic_interval_ms")]
        interval_ms: u64,
        #[serde(default = "default_traffic_timeout_ms")]
        timeout_ms: u64,
    },
    Command {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default = "default_traffic_interval_ms")]
        interval_ms: u64,
    },
}

const fn default_traffic_interval_ms() -> u64 {
    1_000
}

const fn default_traffic_timeout_ms() -> u64 {
    2_000
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "runtime", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkloadSpec {
    Local {
        interface: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        process: Option<LocalProcess>,
    },
    Docker {
        container: String,
        #[serde(default = "default_interface")]
        interface: String,
        #[serde(default)]
        lifecycle: WorkloadLifecycle,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provision: Option<DockerProvision>,
    },
    Lxc {
        container: String,
        #[serde(default = "default_interface")]
        interface: String,
        #[serde(default)]
        lifecycle: WorkloadLifecycle,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provision: Option<LxcProvision>,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalProcess {
    pub program: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DockerProvision {
    pub image: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,
    /// Remove a container created by this experiment during cleanup. This does
    /// not affect a same-named container that existed before the experiment.
    #[serde(default = "default_true")]
    pub remove_on_exit: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LxcProvision {
    pub distribution: String,
    pub release: String,
    pub architecture: String,
    #[serde(default = "default_true")]
    pub remove_on_exit: bool,
}

const fn default_true() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadLifecycle {
    /// Require an already-running workload and never alter its lifecycle.
    #[default]
    Existing,
    /// Start a stopped workload and stop it after the owning experiment. A
    /// workload that was already running remains running.
    Session,
}

fn default_interface() -> String {
    "auto".to_owned()
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationSpec {
    /// An IPv4/IPv6 address, CIDR, or hostname. Hostnames are merely an input
    /// convenience and are snapshotted into L3 host routes before execution.
    pub selector: String,
    #[serde(default)]
    pub protocol: NetworkProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default)]
    pub resolution: ResolutionStrategy,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommunicationSelector {
    pub name: String,
    /// Optional source address/CIDR/hostname. An omitted source is a catch-all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(flatten)]
    pub destination: DestinationSpec,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStrategy {
    #[default]
    Snapshot,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProtocol {
    #[default]
    Any,
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FaultProfile {
    pub duration_ms: u64,
    pub events: Vec<FaultEvent>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FaultEvent {
    pub at_ms: u64,
    #[serde(flatten)]
    pub fault: FaultSpec,
    /// Complete named fault state for experiments using `selectors`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub faults: BTreeMap<String, FaultSpec>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FaultSpec {
    pub drop_permyriad: u32,
    pub duplicate_permyriad: u32,
    pub reorder_permyriad: u32,
    pub delay_ns: u64,
    pub jitter_ns: u64,
    pub bandwidth_bps: u64,
    pub seed: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ResolvedExperiment {
    pub version: u32,
    pub name: String,
    pub attach: AttachSpec,
    /// Kept for readers of version-1 single-selector artifacts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<ResolvedDestination>,
    pub selectors: Vec<ResolvedSelector>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selection_notes: Vec<String>,
    pub timeline: Timeline,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<ExecutionEnvironment>,
    /// Snapshot after the agent has attached and installed any required qdisc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_environment: Option<ExecutionEnvironment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExperimentExecution>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traffic: Option<TrafficSpec>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ExperimentExecution {
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
    pub applied_events: Vec<AppliedEventRecord>,
    /// Time-series samples pair the accepted configuration with the resulting
    /// dataplane counters. `delayed` means an EDT was scheduled; it is not an
    /// end-to-end latency measurement.
    pub rule_observations: Vec<RuleObservation>,
    pub selection_diagnostics: Vec<SelectionDiagnosticObservation>,
    /// Last cumulative dataplane report for each concrete rule. A rule with no
    /// entry was accepted but never observed in a stats report.
    pub final_rule_stats: BTreeMap<u32, Value>,
    /// Global selection misses are kept separate because no rule has been
    /// selected at that point in the dataplane.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_diagnostics: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RuleObservation {
    pub observed_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_event_index: Option<usize>,
    /// True for the first report after a ruleset swap. Its interval delta may
    /// include packets from the preceding generation.
    pub interval_may_span_rule_change: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configured_rule: Option<RuleSpec>,
    pub stats: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SelectionDiagnosticObservation {
    pub observed_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_event_index: Option<usize>,
    pub diagnostics: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AppliedEventRecord {
    pub event_index: usize,
    pub scheduled_at_ms: u64,
    pub requested_at_ms: u64,
    pub applied_at_ms: u64,
    pub rule_ids: Vec<u32>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ExecutionEnvironment {
    pub captured_at_unix_ms: u64,
    pub target: String,
    pub interface: String,
    pub faultline_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_release: Option<String>,
    pub offloads: BTreeMap<String, bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qdiscs: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "runtime", rename_all = "snake_case")]
pub enum AttachSpec {
    Local {
        interface: String,
        process: Option<LocalProcess>,
    },
    Docker {
        container: String,
        interface: String,
        lifecycle: WorkloadLifecycle,
        provision: Option<DockerProvision>,
    },
    Lxc {
        container: String,
        interface: String,
        lifecycle: WorkloadLifecycle,
        provision: Option<LxcProvision>,
    },
}

impl AttachSpec {
    pub fn target_uri(&self) -> String {
        match self {
            Self::Local { interface, .. } => format!("local://{interface}"),
            Self::Docker {
                container,
                interface,
                ..
            } => format!("docker://{container}/{interface}"),
            Self::Lxc {
                container,
                interface,
                ..
            } => format!("lxc://{container}/{interface}"),
        }
    }

    fn validate_concrete(&self) -> Result<(), String> {
        let interface = match self {
            Self::Local { interface, .. }
            | Self::Docker { interface, .. }
            | Self::Lxc { interface, .. } => interface,
        };
        validate_non_empty(interface, "resolved interface must not be empty")?;
        if interface == "auto" {
            return Err("resolved interface must be concrete, not auto".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ResolvedDestination {
    pub selector: String,
    pub networks: Vec<IpNet>,
    pub protocol: NetworkProtocol,
    pub port: Option<u16>,
    pub resolution: ResolutionStrategy,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ResolvedSelector {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_selector: Option<String>,
    pub source_networks: Vec<IpNet>,
    pub destination: ResolvedDestination,
    /// Concrete rule bindings let a stats `rule_id` be traced back to the
    /// authored communication selector.
    pub rules: Vec<ResolvedRuleBinding>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ResolvedRuleBinding {
    pub rule_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<IpNet>,
    pub destination: IpNet,
    pub protocol: NetworkProtocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Dataplane selection is destination LPM first, then source LPM. Protocol
    /// and port are filters on the selected source rule, not tie-breakers.
    pub precedence: String,
}

pub trait DestinationResolver {
    fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, String>;
}

pub struct SystemResolver;

impl DestinationResolver for SystemResolver {
    fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, String> {
        (hostname, 0)
            .to_socket_addrs()
            .map(|addresses| addresses.map(|address| address.ip()).collect())
            .map_err(|error| format!("could not resolve {hostname}: {error}"))
    }
}

impl ResolvedExperiment {
    /// Validate a frozen plan before replaying it without authoring-time DNS
    /// resolution or workload provisioning.
    pub fn validate_for_rerun(&self) -> Result<(), String> {
        if self.version != EXPERIMENT_VERSION {
            return Err(format!("unsupported experiment version {}", self.version));
        }
        self.attach.validate_concrete()?;
        self.timeline.validate()?;
        if self.timeline.target.as_deref() != Some(self.attach.target_uri().as_str()) {
            return Err("resolved timeline target does not match its attach point".to_owned());
        }
        if self.selectors.is_empty() {
            return Err("resolved experiment has no selectors".to_owned());
        }
        let bindings = self
            .selectors
            .iter()
            .flat_map(|selector| selector.rules.iter())
            .map(|binding| (binding.rule_id, binding))
            .collect::<BTreeMap<_, _>>();
        let binding_count = self
            .selectors
            .iter()
            .map(|selector| selector.rules.len())
            .sum::<usize>();
        if bindings.len() != binding_count {
            return Err("resolved selector bindings repeat a rule id".to_owned());
        }
        for (event_index, event) in self.timeline.events.iter().enumerate() {
            if event.rules.len() != bindings.len() {
                return Err(format!(
                    "resolved event {event_index} does not contain the complete selector ruleset"
                ));
            }
            for rule in &event.rules {
                let binding = bindings.get(&rule.id).ok_or_else(|| {
                    format!(
                        "resolved event {event_index} has unknown rule id {}",
                        rule.id
                    )
                })?;
                if rule.source != binding.source
                    || rule.destination != binding.destination
                    || rule.protocol != binding.protocol.number()
                    || rule.destination_port != binding.port.unwrap_or(0)
                {
                    return Err(format!(
                        "resolved event {event_index} rule {} does not match its selector binding",
                        rule.id
                    ));
                }
            }
        }
        Ok(())
    }
}

impl ExperimentSpec {
    pub fn compile(
        &self,
        resolver: &impl DestinationResolver,
        attach: AttachSpec,
    ) -> Result<ResolvedExperiment, String> {
        self.validate()?;
        attach.validate_concrete()?;
        self.source.validate_attach(&attach)?;
        let authored_selectors = self.authored_selectors();
        let selectors = compile_selectors(&authored_selectors, resolver)?;
        let selection_notes = validate_resolved_bindings(&selectors)?;
        let timeline = Timeline {
            version: TIMELINE_VERSION,
            kind: TimelineKind::Profile,
            name: Some(self.name.clone()),
            target: Some(attach.target_uri()),
            duration_ms: self.profile.duration_ms,
            events: compile_events(&self.profile.events, &selectors),
        };
        timeline.validate()?;
        Ok(ResolvedExperiment {
            version: self.version,
            name: self.name.clone(),
            attach,
            destination: self
                .destination
                .as_ref()
                .map(|_| selectors[0].destination.clone()),
            selectors,
            selection_notes,
            timeline,
            environment: None,
            effective_environment: None,
            execution: None,
            execution_error: None,
            traffic: self.traffic.clone(),
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != EXPERIMENT_VERSION {
            return Err(format!("unsupported experiment version {}", self.version));
        }
        validate_non_empty(&self.name, "experiment name must not be empty")?;
        self.source.validate()?;
        if self.destination.is_some() && !self.selectors.is_empty() {
            return Err("use either destination or selectors, not both".to_owned());
        }
        let selectors = self.authored_selectors();
        if selectors.is_empty() {
            return Err("experiment requires destination or selectors".to_owned());
        }
        selectors.iter().try_for_each(|selector| {
            validate_non_empty(&selector.name, "selector name must not be empty")?;
            selector.destination.validate()?;
            (!selector.source.as_deref().is_some_and(str::is_empty))
                .then_some(())
                .ok_or_else(|| format!("selector {} has an empty source", selector.name))
        })?;
        let names = selectors
            .iter()
            .map(|selector| selector.name.as_str())
            .collect::<BTreeSet<_>>();
        if names.len() != selectors.len() {
            return Err("selector names must be unique".to_owned());
        }
        self.profile.validate(&names, !self.selectors.is_empty())?;
        validate_optional(self.traffic.as_ref(), TrafficSpec::validate)
    }

    fn authored_selectors(&self) -> Vec<CommunicationSelector> {
        if !self.selectors.is_empty() {
            return self.selectors.clone();
        }
        self.destination
            .clone()
            .map(|destination| CommunicationSelector {
                name: "default".to_owned(),
                source: None,
                destination,
            })
            .into_iter()
            .collect()
    }
}

struct ResolvedSelectorInput {
    authored: CommunicationSelector,
    source_networks: Vec<IpNet>,
    destination_networks: Vec<IpNet>,
    bindings: Vec<(Option<IpNet>, IpNet)>,
}

fn compile_selectors(
    authored: &[CommunicationSelector],
    resolver: &impl DestinationResolver,
) -> Result<Vec<ResolvedSelector>, String> {
    authored
        .iter()
        .map(|selector| resolve_selector_input(selector, resolver))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .scan(0u32, |next_rule_id, input| {
            let first_rule_id = *next_rule_id;
            let count = u32::try_from(input.bindings.len())
                .map_err(|_| "experiment produces too many rules".to_owned());
            let result = count.and_then(|count| {
                *next_rule_id = next_rule_id
                    .checked_add(count)
                    .ok_or_else(|| "experiment produces too many rules".to_owned())?;
                Ok(input.into_resolved(first_rule_id))
            });
            Some(result)
        })
        .collect()
}

fn resolve_selector_input(
    selector: &CommunicationSelector,
    resolver: &impl DestinationResolver,
) -> Result<ResolvedSelectorInput, String> {
    let destination_networks = resolve_selector(&selector.destination.selector, resolver)?;
    let source_networks = selector
        .source
        .as_deref()
        .map(|source| resolve_selector(source, resolver))
        .transpose()?
        .unwrap_or_default();
    let bindings = destination_networks
        .iter()
        .flat_map(|destination| {
            compatible_sources(selector, &source_networks, *destination)
                .into_iter()
                .map(|source| (source, *destination))
        })
        .collect::<Vec<_>>();
    if bindings.is_empty() {
        return Err(format!(
            "selector {} has no source and destination addresses in the same family",
            selector.name
        ));
    }
    Ok(ResolvedSelectorInput {
        authored: selector.clone(),
        source_networks,
        destination_networks,
        bindings,
    })
}

fn compatible_sources(
    selector: &CommunicationSelector,
    sources: &[IpNet],
    destination: IpNet,
) -> Vec<Option<IpNet>> {
    selector.source.as_ref().map_or_else(
        || vec![None],
        |_| {
            sources
                .iter()
                .copied()
                .filter(|source| source.addr().is_ipv4() == destination.addr().is_ipv4())
                .map(Some)
                .collect()
        },
    )
}

impl ResolvedSelectorInput {
    fn into_resolved(self, first_rule_id: u32) -> ResolvedSelector {
        let rules = self
            .bindings
            .into_iter()
            .enumerate()
            .map(|(offset, (source, destination))| ResolvedRuleBinding {
                rule_id: first_rule_id + offset as u32,
                source,
                destination,
                protocol: self.authored.destination.protocol,
                port: self.authored.destination.port,
                precedence: format!(
                    "destination /{} then source /{}; protocol and port filter the selected rule",
                    destination.prefix_len(),
                    source_prefix_len(source)
                ),
            })
            .collect();
        ResolvedSelector {
            name: self.authored.name,
            source_selector: self.authored.source,
            source_networks: self.source_networks,
            destination: ResolvedDestination {
                selector: self.authored.destination.selector,
                networks: self.destination_networks,
                protocol: self.authored.destination.protocol,
                port: self.authored.destination.port,
                resolution: self.authored.destination.resolution,
            },
            rules,
        }
    }
}

fn compile_events(events: &[FaultEvent], selectors: &[ResolvedSelector]) -> Vec<TimelineEvent> {
    events
        .iter()
        .map(|event| TimelineEvent {
            at_ms: event.at_ms,
            rules: selectors
                .iter()
                .flat_map(|selector| {
                    let fault = event.faults.get(&selector.name).unwrap_or(&event.fault);
                    selector.rules.iter().map(move |binding| {
                        fault.rule_for(
                            binding.rule_id,
                            binding.source,
                            binding.destination,
                            binding.protocol.number(),
                            binding.port.unwrap_or(0),
                        )
                    })
                })
                .collect(),
        })
        .collect()
}

type NamedBinding<'a> = (&'a str, &'a ResolvedRuleBinding);

fn validate_resolved_bindings(selectors: &[ResolvedSelector]) -> Result<Vec<String>, String> {
    let bindings = selectors
        .iter()
        .flat_map(|selector| {
            selector
                .rules
                .iter()
                .map(|rule| (selector.name.as_str(), rule))
        })
        .collect::<Vec<_>>();
    if bindings.len() > MAX_RULES as usize {
        return Err(format!(
            "experiment produces more than {MAX_RULES} concrete rules"
        ));
    }
    if let Some(((left_name, _), (right_name, _))) =
        binding_pairs(&bindings).find(|((_, left), (_, right))| {
            left.destination == right.destination && same_source_key(left.source, right.source)
        })
    {
        return Err(format!(
            "selectors {left_name} and {right_name} resolve to the same destination/source prefix; protocol and port do not participate in dataplane precedence"
        ));
    }
    Ok(binding_pairs(&bindings)
        .filter_map(precedence_note)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn binding_pairs<'a>(
    bindings: &'a [NamedBinding<'a>],
) -> impl Iterator<Item = (NamedBinding<'a>, NamedBinding<'a>)> + 'a {
    bindings
        .iter()
        .enumerate()
        .flat_map(|(index, right)| bindings[..index].iter().map(move |left| (*left, *right)))
}

fn precedence_note(
    ((left_name, left), (right_name, right)): (NamedBinding<'_>, NamedBinding<'_>),
) -> Option<String> {
    match (
        networks_overlap(left.destination, right.destination),
        left.destination == right.destination,
        sources_overlap(left.source, right.source),
    ) {
        (false, _, _) | (true, true, false) => None,
        (true, false, _) => {
            let (winner_name, winner) = [(left_name, left), (right_name, right)]
                .into_iter()
                .max_by_key(|(_, binding)| binding.destination.prefix_len())?;
            Some(format!(
                "selector {winner_name} destination {} wins inside its prefix before source selection; a protocol/port miss does not fall back to the less-specific destination",
                winner.destination
            ))
        }
        (true, true, true) => {
            let (winner_name, winner) = [(left_name, left), (right_name, right)]
                .into_iter()
                .max_by_key(|(_, binding)| source_prefix_len(binding.source))?;
            Some(format!(
                "selector {winner_name} source {} wins for destination {}; a protocol/port miss does not fall back to the less-specific source",
                winner
                    .source
                    .map_or_else(|| "catch-all".to_owned(), |source| source.to_string()),
                winner.destination
            ))
        }
    }
}

fn same_source_key(left: Option<IpNet>, right: Option<IpNet>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => left == right,
        (None, Some(network)) | (Some(network), None) => network.prefix_len() == 0,
    }
}

fn networks_overlap(left: IpNet, right: IpNet) -> bool {
    left.addr().is_ipv4() == right.addr().is_ipv4()
        && (left.contains(&right.addr()) || right.contains(&left.addr()))
}

fn sources_overlap(left: Option<IpNet>, right: Option<IpNet>) -> bool {
    match (left, right) {
        (None, _) | (_, None) => true,
        (Some(left), Some(right)) => networks_overlap(left, right),
    }
}

fn source_prefix_len(source: Option<IpNet>) -> u8 {
    source.map_or(0, |network| network.prefix_len())
}

impl DestinationSpec {
    fn validate(&self) -> Result<(), String> {
        validate_non_empty(&self.selector, "destination selector must not be empty")?;
        if self.port == Some(0) {
            return Err("destination port must be non-zero when present".to_owned());
        }
        if self.port.is_some() && self.protocol == NetworkProtocol::Any {
            return Err("destination port requires tcp or udp".to_owned());
        }
        Ok(())
    }
}

impl NetworkProtocol {
    const fn number(self) -> u8 {
        match self {
            Self::Any => 0,
            Self::Tcp => PROTOCOL_TCP,
            Self::Udp => PROTOCOL_UDP,
        }
    }
}

impl FaultProfile {
    fn validate(&self, selector_names: &BTreeSet<&str>, named: bool) -> Result<(), String> {
        if self.events.first().is_none_or(|event| event.at_ms != 0) {
            return Err("profile must contain an event at 0ms".to_owned());
        }

        self.events
            .iter()
            .enumerate()
            .try_fold(0, |previous, (index, event)| {
                event.validate_after(index, previous, self.duration_ms, selector_names, named)
            })?;
        Ok(())
    }
}

impl FaultEvent {
    fn validate_after(
        &self,
        index: usize,
        previous_at_ms: u64,
        duration_ms: u64,
        selector_names: &BTreeSet<&str>,
        named: bool,
    ) -> Result<u64, String> {
        if self.at_ms < previous_at_ms {
            return Err(format!("profile event {index} is out of order"));
        }
        if self.at_ms > duration_ms {
            return Err(format!("profile event {index} exceeds duration"));
        }
        self.fault.validate(index)?;
        if named {
            let event_names = self
                .faults
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            if &event_names != selector_names {
                return Err(format!(
                    "profile event {index} faults must name every selector exactly once"
                ));
            }
        } else if !self.faults.is_empty() {
            return Err(format!(
                "profile event {index} uses faults without selectors"
            ));
        }
        self.faults
            .values()
            .try_for_each(|fault| fault.validate(index))?;
        Ok(self.at_ms)
    }
}

impl FaultSpec {
    fn validate(&self, event_index: usize) -> Result<(), String> {
        [
            ("loss", self.drop_permyriad),
            ("duplication", self.duplicate_permyriad),
            ("reordering", self.reorder_permyriad),
        ]
        .into_iter()
        .try_for_each(|(name, value)| {
            if value > 10_000 {
                Err(format!("profile event {event_index} has {name} above 100%"))
            } else {
                Ok(())
            }
        })
    }

    fn rule_for(
        &self,
        id: u32,
        source: Option<IpNet>,
        destination: IpNet,
        protocol: u8,
        destination_port: u16,
    ) -> RuleSpec {
        RuleSpec {
            id,
            source,
            destination,
            protocol,
            loss_algorithm: LOSS_ALGORITHM_HASH,
            destination_port,
            drop_permyriad: self.drop_permyriad,
            ge_enter_permyriad: 0,
            ge_recover_permyriad: 0,
            ge_good_loss_permyriad: 0,
            ge_bad_loss_permyriad: 0,
            ge_idle_reset_secs: 0,
            duplicate_permyriad: self.duplicate_permyriad,
            reorder_permyriad: self.reorder_permyriad,
            delay_ns: self.delay_ns,
            jitter_ns: self.jitter_ns,
            bandwidth_bps: self.bandwidth_bps,
            seed: self.seed.max(1),
        }
    }
}

impl TrafficSpec {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Http {
                url,
                interval_ms,
                timeout_ms,
            } => {
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    return Err("HTTP traffic URL must begin with http:// or https://".to_owned());
                }
                [*interval_ms, *timeout_ms]
                    .into_iter()
                    .try_for_each(|value| {
                        validate_non_zero(
                            value,
                            "HTTP traffic interval and timeout must be non-zero",
                        )
                    })
            }
            Self::Command {
                program,
                interval_ms,
                ..
            } => {
                validate_non_empty(program, "traffic command program must not be empty")?;
                validate_non_zero(*interval_ms, "traffic command interval must be non-zero")
            }
        }
    }

    pub const fn interval_ms(&self) -> u64 {
        match self {
            Self::Http { interval_ms, .. } | Self::Command { interval_ms, .. } => *interval_ms,
        }
    }
}

impl WorkloadSpec {
    pub fn target_uri(&self) -> String {
        match self {
            Self::Local { interface, .. } => format!("local://{interface}"),
            Self::Docker {
                container,
                interface,
                ..
            } => format!("docker://{container}/{interface}"),
            Self::Lxc {
                container,
                interface,
                ..
            } => format!("lxc://{container}/{interface}"),
        }
    }

    pub fn resolved_attach(&self, resolved_interface: String) -> Result<AttachSpec, String> {
        validate_non_empty(&resolved_interface, "resolved interface must not be empty")?;
        if resolved_interface == "auto" {
            return Err("resolved interface must be concrete, not auto".to_owned());
        }
        let requested = match self {
            Self::Local { interface, .. }
            | Self::Docker { interface, .. }
            | Self::Lxc { interface, .. } => interface,
        };
        if requested != "auto" && requested != &resolved_interface {
            return Err(format!(
                "resolved interface {resolved_interface} does not match requested interface {requested}"
            ));
        }
        Ok(match self {
            Self::Local { process, .. } => AttachSpec::Local {
                interface: resolved_interface,
                process: process.clone(),
            },
            Self::Docker {
                container,
                lifecycle,
                provision,
                ..
            } => AttachSpec::Docker {
                container: container.clone(),
                interface: resolved_interface,
                lifecycle: *lifecycle,
                provision: provision.clone(),
            },
            Self::Lxc {
                container,
                lifecycle,
                provision,
                ..
            } => AttachSpec::Lxc {
                container: container.clone(),
                interface: resolved_interface,
                lifecycle: *lifecycle,
                provision: provision.clone(),
            },
        })
    }

    fn validate_attach(&self, attach: &AttachSpec) -> Result<(), String> {
        let interface = match attach {
            AttachSpec::Local { interface, .. }
            | AttachSpec::Docker { interface, .. }
            | AttachSpec::Lxc { interface, .. } => interface.clone(),
        };
        if self.resolved_attach(interface)? != *attach {
            return Err("resolved attach does not match the experiment source".to_owned());
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        match self {
            Self::Local { interface, process } => {
                validate_non_empty(interface, "source interface must not be empty")?;
                if interface == "auto" {
                    return Err("local source requires an explicit interface".to_owned());
                }
                validate_optional(process.as_ref(), LocalProcess::validate)
            }
            Self::Docker {
                container,
                interface,
                provision,
                ..
            } => {
                validate_container(container, interface)?;
                validate_optional(provision.as_ref(), DockerProvision::validate)
            }
            Self::Lxc {
                container,
                interface,
                provision,
                ..
            } => {
                validate_container(container, interface)?;
                validate_optional(provision.as_ref(), LxcProvision::validate)
            }
        }
    }
}

impl LocalProcess {
    fn validate(&self) -> Result<(), String> {
        validate_non_empty(&self.program, "local process program must not be empty")
    }
}

impl DockerProvision {
    fn validate(&self) -> Result<(), String> {
        validate_non_empty(&self.image, "Docker provision image must not be empty")
    }
}

impl LxcProvision {
    fn validate(&self) -> Result<(), String> {
        [&self.distribution, &self.release, &self.architecture]
            .into_iter()
            .try_for_each(|value| {
                validate_non_empty(
                    value,
                    "LXC provision distribution, release, and architecture are required",
                )
            })
    }
}

fn validate_container(container: &str, interface: &str) -> Result<(), String> {
    validate_non_empty(container, "source container must not be empty")?;
    validate_non_empty(interface, "source interface must not be empty")
}

fn validate_non_empty(value: &str, message: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(message.to_owned())
    } else {
        Ok(())
    }
}

fn validate_non_zero(value: u64, message: &str) -> Result<(), String> {
    if value == 0 {
        Err(message.to_owned())
    } else {
        Ok(())
    }
}

fn validate_optional<T>(
    value: Option<&T>,
    validate: impl FnOnce(&T) -> Result<(), String>,
) -> Result<(), String> {
    value.map(validate).transpose().map(drop)
}

fn resolve_selector(
    selector: &str,
    resolver: &impl DestinationResolver,
) -> Result<Vec<IpNet>, String> {
    if let Ok(network) = selector.parse::<IpNet>() {
        return Ok(vec![network]);
    }
    if let Ok(address) = selector.parse::<IpAddr>() {
        return Ok(vec![IpNet::from(address)]);
    }
    let networks = resolver
        .resolve(selector)?
        .into_iter()
        .map(IpNet::from)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if networks.is_empty() {
        return Err(format!("destination {selector} resolved to no addresses"));
    }
    Ok(networks)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Resolver;
    impl DestinationResolver for Resolver {
        fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, String> {
            assert_eq!(hostname, "api.example.test");
            Ok(vec![
                "2001:db8::4".parse().unwrap(),
                "192.0.2.4".parse().unwrap(),
                "192.0.2.4".parse().unwrap(),
            ])
        }
    }

    const MANIFEST: &str = r#"
version: 1
name: api outage
source:
  runtime: docker
  container: web-01
destination:
  selector: api.example.test
  protocol: tcp
  port: 443
profile:
  duration_ms: 1000
  events:
    - at_ms: 0
      drop_permyriad: 0
    - at_ms: 250
      drop_permyriad: 10000
    - at_ms: 750
      drop_permyriad: 0
extensions:
  ui.color: cyan
"#;

    fn compile(spec: &ExperimentSpec) -> ResolvedExperiment {
        let attach = spec.source.resolved_attach("eth0".into()).unwrap();
        spec.compile(&Resolver, attach).unwrap()
    }

    #[test]
    fn manifest_round_trips_without_losing_extensions() {
        let spec: ExperimentSpec = yaml_serde::from_str(MANIFEST).unwrap();
        spec.validate().unwrap();
        let encoded = yaml_serde::to_string(&spec).unwrap();
        let decoded: ExperimentSpec = yaml_serde::from_str(&encoded).unwrap();
        assert_eq!(decoded, spec);
        assert_eq!(decoded.source.target_uri(), "docker://web-01/auto");
        assert_eq!(decoded.extensions["ui.color"], "cyan");
    }

    #[test]
    fn hostname_is_snapshotted_to_l3_rules_and_recorded() {
        let spec: ExperimentSpec = yaml_serde::from_str(MANIFEST).unwrap();
        let plan = compile(&spec);
        assert_eq!(
            plan.destination.unwrap().networks,
            vec![
                "192.0.2.4/32".parse().unwrap(),
                "2001:db8::4/128".parse().unwrap()
            ]
        );
        assert_eq!(plan.timeline.events.len(), 3);
        assert_eq!(plan.timeline.events[1].rules.len(), 2);
        assert!(
            plan.timeline.events[1]
                .rules
                .iter()
                .all(|rule| rule.drop_permyriad == 10_000 && rule.destination_port == 443)
        );
    }

    #[test]
    fn resolved_artifact_round_trips_and_rejects_selector_drift() {
        let spec: ExperimentSpec = yaml_serde::from_str(MANIFEST).unwrap();
        let plan = compile(&spec);
        let encoded = serde_json::to_vec(&plan).unwrap();
        let mut decoded: ResolvedExperiment = serde_json::from_slice(&encoded).unwrap();
        decoded.validate_for_rerun().unwrap();
        decoded.timeline.events[0].rules[0].destination = "198.51.100.1/32".parse().unwrap();
        assert!(
            decoded
                .validate_for_rerun()
                .unwrap_err()
                .contains("does not match its selector binding")
        );
    }

    #[test]
    fn cidr_does_not_invoke_dns_and_port_requires_transport() {
        let mut spec: ExperimentSpec = yaml_serde::from_str(MANIFEST).unwrap();
        spec.destination.as_mut().unwrap().selector = "10.0.0.0/8".to_owned();
        spec.destination.as_mut().unwrap().protocol = NetworkProtocol::Any;
        assert!(spec.validate().unwrap_err().contains("requires tcp or udp"));
        spec.destination.as_mut().unwrap().port = None;
        assert_eq!(
            compile(&spec).destination.unwrap().networks,
            vec!["10.0.0.0/8".parse().unwrap()]
        );
    }

    #[test]
    fn all_source_runtimes_compile_to_transport_uris() {
        assert_eq!(
            WorkloadSpec::Local {
                interface: "eth9".into(),
                process: None,
            }
            .target_uri(),
            "local://eth9"
        );
        assert_eq!(
            WorkloadSpec::Lxc {
                container: "db".into(),
                interface: "net1".into(),
                lifecycle: WorkloadLifecycle::Existing,
                provision: None,
            }
            .target_uri(),
            "lxc://db/net1"
        );
    }

    #[test]
    fn concrete_attach_is_injected_into_the_effective_target() {
        let spec: ExperimentSpec = yaml_serde::from_str(MANIFEST).unwrap();
        let attach = spec.source.resolved_attach("ens5".into()).unwrap();
        let plan = spec.compile(&Resolver, attach).unwrap();
        assert_eq!(plan.attach.target_uri(), "docker://web-01/ens5");
        assert_eq!(
            plan.timeline.target.as_deref(),
            Some("docker://web-01/ens5")
        );
    }

    #[test]
    fn auto_cannot_enter_a_resolved_experiment() {
        let spec: ExperimentSpec = yaml_serde::from_str(MANIFEST).unwrap();
        assert!(spec.source.resolved_attach("auto".into()).is_err());
    }

    #[test]
    fn traffic_is_validated_and_preserved_in_the_effective_plan() {
        let mut spec: ExperimentSpec = yaml_serde::from_str(MANIFEST).unwrap();
        spec.traffic = Some(TrafficSpec::Http {
            url: "https://api.example.test/health".into(),
            interval_ms: 250,
            timeout_ms: 1_000,
        });
        assert_eq!(compile(&spec).traffic, spec.traffic);
        spec.traffic = Some(TrafficSpec::Command {
            program: String::new(),
            args: Vec::new(),
            interval_ms: 1_000,
        });
        assert!(spec.validate().unwrap_err().contains("program"));
    }

    #[test]
    fn named_selectors_compile_source_and_destination_relations_to_stable_rule_ids() {
        let spec: ExperimentSpec = yaml_serde::from_str(
            r#"
version: 1
name: isolate one relation
source:
  runtime: local
  interface: eth0
selectors:
  - name: a_to_b
    source: 10.0.0.10/32
    selector: 10.0.1.20/32
    protocol: tcp
    port: 443
  - name: a_to_c
    source: 10.0.0.10/32
    selector: 10.0.2.30/32
    protocol: tcp
    port: 443
profile:
  duration_ms: 1000
  events:
    - at_ms: 0
      faults:
        a_to_b: {}
        a_to_c: {}
    - at_ms: 250
      faults:
        a_to_b:
          drop_permyriad: 10000
          seed: 7
        a_to_c: {}
"#,
        )
        .unwrap();
        let plan = spec
            .compile(
                &Resolver,
                spec.source.resolved_attach("eth0".into()).unwrap(),
            )
            .unwrap();
        assert!(plan.destination.is_none());
        assert_eq!(plan.selectors.len(), 2);
        assert_eq!(plan.selectors[0].rules[0].rule_id, 0);
        assert_eq!(plan.selectors[1].rules[0].rule_id, 1);
        assert_eq!(plan.timeline.events[1].rules[0].drop_permyriad, 10_000);
        assert_eq!(plan.timeline.events[1].rules[1].drop_permyriad, 0);
        assert_eq!(
            plan.timeline.events[1].rules[0].source,
            Some("10.0.0.10/32".parse().unwrap())
        );
        assert!(
            plan.selectors[0].rules[0]
                .precedence
                .contains("destination /32")
        );
    }

    #[test]
    fn selectors_that_collapse_to_the_same_dataplane_key_are_rejected() {
        let mut spec: ExperimentSpec = yaml_serde::from_str(MANIFEST).unwrap();
        let destination = spec.destination.take().unwrap();
        spec.selectors = vec![
            CommunicationSelector {
                name: "https".into(),
                source: None,
                destination: destination.clone(),
            },
            CommunicationSelector {
                name: "dns".into(),
                // Explicit /0 and an omitted source compile to the same LPM
                // key and must not be treated as distinct selectors.
                source: Some("0.0.0.0/0".into()),
                destination: DestinationSpec {
                    protocol: NetworkProtocol::Udp,
                    port: Some(53),
                    ..destination
                },
            },
        ];
        for event in &mut spec.profile.events {
            event.faults.insert("https".into(), event.fault.clone());
            event.faults.insert("dns".into(), FaultSpec::default());
        }
        let error = spec
            .compile(
                &Resolver,
                spec.source.resolved_attach("eth0".into()).unwrap(),
            )
            .unwrap_err();
        assert!(error.contains("protocol and port do not participate"));
    }

    #[test]
    fn overlapping_prefix_precedence_is_explained_in_the_resolved_plan() {
        let spec: ExperimentSpec = yaml_serde::from_str(
            r#"
version: 1
name: source precedence
source: { runtime: local, interface: eth0 }
selectors:
  - { name: catch_all, selector: 192.0.2.0/24 }
  - { name: client_a, source: 10.0.0.7/32, selector: 192.0.2.0/24, protocol: tcp, port: 443 }
profile:
  duration_ms: 1
  events:
    - at_ms: 0
      faults: { catch_all: {}, client_a: { drop_permyriad: 10000 } }
"#,
        )
        .unwrap();
        let plan = spec
            .compile(
                &Resolver,
                spec.source.resolved_attach("eth0".into()).unwrap(),
            )
            .unwrap();
        assert_eq!(plan.selection_notes.len(), 1);
        assert!(plan.selection_notes[0].contains("client_a source 10.0.0.7/32 wins"));
        assert!(plan.selection_notes[0].contains("does not fall back"));
    }
}
