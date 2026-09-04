//! User-facing experiment model and its compilation into a Linux-neutral plan.
//!
//! Workloads and convenient destination names stop at this boundary. The
//! privileged agent consumes only [`AttachSpec`] and concrete `RuleSpec`s.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, ToSocketAddrs},
};

use faultline_common::{LOSS_ALGORITHM_HASH, PROTOCOL_TCP, PROTOCOL_UDP};
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
    pub destination: DestinationSpec,
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

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ResolvedExperiment {
    pub version: u32,
    pub name: String,
    pub attach: AttachSpec,
    pub destination: ResolvedDestination,
    pub timeline: Timeline,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traffic: Option<TrafficSpec>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
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

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ResolvedDestination {
    pub selector: String,
    pub networks: Vec<IpNet>,
    pub protocol: NetworkProtocol,
    pub port: Option<u16>,
    pub resolution: ResolutionStrategy,
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

impl ExperimentSpec {
    pub fn compile(
        &self,
        resolver: &impl DestinationResolver,
        attach: AttachSpec,
    ) -> Result<ResolvedExperiment, String> {
        self.validate()?;
        attach.validate_concrete()?;
        self.source.validate_attach(&attach)?;
        let networks = resolve_selector(&self.destination.selector, resolver)?;
        let protocol = self.destination.protocol.number();
        let destination_port = self.destination.port.unwrap_or(0);
        let events = self
            .profile
            .events
            .iter()
            .map(|event| {
                let rules = networks
                    .iter()
                    .enumerate()
                    .map(|(id, destination)| {
                        event
                            .fault
                            .rule_for(id as u32, *destination, protocol, destination_port)
                    })
                    .collect();
                TimelineEvent {
                    at_ms: event.at_ms,
                    rules,
                }
            })
            .collect();
        let timeline = Timeline {
            version: TIMELINE_VERSION,
            kind: TimelineKind::Profile,
            name: Some(self.name.clone()),
            target: Some(attach.target_uri()),
            duration_ms: self.profile.duration_ms,
            events,
        };
        timeline.validate()?;
        Ok(ResolvedExperiment {
            version: self.version,
            name: self.name.clone(),
            attach,
            destination: ResolvedDestination {
                selector: self.destination.selector.clone(),
                networks,
                protocol: self.destination.protocol,
                port: self.destination.port,
                resolution: self.destination.resolution,
            },
            timeline,
            traffic: self.traffic.clone(),
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != EXPERIMENT_VERSION {
            return Err(format!("unsupported experiment version {}", self.version));
        }
        validate_non_empty(&self.name, "experiment name must not be empty")?;
        self.source.validate()?;
        self.destination.validate()?;
        self.profile.validate()?;
        validate_optional(self.traffic.as_ref(), TrafficSpec::validate)
    }
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
    fn validate(&self) -> Result<(), String> {
        if self.events.first().is_none_or(|event| event.at_ms != 0) {
            return Err("profile must contain an event at 0ms".to_owned());
        }

        self.events
            .iter()
            .enumerate()
            .try_fold(0, |previous, (index, event)| {
                event.validate_after(index, previous, self.duration_ms)
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
    ) -> Result<u64, String> {
        if self.at_ms < previous_at_ms {
            return Err(format!("profile event {index} is out of order"));
        }
        if self.at_ms > duration_ms {
            return Err(format!("profile event {index} exceeds duration"));
        }
        self.fault.validate(index)?;
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
        destination: IpNet,
        protocol: u8,
        destination_port: u16,
    ) -> RuleSpec {
        RuleSpec {
            id,
            source: None,
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
            plan.destination.networks,
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
    fn cidr_does_not_invoke_dns_and_port_requires_transport() {
        let mut spec: ExperimentSpec = yaml_serde::from_str(MANIFEST).unwrap();
        spec.destination.selector = "10.0.0.0/8".to_owned();
        spec.destination.protocol = NetworkProtocol::Any;
        assert!(spec.validate().unwrap_err().contains("requires tcp or udp"));
        spec.destination.port = None;
        assert_eq!(
            compile(&spec).destination.networks,
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
}
