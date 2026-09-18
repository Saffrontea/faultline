//! End-to-end preparation of an authored experiment into a concrete plan.

use std::{collections::BTreeMap, process::Command, time::SystemTime};

#[cfg(test)]
use faultline_common::FAULTLINE_AGENT_APPLICATION;
use faultline_runtime::{
    AttachSpec, DestinationResolver, ExecutionEnvironment, ExperimentSpec, ResolvedExperiment,
};

use crate::workload::{self, WorkloadGuard};

#[derive(Clone, Copy, Debug)]
pub struct Tooling<'a> {
    pub agent: &'a str,
    pub engine: Option<&'a str>,
}

/// A concrete execution plan together with ownership of resources started to
/// produce it. Keep this value alive for the entire agent session.
pub struct PreparedExperiment {
    plan: ResolvedExperiment,
    workload: WorkloadGuard,
}

impl PreparedExperiment {
    pub const fn plan(&self) -> &ResolvedExperiment {
        &self.plan
    }

    pub fn into_parts(self) -> (ResolvedExperiment, WorkloadGuard) {
        (self.plan, self.workload)
    }
}

pub fn prepare_experiment(
    spec: &ExperimentSpec,
    resolver: &impl DestinationResolver,
    tooling: Tooling<'_>,
) -> anyhow::Result<PreparedExperiment> {
    spec.validate().map_err(anyhow::Error::msg)?;
    let workload = workload::prepare(&spec.source, tooling.agent, tooling.engine)?;
    let attach = workload::resolve_attach(&spec.source)?;
    let plan = spec.compile(resolver, attach).map_err(anyhow::Error::msg)?;
    let plan = ResolvedExperiment {
        environment: Some(capture_environment(&plan.attach)),
        ..plan
    };
    Ok(PreparedExperiment { plan, workload })
}

pub fn capture_environment(attach: &AttachSpec) -> ExecutionEnvironment {
    let interface = match attach {
        AttachSpec::Local { interface, .. }
        | AttachSpec::Docker { interface, .. }
        | AttachSpec::Lxc { interface, .. } => interface.clone(),
    };
    let kernel = capture_command(attach, "uname", &["-r"])
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("kernel: {error}"));
    let offloads = capture_command(attach, "ethtool", &["-k", &interface])
        .map(|output| parse_offloads(&output))
        .map_err(|error| format!("offloads: {error}"));
    let qdiscs = capture_command(attach, "tc", &["-j", "qdisc", "show", "dev", &interface])
        .and_then(|output| {
            serde_json::from_str(&output).map_err(|error| format!("invalid tc JSON: {error}"))
        })
        .map_err(|error| format!("qdiscs: {error}"));
    let diagnostics = [
        kernel.as_ref().err(),
        offloads.as_ref().err(),
        qdiscs.as_ref().err(),
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect();
    ExecutionEnvironment {
        captured_at_unix_ms: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64,
        target: attach.target_uri(),
        interface,
        faultline_version: env!("CARGO_PKG_VERSION").to_owned(),
        kernel_release: kernel.ok(),
        offloads: offloads.unwrap_or_default(),
        qdiscs: qdiscs.ok(),
        diagnostics,
    }
}

fn capture_command(attach: &AttachSpec, program: &str, args: &[&str]) -> Result<String, String> {
    let mut command = match attach {
        AttachSpec::Local { .. } => Command::new(program),
        AttachSpec::Docker { container, .. } => {
            let mut command = Command::new("docker");
            command.args(["exec", container, program]);
            command
        }
        AttachSpec::Lxc { container, .. } => {
            let mut command = Command::new("lxc-attach");
            command.args(["-n", container, "--", program]);
            command
        }
    };
    let output = command
        .args(args)
        .output()
        .map_err(|error| format!("could not run {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("{program} returned non-UTF-8: {error}"))
}

fn parse_offloads(output: &str) -> BTreeMap<String, bool> {
    output
        .lines()
        .filter_map(|line| {
            let (name, state) = line.trim().split_once(':')?;
            match state.split_whitespace().next()? {
                "on" => Some((name.to_owned(), true)),
                "off" => Some((name.to_owned(), false)),
                _ => None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::IpAddr};

    use faultline_runtime::{
        DestinationSpec, EXPERIMENT_VERSION, FaultEvent, FaultProfile, FaultSpec, NetworkProtocol,
        ResolutionStrategy, WorkloadSpec,
    };

    use super::*;

    struct Resolver;

    impl DestinationResolver for Resolver {
        fn resolve(&self, _: &str) -> Result<Vec<IpAddr>, String> {
            Ok(vec!["192.0.2.1".parse().unwrap()])
        }
    }

    #[test]
    fn local_experiment_becomes_a_concrete_owned_plan_without_a_frontend() {
        let spec = ExperimentSpec {
            version: EXPERIMENT_VERSION,
            name: "library consumer".into(),
            source: WorkloadSpec::Local {
                interface: "lo".into(),
                process: None,
            },
            destination: Some(DestinationSpec {
                selector: "example.test".into(),
                protocol: NetworkProtocol::Tcp,
                port: Some(443),
                resolution: ResolutionStrategy::Snapshot,
            }),
            selectors: Vec::new(),
            profile: FaultProfile {
                duration_ms: 1,
                events: vec![FaultEvent {
                    at_ms: 0,
                    fault: FaultSpec::default(),
                    faults: BTreeMap::new(),
                }],
            },
            traffic: None,
            extensions: BTreeMap::new(),
        };
        let prepared = prepare_experiment(
            &spec,
            &Resolver,
            Tooling {
                agent: FAULTLINE_AGENT_APPLICATION,
                engine: None,
            },
        )
        .unwrap();
        assert_eq!(prepared.plan().attach.target_uri(), "local://lo");
        assert_eq!(
            prepared.plan().timeline.target.as_deref(),
            Some("local://lo")
        );
        let environment = prepared.plan().environment.as_ref().unwrap();
        assert_eq!(environment.target, "local://lo");
        assert_eq!(environment.interface, "lo");
    }

    #[test]
    fn ethtool_features_are_recorded_as_boolean_conditions() {
        let parsed = parse_offloads(
            "Features for eth0:\ntcp-segmentation-offload: on\ngeneric-receive-offload: off [fixed]\n",
        );
        assert!(parsed["tcp-segmentation-offload"]);
        assert!(!parsed["generic-receive-offload"]);
    }
}
