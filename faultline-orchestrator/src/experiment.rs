//! End-to-end preparation of an authored experiment into a concrete plan.

#[cfg(test)]
use faultline_common::FAULTLINE_AGENT_APPLICATION;
use faultline_runtime::{DestinationResolver, ExperimentSpec, ResolvedExperiment};

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
    Ok(PreparedExperiment { plan, workload })
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
            destination: DestinationSpec {
                selector: "example.test".into(),
                protocol: NetworkProtocol::Tcp,
                port: Some(443),
                resolution: ResolutionStrategy::Snapshot,
            },
            profile: FaultProfile {
                duration_ms: 1,
                events: vec![FaultEvent {
                    at_ms: 0,
                    fault: FaultSpec::default(),
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
    }
}
