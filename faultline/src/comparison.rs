use std::collections::BTreeMap;

use faultline_runtime::{ExecutionEnvironment, ResolvedExperiment};
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize)]
pub(super) struct ComparisonReport<'a> {
    conditions_equal: bool,
    conditions: ConditionComparison,
    environment: EnvironmentComparison<'a>,
    effects: EffectComparison<'a>,
}

#[derive(Serialize)]
struct ConditionComparison {
    attach_equal: bool,
    selectors_equal: bool,
    timeline_equal: bool,
}

#[derive(Serialize)]
struct EnvironmentComparison<'a> {
    kernel_equal: bool,
    offloads_equal: bool,
    qdiscs_equal: bool,
    base: Option<&'a ExecutionEnvironment>,
    candidate: Option<&'a ExecutionEnvironment>,
}

#[derive(Serialize)]
struct EffectComparison<'a> {
    base_execution_error: Option<&'a str>,
    candidate_execution_error: Option<&'a str>,
    base_final_rule_stats: Option<&'a BTreeMap<u32, Value>>,
    candidate_final_rule_stats: Option<&'a BTreeMap<u32, Value>>,
    base_final_selection_diagnostics: Option<&'a Value>,
    candidate_final_selection_diagnostics: Option<&'a Value>,
}

pub(super) fn compare<'a>(
    base: &'a ResolvedExperiment,
    candidate: &'a ResolvedExperiment,
) -> ComparisonReport<'a> {
    let conditions = ConditionComparison {
        attach_equal: base.attach == candidate.attach,
        selectors_equal: base.selectors == candidate.selectors,
        timeline_equal: base.timeline == candidate.timeline,
    };
    let base_environment = effective_environment(base);
    let candidate_environment = effective_environment(candidate);
    ComparisonReport {
        conditions_equal: conditions.attach_equal
            && conditions.selectors_equal
            && conditions.timeline_equal,
        conditions,
        environment: EnvironmentComparison {
            kernel_equal: base_environment.and_then(|value| value.kernel_release.as_ref())
                == candidate_environment.and_then(|value| value.kernel_release.as_ref()),
            offloads_equal: base_environment.map(|value| &value.offloads)
                == candidate_environment.map(|value| &value.offloads),
            qdiscs_equal: base_environment.and_then(|value| value.qdiscs.as_ref())
                == candidate_environment.and_then(|value| value.qdiscs.as_ref()),
            base: base_environment,
            candidate: candidate_environment,
        },
        effects: EffectComparison {
            base_execution_error: base.execution_error.as_deref(),
            candidate_execution_error: candidate.execution_error.as_deref(),
            base_final_rule_stats: base
                .execution
                .as_ref()
                .map(|execution| &execution.final_rule_stats),
            candidate_final_rule_stats: candidate
                .execution
                .as_ref()
                .map(|execution| &execution.final_rule_stats),
            base_final_selection_diagnostics: base
                .execution
                .as_ref()
                .and_then(|execution| execution.final_diagnostics.as_ref()),
            candidate_final_selection_diagnostics: candidate
                .execution
                .as_ref()
                .and_then(|execution| execution.final_diagnostics.as_ref()),
        },
    }
}

fn effective_environment(plan: &ResolvedExperiment) -> Option<&ExecutionEnvironment> {
    plan.effective_environment
        .as_ref()
        .or(plan.environment.as_ref())
}
