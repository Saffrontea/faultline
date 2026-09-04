use std::{fs, path::Path};

use anyhow::{Context as _, bail};
use ipnet::IpNet;
use serde::Deserialize;

use faultline_common::{
    LOSS_ALGORITHM_GILBERT_ELLIOTT, LOSS_ALGORITHM_HASH, LOSS_ALGORITHM_RANDOM, PROTOCOL_ANY,
    PROTOCOL_TCP, PROTOCOL_UDP,
};

use faultline_protocol::RuleSpec;

use crate::{parse_bandwidth, parse_duration, rule::RuleInput};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    rules: Vec<ScenarioRule>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Protocol {
    #[default]
    Any,
    Tcp,
    Udp,
}

impl Protocol {
    const fn number(self) -> u8 {
        match self {
            Self::Any => PROTOCOL_ANY,
            Self::Tcp => PROTOCOL_TCP,
            Self::Udp => PROTOCOL_UDP,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum LossAlgorithm {
    #[default]
    Hash,
    Random,
    GilbertElliott,
}

impl LossAlgorithm {
    const fn number(self) -> u8 {
        match self {
            Self::Hash => LOSS_ALGORITHM_HASH,
            Self::Random => LOSS_ALGORITHM_RANDOM,
            Self::GilbertElliott => LOSS_ALGORITHM_GILBERT_ELLIOTT,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioRule {
    id: u32,
    source: Option<IpNet>,
    destination: IpNet,
    #[serde(default)]
    protocol: Protocol,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    loss: f64,
    #[serde(default)]
    loss_algorithm: LossAlgorithm,
    #[serde(default = "default_seed")]
    seed: u32,
    burst_loss: Option<f64>,
    #[serde(default = "default_recovery")]
    burst_recovery: f64,
    #[serde(default = "default_bad_loss")]
    burst_bad_loss: f64,
    #[serde(default)]
    burst_good_loss: f64,
    burst_idle_reset: Option<String>,
    #[serde(default)]
    duplicate: f64,
    #[serde(default)]
    reorder: f64,
    delay: Option<String>,
    jitter: Option<String>,
    bandwidth: Option<String>,
}

impl ScenarioRule {
    fn compile(self) -> anyhow::Result<RuleSpec> {
        let burst_idle_reset =
            self.parse_optional_duration("burst_idle_reset", self.burst_idle_reset.as_deref())?;
        let delay = self.parse_optional_duration("delay", self.delay.as_deref())?;
        let jitter = self.parse_optional_duration("jitter", self.jitter.as_deref())?;
        let bandwidth_bps = self
            .bandwidth
            .as_deref()
            .map(parse_bandwidth)
            .transpose()
            .with_context(|| format!("rule {} has invalid bandwidth", self.id))?;

        RuleInput {
            id: self.id,
            source: self.source,
            destination: self.destination,
            protocol: self.protocol.number(),
            destination_port: self.port,
            loss: self.loss,
            loss_algorithm: self.loss_algorithm.number(),
            seed: self.seed,
            burst_loss: self.burst_loss,
            burst_recovery: self.burst_recovery,
            burst_bad_loss: self.burst_bad_loss,
            burst_good_loss: self.burst_good_loss,
            burst_idle_reset,
            duplicate: self.duplicate,
            reorder: self.reorder,
            delay,
            jitter,
            bandwidth_bps,
        }
        .compile()
    }

    fn parse_optional_duration(
        &self,
        name: &str,
        value: Option<&str>,
    ) -> anyhow::Result<Option<std::time::Duration>> {
        value
            .map(parse_duration)
            .transpose()
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("rule {} has invalid {name}", self.id))
    }
}

const fn default_seed() -> u32 {
    1
}
const fn default_recovery() -> f64 {
    25.0
}
const fn default_bad_loss() -> f64 {
    100.0
}

pub fn load(path: &Path) -> anyhow::Result<Vec<RuleSpec>> {
    let bytes = fs::read(path).with_context(|| format!("reading scenario {}", path.display()))?;
    let scenario = decode(path, &bytes)?;
    if scenario.rules.is_empty() {
        bail!("scenario must contain at least one rule");
    }
    scenario
        .rules
        .into_iter()
        .map(ScenarioRule::compile)
        .collect()
}

fn decode(path: &Path, bytes: &[u8]) -> anyhow::Result<Scenario> {
    match path.extension().and_then(|value| value.to_str()) {
        Some("yaml" | "yml") => yaml_serde::from_slice(bytes)
            .with_context(|| format!("decoding YAML scenario {}", path.display())),
        Some("json") => serde_json::from_slice(bytes)
            .with_context(|| format!("decoding JSON scenario {}", path.display())),
        _ => bail!("scenario file must have a .yaml, .yml, or .json extension"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_multiple_dual_stack_rules() {
        let scenario: Scenario = serde_json::from_str(r#"{"rules":[
          {"id":1,"destination":"10.0.0.0/8","protocol":"tcp","port":443,"loss":5.0},
          {"id":2,"source":"2001:db8:1::/48","destination":"2001:db8:2::/48","delay":"20ms","jitter":"5ms","bandwidth":"10mbit"}
        ]}"#).unwrap();
        let rules: Vec<_> = scenario
            .rules
            .into_iter()
            .map(ScenarioRule::compile)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].drop_permyriad, 500);
        assert_eq!(rules[1].delay_ns, 20_000_000);
        assert_eq!(rules[1].bandwidth_bps, 10_000_000);
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(serde_json::from_str::<Scenario>(r#"{"rules":[],"typo":true}"#).is_err());
    }

    #[test]
    fn decodes_yaml_with_the_same_schema() {
        let scenario = decode(
            Path::new("scenario.yaml"),
            br#"rules:
  - id: 7
    destination: 10.0.0.0/8
    protocol: tcp
    port: 443
    loss: 5.0
"#,
        )
        .unwrap();
        let rule = scenario
            .rules
            .into_iter()
            .next()
            .unwrap()
            .compile()
            .unwrap();
        assert_eq!(rule.id, 7);
        assert_eq!(rule.drop_permyriad, 500);
    }

    #[test]
    fn rejects_ambiguous_extensions() {
        assert!(decode(Path::new("scenario.txt"), b"rules: []").is_err());
    }

    #[test]
    fn scenario_and_cli_share_ambiguous_loss_validation() {
        for input in [
            r#"{"rules":[{"id":1,"destination":"10.0.0.0/8","loss":5.0,"burst_loss":1.0}]}"#,
            r#"{"rules":[{"id":1,"destination":"10.0.0.0/8","loss_algorithm":"random","burst_loss":1.0}]}"#,
        ] {
            let scenario: Scenario = serde_json::from_str(input).unwrap();
            assert!(
                scenario
                    .rules
                    .into_iter()
                    .next()
                    .unwrap()
                    .compile()
                    .is_err()
            );
        }
    }
}
