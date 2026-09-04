use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Duration;

use faultline_common::{
    LOSS_ALGORITHM_GILBERT_ELLIOTT, LOSS_ALGORITHM_HASH, LOSS_ALGORITHM_RANDOM, MAX_RULES,
    PROTOCOL_TCP, PROTOCOL_UDP,
};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub id: u32,
    #[serde(default)]
    pub source: Option<IpNet>,
    pub destination: IpNet,
    #[serde(default)]
    pub protocol: u8,
    #[serde(default)]
    pub loss_algorithm: u8,
    #[serde(default)]
    pub destination_port: u16,
    #[serde(default)]
    pub drop_permyriad: u32,
    #[serde(default)]
    pub ge_enter_permyriad: u32,
    #[serde(default)]
    pub ge_recover_permyriad: u32,
    #[serde(default)]
    pub ge_good_loss_permyriad: u32,
    #[serde(default)]
    pub ge_bad_loss_permyriad: u32,
    #[serde(default)]
    pub ge_idle_reset_secs: u32,
    #[serde(default)]
    pub duplicate_permyriad: u32,
    #[serde(default)]
    pub reorder_permyriad: u32,
    #[serde(default)]
    pub delay_ns: u64,
    #[serde(default)]
    pub jitter_ns: u64,
    #[serde(default)]
    pub bandwidth_bps: u64,
    #[serde(default = "default_rule_seed")]
    pub seed: u32,
}

const fn default_rule_seed() -> u32 {
    1
}

impl RuleSpec {
    pub fn source_network_and_mask(&self) -> ([u8; 16], [u8; 16]) {
        self.source
            .map(|source| {
                let mut network = [0; 16];
                let mut mask = [0; 16];
                match source {
                    IpNet::V4(value) => {
                        network[..4].copy_from_slice(&value.network().octets());
                        mask[..4].copy_from_slice(&value.netmask().octets());
                    }
                    IpNet::V6(value) => {
                        network = value.network().octets();
                        mask = value.netmask().octets();
                    }
                }
                (network, mask)
            })
            .unwrap_or(([0; 16], [0; 16]))
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_identity()?;
        self.validate_loss()?;
        self.validate_transport()
    }

    fn validate_identity(&self) -> Result<(), String> {
        if self.id >= MAX_RULES {
            return Err(format!("rule id {} is outside STATS map bounds", self.id));
        }
        if self
            .source
            .is_some_and(|source| source.addr().is_ipv4() != self.destination.addr().is_ipv4())
        {
            return Err(format!(
                "rule {} mixes IPv4 and IPv6 source/destination",
                self.id
            ));
        }
        Ok(())
    }

    fn validate_transport(&self) -> Result<(), String> {
        if self.destination_port != 0
            && self.protocol != PROTOCOL_TCP
            && self.protocol != PROTOCOL_UDP
        {
            return Err(format!(
                "rule {} specifies a port without TCP or UDP",
                self.id
            ));
        }
        Ok(())
    }

    fn validate_loss(&self) -> Result<(), String> {
        if ![
            LOSS_ALGORITHM_HASH,
            LOSS_ALGORITHM_RANDOM,
            LOSS_ALGORITHM_GILBERT_ELLIOTT,
        ]
        .contains(&self.loss_algorithm)
        {
            return Err(format!("rule {} has an unknown loss algorithm", self.id));
        }
        [
            ("a loss rate", self.drop_permyriad),
            ("GE enter", self.ge_enter_permyriad),
            ("GE recovery", self.ge_recover_permyriad),
            ("GE good-state loss", self.ge_good_loss_permyriad),
            ("GE bad-state loss", self.ge_bad_loss_permyriad),
            ("duplication", self.duplicate_permyriad),
            ("reordering", self.reorder_permyriad),
        ]
        .into_iter()
        .try_for_each(|(name, value)| validate_permyriad(self.id, name, value))?;
        if self.loss_algorithm == LOSS_ALGORITHM_GILBERT_ELLIOTT
            && (self.ge_enter_permyriad == 0 || self.ge_recover_permyriad == 0)
        {
            return Err(format!(
                "rule {} requires non-zero GE enter and recovery probabilities",
                self.id
            ));
        }
        Ok(())
    }
}

fn validate_permyriad(rule_id: u32, name: &str, value: u32) -> Result<(), String> {
    if value > 10_000 {
        Err(format!("rule {rule_id} has {name} above 100%"))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ControlState {
    pub rules: Vec<RuleSpec>,
}

pub const TIMELINE_VERSION: u32 = 1;

/// Deadlines shared by both ends of the control protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlTimeouts {
    pub acknowledgement: Duration,
    pub state: Duration,
    pub control_loop: Duration,
    pub shutdown: Duration,
}

impl Default for ControlTimeouts {
    fn default() -> Self {
        Self {
            acknowledgement: Duration::from_secs(5),
            state: Duration::from_secs(5),
            control_loop: Duration::from_secs(5),
            shutdown: Duration::from_secs(1),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineKind {
    Profile,
    Replay,
}

/// A portable sequence of atomic rule replacements.
///
/// Profiles are authored timelines and replays are timelines captured from a
/// live session. Both deliberately share the same wire representation so a
/// capture can be fed directly to the headless player.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Timeline {
    pub version: u32,
    pub kind: TimelineKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Total playback duration. The final event remains active until this
    /// point, after which an owned agent session is stopped and detached.
    pub duration_ms: u64,
    pub events: Vec<TimelineEvent>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineEvent {
    /// Milliseconds since the start of the session.
    pub at_ms: u64,
    /// The complete ruleset installed atomically at this point.
    pub rules: Vec<RuleSpec>,
}

impl TimelineEvent {
    fn validate_after(&self, index: usize, previous_at_ms: u64) -> Result<u64, String> {
        if index != 0 && self.at_ms <= previous_at_ms {
            return Err(format!(
                "timeline event {index} must occur after the previous event"
            ));
        }
        if self.rules.is_empty() {
            return Err(format!("timeline event {index} has no rules"));
        }

        self.rules
            .iter()
            .try_fold(BTreeSet::new(), |mut ids, rule| {
                rule.validate()?;
                if !ids.insert(rule.id) {
                    return Err(format!(
                        "timeline event {index} repeats rule id {}",
                        rule.id
                    ));
                }
                Ok(ids)
            })?;

        Ok(self.at_ms)
    }
}

impl Timeline {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != TIMELINE_VERSION {
            return Err(format!(
                "unsupported timeline version {}; expected {TIMELINE_VERSION}",
                self.version
            ));
        }
        if self.events.is_empty() {
            return Err("timeline must contain at least one event".to_owned());
        }
        if self.events[0].at_ms != 0 {
            return Err("timeline must begin at at_ms=0".to_owned());
        }
        if self.duration_ms < self.events.last().map_or(0, |event| event.at_ms) {
            return Err("timeline duration ends before its final event".to_owned());
        }
        self.events
            .iter()
            .enumerate()
            .try_fold(0, |previous, (index, event)| {
                event.validate_after(index, previous)
            })?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Ping { id: u64 },
    GetState { id: u64 },
    ReplaceRules { id: u64, rules: Vec<RuleSpec> },
    Stop { id: u64 },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Pong { id: u64 },
    State { id: u64, state: ControlState },
    Applied { id: u64, state: ControlState },
    Stopping { id: u64 },
    Error { id: Option<u64>, message: String },
}

pub fn encode_line(value: &impl Serialize) -> serde_json::Result<Vec<u8>> {
    let mut line = serde_json::to_vec(value)?;
    line.push(b'\n');
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_a_single_json_line_and_round_trips() {
        let request = Request::Ping { id: 7 };
        let line = encode_line(&request).unwrap();
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(serde_json::from_slice::<Request>(&line).unwrap(), request);
    }

    #[test]
    fn request_rejects_unknown_rule_fields() {
        let request = br#"{
            "type":"replace_rules",
            "id":1,
            "rules":[{
                "id":0,
                "destination":"10.0.0.0/8",
                "drop_permiriad":500
            }]
        }"#;
        let error = serde_json::from_slice::<Request>(request).unwrap_err();
        assert!(error.to_string().contains("unknown field `drop_permiriad`"));
    }

    fn rule(id: u32) -> RuleSpec {
        RuleSpec {
            id,
            source: None,
            destination: "10.0.0.0/8".parse().unwrap(),
            protocol: 0,
            loss_algorithm: LOSS_ALGORITHM_HASH,
            destination_port: 0,
            drop_permyriad: 500,
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
            seed: 1,
        }
    }

    #[test]
    fn timeline_round_trips_and_validates_atomic_events() {
        let timeline = Timeline {
            version: TIMELINE_VERSION,
            kind: TimelineKind::Profile,
            name: Some("brief outage".to_owned()),
            target: None,
            duration_ms: 500,
            events: vec![
                TimelineEvent {
                    at_ms: 0,
                    rules: vec![rule(0)],
                },
                TimelineEvent {
                    at_ms: 250,
                    rules: vec![rule(0), rule(1)],
                },
            ],
        };
        timeline.validate().unwrap();
        let encoded = serde_json::to_vec(&timeline).unwrap();
        assert_eq!(
            serde_json::from_slice::<Timeline>(&encoded).unwrap(),
            timeline
        );
    }

    #[test]
    fn timeline_rejects_non_increasing_events_and_duplicate_rule_ids() {
        let mut timeline = Timeline {
            version: TIMELINE_VERSION,
            kind: TimelineKind::Replay,
            name: None,
            target: None,
            duration_ms: 10,
            events: vec![
                TimelineEvent {
                    at_ms: 0,
                    rules: vec![rule(0)],
                },
                TimelineEvent {
                    at_ms: 10,
                    rules: vec![rule(0), rule(0)],
                },
            ],
        };
        assert!(timeline.validate().unwrap_err().contains("repeats rule id"));
        timeline.events[1] = TimelineEvent {
            at_ms: 0,
            rules: vec![rule(1)],
        };
        assert!(
            timeline
                .validate()
                .unwrap_err()
                .contains("must occur after the previous event")
        );
        timeline.events[1].at_ms = 9;
        timeline.events.push(TimelineEvent {
            at_ms: 8,
            rules: vec![rule(2)],
        });
        assert!(
            timeline
                .validate()
                .unwrap_err()
                .contains("must occur after the previous event")
        );
    }
}
