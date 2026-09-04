//! Timeline scheduling and control-channel operations independent of a UI.

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, bail};
use faultline_protocol::{ControlTimeouts, Request, RuleSpec, Timeline, TimelineKind, encode_line};
use faultline_runtime::{AttachSpec, TrafficSpec};
use serde_json::Value;

use crate::{TrafficGuard, TrafficStatus};

#[derive(Clone, Debug, PartialEq)]
pub struct ApplyEvent {
    pub id: u64,
    pub index: usize,
    pub at_ms: u64,
    pub rules: Vec<RuleSpec>,
}

/// Deterministic timeline state machine. Frontends decide how to wait, render,
/// and transport requests; this type owns ordering and acknowledgement gates.
pub struct TimelineDriver<'a> {
    timeline: &'a Timeline,
    next_event: usize,
    pending: Option<(u64, usize)>,
}

impl<'a> TimelineDriver<'a> {
    pub const fn new(timeline: &'a Timeline) -> Self {
        Self {
            timeline,
            next_event: 0,
            pending: None,
        }
    }

    pub fn next_at(&mut self, elapsed: Duration) -> Option<ApplyEvent> {
        if self.pending.is_some() {
            return None;
        }
        let event = self.timeline.events.get(self.next_event)?;
        if elapsed < Duration::from_millis(event.at_ms) {
            return None;
        }
        let index = self.next_event;
        let id = index as u64 + 1;
        self.next_event += 1;
        self.pending = Some((id, index));
        Some(ApplyEvent {
            id,
            index,
            at_ms: event.at_ms,
            rules: event.rules.clone(),
        })
    }

    pub fn acknowledge(&mut self, id: u64) -> anyhow::Result<Option<usize>> {
        match self.pending {
            Some((pending_id, index)) if pending_id == id => {
                self.pending = None;
                Ok(Some(index))
            }
            Some((pending_id, _)) => {
                bail!("acknowledgement {id} does not match pending event {pending_id}")
            }
            None => Ok(None),
        }
    }

    pub fn complete(&self, elapsed: Duration) -> bool {
        elapsed >= Duration::from_millis(self.timeline.duration_ms)
            && self.next_event == self.timeline.events.len()
            && self.pending.is_none()
    }
}

/// Timeline plus experiment-owned traffic policy. Traffic begins only after
/// event zero has been acknowledged, so the first request is observable for
/// every snapshot-resolved destination.
pub struct ExperimentDriver<'a> {
    timeline: TimelineDriver<'a>,
    traffic_plan: Option<(&'a AttachSpec, &'a TrafficSpec)>,
    traffic: Option<TrafficGuard>,
}

impl<'a> ExperimentDriver<'a> {
    pub const fn new(
        timeline: &'a Timeline,
        traffic_plan: Option<(&'a AttachSpec, &'a TrafficSpec)>,
    ) -> Self {
        Self {
            timeline: TimelineDriver::new(timeline),
            traffic_plan,
            traffic: None,
        }
    }

    pub fn next_at(&mut self, elapsed: Duration) -> Option<ApplyEvent> {
        self.timeline.next_at(elapsed)
    }

    pub fn acknowledge(&mut self, id: u64) -> anyhow::Result<Option<usize>> {
        let event = self.timeline.acknowledge(id)?;
        if event == Some(0)
            && let Some((attach, traffic)) = self.traffic_plan
        {
            self.traffic = Some(TrafficGuard::start(attach, traffic)?);
        }
        Ok(event)
    }

    pub fn traffic_status(&self) -> TrafficStatus {
        self.traffic
            .as_ref()
            .map(TrafficGuard::status)
            .unwrap_or_default()
    }

    pub fn complete(&self, elapsed: Duration) -> bool {
        self.timeline.complete(elapsed)
    }
}

pub fn load(path: &Path, expected_kind: TimelineKind) -> anyhow::Result<Timeline> {
    let bytes = fs::read(path).with_context(|| format!("reading timeline {}", path.display()))?;
    let timeline: Timeline = match path.extension().and_then(|value| value.to_str()) {
        Some("yaml" | "yml") => yaml_serde::from_slice(&bytes)
            .with_context(|| format!("decoding YAML timeline {}", path.display()))?,
        Some("json") => serde_json::from_slice(&bytes)
            .with_context(|| format!("decoding JSON timeline {}", path.display()))?,
        _ => bail!("timeline file must have a .yaml, .yml, or .json extension"),
    };
    timeline.validate().map_err(anyhow::Error::msg)?;
    if timeline.kind != expected_kind {
        bail!(
            "timeline {} has kind {:?}, expected {:?}",
            path.display(),
            timeline.kind,
            expected_kind
        );
    }
    Ok(timeline)
}

pub fn play(
    timeline: &Timeline,
    reader: Box<dyn Read + Send>,
    writer: &mut dyn Write,
) -> anyhow::Result<()> {
    play_with_timeouts(timeline, reader, writer, ControlTimeouts::default())
}

fn play_with_timeouts(
    timeline: &Timeline,
    reader: Box<dyn Read + Send>,
    writer: &mut dyn Write,
    timeouts: ControlTimeouts,
) -> anyhow::Result<()> {
    let messages = MessageReader::spawn(reader);
    let started = Instant::now();
    let mut driver = TimelineDriver::new(timeline);
    loop {
        let elapsed = started.elapsed();
        if let Some(event) = driver.next_at(elapsed) {
            writer.write_all(&encode_line(&Request::ReplaceRules {
                id: event.id,
                rules: event.rules,
            })?)?;
            writer.flush()?;
            let response = read_matching_message(
                &messages,
                timeouts.acknowledgement,
                &format!(
                    "control channel closed while applying timeline event {}",
                    event.index
                ),
                |response| {
                    response.get("id").and_then(Value::as_u64) == Some(event.id)
                        && matches!(
                            response.get("type").and_then(Value::as_str),
                            Some("applied" | "error")
                        )
                },
            )?;
            match response.get("type").and_then(Value::as_str) {
                Some("applied") => {
                    driver.acknowledge(event.id)?;
                    println!("applied event {} at {}ms", event.index, event.at_ms);
                }
                Some("error") => bail!(
                    "timeline event {} failed: {}",
                    event.index,
                    response["message"].as_str().unwrap_or("unknown error")
                ),
                _ => unreachable!("response predicate accepts only applied or error"),
            }
            continue;
        }
        if driver.complete(elapsed) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(1));
    }
}

pub fn rules_impair(rules: &[RuleSpec]) -> bool {
    rules.iter().any(|rule| {
        rule.drop_permyriad != 0
            || rule.duplicate_permyriad != 0
            || rule.reorder_permyriad != 0
            || rule.delay_ns != 0
            || rule.jitter_ns != 0
            || rule.bandwidth_bps != 0
    })
}

pub fn set_loss_once(
    reader: Box<dyn Read + Send>,
    stream: &mut dyn Write,
    loss: f64,
) -> anyhow::Result<()> {
    let messages = MessageReader::spawn(reader);
    let timeouts = ControlTimeouts::default();
    if !loss.is_finite() || !(0.0..=100.0).contains(&loss) {
        bail!("--set-loss must be between 0 and 100");
    }
    stream.write_all(&encode_line(&Request::GetState { id: 1 })?)?;
    stream.flush()?;
    let mut state = read_matching_message(
        &messages,
        timeouts.state,
        "control socket closed before state response",
        |message| message.get("id").and_then(Value::as_u64) == Some(1),
    )?;
    if state.get("type").and_then(Value::as_str) != Some("state") {
        bail!("control state request failed: {state}");
    }
    let rules = state
        .pointer_mut("/state/rules")
        .and_then(Value::as_array_mut)
        .context("state response has no rules")?;
    rules
        .first_mut()
        .and_then(Value::as_object_mut)
        .context("state response has no first rule")?
        .insert(
            "drop_permyriad".to_owned(),
            Value::from((loss * 100.0).round() as u64),
        );
    let rules = serde_json::from_value::<Vec<RuleSpec>>(Value::Array(rules.clone()))?;
    stream.write_all(&encode_line(&Request::ReplaceRules { id: 2, rules })?)?;
    stream.flush()?;
    let message = read_matching_message(
        &messages,
        timeouts.acknowledgement,
        "control socket closed before apply response",
        |message| message.get("id").and_then(Value::as_u64) == Some(2),
    )?;
    println!("{}", serde_json::to_string(&message)?);
    if message.get("type").and_then(Value::as_str) != Some("applied") {
        bail!("control update failed: {message}");
    }
    Ok(())
}

struct MessageReader {
    incoming: mpsc::Receiver<Result<String, String>>,
}

impl MessageReader {
    fn spawn(reader: Box<dyn Read + Send>) -> Self {
        let (messages, incoming) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(reader).lines() {
                let message = line.map_err(|error| error.to_string());
                let _ = messages.send(message);
            }
        });
        Self { incoming }
    }
}

fn read_matching_message(
    reader: &MessageReader,
    timeout: Duration,
    closed_message: &str,
    mut predicate: impl FnMut(&Value) -> bool,
) -> anyhow::Result<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| anyhow::anyhow!("control response timed out after {timeout:?}"))?;
        let line = reader
            .incoming
            .recv_timeout(remaining)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => {
                    anyhow::anyhow!("control response timed out after {timeout:?}")
                }
                mpsc::RecvTimeoutError::Disconnected => anyhow::anyhow!(closed_message.to_owned()),
            })?
            .map_err(anyhow::Error::msg)?;
        let message: Value = serde_json::from_str(&line)?;
        if predicate(&message) {
            return Ok(message);
        }
    }
}

#[cfg(test)]
mod tests {
    use faultline_protocol::{TIMELINE_VERSION, TimelineEvent};

    use super::*;

    fn timeline() -> Timeline {
        Timeline {
            version: TIMELINE_VERSION,
            kind: TimelineKind::Profile,
            name: None,
            target: None,
            duration_ms: 20,
            events: vec![
                TimelineEvent {
                    at_ms: 0,
                    rules: Vec::new(),
                },
                TimelineEvent {
                    at_ms: 5,
                    rules: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn driver_serializes_events_on_acknowledgements() {
        let timeline = timeline();
        let mut driver = TimelineDriver::new(&timeline);
        let first = driver.next_at(Duration::ZERO).unwrap();
        assert!(driver.next_at(Duration::from_secs(1)).is_none());
        assert_eq!(driver.acknowledge(first.id).unwrap(), Some(0));
        let second = driver.next_at(Duration::from_millis(5)).unwrap();
        assert_eq!(driver.acknowledge(second.id).unwrap(), Some(1));
        assert!(driver.complete(Duration::from_millis(20)));
    }

    #[test]
    fn driver_rejects_an_out_of_order_acknowledgement() {
        let timeline = timeline();
        let mut driver = TimelineDriver::new(&timeline);
        driver.next_at(Duration::ZERO).unwrap();
        assert!(
            driver
                .acknowledge(2)
                .unwrap_err()
                .to_string()
                .contains("pending event 1")
        );
    }

    #[cfg(unix)]
    #[test]
    fn playback_times_out_when_an_acknowledgement_never_arrives() {
        let (reader, _silent_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut written = Vec::new();
        let timeout = Duration::from_millis(20);
        let error = play_with_timeouts(
            &timeline(),
            Box::new(reader),
            &mut written,
            ControlTimeouts {
                acknowledgement: timeout,
                ..ControlTimeouts::default()
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(!written.is_empty());
    }
}
