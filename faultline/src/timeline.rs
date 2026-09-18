use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader, Read, Write, stdout},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime},
};

use anyhow::bail;
use crossterm::event::{self, Event, KeyCode};
use faultline_protocol::{ControlTimeouts, Request, RuleSpec, Timeline, encode_line};
use faultline_runtime::{
    AppliedEventRecord, ExperimentExecution, RuleObservation, SelectionDiagnosticObservation,
};
use ratatui::{Terminal, backend::CrosstermBackend};
use serde_json::Value;

use crate::app::{App, TerminalGuard, draw, render_snapshot};
use faultline_orchestrator::timeline::{ApplyEvent, ExperimentDriver, rules_impair};

pub(super) fn run_observed(
    timeline: &Timeline,
    reader: Box<dyn Read + Send>,
    writer: &mut dyn Write,
    label: &str,
    traffic_plan: Option<&(
        faultline_runtime::AttachSpec,
        faultline_runtime::TrafficSpec,
    )>,
    snapshot_after_ms: Option<u64>,
) -> anyhow::Result<ExperimentExecution> {
    run_observed_with_timeouts(
        timeline,
        reader,
        writer,
        label,
        traffic_plan,
        snapshot_after_ms,
        ControlTimeouts::default(),
    )
}

fn run_observed_with_timeouts(
    timeline: &Timeline,
    reader: Box<dyn Read + Send>,
    writer: &mut dyn Write,
    label: &str,
    traffic_plan: Option<&(
        faultline_runtime::AttachSpec,
        faultline_runtime::TrafficSpec,
    )>,
    snapshot_after_ms: Option<u64>,
    timeouts: ControlTimeouts,
) -> anyhow::Result<ExperimentExecution> {
    let (messages, incoming) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            match line {
                Ok(line) => {
                    if messages.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    if snapshot_after_ms == Some(0) {
        bail!("--snapshot-after-ms must be greater than zero");
    }
    let guard = snapshot_after_ms
        .is_none()
        .then(TerminalGuard::enter)
        .transpose()?;
    let mut terminal = snapshot_after_ms
        .is_none()
        .then(|| Terminal::new(CrosstermBackend::new(stdout())))
        .transpose()?;
    let mut app = App::new();
    app.phase = "Connect";
    let started_at_unix_ms = unix_ms();
    let started = Instant::now();
    let mut driver = ExperimentDriver::new(
        timeline,
        traffic_plan.map(|(attach, traffic)| (attach, traffic)),
    );
    let duration = Duration::from_millis(
        snapshot_after_ms
            .unwrap_or(timeline.duration_ms)
            .min(timeline.duration_ms),
    );
    let mut cancelled = false;
    let mut observations = ObservationRecorder::default();
    let acknowledgement_timeout = timeouts.acknowledgement;
    loop {
        let elapsed = started.elapsed();
        if let Some(event) = driver.next_at(elapsed) {
            writer.write_all(&encode_line(&Request::ReplaceRules {
                id: event.id,
                rules: event.rules.clone(),
            })?)?;
            writer.flush()?;
            observations.requested(&event, elapsed);
            app.phase = if rules_impair(&event.rules) {
                "Impair"
            } else if event.index == 0 {
                "Connect"
            } else {
                "Observe"
            };
            app.status = format!("applying event {} at {}ms", event.index, event.at_ms);
        }
        while let Ok(message) = incoming.try_recv() {
            let parsed = serde_json::from_str::<Value>(&message).ok();
            if let Some(response) = parsed.as_ref()
                && response.get("type").and_then(Value::as_str) == Some("error")
            {
                bail!(
                    "timeline event failed: {}",
                    response
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown agent error")
                );
            }
            let applied = parsed.as_ref().and_then(|response| {
                (response.get("type").and_then(Value::as_str) == Some("applied"))
                    .then(|| response.get("id").and_then(Value::as_u64))
                    .flatten()
            });
            parsed
                .as_ref()
                .into_iter()
                .for_each(|value| observations.message(value, started.elapsed()));
            app.handle_message(message);
            if let Some(id) = applied {
                let acknowledged_index = driver.acknowledge(id)?;
                acknowledged_index
                    .into_iter()
                    .for_each(|index| observations.applied(index, started.elapsed()));
            }
        }
        app.traffic = driver.traffic_status();
        if let Some(terminal) = &mut terminal {
            terminal.draw(|frame| draw(frame, &app, label))?;
        }
        if observations.acknowledgement_timed_out(acknowledgement_timeout) {
            bail!("timeline acknowledgement timed out after {acknowledgement_timeout:?}");
        }
        if driver.complete(elapsed)
            || (snapshot_after_ms.is_some() && elapsed >= duration && !observations.has_pending())
            || cancelled
        {
            break;
        }
        if terminal.is_some()
            && event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
            && key.kind == crossterm::event::KeyEventKind::Press
            && matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
        {
            cancelled = true;
        }
    }
    if snapshot_after_ms.is_some() {
        print!("{}", render_snapshot(&app, label, 140, 32)?);
    }
    drop(terminal);
    drop(guard);
    Ok(observations.finish(started_at_unix_ms))
}

struct PendingObservation {
    event_index: usize,
    scheduled_at_ms: u64,
    requested_at_ms: u64,
    rules: Vec<RuleSpec>,
    sent_at: Instant,
}

#[derive(Default)]
struct ObservationRecorder {
    pending: Option<PendingObservation>,
    applied_events: Vec<AppliedEventRecord>,
    active_event_index: Option<usize>,
    active_rules: Vec<RuleSpec>,
    observed_since_apply: BTreeSet<u32>,
    rule_observations: Vec<RuleObservation>,
    selection_diagnostics: Vec<SelectionDiagnosticObservation>,
    final_rule_stats: BTreeMap<u32, Value>,
    final_diagnostics: Option<Value>,
}

impl ObservationRecorder {
    fn requested(&mut self, event: &ApplyEvent, elapsed: Duration) {
        self.pending = Some(PendingObservation {
            event_index: event.index,
            scheduled_at_ms: event.at_ms,
            requested_at_ms: duration_ms(elapsed),
            rules: event.rules.clone(),
            sent_at: Instant::now(),
        });
    }

    fn message(&mut self, value: &Value, elapsed: Duration) {
        match value.get("type").and_then(Value::as_str) {
            Some("stats") => self.stats(value, elapsed),
            Some("diagnostics") => self.diagnostics(value, elapsed),
            _ => {}
        }
    }

    fn stats(&mut self, value: &Value, elapsed: Duration) {
        let Some(rule_id) = value
            .get("rule_id")
            .and_then(Value::as_u64)
            .and_then(|id| u32::try_from(id).ok())
        else {
            return;
        };
        self.final_rule_stats.insert(rule_id, value.clone());
        self.rule_observations.push(RuleObservation {
            observed_at_ms: duration_ms(elapsed),
            active_event_index: self.active_event_index,
            interval_may_span_rule_change: self.active_event_index.is_none()
                || self.observed_since_apply.insert(rule_id),
            configured_rule: self
                .active_rules
                .iter()
                .find(|rule| rule.id == rule_id)
                .cloned(),
            stats: value.clone(),
        });
    }

    fn diagnostics(&mut self, value: &Value, elapsed: Duration) {
        self.final_diagnostics = Some(value.clone());
        self.selection_diagnostics
            .push(SelectionDiagnosticObservation {
                observed_at_ms: duration_ms(elapsed),
                active_event_index: self.active_event_index,
                diagnostics: value.clone(),
            });
    }

    fn applied(&mut self, event_index: usize, elapsed: Duration) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        debug_assert_eq!(event_index, pending.event_index);
        self.applied_events.push(AppliedEventRecord {
            event_index,
            scheduled_at_ms: pending.scheduled_at_ms,
            requested_at_ms: pending.requested_at_ms,
            applied_at_ms: duration_ms(elapsed),
            rule_ids: pending.rules.iter().map(|rule| rule.id).collect(),
        });
        self.active_event_index = Some(event_index);
        self.active_rules = pending.rules;
        self.observed_since_apply.clear();
    }

    fn acknowledgement_timed_out(&self, timeout: Duration) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| pending.sent_at.elapsed() >= timeout)
    }

    fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    fn finish(self, started_at_unix_ms: u64) -> ExperimentExecution {
        ExperimentExecution {
            started_at_unix_ms,
            completed_at_unix_ms: unix_ms(),
            applied_events: self.applied_events,
            rule_observations: self.rule_observations,
            selection_diagnostics: self.selection_diagnostics,
            final_rule_stats: self.final_rule_stats,
            final_diagnostics: self.final_diagnostics,
        }
    }
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io::{Read, Write},
        sync::mpsc::{self, Receiver, Sender},
        time::Duration,
    };

    use faultline_protocol::{TIMELINE_VERSION, TimelineEvent, TimelineKind};

    use super::*;

    struct ChannelReader {
        input: Receiver<Vec<u8>>,
        buffered: VecDeque<u8>,
    }

    impl Read for ChannelReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.buffered.is_empty() {
                self.buffered.extend(
                    self.input
                        .recv()
                        .map_err(|_| std::io::ErrorKind::UnexpectedEof)?,
                );
            }
            let count = output.len().min(self.buffered.len());
            for slot in &mut output[..count] {
                *slot = self.buffered.pop_front().unwrap();
            }
            Ok(count)
        }
    }

    struct ChannelWriter(Sender<Vec<u8>>);

    impl Write for ChannelWriter {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            self.0
                .send(input.to_vec())
                .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
            Ok(input.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn observed_rule(delay_ns: u64, bandwidth_bps: u64) -> RuleSpec {
        RuleSpec {
            id: 0,
            source: Some("10.0.0.10/32".parse().unwrap()),
            destination: "10.0.1.20/32".parse().unwrap(),
            protocol: faultline_common::PROTOCOL_TCP,
            loss_algorithm: faultline_common::LOSS_ALGORITHM_HASH,
            destination_port: 443,
            drop_permyriad: 0,
            ge_enter_permyriad: 0,
            ge_recover_permyriad: 0,
            ge_good_loss_permyriad: 0,
            ge_bad_loss_permyriad: 0,
            ge_idle_reset_secs: 0,
            duplicate_permyriad: 0,
            reorder_permyriad: 0,
            delay_ns,
            jitter_ns: 0,
            bandwidth_bps,
            seed: 7,
        }
    }

    #[test]
    fn observed_timeline_waits_for_each_applied_response() {
        let timeline = Timeline {
            version: TIMELINE_VERSION,
            kind: TimelineKind::Profile,
            name: None,
            target: None,
            duration_ms: 30,
            events: vec![
                TimelineEvent {
                    at_ms: 0,
                    rules: vec![observed_rule(10_000_000, 1_000_000)],
                },
                TimelineEvent {
                    at_ms: 0,
                    rules: vec![observed_rule(20_000_000, 2_000_000)],
                },
            ],
        };
        let (request_tx, request_rx) = mpsc::channel();
        let (response_tx, response_rx) = mpsc::channel();
        let reader = Box::new(ChannelReader {
            input: response_rx,
            buffered: VecDeque::new(),
        });
        let mut writer = ChannelWriter(request_tx);
        let (result_tx, result_rx) = mpsc::channel();

        let agent = std::thread::spawn(move || {
            let first = request_rx.recv().unwrap();
            let first: Value = serde_json::from_slice(&first).unwrap();
            let second_arrived_before_ack =
                request_rx.recv_timeout(Duration::from_millis(10)).is_ok();
            result_tx.send(second_arrived_before_ack).unwrap();
            response_tx
                .send(
                    serde_json::to_string(
                        &serde_json::json!({"type":"applied","id":1,"state":{"rules":[]}}),
                    )
                    .unwrap()
                    .into_bytes()
                    .into_iter()
                    .chain(std::iter::once(b'\n'))
                    .collect(),
                )
                .unwrap();
            response_tx
                .send(b"{\"type\":\"stats\",\"rule_id\":0,\"matched\":4,\"dropped\":1}\n".to_vec())
                .unwrap();
            let second = request_rx.recv().unwrap();
            let second: Value = serde_json::from_slice(&second).unwrap();
            response_tx
                .send(
                    serde_json::to_string(
                        &serde_json::json!({"type":"applied","id":2,"state":{"rules":[]}}),
                    )
                    .unwrap()
                    .into_bytes()
                    .into_iter()
                    .chain(std::iter::once(b'\n'))
                    .collect(),
                )
                .unwrap();
            (first["id"].as_u64(), second["id"].as_u64())
        });

        let execution = run_observed(
            &timeline,
            reader,
            &mut writer,
            "test://timeline",
            None,
            Some(30),
        )
        .unwrap();
        assert_eq!(execution.applied_events.len(), 2);
        assert_eq!(execution.applied_events[0].event_index, 0);
        assert_eq!(execution.rule_observations.len(), 1);
        assert_eq!(execution.rule_observations[0].active_event_index, Some(0));
        assert_eq!(
            execution.rule_observations[0]
                .configured_rule
                .as_ref()
                .unwrap()
                .delay_ns,
            10_000_000
        );
        assert_eq!(
            execution.rule_observations[0]
                .configured_rule
                .as_ref()
                .unwrap()
                .bandwidth_bps,
            1_000_000
        );
        assert_eq!(execution.final_rule_stats[&0]["matched"], 4);
        assert!(!result_rx.recv().unwrap());
        assert_eq!(agent.join().unwrap(), (Some(1), Some(2)));
    }

    #[test]
    fn observed_timeline_reports_a_missing_acknowledgement() {
        let timeline = Timeline {
            version: TIMELINE_VERSION,
            kind: TimelineKind::Profile,
            name: None,
            target: None,
            duration_ms: 1,
            events: vec![TimelineEvent {
                at_ms: 0,
                rules: Vec::new(),
            }],
        };
        let (_response_tx, response_rx) = mpsc::channel();
        let reader = Box::new(ChannelReader {
            input: response_rx,
            buffered: VecDeque::new(),
        });
        let (request_tx, request_rx) = mpsc::channel();
        let mut writer = ChannelWriter(request_tx);
        let error = run_observed_with_timeouts(
            &timeline,
            reader,
            &mut writer,
            "test://timeline",
            None,
            Some(1),
            ControlTimeouts {
                acknowledgement: Duration::from_millis(20),
                ..ControlTimeouts::default()
            },
        )
        .unwrap_err();
        assert!(request_rx.recv().is_ok());
        assert!(error.to_string().contains("acknowledgement timed out"));
    }
}
