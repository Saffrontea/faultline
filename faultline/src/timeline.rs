use std::{
    io::{BufRead, BufReader, Read, Write, stdout},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use anyhow::bail;
use crossterm::event::{self, Event, KeyCode};
use faultline_protocol::{ControlTimeouts, Request, Timeline, encode_line};
use ratatui::{Terminal, backend::CrosstermBackend};
use serde_json::Value;

use crate::app::{App, TerminalGuard, draw, render_snapshot};
use faultline_orchestrator::timeline::{ExperimentDriver, rules_impair};

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
) -> anyhow::Result<()> {
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
) -> anyhow::Result<()> {
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
    let mut pending_since = None;
    let acknowledgement_timeout = timeouts.acknowledgement;
    loop {
        let elapsed = started.elapsed();
        if let Some(event) = driver.next_at(elapsed) {
            writer.write_all(&encode_line(&Request::ReplaceRules {
                id: event.id,
                rules: event.rules.clone(),
            })?)?;
            writer.flush()?;
            pending_since = Some(Instant::now());
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
            app.handle_message(message);
            if let Some(id) = applied {
                driver.acknowledge(id)?;
                pending_since = None;
            }
        }
        app.traffic = driver.traffic_status();
        if let Some(terminal) = &mut terminal {
            terminal.draw(|frame| draw(frame, &app, label))?;
        }
        if pending_since.is_some_and(|sent| sent.elapsed() >= acknowledgement_timeout) {
            bail!("timeline acknowledgement timed out after {acknowledgement_timeout:?}");
        }
        if driver.complete(elapsed)
            || (snapshot_after_ms.is_some() && elapsed >= duration && pending_since.is_none())
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
    Ok(())
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
                    rules: Vec::new(),
                },
                TimelineEvent {
                    at_ms: 0,
                    rules: Vec::new(),
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

        run_observed(
            &timeline,
            reader,
            &mut writer,
            "test://timeline",
            None,
            Some(30),
        )
        .unwrap();
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
