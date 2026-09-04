use std::{
    collections::VecDeque,
    fs,
    io::{Write, stdout},
    path::PathBuf,
    time::Instant,
};

use anyhow::{Context as _, bail};
use crossterm::{
    event::{KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use faultline_protocol::{
    Request, RuleSpec, TIMELINE_VERSION, Timeline, TimelineEvent, TimelineKind, encode_line,
};
use ratatui::{
    Frame, Terminal,
    backend::TestBackend,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
};
use serde_json::Value;

use faultline_orchestrator::TrafficStatus;

#[derive(Clone, Copy)]
pub(super) struct Parameter {
    pub(super) label: &'static str,
    pub(super) key: &'static str,
    pub(super) maximum: u64,
    pub(super) step: u64,
    pub(super) unit: Unit,
}

#[derive(Clone, Copy)]
pub(super) enum Unit {
    Percent,
    Duration,
    Bitrate,
}

pub(super) const PARAMETERS: [Parameter; 6] = [
    Parameter {
        label: "LOSS",
        key: "drop_permyriad",
        maximum: 10_000,
        step: 25,
        unit: Unit::Percent,
    },
    Parameter {
        label: "DUPLICATE",
        key: "duplicate_permyriad",
        maximum: 10_000,
        step: 25,
        unit: Unit::Percent,
    },
    Parameter {
        label: "REORDER",
        key: "reorder_permyriad",
        maximum: 10_000,
        step: 25,
        unit: Unit::Percent,
    },
    Parameter {
        label: "DELAY",
        key: "delay_ns",
        maximum: 1_000_000_000,
        step: 1_000_000,
        unit: Unit::Duration,
    },
    Parameter {
        label: "JITTER",
        key: "jitter_ns",
        maximum: 500_000_000,
        step: 1_000_000,
        unit: Unit::Duration,
    },
    Parameter {
        label: "BANDWIDTH",
        key: "bandwidth_bps",
        maximum: 1_000_000_000,
        step: 1_000_000,
        unit: Unit::Bitrate,
    },
];

pub(super) struct App {
    pub(super) rules: Vec<Value>,
    pub(super) stats: Value,
    pub(super) diagnostics: Value,
    pub(super) selected_rule: usize,
    pub(super) selected_parameter: usize,
    next_id: u64,
    pub(super) status: String,
    pub(super) events: VecDeque<String>,
    pub(super) recording: Option<Recording>,
    pub(super) phase: &'static str,
    pub(super) traffic: TrafficStatus,
}

pub(super) struct Recording {
    path: PathBuf,
    started: Instant,
    pub(super) timeline: Timeline,
}

impl Recording {
    fn record(&mut self, rules: Vec<RuleSpec>) {
        if self.timeline.events.last().map(|event| &event.rules) == Some(&rules) {
            return;
        }
        let at_ms = if self.timeline.events.is_empty() {
            0
        } else {
            elapsed_ms(self.started)
        };
        self.timeline.events.push(TimelineEvent { at_ms, rules });
    }

    fn finish(mut self) -> anyhow::Result<PathBuf> {
        self.timeline.duration_ms = elapsed_ms(self.started);
        self.timeline.validate().map_err(anyhow::Error::msg)?;
        let bytes = serde_json::to_vec_pretty(&self.timeline)?;
        fs::write(&self.path, bytes)
            .with_context(|| format!("writing replay {}", self.path.display()))?;
        Ok(self.path)
    }
}

impl App {
    pub(super) fn new() -> Self {
        Self {
            rules: Vec::new(),
            stats: Value::Null,
            diagnostics: Value::Null,
            selected_rule: 0,
            selected_parameter: 0,
            next_id: 1,
            status: "connecting".to_owned(),
            events: VecDeque::new(),
            recording: None,
            phase: "Connect",
            traffic: TrafficStatus::default(),
        }
    }

    pub(super) fn start_recording(&mut self, path: PathBuf, target: String) {
        self.recording = Some(Recording {
            path,
            started: Instant::now(),
            timeline: Timeline {
                version: TIMELINE_VERSION,
                kind: TimelineKind::Replay,
                name: None,
                target: Some(target),
                duration_ms: 0,
                events: Vec::new(),
            },
        });
    }

    pub(super) fn request(&mut self, writer: &mut dyn Write, kind: &str) -> anyhow::Result<()> {
        let id = self.next_id;
        self.next_id += 1;
        let request = match kind {
            "get_state" => Request::GetState { id },
            "replace_rules" => Request::ReplaceRules {
                id,
                rules: serde_json::from_value::<Vec<RuleSpec>>(Value::Array(self.rules.clone()))?,
            },
            "stop" => Request::Stop { id },
            _ => bail!("unknown request kind {kind}"),
        };
        writer.write_all(&encode_line(&request)?)?;
        writer.flush()?;
        self.status = format!("{kind} #{id} pending");
        Ok(())
    }

    pub(super) fn handle_message(&mut self, line: String) {
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            self.push_event(format!("invalid event: {line}"));
            return;
        };
        match message.get("type").and_then(Value::as_str) {
            Some("state" | "applied") => {
                if let Some(rules) = message.pointer("/state/rules").and_then(Value::as_array) {
                    self.update_rules(rules);
                }
                self.status = format!(
                    "{} #{}",
                    message["type"].as_str().unwrap_or("ack"),
                    message["id"]
                );
                self.push_event(self.status.clone());
            }
            Some("stats") => self.stats = message,
            Some("diagnostics") => self.diagnostics = message,
            Some("error") => {
                self.status = format!(
                    "ERROR: {}",
                    message["message"].as_str().unwrap_or("unknown")
                );
                self.push_event(self.status.clone());
            }
            Some(kind) => self.push_event(format!("{kind}: {line}")),
            None => self.push_event(format!("event: {line}")),
        }
    }

    pub(super) fn finish_recording(&mut self) -> anyhow::Result<Option<PathBuf>> {
        self.recording.take().map(Recording::finish).transpose()
    }

    fn update_rules(&mut self, rules: &[Value]) {
        self.rules = rules.to_vec();
        self.selected_rule = self.selected_rule.min(self.rules.len().saturating_sub(1));
        let parsed = serde_json::from_value::<Vec<RuleSpec>>(Value::Array(self.rules.clone()));
        if let (Some(recording), Ok(rules)) = (&mut self.recording, parsed) {
            recording.record(rules);
        }
    }

    pub(super) fn adjust(&mut self, direction: i8, coarse: bool) -> bool {
        let Some(rule) = self.rules.get_mut(self.selected_rule) else {
            return false;
        };
        let parameter = PARAMETERS[self.selected_parameter];
        let Some(object) = rule.as_object_mut() else {
            return false;
        };
        let current = object
            .get(parameter.key)
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let step = parameter.step.saturating_mul(if coarse { 10 } else { 1 });
        let next = if direction > 0 {
            current.saturating_add(step).min(parameter.maximum)
        } else {
            current.saturating_sub(step)
        };
        if next == current {
            return false;
        }
        object.insert(parameter.key.to_owned(), Value::from(next));
        true
    }

    fn push_event(&mut self, event: String) {
        self.events.push_front(event);
        self.events.truncate(8);
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

pub(super) struct TerminalGuard;

impl TerminalGuard {
    pub(super) fn enter() -> anyhow::Result<Self> {
        enable_raw_mode()?;
        execute!(stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen);
    }
}

pub(super) fn render_snapshot(
    app: &App,
    label: &str,
    width: u16,
    height: u16,
) -> anyhow::Result<String> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend)?;
    terminal.draw(|frame| draw(frame, app, label))?;
    let mut rendered = String::new();
    for row in terminal.backend().buffer().content().chunks(width as usize) {
        let line = row.iter().map(|cell| cell.symbol()).collect::<String>();
        rendered.push_str(line.trim_end());
        rendered.push('\n');
    }
    Ok(rendered)
}

pub(super) fn handle_key(
    key: KeyEvent,
    app: &mut App,
    writer: &mut dyn Write,
) -> anyhow::Result<bool> {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
        KeyCode::Char('x') => app.request(writer, "stop")?,
        KeyCode::Char('r') => app.request(writer, "get_state")?,
        KeyCode::Up | KeyCode::Char('k') => {
            app.selected_parameter = app.selected_parameter.saturating_sub(1)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.selected_parameter = (app.selected_parameter + 1).min(PARAMETERS.len() - 1)
        }
        KeyCode::PageUp | KeyCode::Char('[') => {
            app.selected_rule = app.selected_rule.saturating_sub(1)
        }
        KeyCode::PageDown | KeyCode::Char(']') => {
            app.selected_rule = (app.selected_rule + 1).min(app.rules.len().saturating_sub(1))
        }
        KeyCode::Left | KeyCode::Char('h') => {
            if app.adjust(-1, key.modifiers.contains(KeyModifiers::SHIFT)) {
                app.request(writer, "replace_rules")?;
            }
        }
        KeyCode::Right | KeyCode::Char('l') => {
            if app.adjust(1, key.modifiers.contains(KeyModifiers::SHIFT)) {
                app.request(writer, "replace_rules")?;
            }
        }
        KeyCode::Char('0') => {
            let parameter = PARAMETERS[app.selected_parameter];
            if let Some(rule) = app
                .rules
                .get_mut(app.selected_rule)
                .and_then(Value::as_object_mut)
            {
                rule.insert(parameter.key.to_owned(), Value::from(0));
                app.request(writer, "replace_rules")?;
            }
        }
        _ => {}
    }
    Ok(false)
}

pub(super) fn draw(frame: &mut Frame, app: &App, socket: &str) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(12),
        Constraint::Length(3),
    ])
    .areas(frame.area());
    let [controls, monitor] =
        Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).areas(body);
    draw_header(frame, header, app, socket);
    draw_controls(frame, controls, app);
    draw_monitor(frame, monitor, app);
    frame.render_widget(
        Paragraph::new(
            "↑↓ select  ←→ tune  Shift=coarse×10  [ ] rule  0 zero  r sync  x stop engine  q quit",
        )
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" PATCH CABLES "),
        ),
        footer,
    );
}

fn draw_header(frame: &mut Frame, area: Rect, app: &App, socket: &str) {
    let rule = app.rules.get(app.selected_rule);
    let route = rule
        .map(|rule| {
            format!(
                "{} → {}",
                text(rule, "source", "*"),
                text(rule, "destination", "?")
            )
        })
        .unwrap_or_else(|| "waiting for state…".to_owned());
    let lifecycle = if area.width >= 110 {
        lifecycle_label(app.phase).to_owned()
    } else {
        format!("[{}]", app.phase)
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " FAULTLINE ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  {}  rule {}/{}  {route}  │  {socket}",
                lifecycle,
                app.selected_rule + 1,
                app.rules.len()
            )),
        ]))
        .block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn lifecycle_label(phase: &str) -> &'static str {
    match phase {
        "Connect" => "✓ Provision → ● Connect → Impair → Observe",
        "Impair" => "✓ Provision → ✓ Connect → ● Impair → Observe",
        "Observe" => "✓ Provision → ✓ Connect → ✓ Impair → ● Observe",
        _ => "● Provision → Connect → Impair → Observe",
    }
}

fn draw_controls(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::vertical([Constraint::Ratio(1, 6); 6]).split(area);
    for (index, parameter) in PARAMETERS.iter().enumerate() {
        let value = app
            .rules
            .get(app.selected_rule)
            .and_then(|rule| rule.get(parameter.key))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let selected = index == app.selected_parameter;
        let color = if selected {
            Color::Magenta
        } else {
            Color::Cyan
        };
        let gauge =
            Gauge::default()
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!(" {} ", parameter.label))
                        .border_style(Style::default().fg(color)),
                )
                .gauge_style(Style::default().fg(color).bg(Color::DarkGray).add_modifier(
                    if selected {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    },
                ))
                .ratio((value as f64 / parameter.maximum as f64).clamp(0.0, 1.0))
                .label(format_value(value, parameter.unit));
        frame.render_widget(gauge, rows[index]);
    }
}

fn draw_monitor(frame: &mut Frame, area: Rect, app: &App) {
    let [meters, events] =
        Layout::vertical([Constraint::Length(14), Constraint::Min(5)]).areas(area);
    let lines = vec![
        Line::from(vec![
            Span::styled("SKB      ", Style::default().fg(Color::Yellow)),
            Span::raw(format!("{:6.2}%", number(&app.stats, "skb_loss_percent"))),
        ]),
        Line::from(vec![
            Span::styled("SEGMENT  ", Style::default().fg(Color::Green)),
            Span::raw(format!(
                "{:6.2}%",
                number(&app.stats, "segment_loss_percent")
            )),
        ]),
        Line::from(vec![
            Span::styled("WIRE     ", Style::default().fg(Color::Cyan)),
            Span::raw(format!("{:6.2}%", number(&app.stats, "byte_loss_percent"))),
        ]),
        Line::raw(format!(
            "matched {:>8}  dropped {:>8}",
            integer(&app.stats, "matched"),
            integer(&app.stats, "dropped")
        )),
        Line::raw(format!("GSO skb {:>10}", integer(&app.stats, "gso_skbs"))),
        Line::raw(format!(
            "NOW loss {:>6.2}%  {:>8.1} pkt/s",
            number(&app.stats, "skb_loss_interval_percent"),
            number(&app.stats, "matched_pps")
        )),
        Line::raw(format!(
            "WIRE {:>8.3} Mbit/s  drop {:>8.3}",
            number(&app.stats, "wire_mbps"),
            number(&app.stats, "dropped_mbps")
        )),
        Line::raw(format!(
            "DUP {:>5}  REORDER {:>5}",
            integer(&app.stats, "duplicated_delta"),
            integer(&app.stats, "reordered_delta")
        )),
        Line::raw(format!(
            "DELAY {:>5}  PACE DROP {:>5}",
            integer(&app.stats, "delayed_delta"),
            integer(&app.stats, "pacing_dropped_delta")
        )),
        Line::raw(format!(
            "MISS DST {:>5}  SRC {:>5}",
            integer(&app.diagnostics, "destination_miss_delta"),
            integer(&app.diagnostics, "source_miss_delta")
        )),
        Line::raw(format!(
            "MISS PROTO {:>3} PORT {:>5} BAD {:>3}",
            integer(&app.diagnostics, "protocol_miss_delta"),
            integer(&app.diagnostics, "port_miss_delta"),
            integer(&app.diagnostics, "malformed_delta")
        )),
        Line::raw(format!(
            "TRAFFIC ok {:>5} fail {:>5} total {:>5}",
            app.traffic.succeeded, app.traffic.failed, app.traffic.attempts
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" OUTPUT METERS "),
        ),
        meters,
    );
    let items = std::iter::once(ListItem::new(Line::styled(
        app.status.clone(),
        Style::default().fg(Color::Yellow),
    )))
    .chain(app.events.iter().map(|line| ListItem::new(line.clone())))
    .collect::<Vec<_>>();
    frame.render_widget(
        List::new(items)
            .block(Block::default().borders(Borders::ALL).title(" EVENT LOG "))
            .highlight_style(Style::default().fg(Color::Magenta))
            .repeat_highlight_symbol(true),
        events,
    );
}

fn format_value(value: u64, unit: Unit) -> String {
    match unit {
        Unit::Percent => format!("{:.2}%", value as f64 / 100.0),
        Unit::Duration => format!("{:.1} ms", value as f64 / 1_000_000.0),
        Unit::Bitrate if value >= 1_000_000 => {
            format!("{:.1} Mbit/s", value as f64 / 1_000_000.0)
        }
        Unit::Bitrate => format!("{} kbit/s", value / 1_000),
    }
}

fn text(value: &Value, key: &str, fallback: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or(fallback)
        .to_owned()
}

fn number(value: &Value, key: &str) -> f64 {
    value.get(key).and_then(Value::as_f64).unwrap_or(0.0)
}

fn integer(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}
