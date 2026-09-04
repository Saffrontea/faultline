use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Context as _;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use faultline_runtime::{
    DestinationSpec, DockerProvision, EXPERIMENT_VERSION, ExperimentSpec, FaultEvent, FaultProfile,
    FaultSpec, LocalProcess, LxcProvision, NetworkProtocol, ResolutionStrategy, TrafficSpec,
    WorkloadLifecycle, WorkloadSpec,
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use crate::TerminalGuard;
use faultline_orchestrator::workload::{self, Discovery};

const FIELD_COUNT: usize = 13;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Runtime {
    Local,
    Docker,
    Lxc,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Template {
    BriefOutage,
    LossyLink,
    SlowLink,
    Custom,
}

impl Template {
    fn label(self) -> &'static str {
        match self {
            Self::BriefOutage => "brief outage",
            Self::LossyLink => "lossy link",
            Self::SlowLink => "slow link",
            Self::Custom => "custom/preserved",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::BriefOutage => Self::LossyLink,
            Self::LossyLink => Self::SlowLink,
            Self::SlowLink | Self::Custom => Self::BriefOutage,
        }
    }
}

impl Runtime {
    fn next(self, direction: i8) -> Self {
        let index = match self {
            Self::Local => 0_i8,
            Self::Docker => 1,
            Self::Lxc => 2,
        };
        match (index + direction).rem_euclid(3) {
            0 => Self::Local,
            1 => Self::Docker,
            _ => Self::Lxc,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Docker => "docker",
            Self::Lxc => "lxc",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BuilderOutcome {
    Save,
    Execute,
    Cancel,
}

pub struct BuilderApp {
    selected: usize,
    runtime: Runtime,
    name: String,
    workload: String,
    image: String,
    interface: String,
    destination: String,
    protocol: NetworkProtocol,
    port: String,
    duration_ms: String,
    outage_start_ms: String,
    outage_end_ms: String,
    loss_percent: String,
    traffic_url: String,
    status: String,
    discovery: Discovery,
    candidate_index: usize,
    original: Option<Box<ExperimentSpec>>,
    template: Template,
    template_delay_ns: u64,
}

impl Default for BuilderApp {
    fn default() -> Self {
        Self {
            selected: 0,
            runtime: Runtime::Local,
            name: "New experiment".to_owned(),
            workload: String::new(),
            image: String::new(),
            interface: "eth0".to_owned(),
            destination: String::new(),
            protocol: NetworkProtocol::Tcp,
            port: "443".to_owned(),
            duration_ms: "10000".to_owned(),
            outage_start_ms: "2000".to_owned(),
            outage_end_ms: "7000".to_owned(),
            loss_percent: "100".to_owned(),
            traffic_url: String::new(),
            status: "Build an experiment; Ctrl-S saves, Ctrl-E saves and runs".to_owned(),
            discovery: Discovery::default(),
            candidate_index: 0,
            original: None,
            template: Template::BriefOutage,
            template_delay_ns: 0,
        }
    }
}

impl BuilderApp {
    fn with_discovery(discovery: Discovery) -> Self {
        let mut app = Self {
            discovery,
            ..Self::default()
        };
        app.adopt_candidate(0);
        app
    }

    fn from_spec(spec: ExperimentSpec, discovery: Discovery) -> Result<Self, String> {
        spec.validate()?;
        if spec.profile.events.len() != 3 || spec.profile.events[0].at_ms != 0 {
            return Err(
                "visual editing currently requires exactly PASS → OUTAGE → RECOVER events"
                    .to_owned(),
            );
        }
        let loss = spec.profile.events[1].fault.drop_permyriad;
        if !loss.is_multiple_of(100) {
            return Err("visual editing requires loss in whole-percent increments".to_owned());
        }
        let (runtime, workload, interface, image) = match &spec.source {
            WorkloadSpec::Local { interface, process } => (
                Runtime::Local,
                String::new(),
                interface.clone(),
                process
                    .as_ref()
                    .map(|value| value.program.clone())
                    .unwrap_or_default(),
            ),
            WorkloadSpec::Docker {
                container,
                interface,
                provision,
                ..
            } => (
                Runtime::Docker,
                container.clone(),
                interface.clone(),
                provision
                    .as_ref()
                    .map(|value| value.image.clone())
                    .unwrap_or_default(),
            ),
            WorkloadSpec::Lxc {
                container,
                interface,
                provision,
                ..
            } => (
                Runtime::Lxc,
                container.clone(),
                interface.clone(),
                provision.as_ref().map(format_lxc_image).unwrap_or_default(),
            ),
        };
        let traffic_url = match &spec.traffic {
            Some(TrafficSpec::Http { url, .. }) => url.clone(),
            _ => String::new(),
        };
        let status = if matches!(spec.traffic, Some(TrafficSpec::Command { .. })) {
            "Editing manifest; command traffic and advanced fields are preserved".to_owned()
        } else {
            "Editing manifest; Ctrl-S saves, Ctrl-E saves and runs".to_owned()
        };
        let template_delay_ns = spec.profile.events[1].fault.delay_ns;
        Ok(Self {
            selected: 0,
            runtime,
            name: spec.name.clone(),
            workload,
            image,
            interface,
            destination: spec.destination.selector.clone(),
            protocol: spec.destination.protocol,
            port: spec
                .destination
                .port
                .map(|value| value.to_string())
                .unwrap_or_default(),
            duration_ms: spec.profile.duration_ms.to_string(),
            outage_start_ms: spec.profile.events[1].at_ms.to_string(),
            outage_end_ms: spec.profile.events[2].at_ms.to_string(),
            loss_percent: (loss / 100).to_string(),
            traffic_url,
            status,
            discovery,
            candidate_index: 0,
            original: Some(Box::new(spec)),
            template: Template::Custom,
            template_delay_ns,
        })
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<BuilderOutcome> {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return match key.code {
                KeyCode::Char('s') => Some(BuilderOutcome::Save),
                KeyCode::Char('e') => Some(BuilderOutcome::Execute),
                KeyCode::Char('q') => Some(BuilderOutcome::Cancel),
                _ => None,
            };
        }
        match key.code {
            KeyCode::Esc => return Some(BuilderOutcome::Cancel),
            KeyCode::F(2) => self.apply_next_template(),
            KeyCode::Tab | KeyCode::Down => self.selected = (self.selected + 1) % FIELD_COUNT,
            KeyCode::BackTab | KeyCode::Up => {
                self.selected = self.selected.checked_sub(1).unwrap_or(FIELD_COUNT - 1)
            }
            KeyCode::Left if self.selected == 0 => {
                self.change_runtime(-1);
            }
            KeyCode::Right if self.selected == 0 => {
                self.change_runtime(1);
            }
            KeyCode::Left
                if self.selected == 2 || self.selected == 3 && self.runtime == Runtime::Local =>
            {
                self.move_candidate(-1)
            }
            KeyCode::Right
                if self.selected == 2 || self.selected == 3 && self.runtime == Runtime::Local =>
            {
                self.move_candidate(1)
            }
            KeyCode::Left if self.selected == 6 => self.cycle_protocol(-1),
            KeyCode::Right if self.selected == 6 => self.cycle_protocol(1),
            KeyCode::Backspace => {
                if let Some(value) = self.selected_text_mut() {
                    value.pop();
                }
            }
            KeyCode::Char(value) => {
                let accepts = !self.selected_is_numeric() || value.is_ascii_digit();
                if accepts && let Some(field) = self.selected_text_mut() {
                    field.push(value);
                }
            }
            _ => {}
        }
        None
    }

    pub fn build(&mut self) -> Result<ExperimentSpec, String> {
        let port = parse_optional_u16(&self.port, "port")?;
        let duration_ms = parse_u64(&self.duration_ms, "duration")?;
        let start = parse_u64(&self.outage_start_ms, "outage start")?;
        let end = parse_u64(&self.outage_end_ms, "outage end")?;
        let loss = self
            .loss_percent
            .parse::<u32>()
            .map_err(|_| "loss must be a whole percentage".to_owned())?;
        if loss > 100 {
            return Err("loss must be between 0 and 100".to_owned());
        }
        if start >= end || end > duration_ms {
            return Err("timeline must satisfy start < end <= duration".to_owned());
        }
        let source = self.build_source()?;
        let profile = self.build_profile(duration_ms, start, end, loss);
        let traffic = self.build_traffic();
        let spec = ExperimentSpec {
            version: self
                .original
                .as_deref()
                .map_or(EXPERIMENT_VERSION, |value| value.version),
            name: self.name.clone(),
            source,
            destination: DestinationSpec {
                selector: self.destination.clone(),
                protocol: self.protocol,
                port,
                resolution: self
                    .original
                    .as_deref()
                    .map_or(ResolutionStrategy::Snapshot, |value| {
                        value.destination.resolution
                    }),
            },
            profile,
            traffic,
            extensions: self
                .original
                .as_deref()
                .map(|value| value.extensions.clone())
                .unwrap_or_default(),
        };
        spec.validate()?;
        Ok(spec)
    }

    fn build_source(&self) -> Result<WorkloadSpec, String> {
        match self.runtime {
            Runtime::Local => Ok(self.build_local_source()),
            Runtime::Docker => Ok(self.build_docker_source()),
            Runtime::Lxc => self.build_lxc_source(),
        }
    }

    fn build_local_source(&self) -> WorkloadSpec {
        let existing = match self.original_source() {
            Some(WorkloadSpec::Local { process, .. }) => process.clone(),
            _ => None,
        };
        let process = update_optional(
            existing,
            &self.image,
            |process| process.program.clone_from(&self.image),
            || LocalProcess {
                program: self.image.clone(),
                args: Vec::new(),
                environment: Default::default(),
                working_directory: None,
            },
        );
        WorkloadSpec::Local {
            interface: self.interface.clone(),
            process,
        }
    }

    fn build_docker_source(&self) -> WorkloadSpec {
        let (lifecycle, existing) = match self.original_source() {
            Some(WorkloadSpec::Docker {
                lifecycle,
                provision,
                ..
            }) => (*lifecycle, provision.clone()),
            _ => (WorkloadLifecycle::Session, None),
        };
        let provision = update_optional(
            existing,
            &self.image,
            |provision| provision.image.clone_from(&self.image),
            || DockerProvision {
                image: self.image.clone(),
                command: Vec::new(),
                environment: Default::default(),
                remove_on_exit: true,
            },
        );
        WorkloadSpec::Docker {
            container: self.workload.clone(),
            interface: self.interface.clone(),
            lifecycle,
            provision,
        }
    }

    fn build_lxc_source(&self) -> Result<WorkloadSpec, String> {
        let (lifecycle, existing) = match self.original_source() {
            Some(WorkloadSpec::Lxc {
                lifecycle,
                provision,
                ..
            }) => (*lifecycle, provision.clone()),
            _ => (WorkloadLifecycle::Session, None),
        };
        let provision = if self.image.trim().is_empty() {
            None
        } else if existing
            .as_ref()
            .is_some_and(|value| format_lxc_image(value) == self.image)
        {
            existing
        } else {
            Some(parse_lxc_provision(&self.image)?)
        };
        Ok(WorkloadSpec::Lxc {
            container: self.workload.clone(),
            interface: self.interface.clone(),
            lifecycle,
            provision,
        })
    }

    fn original_source(&self) -> Option<&WorkloadSpec> {
        self.original.as_deref().map(|value| &value.source)
    }

    fn build_profile(&self, duration_ms: u64, start: u64, end: u64, loss: u32) -> FaultProfile {
        if let Some(original) = self.original.as_deref() {
            let mut profile = original.profile.clone();
            profile.duration_ms = duration_ms;
            profile.events[0].at_ms = 0;
            profile.events[1].at_ms = start;
            profile.events[1].fault.drop_permyriad = loss * 100;
            profile.events[2].at_ms = end;
            profile
        } else {
            let pass = FaultSpec::default();
            let outage = FaultSpec {
                drop_permyriad: loss * 100,
                delay_ns: self.template_delay_ns,
                seed: 1,
                ..FaultSpec::default()
            };
            FaultProfile {
                duration_ms,
                events: vec![
                    FaultEvent {
                        at_ms: 0,
                        fault: pass.clone(),
                    },
                    FaultEvent {
                        at_ms: start,
                        fault: outage,
                    },
                    FaultEvent {
                        at_ms: end,
                        fault: pass,
                    },
                ],
            }
        }
    }

    fn build_traffic(&self) -> Option<TrafficSpec> {
        if !self.traffic_url.trim().is_empty() {
            match self
                .original
                .as_deref()
                .and_then(|value| value.traffic.as_ref())
            {
                Some(TrafficSpec::Http {
                    interval_ms,
                    timeout_ms,
                    ..
                }) => Some(TrafficSpec::Http {
                    url: self.traffic_url.clone(),
                    interval_ms: *interval_ms,
                    timeout_ms: *timeout_ms,
                }),
                _ => Some(TrafficSpec::Http {
                    url: self.traffic_url.clone(),
                    interval_ms: 1_000,
                    timeout_ms: 2_000,
                }),
            }
        } else {
            self.original
                .as_deref()
                .and_then(|value| value.traffic.clone())
        }
    }

    fn selected_text_mut(&mut self) -> Option<&mut String> {
        match self.selected {
            1 => Some(&mut self.name),
            2 => Some(&mut self.workload),
            3 => Some(&mut self.interface),
            4 => Some(&mut self.image),
            5 => Some(&mut self.destination),
            7 => Some(&mut self.port),
            8 => Some(&mut self.duration_ms),
            9 => Some(&mut self.outage_start_ms),
            10 => Some(&mut self.outage_end_ms),
            11 => Some(&mut self.loss_percent),
            12 => Some(&mut self.traffic_url),
            _ => None,
        }
    }

    fn selected_is_numeric(&self) -> bool {
        matches!(self.selected, 7..=11)
    }

    fn cycle_protocol(&mut self, direction: i8) {
        let index = match self.protocol {
            NetworkProtocol::Any => 0_i8,
            NetworkProtocol::Tcp => 1,
            NetworkProtocol::Udp => 2,
        };
        self.protocol = match (index + direction).rem_euclid(3) {
            0 => NetworkProtocol::Any,
            1 => NetworkProtocol::Tcp,
            _ => NetworkProtocol::Udp,
        };
    }

    fn candidates(&self) -> &[String] {
        match self.runtime {
            Runtime::Local => &self.discovery.local_interfaces,
            Runtime::Docker => &self.discovery.docker,
            Runtime::Lxc => &self.discovery.lxc,
        }
    }

    fn change_runtime(&mut self, direction: i8) {
        self.runtime = self.runtime.next(direction);
        self.image.clear();
        self.interface = match self.runtime {
            Runtime::Local => self
                .discovery
                .local_interfaces
                .first()
                .cloned()
                .unwrap_or_else(|| "eth0".to_owned()),
            Runtime::Docker | Runtime::Lxc => "auto".to_owned(),
        };
        self.adopt_candidate(0);
    }

    fn move_candidate(&mut self, direction: i8) {
        let count = self.candidates().len();
        if count == 0 {
            return;
        }
        self.candidate_index =
            (self.candidate_index as i64 + direction as i64).rem_euclid(count as i64) as usize;
        self.adopt_candidate(self.candidate_index);
    }

    fn adopt_candidate(&mut self, index: usize) {
        self.candidate_index = index;
        let candidate = self.candidates().get(index).cloned();
        match self.runtime {
            Runtime::Local => {
                if let Some(interface) = candidate {
                    self.interface = interface;
                }
            }
            Runtime::Docker | Runtime::Lxc => {
                if let Some(workload) = candidate {
                    self.workload = workload;
                }
            }
        }
    }

    fn set_status(&mut self, status: impl Into<String>) {
        self.status = status.into();
    }

    fn apply_next_template(&mut self) {
        self.template = self.template.next();
        match self.template {
            Template::BriefOutage => {
                self.loss_percent = "100".to_owned();
                self.template_delay_ns = 0;
            }
            Template::LossyLink => {
                self.loss_percent = "25".to_owned();
                self.template_delay_ns = 0;
            }
            Template::SlowLink => {
                self.loss_percent = "0".to_owned();
                self.template_delay_ns = 100_000_000;
            }
            Template::Custom => {}
        }
        self.status = format!("Template: {}", self.template.label());
    }
}

pub fn run(path: &PathBuf) -> anyhow::Result<Option<ExperimentSpec>> {
    run_app(path, BuilderApp::with_discovery(workload::discover()))
}

pub fn edit(path: &PathBuf, spec: ExperimentSpec) -> anyhow::Result<Option<ExperimentSpec>> {
    let app = BuilderApp::from_spec(spec, workload::discover()).map_err(anyhow::Error::msg)?;
    run_app(path, app)
}

fn run_app(path: &PathBuf, mut app: BuilderApp) -> anyhow::Result<Option<ExperimentSpec>> {
    let guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    loop {
        terminal.draw(|frame| draw(frame, &app, path))?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != crossterm::event::KeyEventKind::Press {
            continue;
        }
        let Some(outcome) = app.handle_key(key) else {
            continue;
        };
        if outcome == BuilderOutcome::Cancel {
            drop(terminal);
            drop(guard);
            return Ok(None);
        }
        match app.build() {
            Ok(spec) => {
                let execute = outcome == BuilderOutcome::Execute;
                let yaml = yaml_serde::to_string(&spec)?;
                fs::write(path, yaml)
                    .with_context(|| format!("writing experiment {}", path.display()))?;
                drop(terminal);
                drop(guard);
                println!("experiment written to {}", path.display());
                return Ok(execute.then_some(spec));
            }
            Err(error) => app.set_status(format!("ERROR: {error}")),
        }
    }
}

pub fn draw(frame: &mut Frame, app: &BuilderApp, path: &Path) {
    let [header, body, timeline, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(14),
        Constraint::Length(7),
        Constraint::Length(4),
    ])
    .areas(frame.area());
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " EXPERIMENT BUILDER ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  {}", path.display())),
        ]))
        .block(Block::default().borders(Borders::ALL)),
        header,
    );
    let fields = [
        ("Source runtime", app.runtime.label().to_owned()),
        ("Experiment name", app.name.clone()),
        (
            "Container",
            if app.runtime == Runtime::Local {
                "(not used for local)".to_owned()
            } else {
                app.workload.clone()
            },
        ),
        ("Source interface", app.interface.clone()),
        (
            match app.runtime {
                Runtime::Local => "Local program (new)",
                Runtime::Docker => "Docker image (new)",
                Runtime::Lxc => "LXC dist:release:arch",
            },
            match app.runtime {
                Runtime::Local | Runtime::Docker | Runtime::Lxc => app.image.clone(),
            },
        ),
        ("Network destination", app.destination.clone()),
        ("Protocol", format!("{:?}", app.protocol).to_lowercase()),
        ("Port", app.port.clone()),
        ("Duration (ms)", app.duration_ms.clone()),
        ("Outage starts (ms)", app.outage_start_ms.clone()),
        ("Outage ends (ms)", app.outage_end_ms.clone()),
        ("Outage loss (%)", app.loss_percent.clone()),
        ("HTTP traffic URL", app.traffic_url.clone()),
    ];
    let items = fields
        .iter()
        .enumerate()
        .map(|(index, (label, value))| {
            let marker = if index == app.selected { "▶" } else { " " };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{marker} {label:<22}"),
                    Style::default().fg(if index == app.selected {
                        Color::Magenta
                    } else {
                        Color::Cyan
                    }),
                ),
                Span::raw(value),
            ]))
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" SOURCE → L3 DESTINATION "),
        ),
        body,
    );
    draw_timeline(frame, timeline, app);
    frame.render_widget(
        Paragraph::new(vec![
            Line::raw(app.status.clone()),
            Line::raw(
                "F2 template  Tab/↑↓ navigate  ←→ choose  type edit  │  Ctrl-S save  Ctrl-E execute  Esc cancel",
            ),
        ])
        .block(Block::default().borders(Borders::ALL)),
        footer,
    );
}

fn draw_timeline(frame: &mut Frame, area: Rect, app: &BuilderApp) {
    let content = vec![
        Line::raw(format!(
            "[{}] 0ms PASS ───── {}ms IMPAIR ({:.0}% loss, {:.0}ms delay) ───── {}ms RECOVER ───── {}ms",
            app.template.label(),
            app.outage_start_ms,
            app.loss_percent.parse::<f64>().unwrap_or(0.0),
            app.template_delay_ns as f64 / 1_000_000.0,
            app.outage_end_ms,
            app.duration_ms
        )),
        Line::raw("The destination is resolved once to concrete IPv4/IPv6 rules when executed."),
    ];
    frame.render_widget(
        Paragraph::new(content).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" FAULT PROFILE "),
        ),
        area,
    );
}

fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("{name} must be a whole number"))
}

fn update_optional<T>(
    existing: Option<T>,
    input: &str,
    update: impl FnOnce(&mut T),
    create: impl FnOnce() -> T,
) -> Option<T> {
    (!input.trim().is_empty()).then(|| {
        existing
            .map(|mut value| {
                update(&mut value);
                value
            })
            .unwrap_or_else(create)
    })
}

fn parse_optional_u16(value: &str, name: &str) -> Result<Option<u16>, String> {
    (!value.is_empty())
        .then(|| {
            value
                .parse()
                .map_err(|_| format!("{name} must be between 1 and 65535"))
        })
        .transpose()
}

fn parse_lxc_provision(value: &str) -> Result<LxcProvision, String> {
    let parts = value.split(':').collect::<Vec<_>>();
    let [distribution, release, architecture] = parts.as_slice() else {
        return Err("LXC image must be distribution:release:architecture".to_owned());
    };
    if [distribution, release, architecture]
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err("LXC image must be distribution:release:architecture".to_owned());
    }
    Ok(LxcProvision {
        distribution: (*distribution).to_owned(),
        release: (*release).to_owned(),
        architecture: (*architecture).to_owned(),
        remove_on_exit: true,
    })
}

fn format_lxc_image(provision: &LxcProvision) -> String {
    format!(
        "{}:{}:{}",
        provision.distribution, provision.release, provision.architecture
    )
}

#[cfg(test)]
mod tests {
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn builder_edits_source_destination_and_produces_the_shared_manifest() {
        let mut app = BuilderApp::default();
        app.handle_key(key(KeyCode::Right));
        assert_eq!(app.runtime, Runtime::Docker);
        app.selected = 2;
        for character in "web-01".chars() {
            app.handle_key(key(KeyCode::Char(character)));
        }
        app.selected = 5;
        for character in "api.example.test".chars() {
            app.handle_key(key(KeyCode::Char(character)));
        }
        let manifest = app.build().unwrap();
        assert_eq!(manifest.source.target_uri(), "docker://web-01/auto");
        assert_eq!(manifest.destination.selector, "api.example.test");
        assert_eq!(manifest.profile.events[1].fault.drop_permyriad, 10_000);
        let yaml = yaml_serde::to_string(&manifest).unwrap();
        assert_eq!(
            yaml_serde::from_str::<ExperimentSpec>(&yaml).unwrap(),
            manifest
        );
    }

    #[test]
    fn optional_http_traffic_becomes_part_of_the_manifest() {
        let mut app = BuilderApp {
            destination: "api.example.test".into(),
            traffic_url: "https://api.example.test/health".into(),
            ..BuilderApp::default()
        };
        assert_eq!(
            app.build().unwrap().traffic,
            Some(TrafficSpec::Http {
                url: "https://api.example.test/health".into(),
                interval_ms: 1_000,
                timeout_ms: 2_000,
            })
        );
    }

    #[test]
    fn builder_rejects_an_invalid_timeline_before_saving() {
        let mut app = BuilderApp {
            destination: "10.0.0.0/8".into(),
            outage_end_ms: "12000".into(),
            ..BuilderApp::default()
        };
        assert!(app.build().unwrap_err().contains("start < end <= duration"));
    }

    #[test]
    fn builder_screen_exposes_the_complete_experiment_flow() {
        let app = BuilderApp::default();
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal
            .draw(|frame| draw(frame, &app, &PathBuf::from("experiment.yaml")))
            .unwrap();
        let screen = terminal
            .backend()
            .buffer()
            .content()
            .chunks(120)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        for expected in [
            "EXPERIMENT BUILDER",
            "Source runtime",
            "Network destination",
            "FAULT PROFILE",
            "brief outage",
            "F2 template",
            "Ctrl-S save",
            "Ctrl-E execute",
        ] {
            assert!(screen.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn built_in_templates_create_distinct_fault_profiles() {
        let mut app = BuilderApp {
            destination: "10.0.0.0/8".into(),
            ..BuilderApp::default()
        };
        app.handle_key(key(KeyCode::F(2)));
        let lossy = app.build().unwrap();
        assert_eq!(lossy.profile.events[1].fault.drop_permyriad, 2_500);
        app.handle_key(key(KeyCode::F(2)));
        let slow = app.build().unwrap();
        assert_eq!(slow.profile.events[1].fault.drop_permyriad, 0);
        assert_eq!(slow.profile.events[1].fault.delay_ns, 100_000_000);
    }

    #[test]
    fn local_builder_can_own_a_process_without_a_shell() {
        let mut app = BuilderApp {
            destination: "127.0.0.1/32".into(),
            image: "/usr/local/bin/service-under-test".into(),
            ..BuilderApp::default()
        };
        let WorkloadSpec::Local { process, .. } = app.build().unwrap().source else {
            panic!("expected local source");
        };
        assert_eq!(
            process.unwrap().program,
            "/usr/local/bin/service-under-test"
        );
    }

    #[test]
    fn lxc_builder_can_describe_a_download_template() {
        let mut app = BuilderApp {
            runtime: Runtime::Lxc,
            workload: "generated-client".into(),
            image: "debian:trixie:amd64".into(),
            destination: "10.0.0.0/8".into(),
            ..BuilderApp::default()
        };
        let WorkloadSpec::Lxc { provision, .. } = app.build().unwrap().source else {
            panic!("expected LXC source");
        };
        let provision = provision.unwrap();
        assert_eq!(provision.distribution, "debian");
        assert_eq!(provision.release, "trixie");
        assert_eq!(provision.architecture, "amd64");
        assert!(provision.remove_on_exit);
    }

    #[test]
    fn discovered_workloads_can_be_selected_without_typing_names() {
        let discovery = Discovery {
            local_interfaces: vec!["eth0".into(), "wlan0".into()],
            docker: vec!["api-1".into(), "api-2".into()],
            lxc: vec!["db-1".into()],
        };
        let mut app = BuilderApp::with_discovery(discovery);
        assert_eq!(app.interface, "eth0");
        app.handle_key(key(KeyCode::Right));
        assert_eq!(app.runtime, Runtime::Docker);
        assert_eq!(app.workload, "api-1");
        app.selected = 2;
        app.handle_key(key(KeyCode::Right));
        assert_eq!(app.workload, "api-2");
        app.handle_key(key(KeyCode::Right));
        assert_eq!(app.workload, "api-1");
    }

    #[test]
    fn visual_edit_round_trip_preserves_non_visual_manifest_fields() {
        let yaml = r#"
version: 1
name: preserved
source:
  runtime: docker
  container: web
  interface: eth7
  lifecycle: existing
  provision:
    image: example/web:v2
    command: [serve, --verbose]
    environment: {MODE: test}
    remove_on_exit: false
destination:
  selector: 192.0.2.0/24
  protocol: tcp
  port: 8443
profile:
  duration_ms: 9000
  events:
    - {at_ms: 0, drop_permyriad: 0, seed: 17}
    - {at_ms: 1000, drop_permyriad: 2500, delay_ns: 3000000, seed: 23}
    - {at_ms: 7000, drop_permyriad: 0, seed: 29}
traffic:
  kind: command
  program: psql
  args: [--command, "select 1"]
  interval_ms: 333
extensions:
  future.feature: {enabled: true}
"#;
        let original: ExperimentSpec = yaml_serde::from_str(yaml).unwrap();
        let mut app = BuilderApp::from_spec(original.clone(), Discovery::default()).unwrap();
        assert_eq!(app.build().unwrap(), original);

        app.name.push_str(" edited");
        let edited = app.build().unwrap();
        assert_eq!(edited.name, "preserved edited");
        assert_eq!(edited.traffic, original.traffic);
        assert_eq!(edited.extensions, original.extensions);
        assert_eq!(edited.profile.events[1].fault.delay_ns, 3_000_000);
        let WorkloadSpec::Docker {
            provision,
            lifecycle,
            ..
        } = edited.source
        else {
            panic!("expected Docker source");
        };
        assert_eq!(lifecycle, WorkloadLifecycle::Existing);
        assert_eq!(provision.unwrap().command, ["serve", "--verbose"]);
    }

    #[test]
    fn visual_edit_rejects_a_timeline_it_cannot_represent() {
        let mut app = BuilderApp {
            destination: "10.0.0.0/8".into(),
            ..BuilderApp::default()
        };
        let mut spec = app.build().unwrap();
        spec.profile.events.push(FaultEvent {
            at_ms: 8000,
            fault: FaultSpec::default(),
        });
        let Err(error) = BuilderApp::from_spec(spec, Discovery::default()) else {
            panic!("unsupported timeline was accepted");
        };
        assert!(error.contains("exactly PASS"));
    }
}
