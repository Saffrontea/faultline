mod app;
mod builder;
mod timeline;
#[cfg(test)]
use std::io::Read;
use std::{
    fs,
    io::{BufRead as _, BufReader, Write, stdout},
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, bail};
use app::{App, TerminalGuard, draw, handle_key, render_snapshot};
use clap::{Parser, ValueEnum};
use crossterm::event::{self, Event};
#[cfg(test)]
use faultline_common::FLT_APPLICATION;
use faultline_common::{DEFAULT_AGENT_IMAGE, FAULTLINE_AGENT_APPLICATION};
#[cfg(test)]
use faultline_orchestrator::TrafficStatus;
#[cfg(test)]
use faultline_orchestrator::session::{
    agent_arguments, agent_command, container_target, resolve_target,
};
use faultline_orchestrator::session::{discover_targets, finish_child};
#[cfg(test)]
use faultline_orchestrator::timeline::rules_impair;
use faultline_orchestrator::timeline::{
    load as load_timeline, play as play_timeline, set_loss_once,
};
use faultline_orchestrator::{Session, SessionOptions, Tooling, prepare_experiment};
use faultline_protocol::{Request, TimelineKind, encode_line};
#[cfg(test)]
use faultline_protocol::{RuleSpec, TIMELINE_VERSION, Timeline, TimelineEvent};
use faultline_runtime::{ExperimentSpec, SystemResolver};
#[cfg(test)]
use ratatui::style::Color;
use ratatui::{Terminal, backend::CrosstermBackend};
#[cfg(test)]
use serde_json::{Value, json};
use timeline::run_observed as run_observed_timeline;

#[derive(Debug, Parser)]
#[command(about = "Build, run, and observe repeatable network fault experiments")]
struct Options {
    /// Target URI: local://IFACE, lxc://CONTAINER/IFACE, docker://CONTAINER/IFACE.
    target: Option<String>,

    /// Discover running Docker/LXC containers and exit.
    #[arg(long)]
    list_targets: bool,

    /// Execute a TUI-authored experiment manifest. The source is resolved to
    /// an agent target and the destination is snapshotted to L3 rules.
    #[arg(long, conflicts_with_all = ["target", "profile", "replay", "record", "set_loss"])]
    experiment: Option<PathBuf>,

    /// Open the visual experiment builder. Ctrl-S saves the manifest and
    /// Ctrl-E saves it, resolves its destination, and executes it immediately.
    #[arg(long, conflicts_with_all = ["target", "experiment", "profile", "replay", "record", "set_loss"])]
    new_experiment: Option<PathBuf>,

    /// Open an existing experiment in the visual builder. Fields outside the
    /// simple visual surface are preserved during round-trip saves.
    #[arg(long, conflicts_with_all = ["target", "experiment", "new_experiment", "profile", "replay", "record", "set_loss"])]
    edit_experiment: Option<PathBuf>,

    /// Write the effective attach point, snapshotted addresses, and timeline.
    #[arg(long)]
    resolved_output: Option<PathBuf>,

    /// Connect to an already-running Unix socket instead of spawning an agent.
    #[cfg(unix)]
    #[arg(short, long, conflicts_with = "target")]
    socket: Option<PathBuf>,

    /// Destination used for an agent's initial pass-through rule.
    #[arg(long, default_value = "0.0.0.0/0")]
    destination: String,

    /// TC direction. auto uses endpoint egress; host-side veth observers can
    /// explicitly select ingress.
    #[arg(long, value_enum, default_value_t = Direction::Auto)]
    direction: Direction,

    #[arg(long, default_value = FAULTLINE_AGENT_APPLICATION)]
    agent: String,

    /// faultline-engine engine path visible inside the selected runtime.
    #[arg(long)]
    engine: Option<String>,

    #[arg(long, default_value = DEFAULT_AGENT_IMAGE)]
    agent_image: String,

    /// Apply one loss value and exit without entering the interactive screen.
    #[arg(long, value_parser = clap::value_parser!(f64))]
    set_loss: Option<f64>,

    /// Keep a non-interactive --set-loss session alive before cleanup.
    #[arg(long, default_value_t = 0, requires = "set_loss")]
    hold_seconds: u64,

    /// Play an authored profile timeline and exit after its duration.
    #[arg(long, conflicts_with_all = ["replay", "record", "set_loss"])]
    profile: Option<PathBuf>,

    /// Replay a previously recorded timeline and exit after its duration.
    #[arg(long, conflicts_with_all = ["profile", "record", "set_loss"])]
    replay: Option<PathBuf>,

    /// Record acknowledged interactive rule states to a JSON replay file.
    #[arg(long, conflicts_with_all = ["profile", "replay", "set_loss"])]
    record: Option<PathBuf>,

    /// Drive the real session without a TTY, render once through TestBackend,
    /// print the screen as text, and exit. Intended for UI integration tests.
    #[arg(long, conflicts_with_all = ["profile", "replay", "record", "set_loss"])]
    snapshot_after_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Direction {
    Auto,
    Ingress,
    Egress,
}

impl Direction {
    const fn orchestration(self) -> faultline_orchestrator::Direction {
        match self {
            Self::Auto => faultline_orchestrator::Direction::Auto,
            Self::Ingress => faultline_orchestrator::Direction::Ingress,
            Self::Egress => faultline_orchestrator::Direction::Egress,
        }
    }
}

impl Options {
    fn session_options(&self) -> SessionOptions {
        SessionOptions {
            target: self.target.clone(),
            #[cfg(unix)]
            socket: self.socket.clone(),
            destination: self.destination.clone(),
            direction: self.direction.orchestration(),
            agent: self.agent.clone(),
            engine: self.engine.clone(),
            agent_image: self.agent_image.clone(),
        }
    }
}

fn main() -> anyhow::Result<()> {
    let mut options = Options::parse();
    if options.list_targets {
        for target in discover_targets() {
            println!("{target}");
        }
        return Ok(());
    }
    if wants_default_builder(&options) {
        options.new_experiment = Some(PathBuf::from("experiment.yaml"));
    }
    let experiment_path = options
        .new_experiment
        .as_ref()
        .or(options.edit_experiment.as_ref())
        .or(options.experiment.as_ref())
        .cloned();
    let built_experiment = if let Some(path) = &options.new_experiment {
        match builder::run(path)? {
            Some(plan) => Some(plan),
            None => return Ok(()),
        }
    } else if let Some(path) = &options.edit_experiment {
        let spec = load_experiment_spec(path)?;
        match builder::edit(path, spec)? {
            Some(plan) => Some(plan),
            None => return Ok(()),
        }
    } else {
        None
    };
    let experiment_spec = built_experiment.or(options
        .experiment
        .as_ref()
        .map(load_experiment_spec)
        .transpose()?);
    if options.resolved_output.is_some() && experiment_spec.is_none() {
        bail!("--resolved-output requires --experiment, --new-experiment, or --edit-experiment");
    }
    let prepared_experiment = experiment_spec
        .as_ref()
        .map(|spec| {
            prepare_experiment(
                spec,
                &SystemResolver,
                Tooling {
                    agent: &options.agent,
                    engine: options.engine.as_deref(),
                },
            )
        })
        .transpose()?;
    let (experiment, _workload) = prepared_experiment
        .map(|prepared| prepared.into_parts())
        .map_or((None, None), |(plan, workload)| {
            (Some(plan), Some(workload))
        });
    if let Some(plan) = &experiment {
        options.target = plan.timeline.target.clone();
        options.destination = plan
            .destination
            .networks
            .first()
            .context("resolved experiment has no destination")?
            .to_string();
        let resolved_path = options
            .resolved_output
            .clone()
            .or_else(|| experiment_path.as_deref().map(resolved_sidecar_path));
        if let Some(path) = &resolved_path {
            fs::write(path, serde_json::to_vec_pretty(plan)?)
                .with_context(|| format!("writing resolved experiment {}", path.display()))?;
        }
    }
    let traffic_plan = experiment.as_ref().and_then(|plan| {
        plan.traffic
            .clone()
            .map(|traffic| (plan.attach.clone(), traffic))
    });
    let observe_experiment = experiment.is_some();
    let playback = experiment.map(|plan| plan.timeline).or(options
        .profile
        .as_ref()
        .map(|path| (path, TimelineKind::Profile))
        .or_else(|| {
            options
                .replay
                .as_ref()
                .map(|path| (path, TimelineKind::Replay))
        })
        .map(|(path, kind)| load_timeline(path, kind))
        .transpose()?);
    if options.target.is_none()
        && let Some(target) = playback
            .as_ref()
            .and_then(|timeline| timeline.target.clone())
    {
        options.target = Some(target);
    }
    let session = Session::open(&options.session_options())?;
    let Session {
        reader,
        mut writer,
        mut child,
        label,
        record_target,
        owned,
    } = session;
    if let Some(timeline) = playback {
        if observe_experiment {
            let result = run_observed_timeline(
                &timeline,
                reader,
                &mut *writer,
                &label,
                traffic_plan.as_ref(),
                options.snapshot_after_ms,
            );
            if owned {
                let _ = writer.write_all(&encode_line(&Request::Stop { id: u64::MAX })?);
                let _ = writer.flush();
            }
            drop(writer);
            finish_child(&mut child);
            return result;
        }
        let result = play_timeline(&timeline, reader, &mut *writer);
        if owned {
            let _ = writer.write_all(&encode_line(&Request::Stop { id: u64::MAX })?);
            let _ = writer.flush();
        }
        drop(writer);
        finish_child(&mut child);
        return result;
    }
    if let Some(loss) = options.set_loss {
        let result = set_loss_once(reader, &mut *writer, loss);
        if result.is_ok() && options.hold_seconds != 0 {
            thread::sleep(Duration::from_secs(options.hold_seconds));
        }
        drop(writer);
        finish_child(&mut child);
        return result;
    }
    let (messages, incoming) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            match line {
                Ok(line) => {
                    // Once the observed screen is gone, keep draining until
                    // the agent closes stdout. Dropping the pipe before its
                    // final Stopping response turns clean shutdown into EPIPE.
                    let _ = messages.send(line);
                }
                Err(_) => break,
            }
        }
    });

    let mut app = App::new();
    if let Some(path) = options.record.clone() {
        app.start_recording(path, record_target);
    }
    app.request(&mut *writer, "get_state")?;
    if let Some(after_ms) = options.snapshot_after_ms {
        if after_ms == 0 {
            bail!("--snapshot-after-ms must be greater than zero");
        }
        let deadline = Instant::now() + Duration::from_millis(after_ms);
        while let Some(wait) = deadline.checked_duration_since(Instant::now()) {
            match incoming.recv_timeout(wait.min(Duration::from_millis(100))) {
                Ok(message) => app.handle_message(message),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        while let Ok(message) = incoming.try_recv() {
            app.handle_message(message);
        }
        println!("{}", render_snapshot(&app, &label, 140, 32)?);
        if owned {
            let _ = app.request(&mut *writer, "stop");
        }
        drop(writer);
        finish_child(&mut child);
        return Ok(());
    }
    let guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    loop {
        while let Ok(message) = incoming.try_recv() {
            app.handle_message(message);
        }
        terminal.draw(|frame| draw(frame, &app, &label))?;
        if !event::poll(Duration::from_millis(50))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != crossterm::event::KeyEventKind::Press {
            continue;
        }
        if handle_key(key, &mut app, &mut *writer)? {
            break;
        }
    }

    // Keys can arrive between the quit event and completion of the agent
    // shutdown. Do not let those raw escape bytes leak into the caller's shell.
    while event::poll(Duration::ZERO).unwrap_or(false) {
        if event::read().is_err() {
            break;
        }
    }
    drop(terminal);
    drop(guard);

    if let Some(path) = app.finish_recording()? {
        println!("replay written to {}", path.display());
    }

    if owned {
        let _ = app.request(&mut *writer, "stop");
    }
    drop(writer);
    finish_child(&mut child);
    Ok(())
}

fn wants_default_builder(options: &Options) -> bool {
    #[cfg(unix)]
    let has_socket = options.socket.is_some();
    #[cfg(not(unix))]
    let has_socket = false;
    options.target.is_none()
        && options.experiment.is_none()
        && options.new_experiment.is_none()
        && options.edit_experiment.is_none()
        && options.profile.is_none()
        && options.replay.is_none()
        && options.record.is_none()
        && options.set_loss.is_none()
        && options.snapshot_after_ms.is_none()
        && options.resolved_output.is_none()
        && !has_socket
}

fn resolved_sidecar_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.resolved.json", path.display()))
}

fn load_experiment_spec(path: &PathBuf) -> anyhow::Result<ExperimentSpec> {
    let bytes = fs::read(path).with_context(|| format!("reading experiment {}", path.display()))?;
    let spec: ExperimentSpec = match path.extension().and_then(|value| value.to_str()) {
        Some("yaml" | "yml") => yaml_serde::from_slice(&bytes)
            .with_context(|| format!("decoding YAML experiment {}", path.display()))?,
        Some("json") => serde_json::from_slice(&bytes)
            .with_context(|| format!("decoding JSON experiment {}", path.display()))?,
        _ => bail!("experiment file must have a .yaml, .yml, or .json extension"),
    };
    spec.validate().map_err(anyhow::Error::msg)?;
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use ratatui::backend::TestBackend;

    use super::*;

    fn app() -> App {
        let mut app = App::new();
        app.rules = vec![json!({
            "id": 0,
            "source": null,
            "destination": "10.20.0.0/16",
            "drop_permyriad": 500,
            "duplicate_permyriad": 0,
            "reorder_permyriad": 0,
            "delay_ns": 20_000_000,
            "jitter_ns": 5_000_000,
            "bandwidth_bps": 10_000_000
        })];
        app.stats = json!({
            "skb_loss_percent": 5.0,
            "segment_loss_percent": 4.8,
            "byte_loss_percent": 5.2,
            "matched": 100,
            "dropped": 5,
            "gso_skbs": 12,
            "skb_loss_interval_percent": 7.5,
            "matched_pps": 1250.0,
            "wire_mbps": 12.5,
            "dropped_mbps": 1.25,
            "duplicated_delta": 3,
            "reordered_delta": 2,
            "delayed_delta": 8,
            "pacing_dropped_delta": 1
        });
        app.diagnostics = json!({
            "destination_miss_delta": 9,
            "source_miss_delta": 4,
            "protocol_miss_delta": 3,
            "port_miss_delta": 2,
            "malformed_delta": 1
        });
        app.status = "applied #2".to_owned();
        app
    }

    #[test]
    fn knob_adjustment_changes_the_wire_rule_value() {
        let mut app = app();
        assert!(app.adjust(1, false));
        assert_eq!(app.rules[0]["drop_permyriad"], 525);
        assert!(app.adjust(-1, true));
        assert_eq!(app.rules[0]["drop_permyriad"], 275);
    }

    #[test]
    fn runtime_target_and_agent_arguments_are_transport_only() {
        assert_eq!(container_target("api/eth7").unwrap(), ("api", "eth7"));
        assert_eq!(container_target("api").unwrap(), ("api", "auto"));
        assert_eq!(
            resolve_target(Some("local://eth9")).unwrap(),
            "local://eth9"
        );

        let options = Options::try_parse_from([
            FLT_APPLICATION,
            "local://eth9",
            "--destination",
            "10.0.0.0/8",
            "--engine",
            "/opt/faultline-engine",
        ])
        .unwrap();
        let mut command = Command::new(FAULTLINE_AGENT_APPLICATION);
        agent_arguments(&mut command, "eth9", "local", &options.session_options());
        let arguments = command
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            arguments,
            [
                "--interface",
                "eth9",
                "--direction",
                "egress",
                "--destination",
                "10.0.0.0/8",
                "--engine",
                "/opt/faultline-engine",
            ]
        );

        let docker = agent_command("docker://api/eth0", &options.session_options()).unwrap();
        assert_eq!(docker.get_program(), "docker");
        let docker_arguments = docker
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            docker_arguments
                .windows(2)
                .any(|args| args == ["--network", "container:api"])
        );
        assert!(
            docker_arguments
                .windows(2)
                .any(|args| args == ["--cap-add", "BPF"])
        );
        assert!(docker_arguments.contains(&DEFAULT_AGENT_IMAGE.to_owned()));
        assert!(
            docker_arguments
                .windows(2)
                .any(|args| args == ["--direction", "egress"])
        );
    }

    #[test]
    fn experiment_is_a_top_level_tui_flow_and_can_emit_its_effective_plan() {
        let options = Options::try_parse_from([
            FLT_APPLICATION,
            "--experiment",
            "experiment.yaml",
            "--resolved-output",
            "effective.json",
        ])
        .unwrap();
        assert_eq!(options.experiment, Some(PathBuf::from("experiment.yaml")));
        assert_eq!(
            options.resolved_output,
            Some(PathBuf::from("effective.json"))
        );
        assert!(
            Options::try_parse_from([
                FLT_APPLICATION,
                "local://eth0",
                "--experiment",
                "experiment.yaml"
            ])
            .is_err()
        );
        assert!(
            Options::try_parse_from([
                FLT_APPLICATION,
                "--edit-experiment",
                "experiment.yaml",
                "--experiment",
                "experiment.yaml"
            ])
            .is_err()
        );
        assert!(
            Options::try_parse_from([FLT_APPLICATION, "--resolved-output", "effective.json",])
                .is_ok()
        );
    }

    #[test]
    fn no_argument_invocation_is_reserved_for_the_visual_builder() {
        let options = Options::try_parse_from([FLT_APPLICATION]).unwrap();
        assert!(wants_default_builder(&options));
        let direct = Options::try_parse_from([FLT_APPLICATION, "local://eth0"]).unwrap();
        assert!(!wants_default_builder(&direct));
    }

    #[test]
    fn effective_plan_uses_a_deterministic_manifest_sidecar() {
        assert_eq!(
            resolved_sidecar_path(&PathBuf::from("experiments/api.yaml")),
            PathBuf::from("experiments/api.yaml.resolved.json")
        );
    }

    #[test]
    fn synthesizer_screen_renders_controls_meters_and_ack() {
        let app = app();
        let terminal = render(&app, 120, 32);
        let screen = screen(&terminal);
        for expected in [
            "FAULTLINE",
            "LOSS",
            "BANDWIDTH",
            "OUTPUT METERS",
            "applied #2",
            "5.00%",
            "20.0 ms",
            "10.0 Mbit/s",
            "10.20.0.0/16",
            "1250.0 pkt/s",
            "12.500 Mbit/s",
            "PACE DROP",
            "MISS DST",
            "MISS PROTO",
        ] {
            assert!(
                screen.contains(expected),
                "screen did not contain {expected}"
            );
        }
        let buffer = terminal.backend().buffer();
        assert!(
            buffer
                .content()
                .iter()
                .any(|cell| cell.fg == Color::Magenta)
        );
        assert!(buffer.content().iter().any(|cell| cell.fg == Color::Cyan));
    }

    #[test]
    fn state_ack_error_and_stats_events_update_the_screen_model() {
        let rule = app().rules[0].clone();
        let mut app = App::new();
        app.handle_message(
            json!({
                "type":"state", "id":1,
                "state":{"rules":[rule]}
            })
            .to_string(),
        );
        assert_eq!(app.rules.len(), 1);
        assert_eq!(app.status, "state #1");

        app.handle_message(
            json!({
                "type":"stats", "rule_id":0, "skb_loss_percent":12.5,
                "segment_loss_percent":11.0, "byte_loss_percent":10.0,
                "matched":80, "dropped":10, "gso_skbs":7
            })
            .to_string(),
        );
        assert_eq!(app.stats["matched"], 80);
        assert!(screen(&render(&app, 100, 28)).contains("12.50%"));

        app.handle_message(
            json!({
                "type":"diagnostics", "seen":100,
                "destination_miss_delta":7, "source_miss_delta":2,
                "protocol_miss_delta":1, "port_miss_delta":3,
                "malformed_delta":4
            })
            .to_string(),
        );
        assert_eq!(app.diagnostics["destination_miss_delta"], 7);
        assert!(screen(&render(&app, 100, 28)).contains("MISS DST"));

        app.handle_message(json!({"type":"error", "id":9, "message":"bad patch"}).to_string());
        assert_eq!(app.status, "ERROR: bad patch");
        assert!(app.events.front().unwrap().contains("bad patch"));
    }

    #[test]
    fn experiment_lifecycle_and_generated_traffic_are_visible() {
        let mut app = app();
        app.phase = "Impair";
        app.traffic = TrafficStatus {
            attempts: 12,
            succeeded: 9,
            failed: 3,
            last_error: None,
        };
        let rendered = screen(&render(&app, 150, 32));
        assert!(rendered.contains("✓ Provision → ✓ Connect → ● Impair → Observe"));
        assert!(rendered.contains("TRAFFIC ok     9 fail     3 total    12"));
    }

    #[test]
    fn impairment_phase_detects_every_supported_fault_action() {
        let mut rules = serde_json::from_value::<Vec<RuleSpec>>(Value::Array(app().rules)).unwrap();
        rules[0].drop_permyriad = 0;
        rules[0].duplicate_permyriad = 0;
        rules[0].reorder_permyriad = 0;
        rules[0].delay_ns = 0;
        rules[0].jitter_ns = 0;
        rules[0].bandwidth_bps = 0;
        assert!(!rules_impair(&rules));
        rules[0].delay_ns = 1;
        assert!(rules_impair(&rules));
    }

    #[test]
    fn selected_rule_and_parameter_survive_compact_resize_rendering() {
        let mut app = app();
        let mut second = app.rules[0].clone();
        second["destination"] = Value::from("2001:db8::/64");
        second["drop_permyriad"] = Value::from(2_500);
        app.rules.push(second);
        app.selected_rule = 1;
        app.selected_parameter = 5;

        for (width, height) in [(80, 24), (56, 18)] {
            let rendered = render(&app, width, height);
            let output = screen(&rendered);
            assert!(output.contains("2001:db8::/64"));
            assert!(
                rendered
                    .backend()
                    .buffer()
                    .content()
                    .iter()
                    .any(|cell| cell.fg == Color::Magenta)
            );
        }
    }

    #[test]
    fn headless_player_sends_each_atomic_ruleset_in_timeline_order() {
        let rule = serde_json::from_value::<RuleSpec>(app().rules[0].clone()).unwrap();
        let mut outage = rule;
        outage.drop_permyriad = 10_000;
        let timeline = Timeline {
            version: TIMELINE_VERSION,
            kind: TimelineKind::Profile,
            name: None,
            target: None,
            duration_ms: 0,
            events: vec![
                TimelineEvent {
                    at_ms: 0,
                    rules: vec![rule],
                },
                TimelineEvent {
                    at_ms: 0,
                    rules: vec![outage],
                },
            ],
        };
        let responses = b"{\"type\":\"applied\",\"id\":1,\"state\":{\"rules\":[]}}\n{\"type\":\"stats\"}\n{\"type\":\"applied\",\"id\":2,\"state\":{\"rules\":[]}}\n".to_vec();
        let reader: Box<dyn Read + Send> = Box::new(std::io::Cursor::new(responses));
        let mut written = Vec::new();

        play_timeline(&timeline, reader, &mut written).unwrap();

        let requests = String::from_utf8(written)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Request>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 2);
        let Request::ReplaceRules { id, rules } = &requests[1] else {
            panic!("expected replace_rules");
        };
        assert_eq!(*id, 2);
        assert_eq!(rules[0].drop_permyriad, 10_000);
    }

    #[test]
    fn recorder_keeps_only_acknowledged_distinct_rule_states() {
        let rule = app().rules[0].clone();
        let mut app = App::new();
        app.start_recording(PathBuf::from("unused.json"), "local://eth0".to_owned());
        for (kind, loss) in [("state", 500), ("applied", 500), ("applied", 750)] {
            let mut state = rule.clone();
            state["drop_permyriad"] = Value::from(loss);
            app.handle_message(json!({"type":kind, "id":1, "state":{"rules":[state]}}).to_string());
        }
        let timeline = &app.recording.as_ref().unwrap().timeline;
        assert_eq!(timeline.events.len(), 2);
        assert_eq!(timeline.events[0].at_ms, 0);
        assert_eq!(timeline.events[1].rules[0].drop_permyriad, 750);
    }

    fn render(app: &App, width: u16, height: u16) -> Terminal<TestBackend> {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw(frame, app, "/tmp/faultline-engine.sock"))
            .unwrap();
        terminal
    }

    fn screen(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }
}
