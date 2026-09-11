use std::{io, path::PathBuf, time::Duration};

use anyhow::{Context as _, bail};
use aya::{
    maps::PerCpuArray,
    programs::{SchedClassifier, TcAttachType},
};
use clap::{Parser, ValueEnum};
use faultline_common::{
    DiagnosticStats, FAULTLINE_ENGINE_APPLICATION, LOSS_ALGORITHM_GILBERT_ELLIOTT,
    LOSS_ALGORITHM_HASH, LOSS_ALGORITHM_RANDOM, PROTOCOL_ANY, PROTOCOL_TCP, PROTOCOL_UDP,
    RuleStats,
};
use ipnet::IpNet;
use log::{debug, info};
use tokio::{
    signal,
    sync::{broadcast, watch},
    time,
};

pub(crate) const APPLICATION_NAME: &str = FAULTLINE_ENGINE_APPLICATION;

use crate::{
    attachment::Attachment,
    control::{ControlChannel, ControlCommand, ControlState, OutageWindow, RuleSpec},
    pacing::PacingBackend,
    rule_store::RuleStore,
    stats::{StatsFormat, StatsReporter, report_stats},
};

#[cfg(test)]
use crate::stats::{Previous, StatsEvent, StatsSnapshot, accumulate, encode_msgpack};

mod attachment;
mod control;
mod pacing;
mod rule;
mod rule_store;
mod scenario;
mod socket;
mod stats;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Direction {
    Ingress,
    Egress,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Protocol {
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

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LossAlgorithm {
    /// Repeatable decisions derived from the 5-tuple, packet sequence, and seed.
    Hash,
    /// Non-repeatable decisions using the kernel's BPF pseudo-random helper.
    Random,
    /// Seeded, per-flow two-state burst-loss process implemented in eBPF.
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

#[derive(Debug, Parser)]
#[command(about = "Low-level Aya/TC eBPF engine for network fault sessions")]
struct Options {
    /// Network interface to attach to.
    #[arg(short, long)]
    interface: String,

    /// Load one or more rules from a JSON scenario file.
    #[arg(long, conflicts_with = "destination")]
    scenario: Option<PathBuf>,

    /// Destination IPv4 or IPv6 network to affect.
    #[arg(long, required_unless_present = "scenario")]
    destination: Option<IpNet>,

    /// Optional source network; its address family must match --destination.
    #[arg(long, conflicts_with = "scenario")]
    source: Option<IpNet>,

    /// Attach to ingress or egress.
    #[arg(long, value_enum, default_value_t = Direction::Egress)]
    direction: Direction,

    /// Match any, TCP, or UDP traffic.
    #[arg(long, value_enum, default_value_t = Protocol::Any, conflicts_with = "scenario")]
    protocol: Protocol,

    /// Destination TCP/UDP port. Zero matches all ports.
    #[arg(long, default_value_t = 0, conflicts_with = "scenario")]
    port: u16,

    /// Percentage of matching packets to drop (0 through 100).
    #[arg(long, value_parser = clap::value_parser!(f64), default_value_t = 0.0, conflicts_with = "scenario")]
    loss: f64,

    /// Seed controlling the deterministic loss pattern.
    #[arg(long, default_value_t = 1, conflicts_with = "scenario")]
    seed: u32,

    /// Algorithm used to decide which matching packets are dropped.
    #[arg(long, value_enum, default_value_t = LossAlgorithm::Hash, conflicts_with = "scenario")]
    loss_algorithm: LossAlgorithm,

    /// Stop and detach automatically after this duration (for example 30s or 2m).
    #[arg(long, value_parser = parse_duration)]
    duration: Option<Duration>,

    /// Interval between statistics reports (for example 250ms or 5s).
    #[arg(long, value_parser = parse_duration, default_value = "1s")]
    stats_interval: Duration,

    /// Statistics output format. JSON and MessagePack are written to stdout.
    #[arg(long, value_enum, default_value_t = StatsFormat::Text)]
    stats_format: StatsFormat,

    /// Serve the live JSON Lines control protocol on this Unix socket.
    #[arg(long)]
    control_socket: Option<PathBuf>,

    /// Seeded egress delay implemented with BPF Earliest Departure Time.
    #[arg(long, value_parser = parse_duration, conflicts_with = "scenario")]
    delay: Option<Duration>,

    /// Seeded uniform delay variation; requires --delay.
    #[arg(long, value_parser = parse_duration, conflicts_with = "scenario")]
    jitter: Option<Duration>,

    /// Seeded percentage of packets duplicated by the BPF classifier.
    #[arg(long, value_parser = clap::value_parser!(f64), default_value_t = 0.0, conflicts_with = "scenario")]
    duplicate: f64,

    /// Seeded percentage of packets sent without their configured delay.
    #[arg(long, value_parser = clap::value_parser!(f64), default_value_t = 0.0, conflicts_with = "scenario")]
    reorder: f64,

    /// Seeded aggregate pacing rate, for example 10mbit or 500kbit.
    #[arg(long, conflicts_with = "scenario")]
    bandwidth: Option<String>,

    /// Gilbert-Elliott probability of entering a burst-loss state.
    #[arg(long, value_parser = clap::value_parser!(f64), conflicts_with = "scenario")]
    burst_loss: Option<f64>,

    /// Probability of recovering from a burst-loss state.
    #[arg(long, value_parser = clap::value_parser!(f64), default_value_t = 25.0, conflicts_with = "scenario")]
    burst_recovery: f64,

    /// Packet loss percentage while in the burst-loss state.
    #[arg(long, value_parser = clap::value_parser!(f64), default_value_t = 100.0, conflicts_with = "scenario")]
    burst_bad_loss: f64,

    /// Packet loss percentage while in the good state.
    #[arg(long, value_parser = clap::value_parser!(f64), default_value_t = 0.0, conflicts_with = "scenario")]
    burst_good_loss: f64,

    /// Reset an idle flow to the good state after this duration.
    #[arg(long, value_parser = parse_duration, requires = "burst_loss", conflicts_with = "scenario")]
    burst_idle_reset: Option<Duration>,

    /// Start a complete filtered outage after this duration.
    #[arg(long, value_parser = parse_duration, requires = "outage_duration")]
    outage_after: Option<Duration>,

    /// Duration of the complete filtered outage.
    #[arg(long, value_parser = parse_duration, requires = "outage_after")]
    outage_duration: Option<Duration>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let options = Options::parse();
    options.validate()?;
    raise_memlock_limit();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/faultline"
    )))?;

    let mut initial_rules = if let Some(path) = &options.scenario {
        scenario::load(path)?
    } else {
        vec![options.compile_rule()]
    };
    validate_rules_for_direction(options.direction, &initial_rules)?;
    let mut control = ControlChannel::for_rules(initial_rules.clone());
    let mut rules = RuleStore::new(
        ebpf.take_map("RULES").context("RULES map not found")?,
        ebpf.take_map("PACE_STATE")
            .context("PACE_STATE map not found")?,
    )?;
    let initial = control
        .receiver
        .recv()
        .await
        .context("control source closed before providing initial rules")?
        .command;
    if !rules.apply(initial)? {
        bail!("control source stopped before attach");
    }
    let attachment = attach(&mut ebpf, &options)?;
    let pacing_required = initial_rules.iter().any(rule_requires_pacing)
        || (options.control_socket.is_some() && matches!(options.direction, Direction::Egress));
    let pacing = PacingBackend.install(&options.interface, pacing_required)?;
    // Tuple fields drop in order: detach before removing queueing resources.
    let _dataplane = (attachment, pacing);
    if let Some(rule) = initial_rules
        .first()
        .copied()
        .filter(|_| options.scenario.is_none())
    {
        control.schedule(rule, options.duration, options.outage());
    } else if let Some(duration) = options.duration {
        let first = initial_rules[0];
        control.schedule(first, Some(duration), None);
    }

    if options.scenario.is_some() {
        info!(
            "loaded {} fault-injection rules on {:?} {}",
            initial_rules.len(),
            options.direction,
            options.interface
        );
    } else {
        let rule = initial_rules[0];
        let effective_loss = rule.drop_permyriad as f64 / 100.0;
        let source = rule
            .source
            .map(|network| network.to_string())
            .unwrap_or_else(|| "*".to_owned());
        match rule.loss_algorithm {
            LOSS_ALGORITHM_HASH => info!(
                "injecting {:.2}% loss on {:?} {} from {} to {} {:?}/{} (algorithm=Hash, seed={}, requested={:.6}%)",
                effective_loss,
                options.direction,
                options.interface,
                source,
                rule.destination,
                options.protocol,
                options.port,
                options.seed,
                options.loss
            ),
            LOSS_ALGORITHM_RANDOM => info!(
                "injecting {:.2}% loss on {:?} {} from {} to {} {:?}/{} (algorithm=Random, requested={:.6}%)",
                effective_loss,
                options.direction,
                options.interface,
                source,
                rule.destination,
                options.protocol,
                options.port,
                options.loss
            ),
            LOSS_ALGORITHM_GILBERT_ELLIOTT => info!(
                "injecting Gilbert-Elliott loss on {:?} {} from {} to {} {:?}/{} (enter={:.2}%, recovery={:.2}%, good_loss={:.2}%, bad_loss={:.2}%, seed={})",
                options.direction,
                options.interface,
                source,
                rule.destination,
                options.protocol,
                options.port,
                options.burst_loss.unwrap_or_default(),
                options.burst_recovery,
                options.burst_good_loss,
                options.burst_bad_loss,
                options.seed
            ),
            _ => unreachable!(),
        }
    }
    match options.duration {
        Some(duration) => info!("stopping automatically after {duration:?}; Ctrl-C stops sooner"),
        None => info!("press Ctrl-C to detach and stop"),
    }
    if pacing_required {
        info!(
            "BPF EDT impairment is active through fq on {} egress",
            options.interface
        );
    }
    if let Some(outage) = options.outage() {
        info!(
            "outage scheduled after {:?} for {:?}",
            outage.after, outage.duration
        );
    }

    let stats: PerCpuArray<_, RuleStats> =
        PerCpuArray::try_from(ebpf.take_map("STATS").context("STATS map not found")?)?;
    let diagnostics: PerCpuArray<_, DiagnosticStats> = PerCpuArray::try_from(
        ebpf.take_map("DIAGNOSTICS")
            .context("DIAGNOSTICS map not found")?,
    )?;
    let mut reporter = StatsReporter::new(options.stats_format);
    let (stats_events, _) = broadcast::channel(64);
    reporter.publish_to(stats_events.clone());
    let (state_sender, state_receiver) = watch::channel(ControlState {
        rules: initial_rules.clone(),
    });
    let _control_socket = options
        .control_socket
        .as_deref()
        .map(|path| {
            socket::ControlSocket::bind(path, control.sender(), state_receiver, stats_events)
        })
        .transpose()?;
    if let Some(path) = &options.control_socket {
        info!("control socket listening on {}", path.display());
    }
    ControlLoop {
        rules: &mut rules,
        stats: &stats,
        diagnostics: &diagnostics,
        commands: &mut control.receiver,
        stats_interval: options.stats_interval,
        reporter: &mut reporter,
        active_rules: &mut initial_rules,
        direction: options.direction,
        state_sender: &state_sender,
    }
    .run()
    .await?;
    info!("detached");
    Ok(())
}

impl Options {
    fn validate(&self) -> anyhow::Result<()> {
        self.validate_runtime()?;
        if self.scenario.is_some() {
            self.validate_scenario()
        } else {
            self.validate_inline()
        }
    }

    fn validate_runtime(&self) -> anyhow::Result<()> {
        validate_non_zero_duration(Some(self.stats_interval), "--stats-interval")?;
        validate_non_zero_duration(self.duration, "--duration")
    }

    fn validate_scenario(&self) -> anyhow::Result<()> {
        if self.outage_after.is_some() || self.outage_duration.is_some() {
            bail!(
                "--outage-after/--outage-duration are inline-rule options and cannot be used with --scenario"
            );
        }
        Ok(())
    }

    fn validate_inline(&self) -> anyhow::Result<()> {
        let rule = self.rule_input()?.compile()?;
        validate_rules_for_direction(self.direction, std::slice::from_ref(&rule))?;
        validate_non_zero_duration(self.outage_duration, "--outage-duration")
    }

    fn outage(&self) -> Option<OutageWindow> {
        Some(OutageWindow {
            after: self.outage_after?,
            duration: self.outage_duration?,
        })
    }

    fn compile_rule(&self) -> RuleSpec {
        self.rule_input()
            .and_then(rule::RuleInput::compile)
            .expect("inline rule must be validated before compilation")
    }

    fn rule_input(&self) -> anyhow::Result<rule::RuleInput> {
        Ok(rule::RuleInput {
            id: 0,
            source: self.source,
            destination: self.destination.context("inline destination is required")?,
            protocol: self.protocol.number(),
            destination_port: self.port,
            loss: self.loss,
            loss_algorithm: self.loss_algorithm.number(),
            seed: self.seed,
            burst_loss: self.burst_loss,
            burst_recovery: self.burst_recovery,
            burst_bad_loss: self.burst_bad_loss,
            burst_good_loss: self.burst_good_loss,
            burst_idle_reset: self.burst_idle_reset,
            duplicate: self.duplicate,
            reorder: self.reorder,
            delay: self.delay,
            jitter: self.jitter,
            bandwidth_bps: self.bandwidth.as_deref().map(parse_bandwidth).transpose()?,
        })
    }
}

fn validate_non_zero_duration(value: Option<Duration>, option: &str) -> anyhow::Result<()> {
    if value.is_some_and(|duration| duration.is_zero()) {
        bail!("{option} must be greater than zero");
    }
    Ok(())
}

fn rule_requires_pacing(rule: &RuleSpec) -> bool {
    rule.delay_ns != 0
        || rule.jitter_ns != 0
        || rule.reorder_permyriad != 0
        || rule.bandwidth_bps != 0
}

fn parse_bandwidth(value: &str) -> anyhow::Result<u64> {
    const UNITS: &[(&str, u64)] = &[
        ("kbit", 1_000),
        ("mbit", 1_000_000),
        ("gbit", 1_000_000_000),
    ];
    let (number, multiplier) =
        split_unit(value, UNITS).context("--bandwidth must end in kbit, mbit, or gbit")?;
    let amount: u64 = number
        .parse()
        .with_context(|| format!("invalid bandwidth: {value}"))?;
    if amount == 0 {
        bail!("--bandwidth must be greater than zero");
    }
    amount
        .checked_mul(multiplier)
        .context("--bandwidth is too large")
}

fn quantize_loss(percent: f64) -> u32 {
    (percent * 100.0).round() as u32
}

fn attach(ebpf: &mut aya::Ebpf, options: &Options) -> anyhow::Result<Attachment> {
    let attach_type = match options.direction {
        Direction::Ingress => TcAttachType::Ingress,
        Direction::Egress => TcAttachType::Egress,
    };
    let program: &mut SchedClassifier = ebpf
        .program_mut("faultline_classifier")
        .context("faultline_classifier program not found")?
        .try_into()?;
    Attachment::attach(program, &options.interface, attach_type)
}

struct ControlLoop<'a> {
    rules: &'a mut RuleStore,
    stats: &'a PerCpuArray<aya::maps::MapData, RuleStats>,
    diagnostics: &'a PerCpuArray<aya::maps::MapData, DiagnosticStats>,
    commands: &'a mut tokio::sync::mpsc::Receiver<control::ControlEnvelope>,
    stats_interval: Duration,
    reporter: &'a mut StatsReporter,
    active_rules: &'a mut Vec<RuleSpec>,
    direction: Direction,
    state_sender: &'a watch::Sender<ControlState>,
}

impl ControlLoop<'_> {
    async fn run(mut self) -> anyhow::Result<()> {
        let mut interval = time::interval(self.stats_interval);
        let shutdown = shutdown_signal();
        tokio::pin!(shutdown);

        loop {
            let keep_running = tokio::select! {
                result = &mut shutdown => {
                    result?;
                    false
                }
                _ = interval.tick() => {
                    self.report()?;
                    true
                }
                envelope = self.commands.recv() => match envelope {
                    Some(envelope) => self.handle_command(envelope)?,
                    None => {
                        info!("control source closed; detaching");
                        false
                    }
                },
            };
            if !keep_running {
                break;
            }
        }
        self.report()
    }

    fn handle_command(&mut self, envelope: control::ControlEnvelope) -> anyhow::Result<bool> {
        let control::ControlEnvelope { command, response } = envelope;
        let replacement = match &command {
            ControlCommand::ReplaceRules(rules) => Some(rules.clone()),
            ControlCommand::Stop => None,
        };
        let result = replacement
            .as_deref()
            .map(|rules| validate_rules_for_direction(self.direction, rules))
            .transpose()
            .and_then(|_| self.rules.apply(command));

        match result {
            Ok(keep_running) => {
                if let Some(replacement) = replacement {
                    *self.active_rules = replacement;
                    self.state_sender.send_replace(self.state());
                    info!("applied updated fault-injection rules");
                }
                if let Some(response) = response {
                    let _ = response.send(Ok(self.state()));
                }
                Ok(keep_running)
            }
            Err(error) => {
                let Some(response) = response else {
                    return Err(error);
                };
                let _ = response.send(Err(format!("{error:#}")));
                Ok(true)
            }
        }
    }

    fn report(&mut self) -> anyhow::Result<()> {
        report_stats(
            self.stats,
            self.diagnostics,
            self.rules.active_rule_ids(),
            self.reporter,
        )
    }

    fn state(&self) -> ControlState {
        ControlState {
            rules: self.active_rules.clone(),
        }
    }
}

fn validate_rules_for_direction(direction: Direction, rules: &[RuleSpec]) -> anyhow::Result<()> {
    if matches!(direction, Direction::Ingress)
        && rules
            .iter()
            .any(|rule| rule_requires_pacing(rule) || rule.duplicate_permyriad != 0)
    {
        bail!("delay, jitter, duplication, reordering, and bandwidth require egress");
    }
    Ok(())
}

/// Waits for process shutdown on the Linux-only engine.
///
/// There is deliberately no non-Unix fallback: `faultline-engine` cannot reach this
/// function on such a target because the binary also requires TC/eBPF, Unix
/// sockets, and `RLIMIT_MEMLOCK` during compilation and startup.
async fn shutdown_signal() -> io::Result<()> {
    let mut terminate = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    const UNITS: &[(&str, u64)] = &[("ms", 1), ("s", 1_000), ("m", 60_000)];
    let (number, multiplier) =
        split_unit(value, UNITS).ok_or_else(|| "duration must end in ms, s, or m".to_owned())?;
    let amount: u64 = number
        .parse()
        .map_err(|_| "duration must contain an unsigned integer".to_owned())?;
    let milliseconds = amount
        .checked_mul(multiplier)
        .ok_or_else(|| "duration is too large".to_owned())?;
    Ok(Duration::from_millis(milliseconds))
}

fn split_unit<'a>(value: &'a str, units: &[(&str, u64)]) -> Option<(&'a str, u64)> {
    units.iter().find_map(|&(suffix, multiplier)| {
        value
            .strip_suffix(suffix)
            .map(|number| (number, multiplier))
    })
}

fn raise_memlock_limit() {
    let limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let result = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
    if result != 0 {
        debug!("failed to remove locked-memory limit: {result}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(arguments: &[&str]) -> Options {
        Options::try_parse_from(arguments).expect("valid CLI arguments")
    }

    #[test]
    fn per_cpu_stats_accumulate_every_counter() {
        let first = RuleStats {
            matched: 1,
            dropped: 2,
            matched_segments: 3,
            dropped_segments: 4,
            matched_bytes: 5,
            dropped_bytes: 6,
            gso_skbs: 7,
            duplicated: 8,
            reordered: 9,
            delayed: 10,
            pacing_dropped: 11,
        };
        assert_eq!(
            accumulate(&[first, first]),
            RuleStats {
                matched: 2,
                dropped: 4,
                matched_segments: 6,
                dropped_segments: 8,
                matched_bytes: 10,
                dropped_bytes: 12,
                gso_skbs: 14,
                duplicated: 16,
                reordered: 18,
                delayed: 20,
                pacing_dropped: 22,
            }
        );

        let first = DiagnosticStats {
            seen: 1,
            duplicate_bypass: 2,
            non_ip: 3,
            malformed: 4,
            no_rules: 5,
            destination_miss: 6,
            source_miss: 7,
            protocol_miss: 8,
            fragment_port_miss: 9,
            port_miss: 10,
            invalid_rule: 11,
        };
        assert_eq!(
            accumulate(&[first, first]),
            DiagnosticStats {
                seen: 2,
                duplicate_bypass: 4,
                non_ip: 6,
                malformed: 8,
                no_rules: 10,
                destination_miss: 12,
                source_miss: 14,
                protocol_miss: 16,
                fragment_port_miss: 18,
                port_miss: 20,
                invalid_rule: 22,
            }
        );
    }

    #[test]
    fn accepts_a_tcp_port_rule() {
        let options = options(&[
            APPLICATION_NAME,
            "--interface",
            "eth0",
            "--destination",
            "10.20.0.0/16",
            "--protocol",
            "tcp",
            "--port",
            "443",
            "--loss",
            "5",
        ]);
        assert!(options.validate().is_ok());
    }

    #[test]
    fn scenario_replaces_inline_rule_arguments() {
        let options = options(&[
            APPLICATION_NAME,
            "--interface",
            "eth0",
            "--scenario",
            "scenario.json",
        ]);
        assert!(options.destination.is_none());
        assert!(options.validate().is_ok());
        assert!(
            Options::try_parse_from([
                APPLICATION_NAME,
                "--interface",
                "eth0",
                "--scenario",
                "scenario.json",
                "--loss",
                "5",
            ])
            .is_err()
        );
    }

    #[test]
    fn rejects_loss_above_one_hundred_percent() {
        let options = options(&[
            APPLICATION_NAME,
            "--interface",
            "eth0",
            "--destination",
            "10.20.0.0/16",
            "--loss",
            "100.1",
        ]);
        assert!(options.validate().is_err());
    }

    #[test]
    fn rejects_a_port_without_tcp_or_udp() {
        let options = options(&[
            APPLICATION_NAME,
            "--interface",
            "eth0",
            "--destination",
            "10.20.0.0/16",
            "--port",
            "443",
            "--loss",
            "5",
        ]);
        assert!(options.validate().is_err());
    }

    #[test]
    fn parses_runtime_durations() {
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert!(parse_duration("30").is_err());
        assert!(parse_duration("1h").is_err());
    }

    #[test]
    fn parses_decimal_bandwidth_units() {
        assert_eq!(parse_bandwidth("10kbit").unwrap(), 10_000);
        assert_eq!(parse_bandwidth("10mbit").unwrap(), 10_000_000);
        assert_eq!(parse_bandwidth("10gbit").unwrap(), 10_000_000_000);
        assert!(parse_bandwidth("10mbps").is_err());
        assert!(parse_bandwidth("0mbit").is_err());
    }

    #[test]
    fn cli_is_decoded_into_a_transport_independent_rule() {
        let options = options(&[
            APPLICATION_NAME,
            "--interface",
            "eth0",
            "--destination",
            "10.20.0.0/16",
            "--protocol",
            "tcp",
            "--port",
            "443",
            "--loss",
            "5",
            "--seed",
            "42",
        ]);
        let rule = options.compile_rule();
        assert_eq!(rule.source, None);
        assert_eq!(Some(rule.destination), options.destination);
        assert_eq!(rule.protocol, PROTOCOL_TCP);
        assert_eq!(rule.loss_algorithm, LOSS_ALGORITHM_HASH);
        assert_eq!(rule.destination_port, 443);
        assert_eq!(rule.drop_permyriad, 500);
        assert_eq!(rule.seed, 42);
    }

    #[test]
    fn decodes_an_optional_source_cidr() {
        let options = options(&[
            APPLICATION_NAME,
            "--interface",
            "eth0",
            "--source",
            "192.0.2.0/24",
            "--destination",
            "10.20.0.0/16",
            "--loss",
            "5",
        ]);

        assert_eq!(
            options.compile_rule().source,
            Some("192.0.2.0/24".parse().unwrap())
        );
    }

    #[test]
    fn selects_the_random_loss_algorithm() {
        let options = options(&[
            APPLICATION_NAME,
            "--interface",
            "eth0",
            "--destination",
            "10.20.0.0/16",
            "--loss",
            "5",
            "--loss-algorithm",
            "random",
        ]);
        assert_eq!(options.compile_rule().loss_algorithm, LOSS_ALGORITHM_RANDOM);
    }

    #[test]
    fn burst_options_compile_to_an_ebpf_gilbert_elliott_rule() {
        let options = options(&[
            APPLICATION_NAME,
            "--interface",
            "eth0",
            "--destination",
            "10.20.0.0/16",
            "--direction",
            "ingress",
            "--burst-loss",
            "1",
            "--burst-recovery",
            "25",
            "--burst-good-loss",
            "0.1",
            "--burst-bad-loss",
            "90",
            "--burst-idle-reset",
            "30s",
        ]);

        assert!(options.validate().is_ok());
        let rule = options.compile_rule();
        assert_eq!(rule.loss_algorithm, LOSS_ALGORITHM_GILBERT_ELLIOTT);
        assert_eq!(rule.ge_enter_permyriad, 100);
        assert_eq!(rule.ge_recover_permyriad, 2_500);
        assert_eq!(rule.ge_good_loss_permyriad, 10);
        assert_eq!(rule.ge_bad_loss_permyriad, 9_000);
        assert_eq!(rule.ge_idle_reset_secs, 30);
        assert!(!rule_requires_pacing(&rule));
    }

    #[test]
    fn stats_snapshot_contains_totals_deltas_and_loss_rate() {
        let mut reporter = StatsReporter::new(StatsFormat::Json);
        reporter.previous.insert(
            7,
            Previous {
                total: RuleStats {
                    matched: 80,
                    dropped: 20,
                    matched_segments: 800,
                    dropped_segments: 240,
                    matched_bytes: 80_000,
                    dropped_bytes: 16_000,
                    ..Default::default()
                },
                elapsed_ms: 0,
            },
        );

        let snapshot = reporter.snapshot(
            7,
            RuleStats {
                matched: 100,
                dropped: 25,
                matched_segments: 1_000,
                dropped_segments: 250,
                matched_bytes: 100_000,
                dropped_bytes: 20_000,
                gso_skbs: 90,
                ..Default::default()
            },
        );

        assert_eq!(snapshot.rule_id, 7);
        assert_eq!(snapshot.matched, 100);
        assert_eq!(snapshot.dropped, 25);
        assert_eq!(snapshot.matched_delta, 20);
        assert_eq!(snapshot.dropped_delta, 5);
        assert_eq!(snapshot.matched_segments_delta, 200);
        assert_eq!(snapshot.dropped_segments_delta, 10);
        assert_eq!(snapshot.matched_bytes_delta, 20_000);
        assert_eq!(snapshot.dropped_bytes_delta, 4_000);
        assert_eq!(snapshot.gso_skbs_delta, 90);
        assert_eq!(snapshot.pacing_dropped_delta, 0);
        assert_eq!(snapshot.loss_percent(), 25.0);
        assert_eq!(snapshot.segment_loss_percent(), 25.0);
        assert_eq!(snapshot.byte_loss_percent(), 20.0);
    }

    #[test]
    fn stats_loss_rate_is_zero_before_any_match() {
        assert_eq!(StatsSnapshot::default().loss_percent(), 0.0);
    }

    #[test]
    fn stats_event_exposes_interval_rates_and_impairment_ratios() {
        let event = StatsEvent::from(StatsSnapshot {
            interval_ms: 500,
            matched_delta: 100,
            dropped_delta: 25,
            matched_segments_delta: 200,
            dropped_segments_delta: 20,
            matched_bytes_delta: 1_000_000,
            dropped_bytes_delta: 250_000,
            gso_skbs_delta: 40,
            duplicated_delta: 10,
            reordered_delta: 5,
            delayed_delta: 50,
            pacing_dropped_delta: 2,
            ..Default::default()
        });

        assert_eq!(event.skb_loss_interval_percent, 25.0);
        assert_eq!(event.segment_loss_interval_percent, 10.0);
        assert_eq!(event.byte_loss_interval_percent, 25.0);
        assert_eq!(event.matched_pps, 200.0);
        assert_eq!(event.dropped_pps, 50.0);
        assert_eq!(event.wire_mbps, 16.0);
        assert_eq!(event.dropped_mbps, 4.0);
        assert_eq!(event.gso_interval_percent, 40.0);
        assert_eq!(event.duplicated_interval_percent, 10.0);
        assert_eq!(event.reordered_interval_percent, 5.0);
        assert_eq!(event.delayed_interval_percent, 50.0);
        assert_eq!(event.pacing_dropped_interval_percent, 2.0);
    }

    #[test]
    fn msgpack_stats_are_prefixed_with_a_big_endian_frame_length() {
        let frame = encode_msgpack(StatsSnapshot {
            rule_id: 7,
            elapsed_ms: 1_000,
            matched: 100,
            dropped: 25,
            matched_delta: 20,
            dropped_delta: 5,
            duplicated: 0,
            reordered: 0,
            delayed: 0,
            pacing_dropped: 0,
            duplicated_delta: 0,
            reordered_delta: 0,
            delayed_delta: 0,
            pacing_dropped_delta: 0,
            ..Default::default()
        })
        .unwrap();
        let payload_length = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;

        assert_eq!(payload_length, frame.len() - 4);
        assert!(!frame[4..].is_empty());
    }

    #[test]
    fn accepts_queue_impairment_options_on_egress() {
        let options = options(&[
            APPLICATION_NAME,
            "--interface",
            "eth0",
            "--destination",
            "10.20.0.0/16",
            "--direction",
            "egress",
            "--delay",
            "100ms",
            "--jitter",
            "20ms",
            "--duplicate",
            "2",
            "--reorder",
            "5",
            "--bandwidth",
            "10mbit",
            "--burst-loss",
            "1",
        ]);

        assert!(options.validate().is_ok());
        let rule = options.compile_rule();
        assert!(rule_requires_pacing(&rule));
        assert_eq!(rule.delay_ns, 100_000_000);
        assert_eq!(rule.jitter_ns, 20_000_000);
        assert_eq!(rule.duplicate_permyriad, 200);
        assert_eq!(rule.reorder_permyriad, 500);
        assert_eq!(rule.bandwidth_bps, 10_000_000);
    }

    #[test]
    fn rejects_queue_impairments_on_ingress() {
        let options = options(&[
            APPLICATION_NAME,
            "--interface",
            "eth0",
            "--destination",
            "10.20.0.0/16",
            "--direction",
            "ingress",
            "--delay",
            "10ms",
        ]);

        assert!(options.validate().is_err());
    }

    #[test]
    fn decodes_an_outage_window() {
        let options = options(&[
            APPLICATION_NAME,
            "--interface",
            "eth0",
            "--destination",
            "10.20.0.0/16",
            "--outage-after",
            "2s",
            "--outage-duration",
            "500ms",
        ]);

        assert_eq!(
            options.outage(),
            Some(OutageWindow {
                after: Duration::from_secs(2),
                duration: Duration::from_millis(500),
            })
        );
    }

    #[test]
    fn loss_quantization_is_explicit_and_rejects_values_that_disappear() {
        let too_small = options(&[
            APPLICATION_NAME,
            "--interface",
            "eth0",
            "--destination",
            "10.20.0.0/16",
            "--loss",
            "0.001",
        ]);
        assert!(too_small.validate().is_err());
        assert_eq!(quantize_loss(0.01), 1);
        assert_eq!(quantize_loss(12.345), 1235);
    }

    #[test]
    fn stats_deltas_are_tracked_independently_per_rule() {
        let mut reporter = StatsReporter::new(StatsFormat::Json);
        let first = reporter.snapshot(
            1,
            RuleStats {
                matched: 10,
                dropped: 2,
                pacing_dropped: 1,
                ..Default::default()
            },
        );
        let second = reporter.snapshot(
            2,
            RuleStats {
                matched: 20,
                dropped: 5,
                ..Default::default()
            },
        );

        assert_eq!(first.matched_delta, 10);
        assert_eq!(first.pacing_dropped_delta, 1);
        assert_eq!(second.matched_delta, 20);
    }
}
