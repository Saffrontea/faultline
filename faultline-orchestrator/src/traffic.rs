//! Shell-free generated traffic owned by an experiment session.

use std::{
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime},
};

use anyhow::Context as _;
use faultline_runtime::{AttachSpec, TrafficSpec};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TrafficStatus {
    pub attempts: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub last_error: Option<String>,
    pub observations: Vec<TrafficAttempt>,
}

impl TrafficStatus {
    fn record(&mut self, observation: TrafficAttempt) {
        self.attempts += 1;
        if observation.cancelled {
            self.cancelled += 1;
        } else if observation.success {
            self.succeeded += 1;
        } else {
            self.failed += 1;
            if let Some(error) = &observation.error {
                self.last_error = Some(error.clone());
            }
        }
        self.observations.push(observation);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TrafficAttempt {
    pub sequence: u64,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
    pub duration_ms: u64,
    pub success: bool,
    pub cancelled: bool,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
}

pub struct TrafficGuard {
    cancel: Arc<AtomicBool>,
    status: Arc<Mutex<TrafficStatus>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TrafficGuard {
    pub fn start(attach: &AttachSpec, spec: &TrafficSpec) -> anyhow::Result<Self> {
        spec.validate().map_err(anyhow::Error::msg)?;
        let invocation = invocation(attach, spec);
        let interval = Duration::from_millis(spec.interval_ms());
        let cancel = Arc::new(AtomicBool::new(false));
        let status = Arc::new(Mutex::new(TrafficStatus::default()));
        let worker_cancel = Arc::clone(&cancel);
        let worker_status = Arc::clone(&status);
        let worker = thread::Builder::new()
            .name("faultline-traffic".to_owned())
            .spawn(move || run(worker_cancel, worker_status, invocation, interval))
            .context("starting traffic generator")?;
        Ok(Self {
            cancel,
            status,
            thread: Some(worker),
        })
    }

    pub fn status(&self) -> TrafficStatus {
        self.status
            .lock()
            .map(|value| value.clone())
            .unwrap_or_default()
    }

    pub fn stop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for TrafficGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Invocation {
    program: String,
    args: Vec<String>,
}

fn invocation(attach: &AttachSpec, traffic: &TrafficSpec) -> Invocation {
    let (program, args) = traffic_command(traffic);
    match attach {
        AttachSpec::Local { .. } => Invocation { program, args },
        AttachSpec::Docker { container, .. } => Invocation {
            program: "docker".to_owned(),
            args: [vec!["exec".to_owned(), container.clone(), program], args].concat(),
        },
        AttachSpec::Lxc { container, .. } => Invocation {
            program: "lxc-attach".to_owned(),
            args: [
                vec!["-n".to_owned(), container.clone(), "--".to_owned(), program],
                args,
            ]
            .concat(),
        },
    }
}

fn traffic_command(traffic: &TrafficSpec) -> (String, Vec<String>) {
    match traffic {
        TrafficSpec::Http {
            url, timeout_ms, ..
        } => (
            "curl".to_owned(),
            vec![
                "--silent".to_owned(),
                "--show-error".to_owned(),
                "--output".to_owned(),
                "/dev/null".to_owned(),
                "--max-time".to_owned(),
                format!("{:.3}", *timeout_ms as f64 / 1_000.0),
                url.clone(),
            ],
        ),
        TrafficSpec::Command { program, args, .. } => (program.clone(), args.clone()),
    }
}

fn run(
    cancel: Arc<AtomicBool>,
    status: Arc<Mutex<TrafficStatus>>,
    invocation: Invocation,
    interval: Duration,
) {
    while !cancel.load(Ordering::Acquire) {
        let started = Instant::now();
        let sequence = status.lock().map(|status| status.attempts + 1).unwrap_or(1);
        let started_at_unix_ms = unix_ms();
        let result = run_once(&cancel, &invocation);
        let completed_at_unix_ms = unix_ms();
        let (success, cancelled, exit_code, error) = match result {
            Ok(result) => (
                result.status.success(),
                result.cancelled,
                result.status.code(),
                None,
            ),
            Err(error) => (false, false, None, Some(error.to_string())),
        };
        let observation = TrafficAttempt {
            sequence,
            started_at_unix_ms,
            completed_at_unix_ms,
            duration_ms: completed_at_unix_ms.saturating_sub(started_at_unix_ms),
            success,
            cancelled,
            exit_code,
            error,
        };
        if let Ok(mut status) = status.lock() {
            status.record(observation);
        }
        let remaining = interval.saturating_sub(started.elapsed());
        let deadline = Instant::now() + remaining;
        while !cancel.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(50)),
            );
        }
    }
}

fn run_once(cancel: &AtomicBool, invocation: &Invocation) -> anyhow::Result<AttemptExit> {
    let mut child = Command::new(&invocation.program)
        .args(&invocation.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("starting traffic command {}", invocation.program))?;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(AttemptExit {
                status,
                cancelled: false,
            });
        }
        if cancel.load(Ordering::Acquire) {
            let _ = child.kill();
            let status = child
                .wait()
                .context("waiting for cancelled traffic command")?;
            return Ok(AttemptExit {
                status,
                cancelled: true,
            });
        }
        thread::sleep(Duration::from_millis(25));
    }
}

struct AttemptExit {
    status: std::process::ExitStatus,
    cancelled: bool,
}

fn unix_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use faultline_runtime::{DockerProvision, WorkloadLifecycle};

    use super::*;

    fn http() -> TrafficSpec {
        TrafficSpec::Http {
            url: "https://api.example.test/health".into(),
            interval_ms: 500,
            timeout_ms: 1_500,
        }
    }

    #[test]
    fn local_http_invocation_is_shell_free_and_bounded() {
        let invocation = invocation(
            &AttachSpec::Local {
                interface: "eth0".into(),
                process: None,
            },
            &http(),
        );
        assert_eq!(invocation.program, "curl");
        assert!(
            invocation
                .args
                .windows(2)
                .any(|pair| pair == ["--max-time", "1.500"])
        );
        assert_eq!(
            invocation.args.last().unwrap(),
            "https://api.example.test/health"
        );
    }

    #[test]
    fn docker_and_lxc_execute_inside_the_source_workload() {
        let docker = invocation(
            &AttachSpec::Docker {
                container: "web".into(),
                interface: "eth0".into(),
                lifecycle: WorkloadLifecycle::Session,
                provision: None::<DockerProvision>,
            },
            &http(),
        );
        assert_eq!(docker.program, "docker");
        assert_eq!(&docker.args[..3], ["exec", "web", "curl"]);

        let lxc = invocation(
            &AttachSpec::Lxc {
                container: "web".into(),
                interface: "eth0".into(),
                lifecycle: WorkloadLifecycle::Session,
                provision: None,
            },
            &http(),
        );
        assert_eq!(lxc.program, "lxc-attach");
        assert_eq!(&lxc.args[..5], ["-n", "web", "--", "curl", "--silent"]);
    }

    #[test]
    fn arbitrary_commands_preserve_argument_boundaries() {
        let spec = TrafficSpec::Command {
            program: "psql".into(),
            args: vec!["--command".into(), "select 1; drop nothing".into()],
            interval_ms: 1000,
        };
        let invocation = invocation(
            &AttachSpec::Local {
                interface: "eth0".into(),
                process: None,
            },
            &spec,
        );
        assert_eq!(invocation.program, "psql");
        assert_eq!(invocation.args[1], "select 1; drop nothing");
    }

    #[test]
    fn traffic_guard_preserves_attempt_level_timing_and_exit_status() {
        let spec = TrafficSpec::Command {
            program: "true".into(),
            args: Vec::new(),
            interval_ms: 1_000,
        };
        let mut guard = TrafficGuard::start(
            &AttachSpec::Local {
                interface: "lo".into(),
                process: None,
            },
            &spec,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while guard.status().observations.is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        guard.stop();
        let status = guard.status();
        assert_eq!(status.attempts, 1);
        assert_eq!(status.succeeded, 1);
        assert_eq!(status.observations[0].exit_code, Some(0));
        assert!(!status.observations[0].cancelled);
        assert!(
            status.observations[0].completed_at_unix_ms
                >= status.observations[0].started_at_unix_ms
        );
    }
}
