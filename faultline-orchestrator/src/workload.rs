#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Arc,
    thread,
    time::Duration,
};

use anyhow::{Context as _, bail};
use faultline_common::FAULTLINE_ENGINE_APPLICATION;
use faultline_runtime::{AttachSpec, WorkloadLifecycle, WorkloadSpec};

use crate::process::command_lines;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Discovery {
    pub local_interfaces: Vec<String>,
    pub docker: Vec<String>,
    pub lxc: Vec<String>,
}

pub fn discover() -> Discovery {
    let mut local_interfaces = std::fs::read_dir("/sys/class/net")
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    let docker = command_lines("docker", &["ps", "-a", "--format", "{{.Names}}"]);
    let lxc = command_lines("lxc-ls", &["-1"]);
    local_interfaces.sort();
    Discovery {
        local_interfaces,
        docker,
        lxc,
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Runtime {
    Docker,
    Lxc,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Cleanup {
    Stop,
    Remove,
}

trait CommandExecutor: Send + Sync {
    fn status(&self, command: &mut Command) -> io::Result<std::process::ExitStatus>;
    fn output(&self, command: &mut Command) -> io::Result<Output>;
}

struct SystemExecutor;

impl CommandExecutor for SystemExecutor {
    fn status(&self, command: &mut Command) -> io::Result<std::process::ExitStatus> {
        command.status()
    }

    fn output(&self, command: &mut Command) -> io::Result<Output> {
        command.output()
    }
}

impl Runtime {
    const fn name(self) -> &'static str {
        match self {
            Self::Docker => "Docker",
            Self::Lxc => "LXC",
        }
    }

    fn start(self, name: &str, executor: &dyn CommandExecutor) -> anyhow::Result<()> {
        let mut command = match self {
            Self::Docker => {
                let mut command = Command::new("docker");
                command.args(["start", name]);
                command
            }
            Self::Lxc => {
                let mut command = Command::new("lxc-start");
                command.args(["-n", name, "-d"]);
                command
            }
        };
        let status = executor
            .status(&mut command)
            .with_context(|| format!("starting {} workload {name}", self.name()))?;
        if !status.success() {
            bail!(
                "{} workload {name} could not be started: {status}",
                self.name()
            );
        }
        Ok(())
    }

    fn inspect_running(
        self,
        name: &str,
        executor: &dyn CommandExecutor,
    ) -> anyhow::Result<Option<bool>> {
        let mut command = match self {
            Self::Docker => {
                let mut command = Command::new("docker");
                command.args(["inspect", "--format", "{{.State.Running}}", name]);
                command
            }
            Self::Lxc => {
                let mut command = Command::new("lxc-info");
                command.args(["-n", name, "-sH"]);
                command
            }
        };
        let output = executor
            .output(&mut command)
            .with_context(|| format!("inspecting {} workload {name}", self.name()))?;
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            let normalized = error.to_ascii_lowercase();
            let missing = match self {
                Self::Docker => ["no such object", "no such container"],
                Self::Lxc => ["doesn't exist", "does not exist"],
            }
            .iter()
            .any(|needle| normalized.contains(needle));
            if missing {
                return Ok(None);
            }
            bail!(
                "{} workload {name} could not be inspected: {}",
                self.name(),
                error.trim()
            );
        }
        let state = String::from_utf8_lossy(&output.stdout);
        Ok(Some(match self {
            Self::Docker => state.trim() == "true",
            Self::Lxc => state.trim().eq_ignore_ascii_case("RUNNING"),
        }))
    }

    fn cleanup_command(self, name: &str, cleanup: Cleanup) -> Command {
        let (program, arguments): (&str, &[&str]) = match (self, cleanup) {
            (Self::Docker, Cleanup::Remove) => ("docker", &["rm", "--force", name]),
            (Self::Docker, Cleanup::Stop) => ("docker", &["stop", name]),
            (Self::Lxc, Cleanup::Remove) => ("lxc-destroy", &["-n", name, "-f"]),
            (Self::Lxc, Cleanup::Stop) => ("lxc-stop", &["-n", name]),
        };
        let mut command = Command::new(program);
        command.args(arguments);
        command
    }

    fn interfaces(self, name: &str) -> anyhow::Result<Vec<String>> {
        let output = match self {
            Self::Docker => Command::new("docker")
                .args(["exec", name, "ls", "-1", "/sys/class/net"])
                .output(),
            Self::Lxc => Command::new("lxc-attach")
                .args(["-n", name, "--", "ls", "-1", "/sys/class/net"])
                .output(),
        }
        .with_context(|| format!("discovering interfaces in {} workload {name}", self.name()))?;
        if !output.status.success() {
            bail!(
                "could not inspect interfaces in {} workload {name}: {}",
                self.name(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|interface| !interface.is_empty())
            .map(str::to_owned)
            .collect())
    }
}

/// Resolves a container's `auto` selector after the workload is running.
/// Explicit interface names pass through unchanged.
pub fn resolve_attach(source: &WorkloadSpec) -> anyhow::Result<AttachSpec> {
    let (runtime, name, interface) = match source {
        WorkloadSpec::Local { interface, .. } => {
            return source
                .resolved_attach(interface.clone())
                .map_err(anyhow::Error::msg);
        }
        WorkloadSpec::Docker {
            container,
            interface,
            ..
        } => (Runtime::Docker, container.as_str(), interface.as_str()),
        WorkloadSpec::Lxc {
            container,
            interface,
            ..
        } => (Runtime::Lxc, container.as_str(), interface.as_str()),
    };
    let resolved = resolve_container_interface(runtime, name, interface)?;
    source.resolved_attach(resolved).map_err(anyhow::Error::msg)
}

fn resolve_container_interface(
    runtime: Runtime,
    name: &str,
    interface: &str,
) -> anyhow::Result<String> {
    if interface != "auto" {
        return Ok(interface.to_owned());
    }

    // A newly started LXC may report RUNNING before its init process is
    // attachable. Retry briefly so lifecycle startup and discovery form one
    // reliable operation from the user's perspective.
    let mut last_error = None;
    for attempt in 0..20 {
        match runtime.interfaces(name) {
            Ok(found) => {
                let interface = select_interface(runtime.name(), name, found)?;
                return Ok(interface);
            }
            Err(error) => last_error = Some(error),
        }
        if attempt != 19 {
            thread::sleep(Duration::from_millis(100));
        }
    }
    Err(last_error.expect("interface discovery always records a result"))
}

pub(crate) fn resolve_target_interface(
    runtime: &str,
    name: &str,
    interface: &str,
) -> anyhow::Result<String> {
    let runtime = match runtime {
        "docker" => Runtime::Docker,
        "lxc" => Runtime::Lxc,
        _ => bail!("unsupported container runtime {runtime}"),
    };
    resolve_container_interface(runtime, name, interface)
}

fn select_interface(runtime: &str, name: &str, interfaces: Vec<String>) -> anyhow::Result<String> {
    let mut candidates = interfaces
        .into_iter()
        .filter(|interface| interface != "lo")
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    match candidates.as_slice() {
        [interface] => Ok(interface.clone()),
        [] => bail!("{runtime} workload {name} has no non-loopback interface"),
        _ => bail!(
            "{runtime} workload {name} has multiple interfaces; set one explicitly: {}",
            candidates.join(", ")
        ),
    }
}

pub struct WorkloadGuard {
    owned: Option<OwnedWorkload>,
}

struct ProvisionRollback {
    runtime: Runtime,
    name: String,
    armed: bool,
    executor: Arc<dyn CommandExecutor>,
}

impl ProvisionRollback {
    fn armed(runtime: Runtime, name: &str, executor: Arc<dyn CommandExecutor>) -> Self {
        Self {
            runtime,
            name: name.to_owned(),
            armed: true,
            executor,
        }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for ProvisionRollback {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut command = self.runtime.cleanup_command(&self.name, Cleanup::Remove);
        let _ = self.executor.status(&mut command);
    }
}

enum OwnedWorkload {
    Container(Runtime, String, Cleanup, Arc<dyn CommandExecutor>),
    LocalProcess(Child),
}

impl Drop for WorkloadGuard {
    fn drop(&mut self) {
        let Some(owned) = self.owned.take() else {
            return;
        };
        match owned {
            OwnedWorkload::LocalProcess(mut child) => {
                let _ = child.kill();
                let _ = child.wait();
            }
            OwnedWorkload::Container(runtime, name, cleanup, executor) => {
                let mut command = runtime.cleanup_command(&name, cleanup);
                let _ = executor.status(&mut command);
            }
        }
    }
}

/// Ensures that the experiment source is available. Ownership is deliberately
/// narrow: only a stopped container started for a `session` is stopped by the
/// returned guard. Existing running workloads are never stopped.
pub fn prepare(
    source: &WorkloadSpec,
    agent: &str,
    engine: Option<&str>,
) -> anyhow::Result<WorkloadGuard> {
    prepare_with_executor(source, agent, engine, Arc::new(SystemExecutor))
}

fn prepare_with_executor(
    source: &WorkloadSpec,
    agent: &str,
    engine: Option<&str>,
    executor: Arc<dyn CommandExecutor>,
) -> anyhow::Result<WorkloadGuard> {
    if let WorkloadSpec::Local {
        process: Some(process),
        ..
    } = source
    {
        let mut command = Command::new(&process.program);
        command
            .args(&process.args)
            .envs(&process.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(directory) = &process.working_directory {
            command.current_dir(directory);
        }
        let child = command
            .spawn()
            .with_context(|| format!("starting local workload {}", process.program))?;
        return Ok(WorkloadGuard {
            owned: Some(OwnedWorkload::LocalProcess(child)),
        });
    }
    let Some((runtime, name, lifecycle)) = runtime_source(source) else {
        return Ok(WorkloadGuard { owned: None });
    };
    let (running, rollback) = match runtime.inspect_running(name, executor.as_ref())? {
        Some(running) => (running, None),
        None => (
            false,
            Some(provision_missing(
                source,
                runtime,
                name,
                agent,
                engine,
                Arc::clone(&executor),
            )?),
        ),
    };
    let provisioned = rollback.is_some();
    let should_start = lifecycle_decision(lifecycle, running)?;
    if !should_start {
        rollback.into_iter().for_each(ProvisionRollback::disarm);
        return Ok(WorkloadGuard { owned: None });
    }
    runtime.start(name, executor.as_ref())?;
    rollback.into_iter().for_each(ProvisionRollback::disarm);
    Ok(WorkloadGuard {
        owned: Some(OwnedWorkload::Container(
            runtime,
            name.to_owned(),
            cleanup_decision(source, provisioned),
            executor,
        )),
    })
}

fn provision_missing(
    source: &WorkloadSpec,
    runtime: Runtime,
    name: &str,
    agent: &str,
    engine: Option<&str>,
    executor: Arc<dyn CommandExecutor>,
) -> anyhow::Result<ProvisionRollback> {
    match source {
        WorkloadSpec::Docker {
            provision: Some(provision),
            ..
        } => {
            let rollback = ProvisionRollback::armed(runtime, name, Arc::clone(&executor));
            provision_docker(name, provision, executor.as_ref())?;
            Ok(rollback)
        }
        WorkloadSpec::Lxc {
            provision: Some(provision),
            ..
        } => {
            let rollback = ProvisionRollback::armed(runtime, name, Arc::clone(&executor));
            provision_lxc(name, provision, executor.as_ref())?;
            install_lxc_tooling(name, agent, engine.unwrap_or(FAULTLINE_ENGINE_APPLICATION))?;
            Ok(rollback)
        }
        _ => bail!("{} workload {name} does not exist", runtime.name()),
    }
}

fn install_lxc_tooling(name: &str, agent: &str, engine: &str) -> anyhow::Result<()> {
    let rootfs = PathBuf::from(format!("/var/lib/lxc/{name}/rootfs"));
    for requested in [agent, engine] {
        let source = resolve_tool(requested)?;
        let requested_path = Path::new(requested);
        let destination = if requested_path.is_absolute() {
            rootfs.join(requested_path.strip_prefix("/").unwrap_or(requested_path))
        } else {
            rootfs.join("usr/local/bin").join(
                requested_path
                    .file_name()
                    .context("tool path has no filename")?,
            )
        };
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&source, &destination).with_context(|| {
            format!(
                "installing {} as {}",
                source.display(),
                destination.display()
            )
        })?;
        #[cfg(unix)]
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn resolve_tool(requested: &str) -> anyhow::Result<PathBuf> {
    let requested_path = PathBuf::from(requested);
    if requested_path.is_file() {
        return Ok(requested_path);
    }
    if let Ok(output) = Command::new("which").arg(requested).output()
        && output.status.success()
    {
        let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
        if path.is_file() {
            return Ok(path);
        }
    }
    let filename = requested_path
        .file_name()
        .context("tool path has no filename")?;
    let sibling = std::env::current_exe()?
        .parent()
        .context("current executable has no parent")?
        .join(filename);
    if sibling.is_file() {
        return Ok(sibling);
    }
    bail!("could not locate host tool {requested} for the new LXC rootfs")
}

fn cleanup_decision(source: &WorkloadSpec, provisioned: bool) -> Cleanup {
    if provisioned
        && matches!(
            source,
            WorkloadSpec::Docker {
                provision: Some(faultline_runtime::DockerProvision {
                    remove_on_exit: true,
                    ..
                }),
                ..
            } | WorkloadSpec::Lxc {
                provision: Some(faultline_runtime::LxcProvision {
                    remove_on_exit: true,
                    ..
                }),
                ..
            }
        )
    {
        Cleanup::Remove
    } else {
        Cleanup::Stop
    }
}

fn provision_lxc(
    name: &str,
    provision: &faultline_runtime::LxcProvision,
    executor: &dyn CommandExecutor,
) -> anyhow::Result<()> {
    let mut command = Command::new("lxc-create");
    command
        .args(["-n", name, "-t", "download", "--"])
        .args(["--dist", &provision.distribution])
        .args(["--release", &provision.release])
        .args(["--arch", &provision.architecture]);
    let status = executor
        .status(&mut command)
        .with_context(|| format!("provisioning LXC workload {name}"))?;
    if !status.success() {
        bail!("LXC workload {name} could not be provisioned: {status}");
    }
    Ok(())
}

fn provision_docker(
    name: &str,
    provision: &faultline_runtime::DockerProvision,
    executor: &dyn CommandExecutor,
) -> anyhow::Result<()> {
    if provision.image.trim().is_empty() {
        bail!("Docker provision image must not be empty");
    }
    let mut command = Command::new("docker");
    command.args(["create", "--name", name]);
    for (key, value) in &provision.environment {
        command.args(["--env", &format!("{key}={value}")]);
    }
    command.arg(&provision.image).args(&provision.command);
    let status = executor
        .status(&mut command)
        .with_context(|| format!("provisioning Docker workload {name}"))?;
    if !status.success() {
        bail!("Docker workload {name} could not be provisioned: {status}");
    }
    Ok(())
}

fn runtime_source(source: &WorkloadSpec) -> Option<(Runtime, &str, WorkloadLifecycle)> {
    match source {
        WorkloadSpec::Local { .. } => None,
        WorkloadSpec::Docker {
            container,
            lifecycle,
            ..
        } => Some((Runtime::Docker, container, *lifecycle)),
        WorkloadSpec::Lxc {
            container,
            lifecycle,
            ..
        } => Some((Runtime::Lxc, container, *lifecycle)),
    }
}

fn lifecycle_decision(lifecycle: WorkloadLifecycle, running: bool) -> anyhow::Result<bool> {
    match (lifecycle, running) {
        (_, true) => Ok(false),
        (WorkloadLifecycle::Session, false) => Ok(true),
        (WorkloadLifecycle::Existing, false) => {
            bail!("source workload is stopped; use lifecycle: session to let the TUI start it")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        os::unix::process::ExitStatusExt,
        sync::Mutex,
    };

    use faultline_runtime::{DockerProvision, LocalProcess, LxcProvision};

    use super::*;

    #[derive(Default)]
    struct RecordingExecutor {
        statuses: Mutex<VecDeque<bool>>,
        outputs: Mutex<VecDeque<Output>>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl RecordingExecutor {
        fn with(statuses: impl IntoIterator<Item = bool>, outputs: Vec<Output>) -> Arc<Self> {
            Arc::new(Self {
                statuses: Mutex::new(statuses.into_iter().collect()),
                outputs: Mutex::new(outputs.into()),
                calls: Mutex::default(),
            })
        }

        fn record(&self, command: &Command) {
            self.calls.lock().unwrap().push(
                std::iter::once(command.get_program())
                    .chain(command.get_args())
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect(),
            );
        }
    }

    impl CommandExecutor for RecordingExecutor {
        fn status(&self, command: &mut Command) -> io::Result<std::process::ExitStatus> {
            self.record(command);
            let success = self.statuses.lock().unwrap().pop_front().unwrap();
            Ok(std::process::ExitStatus::from_raw(if success {
                0
            } else {
                256
            }))
        }

        fn output(&self, command: &mut Command) -> io::Result<Output> {
            self.record(command);
            Ok(self.outputs.lock().unwrap().pop_front().unwrap())
        }
    }

    fn missing_container_output(message: &str) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(256),
            stdout: Vec::new(),
            stderr: message.as_bytes().to_vec(),
        }
    }

    fn docker_source() -> WorkloadSpec {
        WorkloadSpec::Docker {
            container: "generated".into(),
            interface: "eth0".into(),
            lifecycle: WorkloadLifecycle::Session,
            provision: Some(DockerProvision {
                image: "alpine:latest".into(),
                command: Vec::new(),
                environment: BTreeMap::new(),
                remove_on_exit: true,
            }),
        }
    }

    fn lxc_source() -> WorkloadSpec {
        WorkloadSpec::Lxc {
            container: "generated".into(),
            interface: "eth0".into(),
            lifecycle: WorkloadLifecycle::Session,
            provision: Some(LxcProvision {
                distribution: "debian".into(),
                release: "trixie".into(),
                architecture: "amd64".into(),
                remove_on_exit: true,
            }),
        }
    }

    fn process_alive(pid: u32) -> bool {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    #[test]
    fn session_starts_only_stopped_workloads() {
        assert!(lifecycle_decision(WorkloadLifecycle::Session, false).unwrap());
        assert!(!lifecycle_decision(WorkloadLifecycle::Session, true).unwrap());
    }

    #[test]
    fn existing_never_takes_lifecycle_ownership() {
        assert!(!lifecycle_decision(WorkloadLifecycle::Existing, true).unwrap());
        assert!(lifecycle_decision(WorkloadLifecycle::Existing, false).is_err());
    }

    #[test]
    fn auto_interface_ignores_loopback_and_selects_the_only_candidate() {
        assert_eq!(
            select_interface("Docker", "api", vec!["lo".into(), "eth7".into()]).unwrap(),
            "eth7"
        );
    }

    #[test]
    fn auto_interface_reports_ambiguous_candidates() {
        let error = select_interface(
            "LXC",
            "router",
            vec!["eth1".into(), "lo".into(), "eth0".into()],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("eth0, eth1"));
        assert!(error.contains("set one explicitly"));
    }

    #[test]
    fn explicit_interface_does_not_require_runtime_discovery() {
        let source = WorkloadSpec::Docker {
            container: "not-running".into(),
            interface: "net2".into(),
            lifecycle: WorkloadLifecycle::Existing,
            provision: None,
        };
        assert_eq!(
            resolve_attach(&source).unwrap().target_uri(),
            "docker://not-running/net2"
        );
    }

    #[test]
    fn only_a_newly_provisioned_container_is_removed() {
        let source = docker_source();
        assert_eq!(cleanup_decision(&source, true), Cleanup::Remove);
        assert_eq!(cleanup_decision(&source, false), Cleanup::Stop);
    }

    #[test]
    fn partial_create_failure_runs_remove_rollback() {
        let executor = RecordingExecutor::with(
            [false, true],
            vec![missing_container_output("No such container")],
        );
        assert!(prepare_with_executor(&docker_source(), "agent", None, executor.clone()).is_err());
        let calls = executor.calls.lock().unwrap();
        assert_eq!(calls[1][..3], ["docker", "create", "--name"]);
        assert_eq!(calls[2], ["docker", "rm", "--force", "generated"]);
    }

    #[test]
    fn partial_lxc_create_failure_runs_destroy_rollback() {
        let executor = RecordingExecutor::with(
            [false, true],
            vec![missing_container_output("container doesn't exist")],
        );
        assert!(prepare_with_executor(&lxc_source(), "agent", None, executor.clone()).is_err());
        let calls = executor.calls.lock().unwrap();
        assert_eq!(calls[1][..3], ["lxc-create", "-n", "generated"]);
        assert_eq!(calls[2], ["lxc-destroy", "-n", "generated", "-f"]);
    }

    #[test]
    fn start_failure_removes_a_newly_created_container() {
        let executor = RecordingExecutor::with(
            [true, false, true],
            vec![missing_container_output("No such container")],
        );
        assert!(prepare_with_executor(&docker_source(), "agent", None, executor.clone()).is_err());
        let calls = executor.calls.lock().unwrap();
        assert_eq!(calls[2], ["docker", "start", "generated"]);
        assert_eq!(calls[3], ["docker", "rm", "--force", "generated"]);
    }

    #[test]
    fn local_process_is_owned_and_reaped_by_the_session_guard() {
        let source = WorkloadSpec::Local {
            interface: "lo".into(),
            process: Some(LocalProcess {
                program: "/bin/sleep".into(),
                args: vec!["30".into()],
                environment: BTreeMap::new(),
                working_directory: None,
            }),
        };
        let guard = prepare(&source, faultline_common::FAULTLINE_AGENT_APPLICATION, None).unwrap();
        let pid = match guard.owned.as_ref().unwrap() {
            OwnedWorkload::LocalProcess(child) => child.id(),
            OwnedWorkload::Container(..) => panic!("expected local child"),
        };
        assert!(process_alive(pid));
        drop(guard);
        assert!(!process_alive(pid));
    }

    #[test]
    fn newly_provisioned_lxc_uses_remove_cleanup() {
        let source = WorkloadSpec::Lxc {
            container: "generated".into(),
            interface: "eth0".into(),
            lifecycle: WorkloadLifecycle::Session,
            provision: Some(LxcProvision {
                distribution: "debian".into(),
                release: "trixie".into(),
                architecture: "amd64".into(),
                remove_on_exit: true,
            }),
        };
        assert_eq!(cleanup_decision(&source, true), Cleanup::Remove);
        assert_eq!(cleanup_decision(&source, false), Cleanup::Stop);
    }
}
