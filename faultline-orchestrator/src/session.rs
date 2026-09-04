#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use anyhow::{Context as _, bail};
use faultline_protocol::ControlTimeouts;

use crate::{process::command_lines, workload::resolve_target_interface};

#[derive(Clone, Debug)]
pub struct SessionOptions {
    pub target: Option<String>,
    #[cfg(unix)]
    pub socket: Option<PathBuf>,
    pub destination: String,
    pub direction: Direction,
    pub agent: String,
    pub engine: Option<String>,
    pub agent_image: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Direction {
    #[default]
    Auto,
    Ingress,
    Egress,
}

impl Direction {
    pub const fn effective(self, _runtime: &str) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
            // Target URIs describe endpoint interfaces. Traffic initiated by
            // that endpoint leaves through egress for every runtime. A host-
            // side veth observer opts into ingress explicitly.
            Self::Auto => "egress",
        }
    }
}

pub struct Session {
    pub reader: Box<dyn Read + Send>,
    pub writer: Box<dyn Write + Send>,
    pub child: Option<Child>,
    pub label: String,
    pub record_target: String,
    pub owned: bool,
}

impl Session {
    pub fn open(options: &SessionOptions) -> anyhow::Result<Self> {
        #[cfg(unix)]
        if let Some(path) = &options.socket {
            return Self::open_unix(path);
        }
        #[cfg(unix)]
        if let Some(path) = options
            .target
            .as_deref()
            .and_then(|target| target.strip_prefix("unix://"))
        {
            return Self::open_unix(&PathBuf::from(path));
        }

        let target = resolve_target(options.target.as_deref())?;
        let runtime = target.split_once("://").map_or("local", |value| value.0);
        let direction = options.direction.effective(runtime);
        let mut command = agent_command(&target, options)?;
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = command
            .spawn()
            .with_context(|| format!("starting agent for {target}"))?;
        let writer = child.stdin.take().context("agent stdin was not piped")?;
        let reader = child.stdout.take().context("agent stdout was not piped")?;
        Ok(Self {
            reader: Box::new(reader),
            writer: Box::new(writer),
            child: Some(child),
            label: format!("{target} [{direction}]"),
            record_target: target,
            owned: true,
        })
    }

    #[cfg(unix)]
    fn open_unix(path: &PathBuf) -> anyhow::Result<Self> {
        let stream = UnixStream::connect(path)
            .with_context(|| format!("connecting to {}", path.display()))?;
        Ok(Self {
            reader: Box::new(stream.try_clone()?),
            writer: Box::new(stream),
            child: None,
            label: format!("unix://{}", path.display()),
            record_target: format!("unix://{}", path.display()),
            owned: false,
        })
    }
}

pub fn agent_command(target: &str, options: &SessionOptions) -> anyhow::Result<Command> {
    let (runtime, location) = target
        .split_once("://")
        .context("target must contain ://")?;
    Ok(match runtime {
        "local" => {
            let mut command = Command::new(&options.agent);
            agent_arguments(&mut command, location, "local", options);
            command
        }
        "lxc" => {
            let (container, interface) = container_target(location)?;
            let mut command = Command::new("lxc-attach");
            command.args(["-n", container, "--", &options.agent]);
            agent_arguments(&mut command, interface, "lxc", options);
            command
        }
        "docker" => {
            let (container, interface) = container_target(location)?;
            let mut command = Command::new("docker");
            command.args([
                "run",
                "--rm",
                "-i",
                "--network",
                &format!("container:{container}"),
                "--cap-add",
                "NET_ADMIN",
                "--cap-add",
                "BPF",
                &options.agent_image,
            ]);
            agent_arguments(&mut command, interface, "docker", options);
            command
        }
        _ => bail!("unsupported target runtime {runtime}"),
    })
}

pub fn resolve_target(requested: Option<&str>) -> anyhow::Result<String> {
    if let Some(location) = requested.and_then(|target| target.strip_prefix("auto://")) {
        let (container, interface) = container_target(location)?;
        let candidates = discover_targets()
            .into_iter()
            .filter(|target| {
                target
                    .strip_prefix("docker://")
                    .or_else(|| target.strip_prefix("lxc://"))
                    .and_then(|value| value.split_once('/'))
                    .is_some_and(|(name, _)| name == container)
            })
            .map(|target| target.replace("/auto", &format!("/{interface}")))
            .collect::<Vec<_>>();
        return match candidates.as_slice() {
            [target] => resolve_explicit_target(target),
            [] => bail!("container {container} was not found in Docker or LXC"),
            _ => bail!("container {container} exists in both Docker and LXC; use an explicit URI"),
        };
    }
    if let Some(target) = requested {
        return resolve_explicit_target(target);
    }
    let targets = discover_targets();
    match targets.as_slice() {
        [target] => resolve_explicit_target(target),
        [] => {
            bail!("no running Docker/LXC target found; specify local://IFACE or start a container")
        }
        _ => bail!(
            "multiple targets found; select one of: {}",
            targets.join(", ")
        ),
    }
}

fn resolve_explicit_target(target: &str) -> anyhow::Result<String> {
    let (runtime, location) = target
        .split_once("://")
        .context("target must contain ://")?;
    match runtime {
        "local" => {
            if location.is_empty() || location == "auto" {
                bail!("local target requires an explicit interface");
            }
            Ok(target.to_owned())
        }
        "lxc" => {
            let (container, interface) = container_target(location)?;
            validate_running_container(
                "LXC",
                container,
                command_lines("lxc-ls", &["--active", "-1"]),
            )?;
            let interface = resolve_target_interface(runtime, container, interface)?;
            Ok(format!("lxc://{container}/{interface}"))
        }
        "docker" => {
            let (container, interface) = container_target(location)?;
            validate_running_container(
                "Docker",
                container,
                command_lines("docker", &["ps", "--format", "{{.Names}}"]),
            )?;
            let interface = resolve_target_interface(runtime, container, interface)?;
            Ok(format!("docker://{container}/{interface}"))
        }
        _ => bail!("unsupported target runtime {runtime}"),
    }
}

fn validate_running_container(
    runtime: &str,
    container: &str,
    running: Vec<String>,
) -> anyhow::Result<()> {
    running
        .iter()
        .any(|name| name == container)
        .then_some(())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{runtime} container {container} is not running or is not visible; start it and check --list-targets"
            )
        })
}

pub fn discover_targets() -> Vec<String> {
    let mut targets = command_lines("docker", &["ps", "--format", "{{.Names}}"])
        .into_iter()
        .map(|name| format!("docker://{name}/auto"))
        .collect::<Vec<_>>();
    targets.extend(
        command_lines("lxc-ls", &["--active", "-1"])
            .into_iter()
            .map(|name| format!("lxc://{name}/auto")),
    );
    targets.sort();
    targets.dedup();
    targets
}

pub fn agent_arguments(
    command: &mut Command,
    interface: &str,
    runtime: &str,
    options: &SessionOptions,
) {
    command
        .args(["--interface", interface])
        .args(["--direction", options.direction.effective(runtime)])
        .args(["--destination", &options.destination]);
    if let Some(engine) = &options.engine {
        command.args(["--engine", engine]);
    }
}

pub fn container_target(location: &str) -> anyhow::Result<(&str, &str)> {
    let (container, interface) = location.split_once('/').unwrap_or((location, "auto"));
    if container.is_empty() || interface.is_empty() {
        bail!("container target must be CONTAINER/INTERFACE");
    }
    Ok((container, interface))
}

pub fn finish_child(child: &mut Option<Child>) {
    if let Some(mut child) = child.take() {
        let deadline = std::time::Instant::now() + ControlTimeouts::default().shutdown;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Err(_) => break,
                Ok(None) if std::time::Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => break,
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finish_child_forcibly_reaps_an_unresponsive_process() {
        let mut child = Some(Command::new("/bin/sleep").arg("30").spawn().unwrap());
        let pid = child.as_ref().unwrap().id();
        finish_child(&mut child);
        assert!(child.is_none());
        assert!(
            !Command::new("kill")
                .args(["-0", &pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        );
    }
}
