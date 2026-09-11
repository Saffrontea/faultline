#[cfg(not(target_os = "linux"))]
compile_error!("the dataplane worker requires Linux; run the TUI on other platforms");

use std::{
    fs,
    io::{BufRead as _, BufReader, Write as _},
    os::unix::net::UnixStream,
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use anyhow::{Context as _, bail};
use clap::{Parser, ValueEnum};
use faultline_common::{FAULTLINE_AGENT_APPLICATION, FAULTLINE_ENGINE_APPLICATION};
use faultline_protocol::{ControlTimeouts, Request, encode_line};

const CAP_NET_ADMIN: u32 = 12;
const CAP_SYS_ADMIN: u32 = 21;
const CAP_BPF: u32 = 39;
const APPLICATION_NAME: &str = FAULTLINE_AGENT_APPLICATION;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Direction {
    Ingress,
    Egress,
}

impl Direction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }
}

#[derive(Debug, Parser)]
#[command(about = "Ephemeral stdio worker that owns one Linux chaos dataplane session")]
struct Options {
    #[arg(long, default_value = FAULTLINE_ENGINE_APPLICATION)]
    engine: PathBuf,
    #[arg(long)]
    interface: String,
    #[arg(long, value_enum, default_value_t = Direction::Ingress)]
    direction: Direction,
    #[arg(long, default_value = "0.0.0.0/0")]
    destination: String,
    #[arg(long, default_value = "any")]
    protocol: String,
    #[arg(long, default_value_t = 0)]
    port: u16,
}

struct EngineGuard {
    child: Child,
    socket: PathBuf,
}

enum ProxyEnd {
    Engine,
    Input,
    Output,
}

impl EngineGuard {
    fn start(options: &Options) -> anyhow::Result<Self> {
        let socket = PathBuf::from(format!(
            "/tmp/{APPLICATION_NAME}-{}.sock",
            std::process::id()
        ));
        let _ = fs::remove_file(&socket);
        let child = options
            .engine_command(&socket)
            .spawn()
            .with_context(|| format!("starting {}", options.engine.display()))?;
        Ok(Self { child, socket })
    }

    fn connect(&mut self) -> anyhow::Result<UnixStream> {
        for _ in 0..100 {
            match UnixStream::connect(&self.socket) {
                Ok(stream) => return Ok(stream),
                Err(_) => {
                    if let Some(status) = self.child.try_wait()? {
                        bail!(
                            "{FAULTLINE_ENGINE_APPLICATION} exited before opening control socket: {status}"
                        );
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            }
        }
        bail!(
            "{FAULTLINE_ENGINE_APPLICATION} did not open {}",
            self.socket.display()
        )
    }

    fn wait(&mut self) -> anyhow::Result<()> {
        let status = self.child.wait()?;
        if !status.success() {
            bail!("{FAULTLINE_ENGINE_APPLICATION} engine exited with {status}");
        }
        Ok(())
    }
}

impl Drop for EngineGuard {
    fn drop(&mut self) {
        // The engine owns an fq qdisc as well as BPF links. SIGKILL closes
        // BPF descriptors but skips PacingGuard, leaving the qdisc behind.
        // Allow bounded graceful cleanup even if the stdio consumer vanished.
        if matches!(self.child.try_wait(), Ok(None)) {
            unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) };
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                match self.child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => thread::sleep(Duration::from_millis(10)),
                    Err(_) => break,
                }
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.socket);
    }
}

fn main() -> anyhow::Result<()> {
    let options = Options::parse();
    verify_capabilities()?;
    let mut engine = EngineGuard::start(&options)?;
    match proxy(engine.connect()?)? {
        ProxyEnd::Engine => engine.wait(),
        // Either half of the controller can end the session. In particular,
        // stdin EOF must still clean up if its stdout consumer is stalled.
        ProxyEnd::Input | ProxyEnd::Output => Ok(()),
    }
}

impl Options {
    fn engine_command(&self, socket: &Path) -> Command {
        let port = self.port.to_string();
        let mut command = Command::new(&self.engine);
        command
            .args([
                "--interface",
                &self.interface,
                "--direction",
                self.direction.as_str(),
            ])
            .args([
                "--destination",
                &self.destination,
                "--protocol",
                &self.protocol,
            ])
            .args(["--port", &port, "--loss", "0"])
            .arg("--control-socket")
            .arg(socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        install_parent_death_signal(&mut command);
        command
    }
}

fn install_parent_death_signal(command: &mut Command) {
    // Do not leave the privileged dataplane behind if this ephemeral agent is
    // terminated before it can forward the normal protocol Stop request.
    let expected_parent = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // The parent may have exited between fork and prctl. In that case
            // PDEATHSIG was armed too late, so fail the exec instead of leaving
            // a privileged, reparented engine behind.
            if libc::getppid() != expected_parent {
                return Err(std::io::Error::other(format!(
                    "{APPLICATION_NAME} parent exited before PDEATHSIG was installed"
                )));
            }
            Ok(())
        });
    }
}

fn proxy(mut stream: UnixStream) -> anyhow::Result<ProxyEnd> {
    let mut request_stream = stream.try_clone()?;
    let (finished, completion) = std::sync::mpsc::channel();
    let input_finished = finished.clone();
    // Neither stdio half can be allowed to block observation of the other
    // half closing. The process owns these forwarding threads; returning to
    // main runs EngineGuard cleanup and process exit ends any blocked I/O.
    thread::spawn(move || {
        let result = forward_input(&mut request_stream).map(|()| ProxyEnd::Input);
        let _ = input_finished.send(result);
    });
    thread::spawn(move || {
        let _ = finished.send(forward_output(&mut stream));
    });
    let result = completion
        .recv()
        .context("stdio forwarding threads stopped")?;
    if matches!(&result, Ok(ProxyEnd::Input)) {
        // Preserve ordered Stop processing and final output for healthy
        // consumers, with only a bounded grace period for stalled ones.
        completion
            .recv_timeout(ControlTimeouts::default().shutdown)
            .unwrap_or(result)
    } else {
        result
    }
}

fn forward_input(stream: &mut UnixStream) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        writeln!(stream, "{}", line?)?;
        stream.flush()?;
    }
    stream.write_all(&encode_line(&Request::Stop { id: u64::MAX })?)?;
    stream.flush()?;
    Ok(())
}

fn forward_output(stream: &mut UnixStream) -> anyhow::Result<ProxyEnd> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    for line in BufReader::new(stream).lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) if is_disconnect(&error) => return Ok(ProxyEnd::Engine),
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = writeln!(output, "{line}").and_then(|()| output.flush()) {
            if is_disconnect(&error) {
                return Ok(ProxyEnd::Output);
            }
            return Err(error.into());
        }
    }
    Ok(ProxyEnd::Engine)
}

fn is_disconnect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
    )
}

fn verify_capabilities() -> anyhow::Result<()> {
    let status = fs::read_to_string("/proc/self/status")
        .context("reading /proc/self/status to verify agent capabilities")?;
    let effective = parse_effective_capabilities(&status)?;
    let has = |capability: u32| effective & (1_u64 << capability) != 0;

    let missing = [
        (!has(CAP_NET_ADMIN)).then_some("CAP_NET_ADMIN"),
        (!(has(CAP_BPF) || has(CAP_SYS_ADMIN)))
            .then_some("CAP_BPF (or CAP_SYS_ADMIN on legacy kernels)"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!(
            "{APPLICATION_NAME} lacks required effective capabilities: {}; grant only these capabilities to the ephemeral agent",
            missing.join(", ")
        );
    }
    Ok(())
}

fn parse_effective_capabilities(status: &str) -> anyhow::Result<u64> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:").map(str::trim))
        .context("/proc/self/status does not contain CapEff")?;
    u64::from_str_radix(value, 16).with_context(|| format!("invalid CapEff value {value:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PDEATH_HELPER_ENV: &str = "FAULTLINE_AGENT_PDEATH_HELPER_FILE";
    const PROXY_HELPER_ENV: &str = "FAULTLINE_AGENT_PROXY_HELPER_SOCKET";

    #[test]
    fn proxy_backpressure_helper() {
        let Some(path) = std::env::var_os(PROXY_HELPER_ENV) else {
            return;
        };
        proxy(UnixStream::connect(path).unwrap()).unwrap();
        std::process::exit(0);
    }

    #[test]
    fn stdin_eof_ends_proxy_even_when_stdout_is_blocked() {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::net::UnixListener;

        let path = std::env::temp_dir().join(format!(
            "{APPLICATION_NAME}-blocked-output-{}.sock",
            std::process::id()
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::proxy_backpressure_helper"])
            .env(PROXY_HELPER_ENV, &path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        // Force stats backpressure while keeping the output reader open.
        assert!(
            unsafe {
                libc::fcntl(
                    child.stdout.as_ref().unwrap().as_raw_fd(),
                    libc::F_SETPIPE_SZ,
                    4096,
                )
            } >= 0
        );
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        let line = [b'x'; 4095].into_iter().chain(*b"\n").collect::<Vec<_>>();
        loop {
            match stream.write(&line) {
                Ok(_) => (),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("writing fake stats: {error}"),
            }
        }
        drop(child.stdin.take());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if std::time::Instant::now() >= deadline {
                break None;
            }
            thread::sleep(Duration::from_millis(10));
        };
        let _ = child.kill();
        let _ = child.wait();
        fs::remove_file(path).unwrap();
        assert!(
            status.is_some_and(|status| status.success()),
            "proxy hung after stdin EOF with a stalled output consumer"
        );
    }

    #[test]
    fn stdin_eof_preserves_final_engine_output() {
        use std::os::unix::net::UnixListener;

        let path = std::env::temp_dir().join(format!(
            "{APPLICATION_NAME}-drain-output-{}.sock",
            std::process::id()
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::proxy_backpressure_helper"])
            .env(PROXY_HELPER_ENV, &path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        drop(child.stdin.take());
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        assert!(matches!(
            serde_json::from_str::<Request>(&request).unwrap(),
            Request::Stop { .. }
        ));
        thread::sleep(Duration::from_millis(50));
        stream.write_all(b"final-engine-stats\n").unwrap();
        drop(stream);
        let output = child.wait_with_output().unwrap();
        fs::remove_file(path).unwrap();
        assert!(output.status.success());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("final-engine-stats")
        );
    }

    #[test]
    fn pdeath_helper() {
        let Some(path) = std::env::var_os(PDEATH_HELPER_ENV) else {
            return;
        };
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        install_parent_death_signal(&mut command);
        let child = command.spawn().unwrap();
        fs::write(path, child.id().to_string()).unwrap();
        std::process::exit(0);
    }

    #[test]
    fn engine_dies_when_its_parent_process_exits() {
        let marker =
            std::env::temp_dir().join(format!("{APPLICATION_NAME}-pdeath-{}", std::process::id()));
        let _ = fs::remove_file(&marker);
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::pdeath_helper"])
            .env(PDEATH_HELPER_ENV, &marker)
            .status()
            .unwrap();
        assert!(status.success());
        let pid: i32 = fs::read_to_string(&marker).unwrap().parse().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            let terminated = fs::read_to_string(format!("/proc/{pid}/status"))
                .map(|status| status.lines().any(|line| line.starts_with("State:\tZ")))
                .unwrap_or(true);
            if terminated {
                let _ = fs::remove_file(&marker);
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = fs::remove_file(&marker);
        panic!("engine process {pid} survived its parent");
    }

    #[test]
    fn engine_guard_allows_sigterm_cleanup_before_reaping() {
        let directory = std::env::temp_dir().join(format!(
            "{APPLICATION_NAME}-graceful-stop-{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let cleaned = directory.join("cleaned");
        let ready = directory.join("ready");
        let child = Command::new("/bin/sh")
            .args(["-c", "trap 'echo cleaned > \"$1\"; exit 0' TERM; echo ready > \"$2\"; while :; do sleep 0.01; done", "engine"])
            .arg(&cleaned)
            .arg(&ready)
            .spawn()
            .unwrap();
        let guard = EngineGuard {
            child,
            socket: directory.join("engine.sock"),
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !ready.exists() {
            assert!(std::time::Instant::now() < deadline, "helper did not start");
            thread::sleep(Duration::from_millis(10));
        }
        drop(guard);
        let did_clean = cleaned.exists();
        fs::remove_dir_all(directory).unwrap();
        assert!(
            did_clean,
            "engine was killed before its SIGTERM cleanup ran"
        );
    }

    #[test]
    fn engine_is_reaped_when_startup_fails_after_spawn() {
        use std::os::unix::fs::PermissionsExt as _;

        let script = std::env::temp_dir().join(format!(
            "{APPLICATION_NAME}-silent-engine-{}",
            std::process::id()
        ));
        fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let options = Options {
            engine: script.clone(),
            interface: "lo".to_owned(),
            direction: Direction::Egress,
            destination: "127.0.0.1/32".to_owned(),
            protocol: "any".to_owned(),
            port: 0,
        };
        let mut engine = EngineGuard::start(&options).unwrap();
        let pid = engine.child.id();
        assert!(
            engine
                .connect()
                .unwrap_err()
                .to_string()
                .contains("did not open")
        );
        drop(engine);
        let alive = Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        let _ = fs::remove_file(script);
        assert!(!alive);
    }

    #[test]
    fn engine_command_contains_the_complete_dataplane_contract() {
        let options = Options {
            engine: PathBuf::from("custom-faultline-engine"),
            interface: "eth7".to_owned(),
            direction: Direction::Egress,
            destination: "10.20.0.0/16".to_owned(),
            protocol: "tcp".to_owned(),
            port: 443,
        };
        let command = options.engine_command(Path::new("/tmp/agent.sock"));
        let arguments = command
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(command.get_program(), "custom-faultline-engine");
        assert_eq!(
            arguments,
            [
                "--interface",
                "eth7",
                "--direction",
                "egress",
                "--destination",
                "10.20.0.0/16",
                "--protocol",
                "tcp",
                "--port",
                "443",
                "--loss",
                "0",
                "--control-socket",
                "/tmp/agent.sock",
            ]
        );
    }

    #[test]
    fn parses_effective_capability_mask() {
        let status = format!(
            "Name:\t{APPLICATION_NAME}\nCapInh:\t0000000000000000\nCapEff:\t0000008000201000\n"
        );
        let capabilities = parse_effective_capabilities(&status).unwrap();
        assert_ne!(capabilities & (1_u64 << CAP_NET_ADMIN), 0);
        assert_ne!(capabilities & (1_u64 << CAP_SYS_ADMIN), 0);
        assert_ne!(capabilities & (1_u64 << CAP_BPF), 0);
    }

    #[test]
    fn rejects_missing_or_malformed_effective_capability_mask() {
        assert!(parse_effective_capabilities(&format!("Name:\t{APPLICATION_NAME}\n")).is_err());
        assert!(parse_effective_capabilities("CapEff:\tnot-hex\n").is_err());
    }
}
