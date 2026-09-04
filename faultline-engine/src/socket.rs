use std::{
    fs,
    os::unix::fs::{FileTypeExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use serde::Serialize;
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::{UnixListener, UnixStream},
    sync::{broadcast, mpsc, oneshot, watch},
    task::JoinHandle,
};

use faultline_protocol::{ControlState, ControlTimeouts, Request, Response};

use crate::control::{ControlCommand, ControlEnvelope, ControlResponse};

pub struct ControlSocket {
    path: PathBuf,
    task: JoinHandle<()>,
}

impl ControlSocket {
    pub fn bind(
        path: &Path,
        commands: mpsc::Sender<ControlEnvelope>,
        state: watch::Receiver<ControlState>,
        stats: broadcast::Sender<String>,
    ) -> anyhow::Result<Self> {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if !metadata.file_type().is_socket() {
                bail!(
                    "refusing to replace non-socket control path {}",
                    path.display()
                );
            }
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                bail!("control socket {} is already active", path.display());
            }
            fs::remove_file(path)
                .with_context(|| format!("removing stale control socket {}", path.display()))?;
        }
        let listener = UnixListener::bind(path)
            .with_context(|| format!("binding control socket {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", path.display()))?;
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let commands = commands.clone();
                let state = state.clone();
                let stats = stats.subscribe();
                tokio::spawn(async move {
                    let _ = serve_connection(stream, commands, state, stats).await;
                });
            }
        });
        Ok(Self {
            path: path.to_owned(),
            task,
        })
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        self.task.abort();
        let _ = fs::remove_file(&self.path);
    }
}

async fn serve_connection(
    stream: UnixStream,
    commands: mpsc::Sender<ControlEnvelope>,
    state: watch::Receiver<ControlState>,
    mut stats: broadcast::Receiver<String>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line? else { return Ok(()); };
                let response = match serde_json::from_str::<Request>(&line) {
                    Ok(Request::Ping { id }) => Response::Pong { id },
                    Ok(Request::GetState { id }) => Response::State { id, state: state.borrow().clone() },
                    Ok(Request::ReplaceRules { id, rules }) => {
                        match request(&commands, ControlCommand::ReplaceRules(rules)).await {
                            Ok(Ok(state)) => Response::Applied { id, state },
                            Ok(Err(message)) => Response::Error { id: Some(id), message },
                            Err(message) => Response::Error { id: Some(id), message },
                        }
                    }
                    Ok(Request::Stop { id }) => {
                        match request(&commands, ControlCommand::Stop).await {
                            Ok(Ok(_)) => Response::Stopping { id },
                            Ok(Err(message)) => Response::Error { id: Some(id), message },
                            Err(message) => Response::Error { id: Some(id), message },
                        }
                    }
                    Err(error) => Response::Error { id: request_id(&line), message: error.to_string() },
                };
                write_json(&mut writer, &response).await?;
            }
            event = stats.recv() => {
                match event {
                    Ok(event) => {
                        write_line(&mut writer, event.as_bytes()).await?;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

async fn request(
    commands: &mpsc::Sender<ControlEnvelope>,
    command: ControlCommand,
) -> Result<ControlResponse, String> {
    request_with_timeout(commands, command, ControlTimeouts::default().control_loop).await
}

async fn request_with_timeout(
    commands: &mpsc::Sender<ControlEnvelope>,
    command: ControlCommand,
    timeout: std::time::Duration,
) -> Result<ControlResponse, String> {
    let (response, receiver) = oneshot::channel();
    tokio::time::timeout(timeout, async {
        commands
            .send(ControlEnvelope {
                command,
                response: Some(response),
            })
            .await
            .map_err(|_| "control loop is not running".to_owned())?;
        receiver
            .await
            .map_err(|_| "control loop closed without a response".to_owned())
    })
    .await
    .map_err(|_| "control loop response timed out".to_owned())?
}

async fn write_json(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    value: &impl Serialize,
) -> anyhow::Result<()> {
    write_line(writer, &serde_json::to_vec(value)?).await
}

async fn write_line(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    line: &[u8],
) -> anyhow::Result<()> {
    writer.write_all(line).await?;
    writer.write_all(b"\n").await?;
    Ok(())
}

fn request_id(line: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()?
        .get("id")?
        .as_u64()
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    use faultline_protocol::RuleSpec;
    use ipnet::IpNet;
    use serde_json::{Value, json};
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        time::timeout,
    };

    use super::*;

    fn rule(loss: u32) -> RuleSpec {
        RuleSpec {
            id: 0,
            source: None,
            destination: IpNet::new(IpAddr::V4(Ipv4Addr::new(10, 20, 0, 0)), 16).unwrap(),
            protocol: faultline_common::PROTOCOL_TCP,
            loss_algorithm: faultline_common::LOSS_ALGORITHM_HASH,
            destination_port: 443,
            drop_permyriad: loss,
            ge_enter_permyriad: 0,
            ge_recover_permyriad: 0,
            ge_good_loss_permyriad: 0,
            ge_bad_loss_permyriad: 0,
            ge_idle_reset_secs: 0,
            duplicate_permyriad: 0,
            reorder_permyriad: 0,
            delay_ns: 0,
            jitter_ns: 0,
            bandwidth_bps: 0,
            seed: 42,
        }
    }

    #[tokio::test]
    async fn json_lines_round_trip_waits_for_apply_and_pushes_stats() {
        let (server, client) = UnixStream::pair().unwrap();
        let initial = ControlState {
            rules: vec![rule(100)],
        };
        let (_state_tx, state_rx) = watch::channel(initial.clone());
        let (stats_tx, _) = broadcast::channel(8);
        let (commands, mut receiver) = mpsc::channel(4);
        let server_task = tokio::spawn(serve_connection(
            server,
            commands,
            state_rx,
            stats_tx.subscribe(),
        ));
        let control_task = tokio::spawn(async move {
            let envelope = receiver.recv().await.unwrap();
            let ControlCommand::ReplaceRules(rules) = envelope.command else {
                panic!("replace expected")
            };
            assert_eq!(rules[0].drop_permyriad, 250);
            envelope
                .response
                .unwrap()
                .send(Ok(ControlState { rules }))
                .unwrap();
        });

        let (reader, mut writer) = client.into_split();
        let mut lines = BufReader::new(reader).lines();
        writer
            .write_all(b"{\"type\":\"ping\",\"id\":1}\n")
            .await
            .unwrap();
        assert_eq!(next(&mut lines).await["type"], "pong");
        writer
            .write_all(b"{\"type\":\"get_state\",\"id\":2}\n")
            .await
            .unwrap();
        assert_eq!(
            next(&mut lines)
                .await
                .pointer("/state/rules/0/drop_permyriad")
                .unwrap(),
            100
        );

        let request = json!({"type":"replace_rules", "id":3, "rules":[rule(250)]});
        writer
            .write_all(serde_json::to_string(&request).unwrap().as_bytes())
            .await
            .unwrap();
        writer.write_all(b"\n").await.unwrap();
        let applied = next(&mut lines).await;
        assert_eq!(applied["type"], "applied");
        assert_eq!(
            applied.pointer("/state/rules/0/drop_permyriad").unwrap(),
            250
        );

        stats_tx
            .send("{\"type\":\"stats\",\"matched\":9}".to_owned())
            .unwrap();
        let stats = next(&mut lines).await;
        assert_eq!(stats["type"], "stats");
        assert_eq!(stats["matched"], 9);

        drop(writer);
        control_task.await.unwrap();
        timeout(Duration::from_secs(1), server_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn malformed_request_returns_an_error_with_its_id() {
        let (server, client) = UnixStream::pair().unwrap();
        let (_, state) = watch::channel(ControlState {
            rules: vec![rule(0)],
        });
        let (stats, _) = broadcast::channel(1);
        let (commands, _) = mpsc::channel(1);
        let task = tokio::spawn(serve_connection(server, commands, state, stats.subscribe()));
        let (reader, mut writer) = client.into_split();
        let mut lines = BufReader::new(reader).lines();
        writer
            .write_all(b"{\"type\":\"unknown\",\"id\":77}\n")
            .await
            .unwrap();
        let response = next(&mut lines).await;
        assert_eq!(response["type"], "error");
        assert_eq!(response["id"], 77);
        drop(writer);
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn control_loop_request_has_a_deadline() {
        let (commands, mut receiver) = mpsc::channel(1);
        let stalled = tokio::spawn(async move {
            let _envelope = receiver.recv().await.unwrap();
            std::future::pending::<()>().await;
        });
        let error =
            request_with_timeout(&commands, ControlCommand::Stop, Duration::from_millis(20))
                .await
                .unwrap_err();
        stalled.abort();
        assert!(error.contains("timed out"));
    }

    async fn next(
        lines: &mut tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    ) -> Value {
        let line = timeout(Duration::from_secs(1), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        serde_json::from_str(&line).unwrap()
    }
}
