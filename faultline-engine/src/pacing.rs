use std::process::{Command, Output};

use anyhow::{Context as _, bail};

/// Installs the fair-queue scheduler used for BPF Earliest Departure Time.
/// All impairment decisions and timestamps are produced by the BPF program;
/// fq only retains packets until their requested delivery time.
pub struct PacingBackend;

pub struct PacingGuard {
    interface: String,
}

impl PacingBackend {
    pub fn install(&self, interface: &str, required: bool) -> anyhow::Result<Option<PacingGuard>> {
        if !required {
            return Ok(None);
        }
        let output = Command::new("tc")
            .args(install_args(interface))
            .output()
            .context("running tc to install the fq pacing qdisc")?;
        ensure_success("installing the fq pacing qdisc", &output)?;
        Ok(Some(PacingGuard {
            interface: interface.to_owned(),
        }))
    }
}

const QUEUE_LIMIT: &str = "100000";
const FLOW_QUEUE_LIMIT: &str = "4294967295";

fn install_args(interface: &str) -> [&str; 15] {
    [
        "qdisc",
        "add",
        "dev",
        interface,
        "root",
        "handle",
        "7fff:",
        "fq",
        "limit",
        QUEUE_LIMIT,
        "flow_limit",
        FLOW_QUEUE_LIMIT,
        "horizon",
        "86400s",
        "horizon_cap",
    ]
}

impl Drop for PacingGuard {
    fn drop(&mut self) {
        let _ = Command::new("tc")
            .args([
                "qdisc",
                "del",
                "dev",
                &self.interface,
                "root",
                "handle",
                "7fff:",
            ])
            .output();
    }
}

fn ensure_success(operation: &str, output: &Output) -> anyhow::Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!(
        "{operation} failed: {}. {} does not replace an existing root qdisc",
        stderr.trim(),
        crate::APPLICATION_NAME
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_only_fq_parameters() {
        assert_eq!(
            install_args("eth0"),
            [
                "qdisc",
                "add",
                "dev",
                "eth0",
                "root",
                "handle",
                "7fff:",
                "fq",
                "limit",
                "100000",
                "flow_limit",
                "4294967295",
                "horizon",
                "86400s",
                "horizon_cap"
            ]
        );
    }
}
