use std::process::Command;

use anyhow::{Context as _, anyhow, bail};
use aya::{
    programs::{
        SchedClassifier, TcAttachType,
        links::LinkOrder,
        tc::{self, NlOptions, SchedClassifierLink, TcAttachOptions, TcError},
    },
    util::KernelVersion,
};
use log::warn;

/// Drop the program link before considering removal of its legacy qdisc.
/// An existing clsact is never owned by this guard.
pub struct Attachment {
    _link: SchedClassifierLink,
    _clsact: Option<ClsactGuard>,
}

impl Attachment {
    pub fn attach(
        program: &mut SchedClassifier,
        interface: &str,
        direction: TcAttachType,
    ) -> anyhow::Result<Self> {
        let kernel =
            KernelVersion::current().map_err(|error| anyhow!("kernel version: {error}"))?;
        Self::attach_with_mode(
            program,
            interface,
            direction,
            kernel >= KernelVersion::new(6, 6, 0),
        )
    }

    fn attach_with_mode(
        program: &mut SchedClassifier,
        interface: &str,
        direction: TcAttachType,
        tcx: bool,
    ) -> anyhow::Result<Self> {
        // A verifier failure must occur before any interface mutation.
        program.load().context("loading the TC classifier")?;
        let clsact = if tcx {
            None
        } else {
            ClsactGuard::install(interface)?
        };
        let options = if tcx {
            TcAttachOptions::TcxOrder(LinkOrder::default())
        } else {
            TcAttachOptions::Netlink(NlOptions::default())
        };
        let id = program
            .attach_with_options(interface, direction, options)
            .with_context(|| format!("attaching to {interface}"))?;
        Ok(Self {
            _link: program.take_link(id)?,
            _clsact: clsact,
        })
    }
}

struct ClsactGuard {
    interface: String,
}

impl ClsactGuard {
    fn install(interface: &str) -> anyhow::Result<Option<Self>> {
        match tc::qdisc_add_clsact(interface) {
            Ok(()) => Ok(Some(Self {
                interface: interface.to_owned(),
            })),
            Err(TcError::NetlinkError(error)) if error.raw_os_error() == Some(libc::EEXIST) => {
                Ok(None)
            }
            Err(error) => Err(error).context("installing the clsact qdisc"),
        }
    }
}

fn has_filters(interface: &str) -> anyhow::Result<bool> {
    for direction in ["ingress", "egress"] {
        let output = Command::new("tc")
            .args(["filter", "show", "dev", interface, direction])
            .output()?;
        if !output.status.success() {
            bail!(
                "checking {interface} {direction} filters: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if !output.stdout.iter().all(u8::is_ascii_whitespace) {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Drop for ClsactGuard {
    fn drop(&mut self) {
        // Another user may have added a filter while we owned clsact. Do not
        // remove their filter when detaching our own program.
        match has_filters(&self.interface) {
            Ok(false) => (),
            Ok(true) => {
                warn!(
                    "retaining clsact on {} because other filters remain",
                    self.interface
                );
                return;
            }
            Err(error) => {
                warn!("retaining clsact on {}: {error:#}", self.interface);
                return;
            }
        }
        match Command::new("tc")
            .args(["qdisc", "del", "dev", &self.interface, "clsact"])
            .output()
        {
            Ok(output) if output.status.success() => (),
            Ok(output) => warn!(
                "removing clsact on {}: {}",
                self.interface,
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => warn!("removing clsact on {}: {error}", self.interface),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::{Object as _, ObjectSection as _};
    use std::{fs, path::PathBuf};

    struct Interface(String);

    impl Interface {
        fn new() -> Self {
            let name = format!("flt-fail{}", std::process::id());
            tc_command("ip", &["link", "add", &name, "type", "dummy"]);
            Self(name)
        }
    }

    impl Drop for Interface {
        fn drop(&mut self) {
            let _ = Command::new("ip").args(["link", "del", &self.0]).output();
        }
    }

    fn tc_command(command: &str, arguments: &[&str]) -> String {
        let output = Command::new(command).args(arguments).output().unwrap();
        assert!(
            output.status.success(),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn snapshot(interface: &str) -> (String, String, String) {
        (
            tc_command("tc", &["-j", "qdisc", "show", "dev", interface]),
            tc_command("tc", &["filter", "show", "dev", interface, "ingress"]),
            tc_command("tc", &["filter", "show", "dev", interface, "egress"]),
        )
    }

    fn object(invalid: bool) -> aya::Ebpf {
        let mut bytes =
            aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/faultline")).to_vec();
        if invalid {
            let file = object::File::parse(bytes.as_slice()).unwrap();
            let section = file
                .section_by_name("classifier")
                .expect("classifier ELF section");
            let (offset, _) = section.file_range().unwrap();
            bytes[offset as usize] = 0xff; // Invalid BPF opcode, rejected at BPF_PROG_LOAD.
        }
        aya::Ebpf::load(&bytes).unwrap()
    }

    fn attach_object(
        ebpf: &mut aya::Ebpf,
        interface: &str,
        direction: TcAttachType,
        tcx: bool,
    ) -> anyhow::Result<Attachment> {
        let classifier = ebpf
            .program_mut("faultline_classifier")
            .unwrap()
            .try_into()
            .unwrap();
        Attachment::attach_with_mode(classifier, interface, direction, tcx)
    }

    fn assert_cli_failure_preserves(interface: &str, extra: &[&str], expected_error: &str) {
        let before = snapshot(interface);
        let engine =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/release/faultline-engine");
        let output = Command::new(engine)
            .args([
                "--interface",
                interface,
                "--direction",
                "egress",
                "--destination",
                "192.0.2.1/32",
                "--duration",
                "1s",
            ])
            .args(extra)
            .output()
            .unwrap();
        assert!(!output.status.success(), "startup unexpectedly succeeded");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected_error),
            "unexpected error: {stderr}"
        );
        assert_eq!(
            snapshot(interface),
            before,
            "startup failure changed qdiscs/filters"
        );
        if KernelVersion::current().unwrap() >= KernelVersion::new(6, 6, 0) {
            assert!(
                SchedClassifier::query_tcx(interface, TcAttachType::Egress)
                    .unwrap()
                    .1
                    .is_empty()
            );
        }
    }

    #[test]
    #[ignore = "requires root, ip/tc, BPF support, and the current release engine; run lab:startup"]
    fn kernel_startup_failure_and_qdisc_ownership() {
        let interface = Interface::new();
        let name = &interface.0;
        let clean = snapshot(name);

        // Verifier failure must not leave even a newly created clsact behind.
        let error = attach_object(&mut object(true), name, TcAttachType::Egress, false)
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("loading the TC classifier"));
        assert_eq!(snapshot(name), clean);
        println!("verifier rejection: qdiscs unchanged");

        // Force netlink attach to an absent parent after installing clsact.
        let error = attach_object(
            &mut object(false),
            name,
            TcAttachType::Custom(0x1234_0000),
            false,
        )
        .err()
        .unwrap();
        assert!(format!("{error:#}").contains("attaching to"));
        assert_eq!(snapshot(name), clean);
        println!("netlink attach failure: owned clsact rolled back");

        // A successful legacy attachment drops the filter before its clsact.
        let mut ebpf = object(false);
        let attachment = attach_object(&mut ebpf, name, TcAttachType::Egress, false).unwrap();
        assert!(has_filters(name).unwrap());
        drop(attachment);
        assert_eq!(snapshot(name), clean);
        println!("legacy normal exit: owned clsact removed");

        // An already existing qdisc and another user's filter are preserved.
        tc_command("tc", &["qdisc", "add", "dev", name, "clsact"]);
        tc_command(
            "tc",
            &[
                "filter", "add", "dev", name, "ingress", "pref", "1", "matchall", "action", "pass",
            ],
        );
        let existing = snapshot(name);
        drop(attach_object(&mut object(false), name, TcAttachType::Egress, false).unwrap());
        assert_eq!(snapshot(name), existing);
        assert!(attach_object(&mut object(true), name, TcAttachType::Egress, false).is_err());
        assert_eq!(snapshot(name), existing);
        println!("existing clsact and filter: preserved on success and failure");
        tc_command("tc", &["qdisc", "del", "dev", name, "clsact"]);

        // A filter added by someone else during our session also survives.
        let attachment =
            attach_object(&mut object(false), name, TcAttachType::Egress, false).unwrap();
        tc_command(
            "tc",
            &[
                "filter", "add", "dev", name, "ingress", "pref", "1", "matchall", "action", "pass",
            ],
        );
        drop(attachment);
        assert_eq!(snapshot(name), existing);
        tc_command("tc", &["qdisc", "del", "dev", name, "clsact"]);
        println!("concurrently added foreign filter: preserved");

        if KernelVersion::current().unwrap() >= KernelVersion::new(6, 6, 0) {
            let attachment =
                attach_object(&mut object(false), name, TcAttachType::Egress, true).unwrap();
            assert_eq!(snapshot(name), clean, "TCX must not add clsact");
            drop(attachment);
            assert!(
                SchedClassifier::query_tcx(name, TcAttachType::Egress)
                    .unwrap()
                    .1
                    .is_empty()
            );
            println!("TCX attachment: no qdisc changes");
        }

        // Fail after both attachment and fq installation, during socket bind.
        let blocker =
            std::env::temp_dir().join(format!("flt-control-blocker-{}", std::process::id()));
        fs::write(&blocker, "preserve me").unwrap();
        assert_cli_failure_preserves(
            name,
            &["--control-socket", blocker.to_str().unwrap()],
            "refusing to replace non-socket",
        );
        assert_eq!(fs::read_to_string(&blocker).unwrap(), "preserve me");
        fs::remove_file(blocker).unwrap();
        println!("control socket startup failure: fq and attachment rolled back");

        tc_command(
            "tc",
            &["qdisc", "add", "dev", name, "root", "handle", "1234:", "fq"],
        );
        assert_cli_failure_preserves(
            name,
            &["--bandwidth", "10mbit"],
            "does not replace an existing root qdisc",
        );
        println!("existing root fq: preserved when pacing setup is rejected");
    }
}
