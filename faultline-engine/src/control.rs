use std::time::Duration;

use tokio::{
    sync::{mpsc, oneshot},
    time,
};

use faultline_common::LOSS_ALGORITHM_HASH;
pub use faultline_protocol::{ControlState, RuleSpec};

/// Commands accepted by the running control plane.
///
/// Future file watchers and socket servers can retain a `Sender` and update
/// rules without coupling their input format to Aya or the BPF map layout.
#[derive(Clone, Debug, PartialEq)]
pub enum ControlCommand {
    ReplaceRules(Vec<RuleSpec>),
    Stop,
}

pub type ControlResponse = Result<ControlState, String>;

pub struct ControlEnvelope {
    pub command: ControlCommand,
    pub response: Option<oneshot::Sender<ControlResponse>>,
}

impl From<ControlCommand> for ControlEnvelope {
    fn from(command: ControlCommand) -> Self {
        Self {
            command,
            response: None,
        }
    }
}

pub struct ControlChannel {
    pub receiver: mpsc::Receiver<ControlEnvelope>,
    sender: mpsc::Sender<ControlEnvelope>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OutageWindow {
    pub after: Duration,
    pub duration: Duration,
}

impl ControlChannel {
    pub fn for_rules(initial_rules: Vec<RuleSpec>) -> Self {
        let (sender, receiver) = mpsc::channel(16);
        sender
            .try_send(ControlCommand::ReplaceRules(initial_rules).into())
            .expect("new control channel has capacity");

        Self { receiver, sender }
    }

    /// Starts timers after programs and qdiscs have been attached, so scenario
    /// timing is measured from the point at which faults can actually apply.
    pub fn schedule(
        &self,
        initial_rule: RuleSpec,
        duration: Option<Duration>,
        outage: Option<OutageWindow>,
    ) {
        if let Some(duration) = duration {
            let timer_sender = self.sender.clone();
            tokio::spawn(async move {
                time::sleep(duration).await;
                let _ = timer_sender.send(ControlCommand::Stop.into()).await;
            });
        }
        if let Some(outage) = outage {
            let outage_sender = self.sender.clone();
            tokio::spawn(async move {
                time::sleep(outage.after).await;
                let mut outage_rule = initial_rule;
                // Force the ordinary 100% loss path even when the original
                // rule uses a stateful Gilbert-Elliott model.
                outage_rule.loss_algorithm = LOSS_ALGORITHM_HASH;
                outage_rule.drop_permyriad = 10_000;
                if outage_sender
                    .send(ControlCommand::ReplaceRules(vec![outage_rule]).into())
                    .await
                    .is_err()
                {
                    return;
                }
                time::sleep(outage.duration).await;
                let _ = outage_sender
                    .send(ControlCommand::ReplaceRules(vec![initial_rule]).into())
                    .await;
            });
        }
    }

    /// Returns a sender used by the Unix socket adapter and future watchers.
    #[allow(dead_code)]
    pub fn sender(&self) -> mpsc::Sender<ControlEnvelope> {
        self.sender.clone()
    }
}

#[cfg(test)]
mod tests {
    use ipnet::IpNet;
    use std::net::Ipv4Addr;

    use super::*;

    async fn recv_command(channel: &mut ControlChannel) -> Option<ControlCommand> {
        channel
            .receiver
            .recv()
            .await
            .map(|envelope| envelope.command)
    }

    fn rule() -> RuleSpec {
        RuleSpec {
            id: 0,
            source: None,
            destination: IpNet::new(Ipv4Addr::new(10, 20, 0, 0).into(), 16).unwrap(),
            protocol: 6,
            loss_algorithm: faultline_common::LOSS_ALGORITHM_HASH,
            destination_port: 443,
            drop_permyriad: 500,
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
    async fn cli_source_sends_initial_rules_then_a_timed_stop() {
        let expected = rule();
        let mut channel = ControlChannel::for_rules(vec![expected]);
        channel.schedule(expected, Some(Duration::from_millis(1)), None);

        assert_eq!(
            recv_command(&mut channel).await,
            Some(ControlCommand::ReplaceRules(vec![expected]))
        );
        assert_eq!(recv_command(&mut channel).await, Some(ControlCommand::Stop));
    }

    #[tokio::test]
    async fn sender_can_be_shared_with_a_future_adapter() {
        let mut channel = ControlChannel::for_rules(vec![rule()]);
        let _ = channel.receiver.recv().await;
        channel
            .sender()
            .send(ControlCommand::Stop.into())
            .await
            .unwrap();
        assert_eq!(recv_command(&mut channel).await, Some(ControlCommand::Stop));
    }

    #[test]
    fn transport_validation_rejects_unknown_algorithms() {
        let mut rule = rule();
        rule.loss_algorithm = 99;
        assert!(rule.validate().is_err());
    }

    #[test]
    fn transport_validation_rejects_invalid_loss_rates() {
        let mut rule = rule();
        rule.drop_permyriad = 10_001;
        assert!(rule.validate().is_err());
    }

    #[test]
    fn source_cidr_is_compiled_in_packet_byte_order() {
        let mut rule = rule();
        rule.source = Some("192.0.2.0/24".parse().unwrap());
        let (network, mask) = rule.source_network_and_mask();

        assert_eq!([192, 0, 2, 42][2] & mask[2], network[2]);
        assert_ne!([192, 0, 3, 42][2] & mask[2], network[2]);
    }

    #[test]
    fn mixed_address_families_are_rejected() {
        let mut value = rule();
        value.source = Some("2001:db8::/32".parse().unwrap());
        assert!(
            value
                .validate()
                .unwrap_err()
                .contains("mixes IPv4 and IPv6")
        );
    }

    #[tokio::test]
    async fn outage_temporarily_replaces_loss_with_one_hundred_percent() {
        let expected = rule();
        let mut channel = ControlChannel::for_rules(vec![expected]);
        assert_eq!(
            recv_command(&mut channel).await,
            Some(ControlCommand::ReplaceRules(vec![expected]))
        );
        channel.schedule(
            expected,
            None,
            Some(OutageWindow {
                after: Duration::ZERO,
                duration: Duration::from_millis(1),
            }),
        );

        let Some(ControlCommand::ReplaceRules(outage)) = recv_command(&mut channel).await else {
            panic!("expected outage rule");
        };
        assert_eq!(outage[0].drop_permyriad, 10_000);
        assert_eq!(outage[0].loss_algorithm, LOSS_ALGORITHM_HASH);
        assert_eq!(
            recv_command(&mut channel).await,
            Some(ControlCommand::ReplaceRules(vec![expected]))
        );
    }
}
