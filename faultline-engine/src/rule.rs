use std::time::Duration;

use anyhow::bail;
use faultline_common::{
    LOSS_ALGORITHM_GILBERT_ELLIOTT, LOSS_ALGORITHM_HASH, LOSS_ALGORITHM_RANDOM, PROTOCOL_ANY,
};
use faultline_protocol::RuleSpec;
use ipnet::IpNet;

use crate::quantize_loss;

/// Input shared by CLI and scenario decoding before conversion to the wire
/// `RuleSpec`. Keeping percentages and optional fields here makes every input
/// path use the same semantic validation and quantization.
pub(crate) struct RuleInput {
    pub id: u32,
    pub source: Option<IpNet>,
    pub destination: IpNet,
    pub protocol: u8,
    pub destination_port: u16,
    pub loss: f64,
    pub loss_algorithm: u8,
    pub seed: u32,
    pub burst_loss: Option<f64>,
    pub burst_recovery: f64,
    pub burst_bad_loss: f64,
    pub burst_good_loss: f64,
    pub burst_idle_reset: Option<Duration>,
    pub duplicate: f64,
    pub reorder: f64,
    pub delay: Option<Duration>,
    pub jitter: Option<Duration>,
    pub bandwidth_bps: Option<u64>,
}

impl RuleInput {
    pub(crate) fn compile(self) -> anyhow::Result<RuleSpec> {
        self.validate()?;
        let ge_enabled = self.ge_enabled();
        let spec = self.into_spec(ge_enabled);
        spec.validate().map_err(anyhow::Error::msg)?;
        Ok(spec)
    }

    fn validate(&self) -> anyhow::Result<()> {
        self.validate_percentages()?;
        self.validate_filter()?;
        self.validate_impairments()?;
        self.validate_burst_loss()?;
        self.validate_algorithm()
    }

    fn validate_percentages(&self) -> anyhow::Result<()> {
        [
            ("loss", self.loss),
            ("burst recovery", self.burst_recovery),
            ("burst bad loss", self.burst_bad_loss),
            ("burst good loss", self.burst_good_loss),
            ("duplication", self.duplicate),
            ("reordering", self.reorder),
        ]
        .into_iter()
        .try_for_each(|(name, value)| validate_percentage(self.id, name, value))?;
        self.burst_loss
            .into_iter()
            .try_for_each(|value| validate_percentage(self.id, "burst loss", value))
    }

    fn validate_filter(&self) -> anyhow::Result<()> {
        if self.destination_port != 0 && self.protocol == PROTOCOL_ANY {
            bail!("rule {} specifies a port without TCP or UDP", self.id);
        }
        Ok(())
    }

    fn validate_impairments(&self) -> anyhow::Result<()> {
        if self.jitter.is_some() && self.delay.is_none() {
            bail!("rule {} uses jitter without delay", self.id);
        }
        if self.reorder > 0.0 && self.delay.is_none() {
            bail!("rule {} uses reordering without delay", self.id);
        }
        if self.delay.is_some_and(|duration| duration.is_zero()) {
            bail!("rule {} has zero delay", self.id);
        }
        if self.jitter.is_some_and(|duration| duration.is_zero()) {
            bail!("rule {} has zero jitter", self.id);
        }
        Ok(())
    }

    fn validate_burst_loss(&self) -> anyhow::Result<()> {
        if self
            .burst_idle_reset
            .is_some_and(|duration| duration < Duration::from_secs(1))
        {
            bail!("rule {} has burst_idle_reset below 1s", self.id);
        }
        if self.burst_loss.is_some() && self.loss != 0.0 {
            bail!(
                "rule {} cannot combine loss with burst_loss; use burst_good_loss instead",
                self.id
            );
        }
        if self.burst_loss.is_some() && self.loss_algorithm == LOSS_ALGORITHM_RANDOM {
            bail!(
                "rule {} cannot combine burst_loss with the random loss algorithm",
                self.id
            );
        }
        let ge_enabled = self.ge_enabled();
        if ge_enabled && self.burst_loss.is_none() {
            bail!("rule {} uses gilbert-elliott without burst_loss", self.id);
        }
        if ge_enabled
            && (self.burst_loss == Some(0.0)
                || self.burst_recovery == 0.0
                || self
                    .burst_loss
                    .is_some_and(|value| quantize_loss(value) == 0)
                || quantize_loss(self.burst_recovery) == 0)
        {
            bail!("rule {} requires non-zero burst loss and recovery", self.id);
        }
        Ok(())
    }

    fn validate_algorithm(&self) -> anyhow::Result<()> {
        if ![
            LOSS_ALGORITHM_HASH,
            LOSS_ALGORITHM_RANDOM,
            LOSS_ALGORITHM_GILBERT_ELLIOTT,
        ]
        .contains(&self.loss_algorithm)
        {
            bail!("rule {} has an unknown loss algorithm", self.id);
        }
        Ok(())
    }

    fn ge_enabled(&self) -> bool {
        self.burst_loss.is_some() || self.loss_algorithm == LOSS_ALGORITHM_GILBERT_ELLIOTT
    }

    fn into_spec(self, ge_enabled: bool) -> RuleSpec {
        RuleSpec {
            id: self.id,
            source: self.source,
            destination: self.destination,
            protocol: self.protocol,
            destination_port: self.destination_port,
            seed: self.seed,
            loss_algorithm: if ge_enabled {
                LOSS_ALGORITHM_GILBERT_ELLIOTT
            } else {
                self.loss_algorithm
            },
            drop_permyriad: quantize_loss(self.loss),
            ge_enter_permyriad: self.burst_loss.map(quantize_loss).unwrap_or(0),
            ge_recover_permyriad: if ge_enabled {
                quantize_loss(self.burst_recovery)
            } else {
                0
            },
            ge_good_loss_permyriad: if ge_enabled {
                quantize_loss(self.burst_good_loss)
            } else {
                0
            },
            ge_bad_loss_permyriad: if ge_enabled {
                quantize_loss(self.burst_bad_loss)
            } else {
                0
            },
            ge_idle_reset_secs: self
                .burst_idle_reset
                .map(|duration| duration.as_secs().min(u32::MAX as u64) as u32)
                .unwrap_or(0),
            duplicate_permyriad: quantize_loss(self.duplicate),
            reorder_permyriad: quantize_loss(self.reorder),
            delay_ns: duration_ns(self.delay),
            jitter_ns: duration_ns(self.jitter),
            bandwidth_bps: self.bandwidth_bps.unwrap_or(0),
        }
    }
}

fn duration_ns(value: Option<Duration>) -> u64 {
    value
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn validate_percentage(id: u32, name: &str, value: f64) -> anyhow::Result<()> {
    if !value.is_finite() || !(0.0..=100.0).contains(&value) {
        bail!("rule {id} has {name} outside 0..=100%");
    }
    if value > 0.0 && quantize_loss(value) == 0 {
        bail!("rule {id} has {name} below the representable minimum of 0.01%");
    }
    Ok(())
}
