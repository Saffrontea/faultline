//! Frontend-independent experiment orchestration.
//!
//! This crate owns operating-system adapters, workload lifecycle, agent
//! sessions, generated traffic, and timeline execution. A TUI, CLI, or test
//! harness supplies configuration and observes results without reimplementing
//! those lifecycle rules.

pub mod experiment;
mod process;
pub mod session;
pub mod timeline;
pub mod traffic;
pub mod workload;

pub use experiment::{PreparedExperiment, Tooling, prepare_experiment};
pub use session::{Direction, Session, SessionOptions};
pub use traffic::{TrafficGuard, TrafficStatus};
pub use workload::{Discovery, WorkloadGuard};
