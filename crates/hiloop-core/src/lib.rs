//! Shared contracts for the hiloop interceptor.
//!
//! [`identity`] defines the fork-tree spine shared by telemetry, snapshots, and
//! state. [`event`] defines the normalized telemetry shape stamped with that
//! identity.

pub mod event;
pub mod identity;
