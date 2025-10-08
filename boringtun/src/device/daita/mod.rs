//! # NOTES
//!
//! This is a work-in-progress implementation of DAITA version 3.
//!
//! ## TODO
//!
//! - Add (and log) error messages in the `ErrorAction::Ignore` variant (otherwise we might as well return `Ok(())` directly)
//! - Look over where `ErrorAction::Ignore` is used, and see if it makes sense to return `ErrorAction::Close` instead
//! - Expose the `PaddingOverhead` stats to the daemon
//! - Support mocked time for tests (this is supported in other parts of GotaTun using `mock_instant` crate)
//! - Make sure that machines that include blocking actions are disabled, until we have tested blocking properly
//! - Test whether we can reliably replace padding packets with outgoing normal packets.
//! - Pick good numbers for `max_blocked_packets` and `min_blocking_capacity` so that the blocking queue doesn't
//!   fill to capacity.
//! - Test blocking with a real machine, ask Tobias for one
//! - Set `max_padding_frac` and `max_blocking_frac` from the daemon using the response of ephemeral peer API.

mod actions;
mod events;
mod hooks;
mod types;

pub use hooks::DaitaHooks;

pub struct DaitaSettings {
    /// The maybenot machines to use.
    pub maybenot_machines: Vec<String>,
    /// Maximum fraction of bandwidth that may be used for padding packets.
    pub max_padding_frac: f64,
    /// Maximum fraction of bandwidth that may be used for blocking packets.
    pub max_blocking_frac: f64,
    /// Maximum number of packets that may be blocked at any time.
    pub max_blocked_packets: usize,
    /// Minimum number of free slots in the blocking queue to continue blocking.
    pub min_blocking_capacity: usize,
}
