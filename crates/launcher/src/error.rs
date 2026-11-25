use std::fmt;
use std::io;

use crate::MissingControl;

/// Errors returned by the launcher. Every error means *no sandbox is running*
/// (any partially started process tree has been killed).
#[derive(Debug)]
pub enum LaunchError {
    /// R10: a mandatory enforcement mechanism is unavailable; launch refused.
    MissingMandatoryControl(Vec<MissingControl>),
    /// The launch profile or configuration is invalid or unsafe.
    InvalidProfile(String),
    /// Building the seccomp filter failed.
    Seccomp(String),
    /// cgroup setup or teardown failed.
    Cgroup(String),
    /// The sandbox started but did not confirm that its confinement is active.
    ConfinementNotConfirmed(String),
    /// Underlying I/O error.
    Io(io::Error),
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LaunchError::MissingMandatoryControl(missing) => {
                write!(f, "launch refused (R10), mandatory control(s) unavailable:")?;
                for m in missing {
                    write!(f, " [{}: {}]", m.control, m.reason)?;
                }
                Ok(())
            }
            LaunchError::InvalidProfile(m) => write!(f, "invalid launch profile: {m}"),
            LaunchError::Seccomp(m) => write!(f, "seccomp filter: {m}"),
            LaunchError::Cgroup(m) => write!(f, "cgroup: {m}"),
            LaunchError::ConfinementNotConfirmed(m) => {
                write!(f, "sandbox did not confirm confinement: {m}")
            }
            LaunchError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for LaunchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LaunchError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for LaunchError {
    fn from(e: io::Error) -> Self {
        LaunchError::Io(e)
    }
}
