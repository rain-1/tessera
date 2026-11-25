use std::fmt;

use serde::Serialize;

use crate::LaunchError;

/// Caller-supplied label naming the sandbox principal.
///
/// The authority core allocates the real installation/epoch-scoped `AgentId`
/// (spec §9.1); the launcher only carries its textual form so that cgroup
/// names, the hostname and the launch record can be correlated. The label is
/// restricted to `[A-Za-z0-9._-]{1,64}` and may not start with `.` so it is
/// safe to embed in file-system paths.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct AgentLabel(String);

impl AgentLabel {
    pub fn new(label: impl Into<String>) -> Result<Self, LaunchError> {
        let label = label.into();
        let ok = !label.is_empty()
            && label.len() <= 64
            && !label.starts_with('.')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if ok {
            Ok(Self(label))
        } else {
            Err(LaunchError::InvalidProfile(format!(
                "agent label {label:?} must match [A-Za-z0-9._-]{{1,64}} and not start with '.'"
            )))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_validation() {
        assert!(AgentLabel::new("agent-1.worker_a").is_ok());
        for bad in ["", ".hidden", "a/b", "..", "a b", "x\0", &"a".repeat(65)] {
            assert!(AgentLabel::new(bad).is_err(), "{bad:?} accepted");
        }
    }
}
