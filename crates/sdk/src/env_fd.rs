//! Taking ownership of the inherited broker channel descriptor.
//!
//! This module holds the crate's only `unsafe` code: one call to
//! [`OwnedFd::from_raw_fd`]. Every other part of the SDK is safe Rust.
//!
//! # Why `unsafe` is needed
//!
//! The launcher installs the broker channel at a fixed descriptor number
//! (`TESSERA_BROKER_FD=3`). Turning a bare number into an owned descriptor
//! asserts that the number names an open descriptor that no other code
//! owns. Rust cannot check this, so every route from a number to an
//! [`OwnedFd`] is `unsafe`. We looked at these safe routes:
//!
//! * `pidfd_getfd(pidfd_open(getpid()), N)` (safe in `rustix`) duplicates
//!   the descriptor without asserting ownership. The launcher's seccomp
//!   filter denies `pidfd_getfd` (ADR-0004: it would let a process lift
//!   descriptors from another process), so this does not work in a sandbox.
//! * Opening `/proc/self/fd/N` fails with `ENXIO` for sockets. It would also
//!   create a new open file description, not reuse the channel.
//! * Crates that offer a "safe" API for inherited descriptors (for example
//!   `listenfd`) contain the same `unsafe` call. Using them would only hide it.
//!
//! # How the call is kept sound
//!
//! * The descriptor can be claimed only once per process. An atomic flag
//!   guarantees that the SDK never creates two owners for the same number.
//! * Numbers 0, 1 and 2 (stdio) are refused, as are negative numbers.
//! * Before the claim, `/proc/self/fd/N` is read with `readlink`. When
//!   `/proc` is available this checks that the descriptor is open and is a
//!   socket. When `/proc` is not available, the claim still goes ahead.
//!   Afterwards, `getsockopt(SO_TYPE)` checks the descriptor. If that check
//!   fails, the descriptor is released with `into_raw_fd` and never closed,
//!   so a descriptor that the SDK does not own is never closed by it.
//!
//! The rest of the program must not use descriptor `N` itself (for example
//! by wrapping it in its own `File`). Use [`crate::Client::from_env`] only once
//! per process and share the returned client.

use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::Error;

static CLAIMED: AtomicBool = AtomicBool::new(false);

/// Parse the value of `TESSERA_BROKER_FD`.
pub(crate) fn parse_fd(value: &str) -> Result<RawFd, Error> {
    let fd: RawFd = value
        .trim()
        .parse()
        .map_err(|_| Error::Config(format!("TESSERA_BROKER_FD={value:?} is not a number")))?;
    if fd <= 2 {
        return Err(Error::Config(format!(
            "TESSERA_BROKER_FD={fd} is a standard stream or invalid; refusing to claim it"
        )));
    }
    Ok(fd)
}

/// Take ownership of inherited descriptor `fd` (once per process).
pub(crate) fn claim(fd: RawFd) -> Result<OwnedFd, Error> {
    if fd <= 2 {
        return Err(Error::Config(format!("refusing to claim descriptor {fd}")));
    }
    // Check with /proc when it is available: the descriptor must exist and
    // be a socket.
    if std::path::Path::new("/proc/self/fd").is_dir() {
        match std::fs::read_link(format!("/proc/self/fd/{fd}")) {
            Ok(target) => {
                if !target.to_string_lossy().starts_with("socket:") {
                    return Err(Error::Config(format!(
                        "descriptor {fd} from TESSERA_BROKER_FD is not a socket"
                    )));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::Config(format!(
                    "descriptor {fd} from TESSERA_BROKER_FD is not open"
                )));
            }
            // Denied (for example by Landlock): the SO_TYPE check below
            // still runs.
            Err(_) => {}
        }
    }
    if CLAIMED.swap(true, Ordering::SeqCst) {
        return Err(Error::Config(
            "the broker channel was already claimed in this process; share one Client".into(),
        ));
    }
    #[allow(unsafe_code)]
    // SAFETY: `fd` > 2 was handed to this process by the trusted launcher as
    // its broker channel. The `CLAIMED` flag makes this the only place, and
    // this the only time, that the SDK creates an owner for it. When /proc is
    // available it was checked above to be an open socket. The caller is
    // documented to not use the number elsewhere. If the descriptor turns
    // out not to be a socket, it is released below without being closed.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    match rustix::net::sockopt::socket_type(&owned) {
        Ok(_) => Ok(owned),
        Err(e) => {
            // Not a socket (or not open): give up ownership without closing.
            let _ = owned.into_raw_fd();
            Err(Error::Config(format!(
                "descriptor {fd} from TESSERA_BROKER_FD is not a usable socket: {e}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_stdio_and_garbage() {
        assert!(parse_fd("0").is_err());
        assert!(parse_fd("2").is_err());
        assert!(parse_fd("-1").is_err());
        assert!(parse_fd("three").is_err());
        assert_eq!(parse_fd("3").unwrap(), 3);
        assert_eq!(parse_fd(" 7\n").unwrap(), 7);
    }
}
