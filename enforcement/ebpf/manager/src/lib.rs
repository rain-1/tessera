//! Tessera BPF LSM manager — WP7 research stub.
//!
//! Direct capability class: unlimited-use **read-only** access to a
//! registered directory subtree, bind-mounted into one sandbox
//! (docs/bpf-lsm.md). This crate contains:
//!
//! * [`maps`]: `#[repr(C)]` mirrors of the BPF map layouts;
//! * [`kernel`]: the [`kernel::KernelPolicy`] seam and an in-memory
//!   [`kernel::FakeKernel`] whose access check mirrors the BPF program;
//! * [`manager`]: the desired/installed generation protocol, lease-based
//!   fail-closed behaviour and revocation acknowledgement, as a pure state
//!   machine.
//!
//! There is **no kernel backend**. Nothing here loads BPF, and nothing has
//! been tested against a kernel (no root on the development host). ADR-0023
//! decides that direct grants do not ship in the MVP.

#![forbid(unsafe_code)]

pub mod kernel;
pub mod manager;
pub mod maps;
