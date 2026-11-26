//! Concrete scope language, canonical protected operations, `permits` and
//! the conservative `is_subset` relation (spec §4.1, WP1).
//!
//! Soundness obligation (T2 building block):
//!
//! ```text
//! is_subset(c, p) && permits(c, o)  ==>  permits(p, o)
//! ```
//!
//! The language is deliberately tiny: exact object / endpoint identity and
//! small rights bitsets. Different resource kinds are never comparable.

use serde::{Deserialize, Serialize};
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::ids::{EndpointId, ObjectId};

/// One file right.
#[cfg_attr(verus_keep_ghost, verus_verify(external_derive))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileRight {
    /// One bounded snapshot read (§9.3).
    Read,
    /// One bounded atomic replacement of the registered slot.
    Replace,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl FileRight {
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.bit_spec()))]
    const fn bit(self) -> u8 {
        match self {
            FileRight::Read => FileRights::READ.0,
            FileRight::Replace => FileRights::REPLACE.0,
        }
    }
}

/// Set of [`FileRight`]s. Only defined bits are representable; decoding
/// rejects unknown bits.
#[cfg_attr(verus_keep_ghost, verus_verify(external_derive))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct FileRights(u8);

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl FileRights {
    /// Read snapshot.
    #[cfg_attr(verus_keep_ghost, verus_spec(ensures Self::READ.raw() == 1u8))]
    pub const READ: FileRights = FileRights(0b01);
    /// Replace content.
    #[cfg_attr(verus_keep_ghost, verus_spec(ensures Self::REPLACE.raw() == 2u8))]
    pub const REPLACE: FileRights = FileRights(0b10);
    const ALL_BITS: u8 = 0b11;

    /// Empty set (permits nothing; rejected as a grant scope).
    pub const fn empty() -> Self {
        FileRights(0)
    }

    /// Decode, rejecting undefined bits.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r matches Some(f) ==> f.wf() && f.raw() == bits, r is None <==> bits & !3u8 != 0))]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::ALL_BITS == 0 {
            Some(FileRights(bits))
        } else {
            None
        }
    }

    /// Raw bits.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Set union.
    pub const fn union(self, other: FileRights) -> Self {
        FileRights(self.0 | other.0)
    }

    /// `other ⊆ self`.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.contains_all_spec(other)))]
    pub const fn contains_all(self, other: FileRights) -> bool {
        self.0 & other.0 == other.0
    }

    /// Membership of one right.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.has_spec(right)))]
    pub const fn has(self, right: FileRight) -> bool {
        self.0 & right.bit() != 0
    }

    /// No rights.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == (self.raw() == 0)))]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl TryFrom<u8> for FileRights {
    type Error = &'static str;
    fn try_from(bits: u8) -> Result<Self, Self::Error> {
        FileRights::from_bits(bits).ok_or("undefined file-right bits")
    }
}

impl From<FileRights> for u8 {
    fn from(r: FileRights) -> u8 {
        r.0
    }
}

/// One HTTP method.
#[cfg_attr(verus_keep_ghost, verus_verify(external_derive))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    /// GET
    Get,
    /// HEAD
    Head,
    /// POST
    Post,
    /// PUT
    Put,
    /// PATCH
    Patch,
    /// DELETE
    Delete,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl HttpMethod {
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.bit_spec()))]
    const fn bit(self) -> u8 {
        match self {
            HttpMethod::Get => 1 << 0,
            HttpMethod::Head => 1 << 1,
            HttpMethod::Post => 1 << 2,
            HttpMethod::Put => 1 << 3,
            HttpMethod::Patch => 1 << 4,
            HttpMethod::Delete => 1 << 5,
        }
    }
}

/// Set of [`HttpMethod`]s. Only defined bits are representable.
#[cfg_attr(verus_keep_ghost, verus_verify(external_derive))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct MethodSet(u8);

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl MethodSet {
    const ALL_BITS: u8 = 0b11_1111;

    /// Empty set.
    pub const fn empty() -> Self {
        MethodSet(0)
    }

    /// Decode, rejecting undefined bits.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r matches Some(f) ==> f.wf() && f.raw() == bits, r is None <==> bits & !0x3fu8 != 0))]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::ALL_BITS == 0 {
            Some(MethodSet(bits))
        } else {
            None
        }
    }

    /// Raw bits.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Add one method.
    pub const fn with(self, m: HttpMethod) -> Self {
        MethodSet(self.0 | m.bit())
    }

    /// Singleton set.
    pub const fn only(m: HttpMethod) -> Self {
        MethodSet(m.bit())
    }

    /// Membership.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.has_spec(m)))]
    pub const fn has(self, m: HttpMethod) -> bool {
        self.0 & m.bit() != 0
    }

    /// `other ⊆ self`.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.contains_all_spec(other)))]
    pub const fn contains_all(self, other: MethodSet) -> bool {
        self.0 & other.0 == other.0
    }

    /// No methods.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == (self.raw() == 0)))]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl TryFrom<u8> for MethodSet {
    type Error = &'static str;
    fn try_from(bits: u8) -> Result<Self, Self::Error> {
        MethodSet::from_bits(bits).ok_or("undefined method bits")
    }
}

impl From<MethodSet> for u8 {
    fn from(m: MethodSet) -> u8 {
        m.0
    }
}

/// A concrete permission: denotes a set of canonical [`Operation`]s.
///
/// `Scope` is a *description*, not authority, so it is `Copy`.
#[cfg_attr(verus_keep_ghost, verus_verify(external_derive))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Scope {
    /// Rights on exactly one registered file object.
    File {
        /// Registered object.
        object: ObjectId,
        /// Permitted rights.
        rights: FileRights,
    },
    /// Requests to exactly one registered HTTPS endpoint.
    Https {
        /// Registered endpoint.
        endpoint: EndpointId,
        /// Permitted methods.
        methods: MethodSet,
        /// Maximum request body size in bytes (inclusive).
        max_body_bytes: u64,
    },
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Scope {
    /// A grantable scope must permit at least one operation. Scopes with an
    /// empty rights/method set are rejected at every issuance point.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.is_well_formed_spec()))]
    pub const fn is_well_formed(&self) -> bool {
        match self {
            Scope::File { rights, .. } => !rights.is_empty(),
            Scope::Https { methods, .. } => !methods.is_empty(),
        }
    }
}

/// A canonical protected operation (element of the universe O, §4.1). Each
/// costs exactly one budget unit in the MVP.
#[cfg_attr(verus_keep_ghost, verus_verify(external_derive))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operation {
    /// One file operation on a registered object.
    File {
        /// Target object.
        object: ObjectId,
        /// Requested right.
        right: FileRight,
    },
    /// One outbound HTTPS request attempt.
    Https {
        /// Target endpoint.
        endpoint: EndpointId,
        /// Method.
        method: HttpMethod,
        /// Exact request body size in bytes.
        body_bytes: u64,
    },
}

/// Does `scope` permit `op`?
///
/// ensures: result ==> same resource kind and identical object/endpoint.
#[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == permits_spec(*scope, *op)))]
pub const fn permits(scope: &Scope, op: &Operation) -> bool {
    match (scope, op) {
        (Scope::File { object, rights }, Operation::File { object: o, right }) => {
            object.to_raw() == o.to_raw() && rights.has(*right)
        }
        (
            Scope::Https {
                endpoint,
                methods,
                max_body_bytes,
            },
            Operation::Https {
                endpoint: e,
                method,
                body_bytes,
            },
        ) => {
            endpoint.to_raw() == e.to_raw()
                && methods.has(*method)
                && *body_bytes <= *max_body_bytes
        }
        _ => false,
    }
}

/// Conservative scope inclusion: `child ⊆ parent`.
///
/// ensures (soundness): `is_subset(c, p) && permits(c, o) ==> permits(p, o)`.
/// Also reflexive and transitive. Mismatched resource kinds are never
/// subsets.
#[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == is_subset_spec(*child, *parent)))]
pub const fn is_subset(child: &Scope, parent: &Scope) -> bool {
    match (child, parent) {
        (
            Scope::File {
                object: co,
                rights: cr,
            },
            Scope::File {
                object: po,
                rights: pr,
            },
        ) => co.to_raw() == po.to_raw() && pr.contains_all(*cr),
        (
            Scope::Https {
                endpoint: ce,
                methods: cm,
                max_body_bytes: cb,
            },
            Scope::Https {
                endpoint: pe,
                methods: pm,
                max_body_bytes: pb,
            },
        ) => ce.to_raw() == pe.to_raw() && pm.contains_all(*cm) && *cb <= *pb,
        _ => false,
    }
}

#[cfg(verus_keep_ghost)]
include!("scope_verus.rs");
