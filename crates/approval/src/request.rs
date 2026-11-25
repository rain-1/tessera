//! The canonical grant request: the exact object a human approves.
//!
//! # Canonical encoding, format version 1
//!
//! ```text
//! request   = magic "TSGR" (4 bytes) || format_version u16 = 0x0001 || field{1..11}
//! field     = tag u8 || len u16 || value[len]          (tags strictly 1,2,...,11)
//!
//! tag len  value
//!  1   2   protocol_version   u16
//!  2  16   installation_id    u128
//!  3   8   authority_epoch    u64
//!  4  16   operator_id        u128
//!  5  24   recipient          epoch u128 || serial u64
//!  6  18   scope (File)       kind u8 = 1 || object_id u128 || rights u8
//!  6  27   scope (Https)      kind u8 = 2 || endpoint_id u128 || methods u16 || max_body_bytes u64
//!  7  10   budget             kind u8 (0 = finite, 1 = unlimited) || amount u64 || unit u8
//!  8   5   depth              kind u8 (0 = finite, 1 = unlimited) || value u32
//!  9   8   grant_expires_at   u64 (trusted ticks)
//! 10  32   nonce              [u8; 32]
//! 11   8   request_expires_at u64 (trusted ticks)
//! ```
//!
//! All integers are big-endian. Unlimited budgets/depths carry a zero
//! amount/value. The decoder rejects anything that is not byte-for-byte what
//! [`GrantRequest::encode`] would produce: wrong magic or version, unknown or
//! reordered tags, wrong lengths, unknown enum discriminants, unknown flag bits,
//! non-zero padding, values failing [`GrantRequest::new`] validation, and
//! trailing bytes. Consequently `decode` is injective and
//! `encode(decode(b)) == b` for every accepted `b`.
//!
//! The approval digest is `SHA-256("tessera/v1/grant-approval\0" || encoding)`
//! and is used verbatim as the FIDO2 `clientDataHash`.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::codec::{DecodeError, Reader, Writer};

/// Magic prefix of the canonical grant-request encoding.
pub const GRANT_REQUEST_MAGIC: [u8; 4] = *b"TSGR";
/// Current canonical-encoding format version.
pub const GRANT_REQUEST_FORMAT_VERSION: u16 = 1;
/// The only Tessera protocol version this crate approves requests for.
pub const SUPPORTED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(1);
/// Upper bound on an encoded request; larger inputs are rejected before parsing.
pub const MAX_ENCODED_REQUEST_LEN: usize = 256;
/// Domain separator for the approval digest (FIDO2 clientDataHash).
pub const GRANT_APPROVAL_DOMAIN: &[u8] = b"tessera/v1/grant-approval\0";

/// Tessera wire-protocol version the request was built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProtocolVersion(pub u16);
/// Identity of this Tessera installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InstallationId(pub u128);
/// Authority epoch; bumping it invalidates all outstanding challenges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AuthorityEpoch(pub u64);
/// Enrolled human operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OperatorId(pub u128);
/// Broker-registered stable file object identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectId(pub u128);
/// Broker-registered HTTPS endpoint identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EndpointId(pub u128);
/// Trusted time supplied by the outer runtime (never by a client).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Tick(pub u64);

/// Sandbox principal receiving the grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AgentId {
    pub epoch: u128,
    pub serial: u64,
}

/// Fresh 256-bit challenge nonce.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce(pub [u8; 32]);

impl Nonce {
    /// Draws a nonce from the operating system CSPRNG.
    pub fn random() -> Result<Self, getrandom::Error> {
        let mut b = [0u8; 32];
        getrandom::getrandom(&mut b)?;
        Ok(Nonce(b))
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({})", crate::codec::hex(&self.0))
    }
}

/// File rights bit set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileRights(u8);

impl FileRights {
    /// Read one bounded snapshot.
    pub const READ: u8 = 0x01;
    /// Atomically replace content.
    pub const REPLACE: u8 = 0x02;
    /// Append bytes.
    pub const APPEND: u8 = 0x04;
    /// Read metadata.
    pub const METADATA: u8 = 0x08;
    /// All defined bits.
    pub const ALL: u8 = 0x0f;

    /// Returns `None` for an empty set or unknown bits.
    pub fn new(bits: u8) -> Option<Self> {
        (bits != 0 && bits & !Self::ALL == 0).then_some(FileRights(bits))
    }
    pub fn bits(self) -> u8 {
        self.0
    }
    pub fn is_subset_of(self, other: FileRights) -> bool {
        self.0 & !other.0 == 0
    }
    pub(crate) fn names(self) -> Vec<&'static str> {
        [
            (Self::READ, "read"),
            (Self::REPLACE, "replace"),
            (Self::APPEND, "append"),
            (Self::METADATA, "metadata"),
        ]
        .into_iter()
        .filter(|(b, _)| self.0 & b != 0)
        .map(|(_, n)| n)
        .collect()
    }
}

/// HTTP method bit set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MethodSet(u16);

impl MethodSet {
    pub const GET: u16 = 0x0001;
    pub const HEAD: u16 = 0x0002;
    pub const POST: u16 = 0x0004;
    pub const PUT: u16 = 0x0008;
    pub const PATCH: u16 = 0x0010;
    pub const DELETE: u16 = 0x0020;
    pub const OPTIONS: u16 = 0x0040;
    pub const ALL: u16 = 0x007f;

    /// Returns `None` for an empty set or unknown bits.
    pub fn new(bits: u16) -> Option<Self> {
        (bits != 0 && bits & !Self::ALL == 0).then_some(MethodSet(bits))
    }
    pub fn bits(self) -> u16 {
        self.0
    }
    pub fn is_subset_of(self, other: MethodSet) -> bool {
        self.0 & !other.0 == 0
    }
    pub(crate) fn names(self) -> Vec<&'static str> {
        [
            (Self::GET, "GET"),
            (Self::HEAD, "HEAD"),
            (Self::POST, "POST"),
            (Self::PUT, "PUT"),
            (Self::PATCH, "PATCH"),
            (Self::DELETE, "DELETE"),
            (Self::OPTIONS, "OPTIONS"),
        ]
        .into_iter()
        .filter(|(b, _)| self.0 & b != 0)
        .map(|(_, n)| n)
        .collect()
    }
}

/// Normalized scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    File {
        object: ObjectId,
        rights: FileRights,
    },
    Https {
        endpoint: EndpointId,
        methods: MethodSet,
        max_body_bytes: u64,
    },
}

impl Scope {
    /// Conservative subset relation: same resource, fewer rights/methods,
    /// no larger body bound.
    pub fn is_subset_of(&self, other: &Scope) -> bool {
        match (self, other) {
            (
                Scope::File {
                    object: a,
                    rights: ra,
                },
                Scope::File {
                    object: b,
                    rights: rb,
                },
            ) => a == b && ra.is_subset_of(*rb),
            (
                Scope::Https {
                    endpoint: a,
                    methods: ma,
                    max_body_bytes: sa,
                },
                Scope::Https {
                    endpoint: b,
                    methods: mb,
                    max_body_bytes: sb,
                },
            ) => a == b && ma.is_subset_of(*mb) && sa <= sb,
            _ => false,
        }
    }
}

/// Unit in which a budget is counted. Units are never mixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BudgetUnit {
    /// One unit per protected-operation attempt (the MVP unit).
    Operations = 1,
    /// Bytes transferred.
    Bytes = 2,
    /// Outbound requests.
    Requests = 3,
}

impl BudgetUnit {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(BudgetUnit::Operations),
            2 => Some(BudgetUnit::Bytes),
            3 => Some(BudgetUnit::Requests),
            _ => None,
        }
    }
    pub(crate) fn noun(self, n: u64) -> &'static str {
        match (self, n == 1) {
            (BudgetUnit::Operations, true) => "operation attempt",
            (BudgetUnit::Operations, false) => "operation attempts",
            (BudgetUnit::Bytes, true) => "byte",
            (BudgetUnit::Bytes, false) => "bytes",
            (BudgetUnit::Requests, true) => "request",
            (BudgetUnit::Requests, false) => "requests",
        }
    }
}

/// Budget amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BudgetAmount {
    Finite(u64),
    Unlimited,
}

/// Budget with its unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Budget {
    pub amount: BudgetAmount,
    pub unit: BudgetUnit,
}

impl Budget {
    /// `self ≤ other`: same unit and no larger amount.
    pub fn is_within(&self, other: &Budget) -> bool {
        self.unit == other.unit
            && match (self.amount, other.amount) {
                (_, BudgetAmount::Unlimited) => true,
                (BudgetAmount::Unlimited, BudgetAmount::Finite(_)) => false,
                (BudgetAmount::Finite(a), BudgetAmount::Finite(b)) => a <= b,
            }
    }
}

/// Delegation depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Depth {
    Finite(u32),
    Unlimited,
}

impl Depth {
    /// `self ≤ other`.
    pub fn is_within(&self, other: &Depth) -> bool {
        match (self, other) {
            (_, Depth::Unlimited) => true,
            (Depth::Unlimited, Depth::Finite(_)) => false,
            (Depth::Finite(a), Depth::Finite(b)) => a <= b,
        }
    }
}

/// Plain, unvalidated fields of a grant request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrantRequestFields {
    pub protocol_version: ProtocolVersion,
    pub installation: InstallationId,
    pub authority_epoch: AuthorityEpoch,
    pub operator: OperatorId,
    pub recipient: AgentId,
    pub scope: Scope,
    pub budget: Budget,
    pub depth: Depth,
    /// When the minted grant expires.
    pub grant_expires_at: Tick,
    pub nonce: Nonce,
    /// Deadline for the human approval itself.
    pub request_expires_at: Tick,
}

/// Why a set of fields is not a valid normalized request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestError {
    UnsupportedProtocolVersion(u16),
    ZeroBudget,
    ZeroNonce,
    ZeroExpiry,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestError::UnsupportedProtocolVersion(v) => {
                write!(f, "unsupported protocol version {v}")
            }
            RequestError::ZeroBudget => write!(f, "finite budget must be positive"),
            RequestError::ZeroNonce => write!(f, "nonce must not be all zero"),
            RequestError::ZeroExpiry => write!(f, "expiry ticks must be positive"),
        }
    }
}

impl std::error::Error for RequestError {}

/// Validated canonical grant request. Construct with [`GrantRequest::new`]
/// or [`GrantRequest::decode`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrantRequest {
    fields: GrantRequestFields,
}

/// SHA-256 approval digest; the FIDO2 `clientDataHash`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestDigest(pub [u8; 32]);

const TAG_PROTOCOL: u8 = 1;
const TAG_INSTALLATION: u8 = 2;
const TAG_EPOCH: u8 = 3;
const TAG_OPERATOR: u8 = 4;
const TAG_RECIPIENT: u8 = 5;
const TAG_SCOPE: u8 = 6;
const TAG_BUDGET: u8 = 7;
const TAG_DEPTH: u8 = 8;
const TAG_GRANT_EXPIRY: u8 = 9;
const TAG_NONCE: u8 = 10;
const TAG_REQUEST_EXPIRY: u8 = 11;

const SCOPE_FILE: u8 = 1;
const SCOPE_HTTPS: u8 = 2;
const KIND_FINITE: u8 = 0;
const KIND_UNLIMITED: u8 = 1;

impl GrantRequest {
    /// Validates normalization rules and wraps the fields.
    ///
    /// Rights/method sets are validated by their constructors; here we check
    /// protocol version, positive finite budget, non-zero nonce and expiries.
    pub fn new(fields: GrantRequestFields) -> Result<Self, RequestError> {
        if fields.protocol_version != SUPPORTED_PROTOCOL_VERSION {
            return Err(RequestError::UnsupportedProtocolVersion(
                fields.protocol_version.0,
            ));
        }
        if fields.budget.amount == BudgetAmount::Finite(0) {
            return Err(RequestError::ZeroBudget);
        }
        if fields.nonce.0 == [0u8; 32] {
            return Err(RequestError::ZeroNonce);
        }
        if fields.grant_expires_at.0 == 0 || fields.request_expires_at.0 == 0 {
            return Err(RequestError::ZeroExpiry);
        }
        Ok(GrantRequest { fields })
    }

    /// Read-only view of the normalized fields.
    pub fn fields(&self) -> &GrantRequestFields {
        &self.fields
    }

    pub fn nonce(&self) -> &Nonce {
        &self.fields.nonce
    }

    /// Deterministic canonical encoding (see module docs).
    pub fn encode(&self) -> Vec<u8> {
        let f = &self.fields;
        let mut w = Writer::new();
        w.raw(&GRANT_REQUEST_MAGIC);
        w.u16(GRANT_REQUEST_FORMAT_VERSION);
        w.field(TAG_PROTOCOL, |w| w.u16(f.protocol_version.0));
        w.field(TAG_INSTALLATION, |w| w.u128(f.installation.0));
        w.field(TAG_EPOCH, |w| w.u64(f.authority_epoch.0));
        w.field(TAG_OPERATOR, |w| w.u128(f.operator.0));
        w.field(TAG_RECIPIENT, |w| {
            w.u128(f.recipient.epoch);
            w.u64(f.recipient.serial);
        });
        w.field(TAG_SCOPE, |w| match f.scope {
            Scope::File { object, rights } => {
                w.u8(SCOPE_FILE);
                w.u128(object.0);
                w.u8(rights.bits());
            }
            Scope::Https {
                endpoint,
                methods,
                max_body_bytes,
            } => {
                w.u8(SCOPE_HTTPS);
                w.u128(endpoint.0);
                w.u16(methods.bits());
                w.u64(max_body_bytes);
            }
        });
        w.field(TAG_BUDGET, |w| {
            match f.budget.amount {
                BudgetAmount::Finite(n) => {
                    w.u8(KIND_FINITE);
                    w.u64(n);
                }
                BudgetAmount::Unlimited => {
                    w.u8(KIND_UNLIMITED);
                    w.u64(0);
                }
            }
            w.u8(f.budget.unit as u8);
        });
        w.field(TAG_DEPTH, |w| match f.depth {
            Depth::Finite(n) => {
                w.u8(KIND_FINITE);
                w.u32(n);
            }
            Depth::Unlimited => {
                w.u8(KIND_UNLIMITED);
                w.u32(0);
            }
        });
        w.field(TAG_GRANT_EXPIRY, |w| w.u64(f.grant_expires_at.0));
        w.field(TAG_NONCE, |w| w.raw(&f.nonce.0));
        w.field(TAG_REQUEST_EXPIRY, |w| w.u64(f.request_expires_at.0));
        w.finish()
    }

    /// Strict canonical decoder; see module docs for what is rejected.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_ENCODED_REQUEST_LEN {
            return Err(DecodeError::TooLarge);
        }
        let mut r = Reader::new(bytes);
        if r.array::<4>()? != GRANT_REQUEST_MAGIC {
            return Err(DecodeError::BadMagic);
        }
        let fv = r.u16()?;
        if fv != GRANT_REQUEST_FORMAT_VERSION {
            return Err(DecodeError::UnsupportedFormatVersion(fv));
        }

        fn fixed<T>(
            r: &mut Reader<'_>,
            tag: u8,
            parse: impl FnOnce(&mut Reader<'_>) -> Result<T, DecodeError>,
        ) -> Result<T, DecodeError> {
            let mut v = r.field(tag)?;
            let out = parse(&mut v).map_err(|e| match e {
                DecodeError::Truncated => DecodeError::BadLength { tag },
                e => e,
            })?;
            v.finish_field(tag)?;
            Ok(out)
        }

        let protocol_version = ProtocolVersion(fixed(&mut r, TAG_PROTOCOL, |v| v.u16())?);
        let installation = InstallationId(fixed(&mut r, TAG_INSTALLATION, |v| v.u128())?);
        let authority_epoch = AuthorityEpoch(fixed(&mut r, TAG_EPOCH, |v| v.u64())?);
        let operator = OperatorId(fixed(&mut r, TAG_OPERATOR, |v| v.u128())?);
        let recipient = fixed(&mut r, TAG_RECIPIENT, |v| {
            Ok(AgentId {
                epoch: v.u128()?,
                serial: v.u64()?,
            })
        })?;
        let scope = fixed(&mut r, TAG_SCOPE, |v| match v.u8()? {
            SCOPE_FILE => {
                let object = ObjectId(v.u128()?);
                let rights =
                    FileRights::new(v.u8()?).ok_or(DecodeError::InvalidValue("file rights"))?;
                Ok(Scope::File { object, rights })
            }
            SCOPE_HTTPS => {
                let endpoint = EndpointId(v.u128()?);
                let methods =
                    MethodSet::new(v.u16()?).ok_or(DecodeError::InvalidValue("http methods"))?;
                let max_body_bytes = v.u64()?;
                Ok(Scope::Https {
                    endpoint,
                    methods,
                    max_body_bytes,
                })
            }
            _ => Err(DecodeError::InvalidValue("scope kind")),
        })?;
        let budget = fixed(&mut r, TAG_BUDGET, |v| {
            let kind = v.u8()?;
            let n = v.u64()?;
            let unit =
                BudgetUnit::from_u8(v.u8()?).ok_or(DecodeError::InvalidValue("budget unit"))?;
            let amount = match (kind, n) {
                (KIND_FINITE, n) => BudgetAmount::Finite(n),
                (KIND_UNLIMITED, 0) => BudgetAmount::Unlimited,
                _ => return Err(DecodeError::InvalidValue("budget amount")),
            };
            Ok(Budget { amount, unit })
        })?;
        let depth = fixed(&mut r, TAG_DEPTH, |v| {
            let kind = v.u8()?;
            let n = v.u32()?;
            match (kind, n) {
                (KIND_FINITE, n) => Ok(Depth::Finite(n)),
                (KIND_UNLIMITED, 0) => Ok(Depth::Unlimited),
                _ => Err(DecodeError::InvalidValue("depth")),
            }
        })?;
        let grant_expires_at = Tick(fixed(&mut r, TAG_GRANT_EXPIRY, |v| v.u64())?);
        let nonce = Nonce(fixed(&mut r, TAG_NONCE, |v| v.array::<32>())?);
        let request_expires_at = Tick(fixed(&mut r, TAG_REQUEST_EXPIRY, |v| v.u64())?);
        r.finish()?;

        let req = GrantRequest::new(GrantRequestFields {
            protocol_version,
            installation,
            authority_epoch,
            operator,
            recipient,
            scope,
            budget,
            depth,
            grant_expires_at,
            nonce,
            request_expires_at,
        })
        .map_err(|_| DecodeError::InvalidValue("request fields"))?;
        // Belt and braces: the encoding must be the unique canonical one.
        if req.encode() != bytes {
            return Err(DecodeError::InvalidValue("non-canonical encoding"));
        }
        Ok(req)
    }

    /// Domain-separated approval digest; the FIDO2 `clientDataHash`.
    pub fn digest(&self) -> RequestDigest {
        let mut h = Sha256::new();
        h.update(GRANT_APPROVAL_DOMAIN);
        h.update(self.encode());
        RequestDigest(h.finalize().into())
    }

    /// Checks that `self` is a narrowing of `original`: identical binding
    /// fields (version, installation, epoch, operator, recipient, nonce) and
    /// every authority dimension no larger. Equality counts as narrowing.
    pub fn check_narrowing_of(&self, original: &GrantRequest) -> Result<(), NarrowingError> {
        let n = &self.fields;
        let o = &original.fields;
        if n.protocol_version != o.protocol_version
            || n.installation != o.installation
            || n.authority_epoch != o.authority_epoch
            || n.operator != o.operator
            || n.recipient != o.recipient
            || n.nonce != o.nonce
        {
            return Err(NarrowingError::BindingFieldChanged);
        }
        if !n.scope.is_subset_of(&o.scope) {
            return Err(NarrowingError::ScopeExpanded);
        }
        if !n.budget.is_within(&o.budget) {
            return Err(NarrowingError::BudgetExpanded);
        }
        if !n.depth.is_within(&o.depth) {
            return Err(NarrowingError::DepthExpanded);
        }
        if n.grant_expires_at > o.grant_expires_at {
            return Err(NarrowingError::GrantExpiryExtended);
        }
        if n.request_expires_at > o.request_expires_at {
            return Err(NarrowingError::RequestExpiryExtended);
        }
        Ok(())
    }
}

/// Why a proposed narrowed request is not a narrowing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NarrowingError {
    BindingFieldChanged,
    ScopeExpanded,
    BudgetExpanded,
    DepthExpanded,
    GrantExpiryExtended,
    RequestExpiryExtended,
}

impl fmt::Display for NarrowingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            NarrowingError::BindingFieldChanged => {
                "version/installation/epoch/operator/recipient/nonce may not change"
            }
            NarrowingError::ScopeExpanded => "scope is not a subset of the original",
            NarrowingError::BudgetExpanded => "budget exceeds the original or changes unit",
            NarrowingError::DepthExpanded => "delegation depth exceeds the original",
            NarrowingError::GrantExpiryExtended => "grant expiry is later than the original",
            NarrowingError::RequestExpiryExtended => {
                "request expiration is later than the original"
            }
        };
        f.write_str(s)
    }
}

impl std::error::Error for NarrowingError {}
