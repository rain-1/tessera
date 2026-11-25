//! Mirror of `crates/capability-core/src/scope.rs`.
//!
//! Soundness obligation (T2 building block), proved below as
//! `lemma_subset_sound`:
//!
//! ```text
//! is_subset(c, p) && permits(c, o)  ==>  permits(p, o)
//! ```
use vstd::prelude::*;

verus! {

/// Mirror of `ObjectId` (raw `u64`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectId(pub u64);

/// Mirror of `EndpointId` (raw `u64`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointId(pub u64);

/// Mirror of `FileRight`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileRight {
    Read,
    Replace,
}

impl FileRight {
    pub open spec fn bit_spec(self) -> u8 {
        match self {
            FileRight::Read => 1u8,
            FileRight::Replace => 2u8,
        }
    }

    pub fn bit(self) -> (r: u8)
        ensures r == self.bit_spec(),
    {
        match self {
            FileRight::Read => 0b01,
            FileRight::Replace => 0b10,
        }
    }
}

/// Mirror of `FileRights` (a `u8` bitset; only bits `0b11` are defined).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileRights(pub u8);

pub const FILE_ALL_BITS: u8 = 0b11;

impl FileRights {
    pub open spec fn wf(self) -> bool {
        self.0 & !FILE_ALL_BITS == 0
    }

    /// Mirror of `FileRights::from_bits`: decoding rejects undefined bits.
    pub fn from_bits(bits: u8) -> (r: Option<FileRights>)
        ensures r matches Some(f) ==> f.wf() && f.0 == bits,
                r is None <==> bits & !FILE_ALL_BITS != 0,
    {
        if bits & !FILE_ALL_BITS == 0 { Some(FileRights(bits)) } else { None }
    }

    pub open spec fn contains_all_spec(self, other: FileRights) -> bool {
        self.0 & other.0 == other.0
    }

    /// Mirror of `FileRights::contains_all` (`other ⊆ self`).
    pub fn contains_all(self, other: FileRights) -> (r: bool)
        ensures r == self.contains_all_spec(other),
    {
        self.0 & other.0 == other.0
    }

    pub open spec fn has_spec(self, right: FileRight) -> bool {
        self.0 & right.bit_spec() != 0
    }

    /// Mirror of `FileRights::has`.
    pub fn has(self, right: FileRight) -> (r: bool)
        ensures r == self.has_spec(right),
    {
        self.0 & right.bit() != 0
    }

    /// Mirror of `FileRights::is_empty`.
    pub fn is_empty(self) -> (r: bool)
        ensures r == (self.0 == 0),
    {
        self.0 == 0
    }
}

/// Mirror of `HttpMethod`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    pub open spec fn bit_spec(self) -> u8 {
        match self {
            HttpMethod::Get => 1u8,
            HttpMethod::Head => 2u8,
            HttpMethod::Post => 4u8,
            HttpMethod::Put => 8u8,
            HttpMethod::Patch => 16u8,
            HttpMethod::Delete => 32u8,
        }
    }

    pub fn bit(self) -> (r: u8)
        ensures r == self.bit_spec(),
    {
        // core: `1 << k`; written as literals so the verifier sees the values.
        match self {
            HttpMethod::Get => 0b00_0001,
            HttpMethod::Head => 0b00_0010,
            HttpMethod::Post => 0b00_0100,
            HttpMethod::Put => 0b00_1000,
            HttpMethod::Patch => 0b01_0000,
            HttpMethod::Delete => 0b10_0000,
        }
    }
}

/// Mirror of `MethodSet` (a `u8` bitset; only bits `0b11_1111` are defined).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MethodSet(pub u8);

pub const METHOD_ALL_BITS: u8 = 0b11_1111;

impl MethodSet {
    pub open spec fn wf(self) -> bool {
        self.0 & !METHOD_ALL_BITS == 0
    }

    /// Mirror of `MethodSet::from_bits`.
    pub fn from_bits(bits: u8) -> (r: Option<MethodSet>)
        ensures r matches Some(m) ==> m.wf() && m.0 == bits,
                r is None <==> bits & !METHOD_ALL_BITS != 0,
    {
        if bits & !METHOD_ALL_BITS == 0 { Some(MethodSet(bits)) } else { None }
    }

    pub open spec fn has_spec(self, m: HttpMethod) -> bool {
        self.0 & m.bit_spec() != 0
    }

    /// Mirror of `MethodSet::has`.
    pub fn has(self, m: HttpMethod) -> (r: bool)
        ensures r == self.has_spec(m),
    {
        self.0 & m.bit() != 0
    }

    pub open spec fn contains_all_spec(self, other: MethodSet) -> bool {
        self.0 & other.0 == other.0
    }

    /// Mirror of `MethodSet::contains_all` (`other ⊆ self`).
    pub fn contains_all(self, other: MethodSet) -> (r: bool)
        ensures r == self.contains_all_spec(other),
    {
        self.0 & other.0 == other.0
    }

    /// Mirror of `MethodSet::is_empty`.
    pub fn is_empty(self) -> (r: bool)
        ensures r == (self.0 == 0),
    {
        self.0 == 0
    }
}

/// Mirror of `Scope`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    File { object: ObjectId, rights: FileRights },
    Https { endpoint: EndpointId, methods: MethodSet, max_body_bytes: u64 },
}

impl Scope {
    pub open spec fn is_well_formed_spec(self) -> bool {
        match self {
            Scope::File { rights, .. } => rights.0 != 0,
            Scope::Https { methods, .. } => methods.0 != 0,
        }
    }

    /// Mirror of `Scope::is_well_formed`.
    pub fn is_well_formed(&self) -> (r: bool)
        ensures r == self.is_well_formed_spec(),
    {
        match self {
            Scope::File { rights, .. } => !rights.is_empty(),
            Scope::Https { methods, .. } => !methods.is_empty(),
        }
    }
}

/// Mirror of `Operation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    File { object: ObjectId, right: FileRight },
    Https { endpoint: EndpointId, method: HttpMethod, body_bytes: u64 },
}

pub open spec fn permits_spec(scope: Scope, op: Operation) -> bool {
    match (scope, op) {
        (Scope::File { object, rights }, Operation::File { object: o, right }) =>
            object.0 == o.0 && rights.has_spec(right),
        (Scope::Https { endpoint, methods, max_body_bytes }, Operation::Https { endpoint: e, method, body_bytes }) =>
            endpoint.0 == e.0 && methods.has_spec(method) && body_bytes <= max_body_bytes,
        _ => false,
    }
}

/// Mirror of `permits`.
pub fn permits(scope: &Scope, op: &Operation) -> (r: bool)
    ensures r == permits_spec(*scope, *op),
{
    match (scope, op) {
        (Scope::File { object, rights }, Operation::File { object: o, right }) => {
            object.0 == o.0 && rights.has(*right)
        },
        (Scope::Https { endpoint, methods, max_body_bytes }, Operation::Https { endpoint: e, method, body_bytes }) => {
            endpoint.0 == e.0 && methods.has(*method) && *body_bytes <= *max_body_bytes
        },
        _ => false,
    }
}

pub open spec fn is_subset_spec(child: Scope, parent: Scope) -> bool {
    match (child, parent) {
        (Scope::File { object: co, rights: cr }, Scope::File { object: po, rights: pr }) =>
            co.0 == po.0 && pr.contains_all_spec(cr),
        (Scope::Https { endpoint: ce, methods: cm, max_body_bytes: cb },
         Scope::Https { endpoint: pe, methods: pm, max_body_bytes: pb }) =>
            ce.0 == pe.0 && pm.contains_all_spec(cm) && cb <= pb,
        _ => false,
    }
}

/// Mirror of `is_subset` (conservative `child ⊆ parent`).
pub fn is_subset(child: &Scope, parent: &Scope) -> (r: bool)
    ensures r == is_subset_spec(*child, *parent),
{
    match (child, parent) {
        (Scope::File { object: co, rights: cr }, Scope::File { object: po, rights: pr }) => {
            co.0 == po.0 && pr.contains_all(*cr)
        },
        (Scope::Https { endpoint: ce, methods: cm, max_body_bytes: cb },
         Scope::Https { endpoint: pe, methods: pm, max_body_bytes: pb }) => {
            ce.0 == pe.0 && pm.contains_all(*cm) && *cb <= *pb
        },
        _ => false,
    }
}

// ------------------------------------------------------------- bit lemmas

pub proof fn lemma_bits_subset_sound(p: u8, c: u8, b: u8)
    requires p & c == c, c & b != 0,
    ensures p & b != 0,
{
    assert(p & c == c && c & b != 0 ==> p & b != 0) by (bit_vector);
}

pub proof fn lemma_bits_subset_trans(a: u8, b: u8, c: u8)
    requires a & b == b, b & c == c,
    ensures a & c == c,
{
    assert(a & b == b && b & c == c ==> a & c == c) by (bit_vector);
}

pub proof fn lemma_bits_subset_refl(a: u8)
    ensures a & a == a,
{
    assert(a & a == a) by (bit_vector);
}

/// Completeness of the bitset encoding on single rights: if every right
/// of `c` is a right of `p`, then `p.contains_all(c)` (for well-formed sets).
pub proof fn lemma_file_rights_complete(p: FileRights, c: FileRights)
    requires
        p.wf(), c.wf(),
        c.has_spec(FileRight::Read) ==> p.has_spec(FileRight::Read),
        c.has_spec(FileRight::Replace) ==> p.has_spec(FileRight::Replace),
    ensures p.contains_all_spec(c),
{
    let (pb, cb) = (p.0, c.0);
    assert(pb & !3u8 == 0 && cb & !3u8 == 0
        && (cb & 1u8 != 0 ==> pb & 1u8 != 0)
        && (cb & 2u8 != 0 ==> pb & 2u8 != 0) ==> pb & cb == cb) by (bit_vector);
}

// ---------------------------------------------------------- scope lemmas

/// **Subset soundness** (T2 building block):
/// `is_subset(c, p) && permits(c, o) ==> permits(p, o)`.
pub proof fn lemma_subset_sound(c: Scope, p: Scope, o: Operation)
    requires is_subset_spec(c, p), permits_spec(c, o),
    ensures permits_spec(p, o),
{
    match (c, p, o) {
        (Scope::File { rights: cr, .. }, Scope::File { rights: pr, .. }, Operation::File { right, .. }) => {
            lemma_bits_subset_sound(pr.0, cr.0, right.bit_spec());
        },
        (Scope::Https { methods: cm, .. }, Scope::Https { methods: pm, .. }, Operation::Https { method, .. }) => {
            lemma_bits_subset_sound(pm.0, cm.0, method.bit_spec());
        },
        _ => {},
    }
}

/// `is_subset` is reflexive.
pub proof fn lemma_subset_refl(s: Scope)
    ensures is_subset_spec(s, s),
{
    match s {
        Scope::File { rights, .. } => lemma_bits_subset_refl(rights.0),
        Scope::Https { methods, .. } => lemma_bits_subset_refl(methods.0),
    }
}

/// `is_subset` is transitive.
pub proof fn lemma_subset_trans(a: Scope, b: Scope, c: Scope)
    requires is_subset_spec(a, b), is_subset_spec(b, c),
    ensures is_subset_spec(a, c),
{
    match (a, b, c) {
        (Scope::File { rights: ar, .. }, Scope::File { rights: br, .. }, Scope::File { rights: cr, .. }) => {
            lemma_bits_subset_trans(cr.0, br.0, ar.0);
        },
        (Scope::Https { methods: am, .. }, Scope::Https { methods: bm, .. }, Scope::Https { methods: cm, .. }) => {
            lemma_bits_subset_trans(cm.0, bm.0, am.0);
        },
        _ => {},
    }
}

/// Different resource kinds are never comparable.
pub proof fn lemma_subset_same_kind(c: Scope, p: Scope)
    requires is_subset_spec(c, p),
    ensures (c is File) == (p is File),
{
}

/// Corollary used by the ledger: soundness through a chain of subsets.
pub proof fn lemma_subset_sound_chain(c: Scope, m: Scope, p: Scope, o: Operation)
    requires is_subset_spec(c, m), is_subset_spec(m, p), permits_spec(c, o),
    ensures permits_spec(p, o),
{
    lemma_subset_trans(c, m, p);
    lemma_subset_sound(c, p, o);
}

} // verus!
