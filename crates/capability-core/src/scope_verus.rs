// Verus-only (included into scope.rs under cfg(verus_keep_ghost)):
// spec twins and lemmas for the production scope language.
verus! {

impl FileRight {
    /// Specification of `bit`.
    pub open spec fn bit_spec(self) -> u8 {
        match self { FileRight::Read => 1u8, FileRight::Replace => 2u8 }
    }
}

impl FileRights {
    /// The wrapped raw value (spec only).
    pub closed spec fn raw(self) -> u8 { self.0 }
    /// Only defined bits are set.
    pub open spec fn wf(self) -> bool { self.raw() & !3u8 == 0 }
    /// Specification of `contains_all`.
    pub open spec fn contains_all_spec(self, other: FileRights) -> bool { self.raw() & other.raw() == other.raw() }
    /// Specification of `has`.
    pub open spec fn has_spec(self, right: FileRight) -> bool { self.raw() & right.bit_spec() != 0 }
}

impl HttpMethod {
    /// Specification of `bit`.
    pub open spec fn bit_spec(self) -> u8 {
        match self {
            HttpMethod::Get => 1u8 << 0, HttpMethod::Head => 1u8 << 1, HttpMethod::Post => 1u8 << 2,
            HttpMethod::Put => 1u8 << 3, HttpMethod::Patch => 1u8 << 4, HttpMethod::Delete => 1u8 << 5,
        }
    }
}

impl MethodSet {
    /// The wrapped raw value (spec only).
    pub closed spec fn raw(self) -> u8 { self.0 }
    /// Only defined bits are set.
    pub open spec fn wf(self) -> bool { self.raw() & !0x3fu8 == 0 }
    /// Specification of `contains_all`.
    pub open spec fn contains_all_spec(self, other: MethodSet) -> bool { self.raw() & other.raw() == other.raw() }
    /// Specification of `has`.
    pub open spec fn has_spec(self, m: HttpMethod) -> bool { self.raw() & m.bit_spec() != 0 }
}

impl Scope {
    /// Specification of `is_well_formed`.
    pub open spec fn is_well_formed_spec(self) -> bool {
        match self {
            Scope::File { rights, .. } => rights.raw() != 0,
            Scope::Https { methods, .. } => methods.raw() != 0,
        }
    }
}

/// Specification of `permits`.
pub open spec fn permits_spec(scope: Scope, op: Operation) -> bool {
    match (scope, op) {
        (Scope::File { object, rights }, Operation::File { object: o, right }) =>
            object.raw() == o.raw() && rights.has_spec(right),
        (Scope::Https { endpoint, methods, max_body_bytes }, Operation::Https { endpoint: e, method, body_bytes }) =>
            endpoint.raw() == e.raw() && methods.has_spec(method) && body_bytes <= max_body_bytes,
        _ => false,
    }
}

/// Specification of `is_subset`.
pub open spec fn is_subset_spec(child: Scope, parent: Scope) -> bool {
    match (child, parent) {
        (Scope::File { object: co, rights: cr }, Scope::File { object: po, rights: pr }) =>
            co.raw() == po.raw() && pr.contains_all_spec(cr),
        (Scope::Https { endpoint: ce, methods: cm, max_body_bytes: cb },
         Scope::Https { endpoint: pe, methods: pm, max_body_bytes: pb }) =>
            ce.raw() == pe.raw() && pm.contains_all_spec(cm) && cb <= pb,
        _ => false,
    }
}

pub proof fn lemma_bits_subset_sound(p: u8, c: u8, b: u8)
    requires p & c == c, c & b != 0, ensures p & b != 0,
{ assert(p & c == c && c & b != 0 ==> p & b != 0) by (bit_vector); }

pub proof fn lemma_bits_subset_trans(a: u8, b: u8, c: u8)
    requires a & b == b, b & c == c, ensures a & c == c,
{ assert(a & b == b && b & c == c ==> a & c == c) by (bit_vector); }

pub proof fn lemma_bits_subset_refl(a: u8) ensures a & a == a,
{ assert(a & a == a) by (bit_vector); }

/// T2 building block, now about the production `is_subset` / `permits`.
pub proof fn lemma_subset_sound(c: Scope, p: Scope, o: Operation)
    requires is_subset_spec(c, p), permits_spec(c, o), ensures permits_spec(p, o),
{
    match (c, p, o) {
        (Scope::File { rights: cr, .. }, Scope::File { rights: pr, .. }, Operation::File { right, .. }) =>
            lemma_bits_subset_sound(pr.raw(), cr.raw(), right.bit_spec()),
        (Scope::Https { methods: cm, .. }, Scope::Https { methods: pm, .. }, Operation::Https { method, .. }) =>
            lemma_bits_subset_sound(pm.raw(), cm.raw(), method.bit_spec()),
        _ => {},
    }
}

pub proof fn lemma_subset_refl(s: Scope) ensures is_subset_spec(s, s),
{
    match s {
        Scope::File { rights, .. } => lemma_bits_subset_refl(rights.raw()),
        Scope::Https { methods, .. } => lemma_bits_subset_refl(methods.raw()),
    }
}

pub proof fn lemma_subset_trans(a: Scope, b: Scope, c: Scope)
    requires is_subset_spec(a, b), is_subset_spec(b, c), ensures is_subset_spec(a, c),
{
    match (a, b, c) {
        (Scope::File { rights: ar, .. }, Scope::File { rights: br, .. }, Scope::File { rights: cr, .. }) =>
            lemma_bits_subset_trans(cr.raw(), br.raw(), ar.raw()),
        (Scope::Https { methods: am, .. }, Scope::Https { methods: bm, .. }, Scope::Https { methods: cm, .. }) =>
            lemma_bits_subset_trans(cm.raw(), bm.raw(), am.raw()),
        _ => {},
    }
}

} // verus!
