//! WP1: scope language, rights bits, boundaries, mismatches, and the
//! subset-soundness obligation `subset(c,p) && permits(c,o) ==> permits(p,o)`.

use proptest::prelude::*;
use tessera_capability_core::*;

const METHODS: [HttpMethod; 6] = [
    HttpMethod::Get,
    HttpMethod::Head,
    HttpMethod::Post,
    HttpMethod::Put,
    HttpMethod::Patch,
    HttpMethod::Delete,
];

fn f(o: u64, bits: u8) -> Scope {
    Scope::File {
        object: ObjectId::from_raw(o),
        rights: FileRights::from_bits(bits).unwrap(),
    }
}
fn h(e: u64, bits: u8, max: u64) -> Scope {
    Scope::Https {
        endpoint: EndpointId::from_raw(e),
        methods: MethodSet::from_bits(bits).unwrap(),
        max_body_bytes: max,
    }
}
fn fop(o: u64, right: FileRight) -> Operation {
    Operation::File {
        object: ObjectId::from_raw(o),
        right,
    }
}
fn hop(e: u64, method: HttpMethod, body: u64) -> Operation {
    Operation::Https {
        endpoint: EndpointId::from_raw(e),
        method,
        body_bytes: body,
    }
}

#[test]
fn every_file_right_bit() {
    for bits in 0..=3u8 {
        let s = f(1, bits);
        assert_eq!(permits(&s, &fop(1, FileRight::Read)), bits & 1 != 0);
        assert_eq!(permits(&s, &fop(1, FileRight::Replace)), bits & 2 != 0);
        assert!(!permits(&s, &fop(2, FileRight::Read)), "other object");
        assert_eq!(s.is_well_formed(), bits != 0);
    }
    assert!(FileRights::from_bits(4).is_none());
    assert!(FileRights::from_bits(0xff).is_none());
}

#[test]
fn every_method_bit_and_body_boundary() {
    for (i, m) in METHODS.iter().enumerate() {
        let s = h(1, 1 << i, 10);
        for (j, m2) in METHODS.iter().enumerate() {
            assert_eq!(permits(&s, &hop(1, *m2, 0)), i == j);
        }
        assert!(permits(&s, &hop(1, *m, 10)), "inclusive bound");
        assert!(!permits(&s, &hop(1, *m, 11)), "one past bound");
        assert!(!permits(&s, &hop(2, *m, 0)), "other endpoint");
    }
    assert!(MethodSet::from_bits(1 << 6).is_none());
    assert!(!h(1, 0, 10).is_well_formed());
    assert!(permits(
        &h(1, 1, u64::MAX),
        &hop(1, HttpMethod::Get, u64::MAX)
    ));
}

#[test]
fn mismatched_resource_kinds_never_permit_or_include() {
    let fs = f(1, 3);
    let hs = h(1, 0x3f, u64::MAX);
    assert!(!permits(&fs, &hop(1, HttpMethod::Get, 0)));
    assert!(!permits(&hs, &fop(1, FileRight::Read)));
    assert!(!is_subset(&fs, &hs));
    assert!(!is_subset(&hs, &fs));
}

#[test]
fn subset_boundaries() {
    assert!(is_subset(&f(1, 1), &f(1, 3)));
    assert!(!is_subset(&f(1, 3), &f(1, 1)));
    assert!(!is_subset(&f(1, 1), &f(2, 1)));
    assert!(is_subset(&h(1, 1, 10), &h(1, 3, 10)));
    assert!(!is_subset(&h(1, 1, 11), &h(1, 3, 10)));
    assert!(!is_subset(&h(1, 4, 10), &h(1, 3, 10)));
    assert!(!is_subset(&h(2, 1, 10), &h(1, 1, 10)));
}

#[test]
fn serde_rejects_undefined_bits() {
    assert!(serde_json::from_str::<FileRights>("3").is_ok());
    assert!(serde_json::from_str::<FileRights>("4").is_err());
    assert!(serde_json::from_str::<MethodSet>("64").is_err());
}

#[test]
fn quantity_orders() {
    use Budget::*;
    assert!(
        Finite(3).within(Finite(3))
            && Finite(3).within(Unlimited)
            && !Unlimited.within(Finite(u64::MAX))
    );
    assert!(Depth::Unlimited.admits_child(Depth::Unlimited));
    assert!(Depth::Finite(2).admits_child(Depth::Finite(1)));
    assert!(!Depth::Finite(2).admits_child(Depth::Finite(2)));
    assert!(!Depth::Finite(0).admits_child(Depth::Finite(0)));
    assert!(!Depth::Finite(5).admits_child(Depth::Unlimited));
    assert_eq!(Depth::Finite(0).decrement(), None);
    assert_eq!(Depth::Finite(1).decrement(), Some(Depth::Finite(0)));
    assert_eq!(Depth::Unlimited.decrement(), Some(Depth::Unlimited));
    let t = Tick::from_raw;
    assert!(!Expiry::At(t(5)).is_expired_at(t(4)) && Expiry::At(t(5)).is_expired_at(t(5)));
    assert!(!Expiry::Never.is_expired_at(t(u64::MAX)));
    assert!(
        Expiry::At(t(5)).within(Expiry::Never) && !Expiry::Never.within(Expiry::At(t(u64::MAX)))
    );
}

fn arb_scope() -> impl Strategy<Value = Scope> {
    prop_oneof![
        (0..3u64, 0..4u8).prop_map(|(o, b)| f(o, b)),
        (0..3u64, 0..64u8, 0..8u64).prop_map(|(e, b, m)| h(e, b, m)),
    ]
}

fn arb_op() -> impl Strategy<Value = Operation> {
    prop_oneof![
        (0..3u64, prop::bool::ANY).prop_map(|(o, r)| fop(
            o,
            if r {
                FileRight::Read
            } else {
                FileRight::Replace
            }
        )),
        (0..3u64, 0..6usize, 0..10u64).prop_map(|(e, m, b)| hop(e, METHODS[m], b)),
    ]
}

/// Exhaustive denotation over the small universe used by the generators.
fn denotation(s: &Scope) -> Vec<Operation> {
    let mut v = Vec::new();
    for o in 0..3 {
        for r in [FileRight::Read, FileRight::Replace] {
            v.push(fop(o, r));
        }
        for m in METHODS {
            for b in 0..10 {
                v.push(hop(o, m, b));
            }
        }
    }
    v.retain(|op| permits(s, op));
    v
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn subset_is_sound(c in arb_scope(), p in arb_scope(), o in arb_op()) {
        if is_subset(&c, &p) && permits(&c, &o) {
            prop_assert!(permits(&p, &o));
        }
    }

    #[test]
    fn subset_matches_denotation_for_well_formed(c in arb_scope(), p in arb_scope()) {
        // Over this finite universe, is_subset is exactly denotational
        // inclusion for non-empty scopes (i.e. it is not merely sound but
        // also not needlessly conservative).
        if c.is_well_formed() {
            let dc = denotation(&c);
            let dp = denotation(&p);
            let incl = dc.iter().all(|o| dp.contains(o));
            prop_assert_eq!(is_subset(&c, &p), incl);
        }
    }

    #[test]
    fn subset_reflexive_transitive(a in arb_scope(), b in arb_scope(), c in arb_scope()) {
        prop_assert!(is_subset(&a, &a));
        if is_subset(&a, &b) && is_subset(&b, &c) {
            prop_assert!(is_subset(&a, &c));
        }
    }
}
