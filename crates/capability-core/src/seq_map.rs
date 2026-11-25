//! Serde helper: encode a `BTreeMap` as a sequence of `(key, value)` pairs so
//! that structured keys survive formats (e.g. JSON) that only allow string
//! map keys. Decoding rejects duplicate keys rather than silently keeping
//! the last one.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{Deserialize, Deserializer, Error, SeqAccess, Visitor};
use serde::ser::{Serialize, Serializer};

pub(crate) fn serialize<K, V, S>(map: &BTreeMap<K, V>, s: S) -> Result<S::Ok, S::Error>
where
    K: Serialize,
    V: Serialize,
    S: Serializer,
{
    s.collect_seq(map.iter())
}

pub(crate) fn deserialize<'de, K, V, D>(d: D) -> Result<BTreeMap<K, V>, D::Error>
where
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
    D: Deserializer<'de>,
{
    struct V2<K, V>(PhantomData<(K, V)>);
    impl<'de, K, V> Visitor<'de> for V2<K, V>
    where
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
    {
        type Value = BTreeMap<K, V>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a sequence of (key, value) pairs")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut map = BTreeMap::new();
            while let Some((k, v)) = seq.next_element::<(K, V)>()? {
                if map.insert(k, v).is_some() {
                    return Err(A::Error::custom("duplicate key"));
                }
            }
            Ok(map)
        }
    }
    d.deserialize_seq(V2(PhantomData))
}
