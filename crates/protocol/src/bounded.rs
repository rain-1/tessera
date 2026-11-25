//! Length-bounded containers used in wire types.
//!
//! Every variable-length field on the wire is one of these types. Their
//! `Deserialize` implementations check the declared length against a
//! compile-time bound *before* materialising the value, so a hostile length
//! prefix cannot cause a large allocation or unbounded loop. Combined with the
//! frame size check in [`crate::frame`] this bounds the memory a single
//! message can make the decoder allocate.

use core::fmt;
use core::marker::PhantomData;

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};

/// Error returned when constructing a bounded value that exceeds its bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("length {len} exceeds bound {max}")]
pub struct BoundExceeded {
    /// Offending length.
    pub len: usize,
    /// Maximum allowed length.
    pub max: usize,
}

/// Byte string of at most `N` bytes.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct BoundedBytes<const N: usize>(Vec<u8>);

impl<const N: usize> BoundedBytes<N> {
    /// Maximum length in bytes.
    pub const MAX: usize = N;

    /// Wraps `bytes` if it fits within the bound.
    pub fn new(bytes: Vec<u8>) -> Result<Self, BoundExceeded> {
        if bytes.len() > N {
            return Err(BoundExceeded {
                len: bytes.len(),
                max: N,
            });
        }
        Ok(Self(bytes))
    }

    /// Borrow the contents.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the byte string is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Unwrap into the inner vector.
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl<const N: usize> fmt::Debug for BoundedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print contents: they may be file data or HTTP bodies.
        write!(f, "BoundedBytes<{N}>(len={})", self.0.len())
    }
}

impl<const N: usize> TryFrom<Vec<u8>> for BoundedBytes<N> {
    type Error = BoundExceeded;
    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(v)
    }
}

impl<const N: usize> TryFrom<&[u8]> for BoundedBytes<N> {
    type Error = BoundExceeded;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Self::new(v.to_vec())
    }
}

impl<const N: usize> Serialize for BoundedBytes<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

struct BytesVisitor<const N: usize>;

impl<'de, const N: usize> Visitor<'de> for BytesVisitor<N> {
    type Value = BoundedBytes<N>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a byte string of at most {N} bytes")
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        if v.len() > N {
            return Err(E::invalid_length(v.len(), &self));
        }
        Ok(BoundedBytes(v.to_vec()))
    }

    fn visit_borrowed_bytes<E: de::Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
        self.visit_bytes(v)
    }
}

impl<'de, const N: usize> Deserialize<'de> for BoundedBytes<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // postcard's `deserialize_bytes` checks the length prefix against the
        // remaining input before borrowing, so no allocation precedes the
        // bound check in `visit_bytes`.
        d.deserialize_bytes(BytesVisitor::<N>)
    }
}

/// UTF-8 string of at most `N` bytes.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct BoundedString<const N: usize>(String);

impl<const N: usize> BoundedString<N> {
    /// Maximum length in bytes.
    pub const MAX: usize = N;

    /// Wraps `s` if its UTF-8 length fits within the bound.
    pub fn new(s: impl Into<String>) -> Result<Self, BoundExceeded> {
        let s = s.into();
        if s.len() > N {
            return Err(BoundExceeded {
                len: s.len(),
                max: N,
            });
        }
        Ok(Self(s))
    }

    /// Borrow as `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Unwrap into the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<const N: usize> fmt::Debug for BoundedString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl<const N: usize> Serialize for BoundedString<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

struct StrVisitor<const N: usize>;

impl<'de, const N: usize> Visitor<'de> for StrVisitor<N> {
    type Value = BoundedString<N>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a UTF-8 string of at most {N} bytes")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        if v.len() > N {
            return Err(E::invalid_length(v.len(), &self));
        }
        Ok(BoundedString(v.to_owned()))
    }

    fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
        self.visit_str(v)
    }
}

impl<'de, const N: usize> Deserialize<'de> for BoundedString<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(StrVisitor::<N>)
    }
}

/// Sequence of at most `N` elements.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BoundedVec<T, const N: usize>(Vec<T>);

impl<T, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T, const N: usize> BoundedVec<T, N> {
    /// Maximum element count.
    pub const MAX: usize = N;

    /// Wraps `v` if it has at most `N` elements.
    pub fn new(v: Vec<T>) -> Result<Self, BoundExceeded> {
        if v.len() > N {
            return Err(BoundExceeded {
                len: v.len(),
                max: N,
            });
        }
        Ok(Self(v))
    }

    /// Borrow the elements.
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Number of elements.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no elements.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Unwrap into the inner vector.
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for BoundedVec<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.iter()).finish()
    }
}

impl<T: Serialize, const N: usize> Serialize for BoundedVec<T, N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for e in &self.0 {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}

struct SeqVisitor<T, const N: usize>(PhantomData<T>);

impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for SeqVisitor<T, N> {
    type Value = BoundedVec<T, N>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a sequence of at most {N} elements")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        // Reject on the declared count before reserving anything.
        if let Some(hint) = seq.size_hint() {
            if hint > N {
                return Err(de::Error::invalid_length(hint, &self));
            }
        }
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(N));
        while let Some(e) = seq.next_element()? {
            if out.len() == N {
                return Err(de::Error::invalid_length(N + 1, &self));
            }
            out.push(e);
        }
        Ok(BoundedVec(out))
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for BoundedVec<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_seq(SeqVisitor::<T, N>(PhantomData))
    }
}
