use std::fmt;
use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// A wrapper that zeroizes its contents on drop
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, ZeroizeOnDrop)]
pub struct Secret<T: zeroize::Zeroize>(#[zeroize(drop)] T);

impl<T> Secret<T>
where
    T: zeroize::Zeroize,
{
    /// Create a new secret wrapper
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Return an explicit plaintext serialization wrapper for this secret.
    ///
    /// This is intentionally opt-in so accidental serde exports of `Secret<T>`
    /// fail instead of leaking wrapped key material.
    #[must_use = "PlaintextSecret is only useful when passed to a serializer"]
    pub fn expose_for_serialization(&self) -> PlaintextSecret<'_, T> {
        PlaintextSecret(&self.0)
    }
}

impl<T> AsMut<T> for Secret<T>
where
    T: zeroize::Zeroize,
{
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> AsRef<T> for Secret<T>
where
    T: zeroize::Zeroize,
{
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> Deref for Secret<T>
where
    T: zeroize::Zeroize,
{
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for Secret<T>
where
    T: zeroize::Zeroize,
{
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> fmt::Debug for Secret<T>
where
    T: zeroize::Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't leak secret in debug output
        write!(f, "Secret(***)")
    }
}

/// Explicit opt-in wrapper for serializing the plaintext value inside a [`Secret`].
pub struct PlaintextSecret<'a, T>(&'a T);

impl<T> fmt::Debug for PlaintextSecret<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlaintextSecret(***)")
    }
}

impl<T> Serialize for Secret<T>
where
    T: zeroize::Zeroize,
{
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(serde::ser::Error::custom(
            "Secret values cannot be serialized",
        ))
    }
}

impl<T> Serialize for PlaintextSecret<'_, T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for Secret<T>
where
    T: zeroize::Zeroize + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Secret)
    }
}

// Re-export Zeroize trait from zeroize crate for convenience
pub use zeroize::Zeroize;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_accessors_and_mutation() {
        let mut secret = Secret::new([1u8, 2, 3, 4]);

        assert_eq!(secret.as_ref(), &[1u8, 2, 3, 4]);

        secret.as_mut()[0] = 5;
        assert_eq!(*secret, [5u8, 2, 3, 4]);

        secret[1] = 6;
        assert_eq!(*secret, [5u8, 6, 3, 4]);
    }

    #[test]
    fn test_secret_debug_redacts_value() {
        let secret = Secret::new([222u8, 173, 190, 239]);
        let debug_str = format!("{:?}", secret);

        assert_eq!(debug_str, "Secret(***)");
        assert!(!debug_str.contains("222"));
        assert!(!debug_str.contains("173"));
        assert!(!debug_str.contains("190"));
        assert!(!debug_str.contains("239"));
    }

    #[test]
    fn test_secret_serialization_is_rejected() {
        let secret = Secret::new([222u8, 173, 190, 239]);

        let err = serde_json::to_value(&secret)
            .expect_err("Secret serialization should not expose plaintext");
        let err = err.to_string();

        assert!(err.contains("Secret values cannot be serialized"));
        assert!(!err.contains("222"));
        assert!(!err.contains("173"));
        assert!(!err.contains("190"));
        assert!(!err.contains("239"));
    }

    #[test]
    fn test_plaintext_secret_serialization_is_explicit() {
        let secret = Secret::new([222u8, 173, 190, 239]);

        let serialized = serde_json::to_value(secret.expose_for_serialization()).unwrap();

        assert_eq!(serialized, serde_json::json!([222, 173, 190, 239]));
    }

    #[test]
    fn test_optional_plaintext_secret_serialization_is_explicit() {
        let secret = Some(Secret::new([222u8, 173, 190, 239]));
        let missing_secret: Option<Secret<[u8; 4]>> = None;

        let serialized =
            serde_json::to_value(secret.as_ref().map(Secret::expose_for_serialization)).unwrap();
        let serialized_missing = serde_json::to_value(
            missing_secret
                .as_ref()
                .map(Secret::expose_for_serialization),
        )
        .unwrap();

        assert_eq!(serialized, serde_json::json!([222, 173, 190, 239]));
        assert_eq!(serialized_missing, serde_json::Value::Null);
    }

    #[test]
    fn test_plaintext_secret_debug_redacts_value() {
        let secret = Secret::new([222u8, 173, 190, 239]);
        let debug_str = format!("{:?}", secret.expose_for_serialization());

        assert_eq!(debug_str, "PlaintextSecret(***)");
        assert!(!debug_str.contains("222"));
        assert!(!debug_str.contains("173"));
        assert!(!debug_str.contains("190"));
        assert!(!debug_str.contains("239"));
    }
}
