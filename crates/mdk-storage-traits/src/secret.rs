use std::fmt;
use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Serialize};

/// A wrapper that zeroizes its contents on drop
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Create a new secret wrapper
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Consumes the wrapper and returns the inner value.
    /// Warning: Returned value will NOT be zeroized on drop unless re-wrapped.
    /// Unused mut is because we want to move the value out without zeroizing it
    pub fn into_inner(#[allow(unused_mut)] mut self) -> T {
        #[allow(unsafe_code)]
        unsafe {
            let inner = std::ptr::read(&self.0);
            std::mem::forget(self);
            inner
        }
    }
}

impl<T: Zeroize> AsMut<T> for Secret<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> AsRef<T> for Secret<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> Deref for Secret<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> DerefMut for Secret<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize + fmt::Debug> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't leak secret in debug output
        write!(f, "Secret(***)")
    }
}

// Serialization support
impl<T: Zeroize + Serialize> Serialize for Secret<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Zeroize + Deserialize<'de>> Deserialize<'de> for Secret<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Secret)
    }
}

/// Trait for types that can be zeroized
pub trait Zeroize {
    /// Zeroize the memory
    fn zeroize(&mut self);
}

impl Zeroize for [u8; 32] {
    fn zeroize(&mut self) {
        #[allow(unsafe_code)]
        unsafe {
            std::ptr::write_volatile(self as *mut [u8; 32], [0u8; 32]);
        }
    }
}

impl Zeroize for [u8; 12] {
    fn zeroize(&mut self) {
        #[allow(unsafe_code)]
        unsafe {
            std::ptr::write_volatile(self as *mut [u8; 12], [0u8; 12]);
        }
    }
}

impl Zeroize for Vec<u8> {
    fn zeroize(&mut self) {
        // We can't easily write volatile to the whole vec capacity pointer without iterating
        // otherwise we risk fucking with data outside of the vec.
        // But we can fill with 0s using a loop.
        for byte in self.iter_mut() {
            #[allow(unsafe_code)]
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    // Mock type to verify zeroize is called
    #[derive(Debug, Clone)]
    struct MockZeroize {
        zeroized: Arc<AtomicBool>,
        data: u8,
    }

    impl Zeroize for MockZeroize {
        fn zeroize(&mut self) {
            self.zeroized.store(true, Ordering::SeqCst);
            self.data = 0;
        }
    }

    #[test]
    fn test_zeroize_on_drop_mock() {
        let zeroized = Arc::new(AtomicBool::new(false));
        let mock = MockZeroize {
            zeroized: zeroized.clone(),
            data: 42,
        };

        {
            let secret = Secret::new(mock);
            assert_eq!(secret.data, 42);
            // Drop happens here
        }

        assert!(
            zeroized.load(Ordering::SeqCst),
            "Zeroize was not called on drop"
        );
    }

    #[test]
    fn test_secret_zeroizes_on_drop() {
        let ptr: *const u8;
        let len = 32;

        {
            let secret = Secret::new([0xFFu8; 32]);
            ptr = secret.as_ref().as_ptr(); // get raw pointer before drop
        } // secret drops here

        // This is intentional UB for testing purposes only. After team discussion,
        // this direct memory inspection was determined to be the most reliable way
        // to verify zeroization behavior. The stack memory remains accessible in
        // practice, even though reading it is technically undefined behavior.
        unsafe {
            let slice = std::slice::from_raw_parts(ptr, len);
            assert!(slice.iter().all(|&b| b == 0), "Memory was not zeroized!");
        }
    }

    #[test]
    fn test_secret_creation_and_access() {
        let secret = Secret::new([42u8; 32]);
        assert_eq!(secret.as_ref()[0], 42);
        assert_eq!(secret.as_ref()[31], 42);
    }

    #[test]
    fn test_secret_deref() {
        let secret = Secret::new([99u8; 32]);
        assert_eq!(secret[0], 99);
        assert_eq!(secret[15], 99);
    }

    #[test]
    fn test_secret_deref_mut() {
        let mut secret = Secret::new([1u8; 32]);
        secret[0] = 255;
        assert_eq!(secret[0], 255);
        assert_eq!(secret[1], 1);
    }

    #[test]
    fn test_into_inner_does_not_zeroize() {
        let data = [0x42u8; 32];
        let secret = Secret::new(data);

        let inner = secret.into_inner();

        // Value should still be intact
        assert_eq!(inner[0], 0x42);
        assert_eq!(inner[31], 0x42);
    }

    #[test]
    fn test_debug_does_not_leak() {
        let secret = Secret::new([0x69u8; 32]);
        let debug_str = format!("{:?}", secret);

        assert_eq!(debug_str, "Secret(***)");
        assert!(!debug_str.contains("69"));
        assert!(!debug_str.contains("105")); // 0x69 in decimal
    }

    #[test]
    fn test_clone() {
        let secret1 = Secret::new([0x11u8; 32]);
        let secret2 = secret1.clone();

        assert_eq!(secret1.as_ref(), secret2.as_ref());
        assert_eq!(secret2[0], 0x11);
    }

    #[test]
    fn test_partial_eq() {
        let secret1 = Secret::new([0x22u8; 32]);
        let secret2 = Secret::new([0x22u8; 32]);
        let secret3 = Secret::new([0x33u8; 32]);

        assert_eq!(secret1, secret2);
        assert_ne!(secret1, secret3);
    }

    #[test]
    fn test_serialization() {
        let secret = Secret::new([0x55u8; 32]);
        let serialized = serde_json::to_string(&secret).unwrap();
        let deserialized: Secret<[u8; 32]> = serde_json::from_str(&serialized).unwrap();

        assert_eq!(secret, deserialized);
    }

    #[test]
    fn test_multiple_drops() {
        // Ensure no double-free or other issues
        let data = vec![0x77; 50];
        let secret = Secret::new(data);
        drop(secret);
        // If we get here without panic, we're good
    }

    #[test]
    fn test_zeroize_trait_array32() {
        let mut data = [0xFFu8; 32];
        data.zeroize();
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_zeroize_trait_array12() {
        let mut data = [0xAAu8; 12];
        data.zeroize();
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_zeroize_trait_vec() {
        let mut data = vec![0xBB; 200];
        data.zeroize();
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_as_mut() {
        let mut secret = Secret::new([0x10u8; 32]);
        let inner_mut = secret.as_mut();
        inner_mut[0] = 0x20;

        assert_eq!(secret[0], 0x20);
    }
}
