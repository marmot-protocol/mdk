//! The code both screens show: seven emoji, Matrix's `emoji` method, from the
//! first 42 bits of six HKDF bytes.

use std::fmt;

use zeroize::Zeroize;

use crate::emoji::{SAS_EMOJI, SasEmoji};
use crate::sas::SAS_BYTES_LEN;

/// Number of emoji in a code.
pub const SAS_EMOJI_COUNT: usize = 7;

/// A session's code. Its `Debug` output hides the value: the code is shown
/// to the user and never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct SasCode([u8; SAS_BYTES_LEN]);

impl SasCode {
    pub(crate) fn from_bytes(bytes: [u8; SAS_BYTES_LEN]) -> Self {
        Self(bytes)
    }

    /// The six HKDF output bytes, for known-answer tests.
    pub fn bytes(&self) -> &[u8; SAS_BYTES_LEN] {
        &self.0
    }

    /// Matrix's `emoji` method: the first 42 bits as seven 6-bit numbers,
    /// most significant first, each an index into [`SAS_EMOJI`].
    pub fn emoji_numbers(&self) -> [u8; SAS_EMOJI_COUNT] {
        let bits = self
            .0
            .iter()
            .fold(0_u64, |acc, byte| (acc << 8) | u64::from(*byte));
        std::array::from_fn(|index| ((bits >> (42 - 6 * index)) & 0x3f) as u8)
    }

    /// The seven emoji, in display order. Show each with its
    /// `description` as the label a screen reader reads.
    pub fn emoji(&self) -> [&'static SasEmoji; SAS_EMOJI_COUNT] {
        self.emoji_numbers()
            .map(|number| &SAS_EMOJI[usize::from(number)])
    }
}

impl fmt::Debug for SasCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SasCode(..)")
    }
}

impl Drop for SasCode {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_extremes_map_to_the_ends_of_the_table() {
        let zero = SasCode::from_bytes([0x00; SAS_BYTES_LEN]);
        assert_eq!(zero.emoji_numbers(), [0; SAS_EMOJI_COUNT]);
        assert_eq!(zero.emoji()[0].description, "Dog");

        let ones = SasCode::from_bytes([0xff; SAS_BYTES_LEN]);
        assert_eq!(ones.emoji_numbers(), [63; SAS_EMOJI_COUNT]);
        assert_eq!(ones.emoji()[6].description, "Pin");
    }

    #[test]
    fn code_uses_only_the_first_bits() {
        // The emoji read 42 bits, so the last six bits of the last byte
        // change nothing.
        let base = SasCode::from_bytes([0x5a, 0x3c, 0x96, 0xe1, 0x0f, 0x00]);
        let tail = SasCode::from_bytes([0x5a, 0x3c, 0x96, 0xe1, 0x0f, 0x3f]);
        assert_eq!(base.emoji_numbers(), tail.emoji_numbers());
        let bit_42 = SasCode::from_bytes([0x5a, 0x3c, 0x96, 0xe1, 0x0f, 0x40]);
        assert_ne!(base.emoji_numbers(), bit_42.emoji_numbers());
    }

    #[test]
    fn code_debug_hides_the_value() {
        let code = SasCode::from_bytes([0x5a; SAS_BYTES_LEN]);
        assert_eq!(format!("{code:?}"), "SasCode(..)");
    }
}
