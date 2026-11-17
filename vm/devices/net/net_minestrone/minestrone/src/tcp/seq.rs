// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TCP sequence-number arithmetic (RFC 9293 section 3.4).

/// A TCP sequence number. Comparisons are modulo 2^32.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Seq(pub u32);

impl Seq {
    pub fn add(self, n: u32) -> Self {
        Self(self.0.wrapping_add(n))
    }

    /// Returns the number of bytes from `earlier` to `self`.
    pub fn since(self, earlier: Self) -> u32 {
        self.0.wrapping_sub(earlier.0)
    }

    /// Returns true if `self` precedes `other`.
    pub fn before(self, other: Self) -> bool {
        (self.0.wrapping_sub(other.0) as i32) < 0
    }

    /// Returns true if `start <= self <= end`, where `end` does not precede
    /// `start`. Used to validate guest acknowledgments against the range of
    /// sent data before releasing any of it.
    pub fn within(self, start: Self, end: Self) -> bool {
        self.since(start) <= end.since(start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn comparisons_wrap() {
        let near_max = Seq(u32::MAX - 1);
        let wrapped = near_max.add(4);
        assert_eq!(wrapped, Seq(2));
        assert_eq!(wrapped.since(near_max), 4);
        assert!(near_max.before(wrapped));
        assert!(!wrapped.before(near_max));

        assert!(Seq(0).within(near_max, wrapped));
        assert!(wrapped.within(near_max, wrapped));
        assert!(!Seq(3).within(near_max, wrapped));
        assert!(!Seq(u32::MAX - 2).within(near_max, wrapped));
    }
}
