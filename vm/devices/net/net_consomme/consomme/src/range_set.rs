// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A fixed-capacity sorted set of non-overlapping, non-adjacent half-open
//! ranges with merge-on-insert. Used by both TCP reassembly and IP fragment
//! reassembly.

use inspect::Inspect;
use std::fmt::Display;

/// Error returned when a [`RangeSet`] is at capacity and a new range does not
/// merge with any existing entry.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RangeSetFull;

/// A fixed-capacity sorted set of non-overlapping, non-adjacent half-open
/// `[start, end)` ranges that merges overlapping or adjacent entries on insert.
///
/// Stores up to `N` ranges in a stack-allocated array. Used as the core
/// building block for both TCP out-of-order segment tracking and IP fragment
/// reassembly.
pub(crate) struct RangeSet<T, const N: usize> {
    /// `ranges[..count]` are valid. Sorted by start.
    /// Invariant: `ranges[i].1 < ranges[i+1].0` for all valid `i`.
    ranges: [(T, T); N],
    count: u8,
}

impl<T: Copy + Ord + Default + Display, const N: usize> Inspect for RangeSet<T, N> {
    fn inspect(&self, req: inspect::Request<'_>) {
        let mut resp = req.respond();
        for (i, &(s, e)) in self.ranges().iter().enumerate() {
            resp.field(&format!("range_{i}"), format!("[{s}, {e})"));
        }
    }
}

impl<T: Copy + Ord + Default, const N: usize> RangeSet<T, N> {
    /// Create an empty range set.
    pub fn new() -> Self {
        Self {
            ranges: [(T::default(), T::default()); N],
            count: 0,
        }
    }

    /// Number of tracked ranges.
    pub fn count(&self) -> u8 {
        self.count
    }

    /// The valid range entries as a slice of `(start, end)` pairs.
    pub fn ranges(&self) -> &[(T, T)] {
        &self.ranges[..self.count as usize]
    }

    /// Insert the range `[start, end)`. Merges with overlapping or adjacent
    /// existing ranges. Returns `Err(RangeSetFull)` if the table is full and
    /// the new range does not merge with any existing entry.
    pub fn insert(&mut self, new_start: T, new_end: T) -> Result<(), RangeSetFull> {
        if new_start >= new_end {
            return Ok(());
        }

        let ranges = &self.ranges[..self.count as usize];
        let first = ranges
            .iter()
            .position(|&(s, e)| s <= new_end && new_start <= e);
        let last = ranges
            .iter()
            .rposition(|&(s, e)| s <= new_end && new_start <= e);

        match (first, last) {
            (Some(first), Some(last)) => {
                let merged_start = new_start.min(self.ranges[first].0);
                let merged_end = new_end.max(self.ranges[last].1);
                self.ranges[first] = (merged_start, merged_end);
                let remove = last - first;
                self.ranges
                    .copy_within(last + 1..self.count as usize, first + 1);
                self.count -= remove as u8;
            }
            (None, None) => {
                let count = self.count as usize;
                if count >= N {
                    return Err(RangeSetFull);
                }
                let pos = ranges
                    .iter()
                    .position(|&(s, _)| s > new_start)
                    .unwrap_or(count);
                self.ranges.copy_within(pos..count, pos + 1);
                self.ranges[pos] = (new_start, new_end);
                self.count += 1;
            }
            _ => unreachable!("first.is_some() iff last.is_some()"),
        }
        Ok(())
    }

    /// Returns `true` when a single range `[0, total)` covers the full span.
    pub fn is_complete(&self, total: T) -> bool {
        self.count == 1 && self.ranges[0] == (T::default(), total)
    }

    /// Reset to the empty state.
    #[cfg(test)]
    pub fn clear(&mut self) {
        self.count = 0;
    }
}

/// Methods requiring subtraction, used by TCP assembler for prefix consumption.
impl<T: Copy + Ord + Default + core::ops::Sub<Output = T>, const N: usize> RangeSet<T, N> {
    /// If the first range starts at zero, remove it and shift all remaining
    /// ranges left by the consumed amount. Returns the consumed length
    /// (end of the first range), or `None` if there is no contiguous prefix
    /// starting at zero.
    pub fn consume_front(&mut self) -> Option<T> {
        if self.count == 0 || self.ranges[0].0 != T::default() {
            return None;
        }
        let front = self.ranges[0].1;
        let new_count = self.count as usize - 1;
        for i in 0..new_count {
            self.ranges[i] = (self.ranges[i + 1].0 - front, self.ranges[i + 1].1 - front);
        }
        self.count = new_count as u8;
        Some(front)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestSet = RangeSet<u16, 16>;

    #[test]
    fn single_insert() {
        let mut rs = TestSet::new();
        rs.insert(0, 100).unwrap();
        assert!(rs.is_complete(100));
        assert!(!rs.is_complete(101));
    }

    #[test]
    fn merge_adjacent() {
        let mut rs = TestSet::new();
        rs.insert(0, 50).unwrap();
        rs.insert(50, 100).unwrap();
        assert!(rs.is_complete(100));
        assert_eq!(rs.count(), 1);
    }

    #[test]
    fn merge_overlap() {
        let mut rs = TestSet::new();
        rs.insert(0, 60).unwrap();
        rs.insert(40, 100).unwrap();
        assert!(rs.is_complete(100));
        assert_eq!(rs.count(), 1);
    }

    #[test]
    fn out_of_order() {
        let mut rs = TestSet::new();
        rs.insert(50, 100).unwrap();
        assert!(!rs.is_complete(100));
        rs.insert(0, 50).unwrap();
        assert!(rs.is_complete(100));
    }

    #[test]
    fn three_ranges_merge() {
        let mut rs = TestSet::new();
        rs.insert(0, 30).unwrap();
        rs.insert(60, 100).unwrap();
        assert_eq!(rs.count(), 2);
        // Middle piece merges all three.
        rs.insert(30, 60).unwrap();
        assert_eq!(rs.count(), 1);
        assert!(rs.is_complete(100));
    }

    #[test]
    fn too_many_ranges() {
        let mut rs = TestSet::new();
        // Insert 16 non-overlapping ranges.
        for i in 0..16u16 {
            rs.insert(i * 100, i * 100 + 10).unwrap();
        }
        assert_eq!(rs.count() as usize, 16);
        // One more non-mergeable range should fail.
        assert_eq!(rs.insert(16 * 100, 16 * 100 + 10), Err(RangeSetFull));
    }

    #[test]
    fn duplicate_insert() {
        let mut rs = TestSet::new();
        rs.insert(0, 100).unwrap();
        rs.insert(0, 100).unwrap();
        assert_eq!(rs.count(), 1);
        assert!(rs.is_complete(100));
    }

    #[test]
    fn consume_front_basic() {
        let mut rs = RangeSet::<u32, 4>::new();
        rs.insert(0, 10).unwrap();
        rs.insert(20, 30).unwrap();
        let consumed = rs.consume_front().unwrap();
        assert_eq!(consumed, 10);
        // [20,30) shifted by 10 → [10,20)
        assert_eq!(rs.ranges(), &[(10, 20)]);
    }

    #[test]
    fn consume_front_no_prefix() {
        let mut rs = RangeSet::<u32, 4>::new();
        rs.insert(5, 10).unwrap();
        assert!(rs.consume_front().is_none());
    }

    #[test]
    fn consume_front_empty() {
        let mut rs = RangeSet::<u32, 4>::new();
        assert!(rs.consume_front().is_none());
    }

    #[test]
    fn clear() {
        let mut rs = TestSet::new();
        rs.insert(0, 50).unwrap();
        rs.insert(60, 100).unwrap();
        assert_eq!(rs.count(), 2);
        rs.clear();
        assert_eq!(rs.count(), 0);
    }

    #[test]
    fn small_capacity() {
        let mut rs = RangeSet::<u32, 2>::new();
        rs.insert(0, 10).unwrap();
        rs.insert(20, 30).unwrap();
        assert_eq!(rs.insert(40, 50), Err(RangeSetFull));
        // Merge still works at capacity.
        rs.insert(10, 20).unwrap();
        assert_eq!(rs.count(), 1);
        assert!(rs.is_complete(30));
    }
}
