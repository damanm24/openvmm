// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helpers for `mmap`-style replacement of overlapping mappings.
//!
//! Mapping over part of an existing mapping replaces just the overlapped part,
//! and unmapping part of a mapping removes just that part. In both cases any
//! portion of an existing mapping outside the target range survives as a
//! smaller mapping of the same backing.

use memory_range::MemoryRange;

/// A mapping of a contiguous range that can be narrowed to a sub-range.
pub(crate) trait SplitMapping: Sized {
    /// The range covered by the mapping.
    fn range(&self) -> MemoryRange;

    /// Returns a mapping of the same backing restricted to `sub`, which must
    /// be within [`range`](Self::range). Any backing offset is advanced by
    /// `sub.start() - self.range().start()`.
    fn slice(&self, sub: MemoryRange) -> Self;
}

/// Returns the parts of `outer` that do not overlap `cut`, in address order.
pub(crate) fn remainder(outer: MemoryRange, cut: MemoryRange) -> impl Iterator<Item = MemoryRange> {
    let before = (outer.start() < cut.start())
        .then(|| MemoryRange::new(outer.start()..cut.start().min(outer.end())));
    let after = (cut.end() < outer.end())
        .then(|| MemoryRange::new(cut.end().max(outer.start())..outer.end()));
    before.into_iter().chain(after)
}

/// Removes `range` from `mappings`, splitting any mapping that straddles one
/// of its boundaries.
///
/// Each mapping that overlaps `range` is replaced in place by its surviving
/// pieces (see [`remainder`]), so the relative order of `mappings` is
/// preserved. Returns the original, unclipped mappings that overlapped
/// `range`, in their previous order.
pub(crate) fn carve<T: SplitMapping>(mappings: &mut Vec<T>, range: MemoryRange) -> Vec<T> {
    if range.is_empty() || !mappings.iter().any(|m| m.range().overlaps(&range)) {
        return Vec::new();
    }
    let mut removed = Vec::new();
    for mapping in std::mem::take(mappings) {
        let mapping_range = mapping.range();
        if !mapping_range.overlaps(&range) {
            mappings.push(mapping);
            continue;
        }
        mappings.extend(remainder(mapping_range, range).map(|sub| mapping.slice(sub)));
        removed.push(mapping);
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::SplitMapping;
    use super::carve;
    use super::remainder;
    use memory_range::MemoryRange;
    use test_with_tracing::test;

    #[derive(Debug, PartialEq, Eq)]
    struct M {
        range: MemoryRange,
        offset: u64,
    }

    impl SplitMapping for M {
        fn range(&self) -> MemoryRange {
            self.range
        }

        fn slice(&self, sub: MemoryRange) -> Self {
            assert!(self.range.contains(&sub));
            Self {
                range: sub,
                offset: self.offset + (sub.start() - self.range.start()),
            }
        }
    }

    fn m(start: u64, end: u64, offset: u64) -> M {
        M {
            range: MemoryRange::new(start..end),
            offset,
        }
    }

    fn r(start: u64, end: u64) -> MemoryRange {
        MemoryRange::new(start..end)
    }

    #[test]
    fn remainder_cases() {
        let outer = r(0x1000, 0x4000);
        let rem = |cut| remainder(outer, cut).collect::<Vec<_>>();
        assert_eq!(rem(r(0x1000, 0x4000)), []);
        assert_eq!(rem(r(0, 0x5000)), []);
        assert_eq!(
            rem(r(0x2000, 0x3000)),
            [r(0x1000, 0x2000), r(0x3000, 0x4000)]
        );
        assert_eq!(rem(r(0, 0x2000)), [r(0x2000, 0x4000)]);
        assert_eq!(rem(r(0x3000, 0x5000)), [r(0x1000, 0x3000)]);
    }

    #[test]
    fn carve_exact_replace() {
        let mut v = vec![m(0, 0x1000, 0), m(0x1000, 0x2000, 0x10)];
        let removed = carve(&mut v, r(0x1000, 0x2000));
        assert_eq!(removed, [m(0x1000, 0x2000, 0x10)]);
        assert_eq!(v, [m(0, 0x1000, 0)]);
    }

    #[test]
    fn carve_middle_splits_with_offsets() {
        let mut v = vec![m(0, 0x4000, 0x10000)];
        let removed = carve(&mut v, r(0x1000, 0x2000));
        assert_eq!(removed, [m(0, 0x4000, 0x10000)]);
        assert_eq!(v, [m(0, 0x1000, 0x10000), m(0x2000, 0x4000, 0x12000)]);
    }

    #[test]
    fn carve_spanning_multiple() {
        let mut v = vec![
            m(0, 0x2000, 0),
            m(0x2000, 0x3000, 0x100000),
            m(0x3000, 0x5000, 0x200000),
            m(0x8000, 0x9000, 0),
        ];
        let removed = carve(&mut v, r(0x1000, 0x4000));
        assert_eq!(
            removed,
            [
                m(0, 0x2000, 0),
                m(0x2000, 0x3000, 0x100000),
                m(0x3000, 0x5000, 0x200000)
            ]
        );
        assert_eq!(
            v,
            [
                m(0, 0x1000, 0),
                m(0x4000, 0x5000, 0x201000),
                m(0x8000, 0x9000, 0)
            ]
        );
    }

    #[test]
    fn carve_no_overlap() {
        let mut v = vec![m(0, 0x1000, 0)];
        assert!(carve(&mut v, r(0x1000, 0x2000)).is_empty());
        assert!(carve(&mut v, MemoryRange::EMPTY).is_empty());
        assert_eq!(v, [m(0, 0x1000, 0)]);
    }
}
