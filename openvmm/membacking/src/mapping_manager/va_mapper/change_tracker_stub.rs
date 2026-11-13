// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Non-Windows stub for the [`change_tracker`](super::change_tracker) module.
//!
//! Other targets replace and unmap mappings atomically (`mmap` with
//! `MAP_FIXED`), so an access never observes a range transiently unmapped and
//! there is nothing to track: [`ChangeTracker`] holds no state and never asks a
//! fault handler to retry. Providing this stub — rather than `cfg`-ing each use
//! site — keeps the parent module free of platform gates.

use std::marker::PhantomData;

/// Stateless stand-in for the Windows `ChangeTracker`.
#[derive(Debug, Default)]
pub(super) struct ChangeTracker;

/// Stand-in for the Windows change guard; holds nothing.
#[must_use]
pub(super) struct MappingChange<'a> {
    _lifetime: PhantomData<&'a ()>,
}

impl ChangeTracker {
    /// Changes are atomic, so there is nothing to bracket.
    pub(super) fn begin(&self) -> MappingChange<'_> {
        MappingChange {
            _lifetime: PhantomData,
        }
    }

    /// Changes are not tracked, so the generation never advances.
    pub(super) fn generation(&self) -> u64 {
        0
    }

    /// No change is ever in progress or missed, so this returns false.
    pub(super) fn changed_since(&self, _generation: u64) -> bool {
        false
    }

    /// A failed access cannot have raced with an atomic change, so it is never
    /// retried.
    pub(super) fn should_retry(&self, _accessible: impl FnMut() -> bool) -> bool {
        false
    }
}
