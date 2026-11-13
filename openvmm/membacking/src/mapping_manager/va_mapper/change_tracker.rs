// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tracks structural changes to the VA mapping, so that a fault that races
//! with one can be told apart from a persistent fault.
//!
//! On Windows, replacing a mapping unmaps the old view before mapping the new
//! one, so an access that lands in between faults even though the VA is mapped
//! both before and after the change. The mapper task brackets each change that
//! can unmap something in use with [`ChangeTracker::begin`]. Fault handlers use
//! the generation and lock it maintains to wait out a change in progress and
//! decide whether to retry the access. See
//! [`ResolveMemoryFault::wait_for_mapping_change`](virt::ResolveMemoryFault::wait_for_mapping_change).
//!
//! This module is compiled only on Windows. Other targets replace and unmap
//! mappings atomically, so they get a stub (see the non-Windows
//! `change_tracker` module) that tracks nothing and never retries.

use parking_lot::Mutex;
use parking_lot::MutexGuard;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// Tracks structural changes to the VA mapping.
#[derive(Debug, Default)]
pub(super) struct ChangeTracker {
    /// Incremented when a change begins and again when it ends, so it is odd
    /// while one is in progress.
    generation: AtomicU64,
    /// Held for the duration of each change, so that fault handlers can wait
    /// one out.
    lock: Mutex<()>,
}

/// A structural change to the VA mapping in progress. See
/// [`ChangeTracker::begin`].
#[must_use]
pub(super) struct MappingChange<'a> {
    generation: &'a AtomicU64,
    _lock: MutexGuard<'a, ()>,
}

impl Drop for MappingChange<'_> {
    fn drop(&mut self) {
        // Runs before `_lock` is released, so a waiter that acquires the lock
        // always observes the completed (even) generation.
        self.generation.fetch_add(1, Ordering::SeqCst);
    }
}

impl ChangeTracker {
    /// Begins a structural change, which lasts until the returned guard is
    /// dropped.
    pub(super) fn begin(&self) -> MappingChange<'_> {
        let lock = self.lock.lock();
        self.generation.fetch_add(1, Ordering::SeqCst);
        MappingChange {
            generation: &self.generation,
            _lock: lock,
        }
    }

    /// Returns the current generation.
    pub(super) fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Returns whether a change may have happened since `generation` was read,
    /// waiting for any change in progress to finish first.
    pub(super) fn changed_since(&self, generation: u64) -> bool {
        if generation.is_multiple_of(2) && self.generation() == generation {
            return false;
        }
        drop(self.lock.lock());
        true
    }

    /// Returns whether a failed access should be retried, where `accessible`
    /// checks whether the access would now succeed.
    ///
    /// Waits out any change in progress, then calls `accessible`. If the check
    /// fails with no change since the wait, the failure is persistent and this
    /// returns false; if a change raced with the check, this waits for it and
    /// checks again.
    pub(super) fn should_retry(&self, mut accessible: impl FnMut() -> bool) -> bool {
        loop {
            let generation = {
                let _lock = self.lock.lock();
                self.generation()
            };
            if accessible() {
                return true;
            }
            if self.generation() == generation {
                return false;
            }
        }
    }
}
