// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! This implements the [`MemoryMapper`] trait and related functionality for
//! [`GuestMemoryManager`](super::GuestMemoryManager).
//!
//! # Overlapping mappings
//!
//! Like `mmap` with `MAP_FIXED`, [`MappedMemoryRegion::map`] replaces the
//! overlapped parts of existing mappings in the region, splitting any that
//! partially overlap, and [`MappedMemoryRegion::unmap`] removes just the
//! requested range. This lets a device such as a virtio-fs DAX window remap
//! parts of its region arbitrarily.
//!
//! Requests whose range lies outside the region, or that would leave the
//! region with more than `MAX_MAPPINGS_PER_REGION` mappings, fail without
//! changing anything. If a map fails otherwise, the requested range is left
//! unmapped rather than restored.
//!
//! A replacement or partial unmap is not atomic everywhere. Windows cannot
//! unmap part of a view, so the host unmaps every overlapped view in full and
//! then maps the new view and the surviving parts of the old ones. Until then,
//! the surviving parts are briefly unmapped too, even though the guest asked
//! to change only the requested range and may be using the rest. To cover this:
//!
//! - Host accesses through guest memory that fault in this window wait for the
//!   change to finish and are retried.
//! - Guest accesses that fault in this window are re-executed when the
//!   hypervisor backend resolves memory faults through
//!   [`virt::ResolveMemoryFault`] (WHP on x86-64). Other backends do not retry
//!   them, so they are handled like accesses to unmapped memory.
//! - DMA targets unmap each overlapped mapping in full and then remap its
//!   surviving parts, so DMA to those parts can briefly fail. Remapping
//!   failures are logged, since DMA targets already treat device memory that
//!   cannot be mapped for DMA as non-fatal.

use super::DEVICE_PRIORITY;
use crate::mapping_manager::Mappable;
use crate::mapping_manager::MappingBacking;
use crate::mapping_manager::MemoryPolicy;
use crate::region_manager::MapParams;
use crate::region_manager::RegionHandle;
use crate::region_manager::RegionManagerClient;
use crate::split::SplitMapping;
use crate::split::carve;
use crate::split::remainder;
use futures::executor::block_on;
use guestmem::MappableGuestMemory;
use guestmem::MappedMemoryRegion;
use guestmem::MemoryMapper;
use memory_range::MemoryRange;
use parking_lot::Mutex;
use std::io;
use std::sync::Arc;

/// A [`MemoryMapper`] implementation for
/// [`GuestMemoryManager`](super::GuestMemoryManager).
#[derive(Clone, Debug)]
pub struct DeviceMemoryMapper {
    region_manager: RegionManagerClient,
}

impl DeviceMemoryMapper {
    pub(super) fn new(region_manager: RegionManagerClient) -> Self {
        Self { region_manager }
    }
}

impl MemoryMapper for DeviceMemoryMapper {
    fn new_region(
        &self,
        len: usize,
        debug_name: String,
    ) -> io::Result<(Box<dyn MappableGuestMemory>, Arc<dyn MappedMemoryRegion>)> {
        let region = Arc::new(DeviceMemoryRegion {
            len,
            debug_name,
            region_manager: self.region_manager.clone(),
            state: Mutex::new(DeviceRegionState {
                handle: None,
                mappings: Vec::new(),
            }),
        });

        Ok((Box::new(DeviceMemoryControl(region.clone())), region))
    }
}

#[derive(Debug)]
struct DeviceMemoryRegion {
    debug_name: String,
    len: usize,
    region_manager: RegionManagerClient,
    state: Mutex<DeviceRegionState>,
}

#[derive(Debug)]
struct DeviceRegionState {
    handle: Option<RegionHandle>,
    mappings: Vec<DeviceMapping>,
}

#[derive(Debug)]
struct DeviceMapping {
    range: MemoryRange,
    file_offset: u64,
    mappable: Mappable,
    writable: bool,
}

impl SplitMapping for DeviceMapping {
    fn range(&self) -> MemoryRange {
        self.range
    }

    fn slice(&self, sub: MemoryRange) -> Self {
        assert!(self.range.contains(&sub));
        Self {
            range: sub,
            file_offset: self.file_offset + (sub.start() - self.range.start()),
            mappable: self.mappable.clone(),
            writable: self.writable,
        }
    }
}

/// The maximum number of mappings in one device memory region.
///
/// A device can fragment its region arbitrarily, and each mapping costs a host
/// view (on Windows, a separately mapped section view), an IOMMU entry per DMA
/// target, and linear work on every later map or unmap. This bounds that cost.
/// It allows a 64 GiB virtio-fs DAX window to be fully mapped in 2 MiB chunks.
const MAX_MAPPINGS_PER_REGION: usize = 32768;

/// Returns how many mappings remain after removing `range` from `mappings`.
fn count_after_carve(mappings: &[DeviceMapping], range: MemoryRange) -> usize {
    mappings
        .iter()
        .map(|m| {
            if m.range.overlaps(&range) {
                remainder(m.range, range).count()
            } else {
                1
            }
        })
        .sum()
}

fn check_mapping_limit(count: usize) -> io::Result<()> {
    if count > MAX_MAPPINGS_PER_REGION {
        return Err(io::Error::other(format!(
            "device memory region would exceed {MAX_MAPPINGS_PER_REGION} mappings"
        )));
    }
    Ok(())
}

impl DeviceMemoryRegion {
    fn validated_memory_range(&self, offset: usize, len: usize) -> io::Result<MemoryRange> {
        let end = offset
            .checked_add(len)
            .filter(|&end| end <= self.len)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "range {offset:#x}+{len:#x} exceeds region length {:#x}",
                        self.len
                    ),
                )
            })?;
        (offset..end)
            .try_into()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
    }
}

impl MappedMemoryRegion for DeviceMemoryRegion {
    fn map(
        &self,
        offset: usize,
        section: &dyn sparse_mmap::AsMappableRef,
        file_offset: u64,
        len: usize,
        writable: bool,
    ) -> io::Result<()> {
        #[cfg(unix)]
        let mappable = section.as_fd().try_clone_to_owned()?;
        #[cfg(windows)]
        let mappable = section.as_handle().try_clone_to_owned()?;

        let range = self.validated_memory_range(offset, len)?;
        let new_mapping = DeviceMapping {
            range,
            file_offset,
            mappable: mappable.into(),
            writable,
        };

        // Like `mmap` with `MAP_FIXED`, replace the overlapped part of any
        // existing mappings. If mapping fails, the range is left unmapped.
        let mut state = self.state.lock();
        check_mapping_limit(count_after_carve(&state.mappings, range) + 1)?;
        carve(&mut state.mappings, range);
        if let Some(handle) = &state.handle {
            block_on(handle.add_mapping(
                new_mapping.range,
                MappingBacking::File {
                    mappable: new_mapping.mappable.clone(),
                    file_offset: new_mapping.file_offset,
                },
                new_mapping.writable,
                MemoryPolicy::none(),
            ))
            .map_err(io::Error::other)?;
        }
        state.mappings.push(new_mapping);
        Ok(())
    }

    fn unmap(&self, offset: usize, len: usize) -> io::Result<()> {
        let range = self.validated_memory_range(offset, len)?;
        let mut state = self.state.lock();
        check_mapping_limit(count_after_carve(&state.mappings, range))?;
        carve(&mut state.mappings, range);
        if let Some(handle) = &state.handle {
            block_on(handle.remove_mappings(range));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct DeviceMemoryControl(Arc<DeviceMemoryRegion>);

impl MappableGuestMemory for DeviceMemoryControl {
    fn map_to_guest(&mut self, gpa: u64, writable: bool) -> io::Result<()> {
        #[expect(clippy::await_holding_lock)] // Treat all this as sync for now.
        block_on(async {
            let mut state = self.0.state.lock();
            if let Some(handle) = state.handle.take() {
                handle.teardown().await;
            }
            let handle = self
                .0
                .region_manager
                .new_region(
                    self.0.debug_name.clone(),
                    MemoryRange::try_from(gpa..gpa.wrapping_add(self.0.len as u64))
                        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?,
                    DEVICE_PRIORITY,
                    crate::region_manager::MappingType::Device,
                )
                .await
                .map_err(io::Error::other)?;

            for mapping in &state.mappings {
                handle
                    .add_mapping(
                        mapping.range,
                        MappingBacking::File {
                            mappable: mapping.mappable.clone(),
                            file_offset: mapping.file_offset,
                        },
                        mapping.writable,
                        MemoryPolicy::none(),
                    )
                    .await
                    .map_err(io::Error::other)?;
            }

            handle
                .map(MapParams {
                    writable,
                    executable: true,
                    prefetch: false,
                })
                .await
                .map_err(io::Error::other)?;

            state.handle = Some(handle);
            Ok(())
        })
    }

    fn unmap_from_guest(&mut self) {
        let mut state = self.0.state.lock();
        if let Some(handle) = state.handle.take() {
            block_on(handle.teardown());
        }
    }
}
