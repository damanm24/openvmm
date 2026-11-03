// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! This implements the [`MemoryMapper`] trait and related functionality for
//! [`GuestMemoryManager`](super::GuestMemoryManager).

use super::DEVICE_PRIORITY;
use crate::mapping_manager::Mappable;
use crate::mapping_manager::MappingBacking;
use crate::mapping_manager::MemoryPolicy;
use crate::region_manager::MapParams;
use crate::region_manager::RegionHandle;
use crate::region_manager::RegionManagerClient;
use crate::region_manager::RegionMappingParams;
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

impl DeviceMemoryRegion {
    fn validated_memory_range(&self, offset: usize, len: usize) -> io::Result<MemoryRange> {
        let end = offset
            .checked_add(len)
            .filter(|&end| len != 0 && end <= self.len)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid device memory range")
            })?;
        (offset..end)
            .try_into()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
    }
}

impl DeviceMapping {
    /// Returns the portion of this mapping covering `range`, which must lie
    /// within the mapping.
    fn slice(&self, range: MemoryRange) -> Self {
        assert!(self.range.contains(&range));
        Self {
            range,
            file_offset: self.file_offset + (range.start() - self.range.start()),
            mappable: self.mappable.clone(),
            writable: self.writable,
        }
    }

    fn region_params(&self) -> RegionMappingParams {
        RegionMappingParams {
            range_in_region: self.range,
            backing: MappingBacking::File {
                mappable: self.mappable.clone(),
                file_offset: self.file_offset,
            },
            writable: self.writable,
            policy: MemoryPolicy::none(),
        }
    }
}

impl DeviceRegionState {
    /// Removes `range` from the region and then adds `new_mapping`, if any.
    ///
    /// Existing mappings that overlap `range` are removed whole, and the
    /// portions outside `range` are remapped. This lets virtiofs DAX replace
    /// or upgrade mappings over ranges that are already mapped. The guest view
    /// is updated as a single region manager operation, which defers faults on
    /// the affected range and restores the original mappings on failure, so
    /// the recorded mappings are only updated on success.
    fn update(&mut self, range: MemoryRange, new_mapping: Option<DeviceMapping>) -> io::Result<()> {
        if new_mapping.is_none() && !self.mappings.iter().any(|m| m.range.overlaps(&range)) {
            return Ok(());
        }

        let mut affected = range;
        let mut mappings = Vec::new();
        for mapping in self.mappings.iter().filter(|m| m.range.overlaps(&range)) {
            affected = MemoryRange::new(
                affected.start().min(mapping.range.start())
                    ..affected.end().max(mapping.range.end()),
            );
            if mapping.range.start() < range.start() {
                mappings
                    .push(mapping.slice(MemoryRange::new(mapping.range.start()..range.start())));
            }
            if range.end() < mapping.range.end() {
                mappings.push(mapping.slice(MemoryRange::new(range.end()..mapping.range.end())));
            }
        }
        mappings.extend(new_mapping);

        if let Some(handle) = &self.handle {
            block_on(handle.replace_mappings(
                affected,
                mappings.iter().map(DeviceMapping::region_params).collect(),
            ))
            .map_err(io::Error::other)?;
        }

        self.mappings.retain(|m| !m.range.overlaps(&range));
        self.mappings.extend(mappings);
        Ok(())
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
        let range = self.validated_memory_range(offset, len)?;
        if !file_offset.is_multiple_of(hvdef::HV_PAGE_SIZE)
            || file_offset.checked_add(range.len() - 1).is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unaligned or overflowing backing range",
            ));
        }

        #[cfg(unix)]
        let mappable = section.as_fd().try_clone_to_owned()?;
        #[cfg(windows)]
        let mappable = section.as_handle().try_clone_to_owned()?;

        let new_mapping = DeviceMapping {
            range,
            file_offset,
            mappable: mappable.into(),
            writable,
        };

        self.state.lock().update(range, Some(new_mapping))
    }

    fn unmap(&self, offset: usize, len: usize) -> io::Result<()> {
        let range = self.validated_memory_range(offset, len)?;
        self.state.lock().update(range, None)
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

#[cfg(test)]
mod tests {
    use super::DeviceMemoryMapper;
    use super::DeviceMemoryRegion;
    use super::DeviceRegionState;
    use crate::mapping_manager::MappingManager;
    use crate::region_manager::RegionManager;
    use futures::executor::block_on;
    use guestmem::GuestMemory;
    use guestmem::MappedMemoryRegion;
    use guestmem::MemoryMapper;
    use memory_range::MemoryRange;
    use pal_async::DefaultPool;
    use parking_lot::Mutex;
    use std::io;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use test_with_tracing::test;

    fn with_region(test: impl FnOnce(&DeviceMemoryRegion)) {
        DefaultPool::run_with(|spawn| async move {
            let mapping_manager = MappingManager::new_without_primary(&spawn, 0x20000, None);
            let region_manager = RegionManager::new(&spawn, mapping_manager.client().clone());
            let region = DeviceMemoryRegion {
                debug_name: "test".into(),
                len: 0x10000,
                region_manager: region_manager.client().clone(),
                state: Mutex::new(DeviceRegionState {
                    handle: None,
                    mappings: Vec::new(),
                }),
            };
            test(&region);
        });
    }

    #[test]
    fn invalid_device_ranges_preserve_existing_mapping() {
        with_region(|region| {
            let section = sparse_mmap::alloc_shared_memory(0x10000, "test").unwrap();
            region.map(0, &section, 0, 0x10000, true).unwrap();

            for (offset, len) in [
                (0x4000, 0),
                (0x4001, 0x1000),
                (0x4000, 0x1001),
                (0xf000, 0x2000),
                (0x10000, 0x1000),
                (usize::MAX - 0xfff, 0x1000),
            ] {
                assert_eq!(
                    region
                        .map(offset, &section, 0, len, false)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidInput,
                    "map offset={offset:#x}, len={len:#x}",
                );
                assert_eq!(
                    region.unmap(offset, len).unwrap_err().kind(),
                    io::ErrorKind::InvalidInput,
                    "unmap offset={offset:#x}, len={len:#x}",
                );

                let state = region.state.lock();
                assert_eq!(state.mappings.len(), 1);
                assert_eq!(state.mappings[0].range, MemoryRange::new(0..0x10000));
                assert_eq!(state.mappings[0].file_offset, 0);
                assert!(state.mappings[0].writable);
            }
        });
    }

    #[test]
    fn invalid_backing_ranges_preserve_existing_mapping() {
        with_region(|region| {
            let section = sparse_mmap::alloc_shared_memory(0x10000, "test").unwrap();
            region.map(0, &section, 0, 0x10000, true).unwrap();

            for file_offset in [1, u64::MAX - 0xfff] {
                assert_eq!(
                    region
                        .map(0x4000, &section, file_offset, 0x2000, false)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidInput,
                );

                let state = region.state.lock();
                assert_eq!(state.mappings.len(), 1);
                assert_eq!(state.mappings[0].range, MemoryRange::new(0..0x10000));
                assert_eq!(state.mappings[0].file_offset, 0);
                assert!(state.mappings[0].writable);
            }
        });
    }

    #[test]
    fn mapping_at_device_boundary_can_be_replaced_and_unmapped() {
        with_region(|region| {
            let section = sparse_mmap::alloc_shared_memory(0x10000, "test").unwrap();
            region.map(0xf000, &section, 0xf000, 0x1000, false).unwrap();
            region.map(0xf000, &section, 0xf000, 0x1000, true).unwrap();

            {
                let state = region.state.lock();
                assert_eq!(state.mappings.len(), 1);
                assert_eq!(state.mappings[0].range, MemoryRange::new(0xf000..0x10000));
                assert_eq!(state.mappings[0].file_offset, 0xf000);
                assert!(state.mappings[0].writable);
            }

            region.unmap(0xf000, 0x1000).unwrap();
            assert!(region.state.lock().mappings.is_empty());
        });
    }

    #[test]
    fn failed_replacement_restores_active_mapping() {
        let (thread, spawn) = DefaultPool::spawn_on_thread("device-memory-test");
        {
            let mapping_manager = MappingManager::new_without_primary(&spawn, 0x20000, None);
            let region_manager = RegionManager::new(&spawn, mapping_manager.client().clone());
            let memory = GuestMemory::new(
                "test",
                block_on(mapping_manager.client().new_mapper(true)).unwrap(),
            );
            let (mut control, region) = DeviceMemoryMapper::new(region_manager.client().clone())
                .new_region(0x10000, "test".into())
                .unwrap();
            let section = sparse_mmap::alloc_shared_memory(0x20000, "test").unwrap();
            region.map(0, &section, 0x4000, 0x10000, true).unwrap();
            control.map_to_guest(0, true).unwrap();

            let pattern: Vec<_> = (0..0x10000).map(|i| (i / 0x1000) as u8).collect();
            memory.write_at(0, &pattern).unwrap();

            let file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
            let read_only = sparse_mmap::new_mappable_from_file(&file, false, false).unwrap();
            for (offset, len) in [(0x4000, 0x4000), (0, 0x10000)] {
                assert!(region.map(offset, &read_only, 0, len, true).is_err());

                let mut data = vec![0; pattern.len()];
                memory.read_at(0, &mut data).unwrap();
                assert_eq!(data, pattern);
                memory
                    .write_at(offset as u64, &pattern[offset..offset + len])
                    .unwrap();
            }

            region.unmap(0, 0x10000).unwrap();
            assert!(memory.read_at(0, &mut [0]).is_err());
            region.map(0, &section, 0x4000, 0x10000, true).unwrap();
            let mut data = vec![0; pattern.len()];
            memory.read_at(0, &mut data).unwrap();
            assert_eq!(data, pattern);
            control.unmap_from_guest();
        }
        drop(spawn);
        thread.join().unwrap();
    }

    #[test]
    fn concurrent_reads_survive_replacement_and_rollback() {
        let (thread, spawn) = DefaultPool::spawn_on_thread("device-memory-test");
        {
            let mapping_manager = MappingManager::new_without_primary(&spawn, 0x20000, None);
            let region_manager = RegionManager::new(&spawn, mapping_manager.client().clone());
            let memory = GuestMemory::new(
                "test",
                block_on(mapping_manager.client().new_mapper(true)).unwrap(),
            );
            let (mut control, region) = DeviceMemoryMapper::new(region_manager.client().clone())
                .new_region(0x10000, "test".into())
                .unwrap();
            let section = sparse_mmap::alloc_shared_memory(0x10000, "test").unwrap();
            region.map(0, &section, 0, 0x10000, true).unwrap();
            control.map_to_guest(0, true).unwrap();
            let pattern = vec![0x5a; 0x10000];
            memory.write_at(0, &pattern).unwrap();
            let file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
            let read_only = sparse_mmap::new_mappable_from_file(&file, false, false).unwrap();
            let done = AtomicBool::new(false);
            std::thread::scope(|scope| {
                let reader = scope.spawn(|| {
                    let mut data = vec![0; pattern.len()];
                    while !done.load(Ordering::Relaxed) {
                        memory.read_at(0, &mut data)?;
                        assert_eq!(data, pattern);
                    }
                    Ok::<_, guestmem::GuestMemoryError>(())
                });
                let result = (|| {
                    for _ in 0..100 {
                        region.map(0x4000, &section, 0x4000, 0x4000, false)?;
                        assert!(region.map(0x4000, &read_only, 0, 0x4000, true).is_err());
                        region.map(0x4000, &section, 0x4000, 0x4000, true)?;
                    }
                    io::Result::Ok(())
                })();
                done.store(true, Ordering::Relaxed);
                reader.join().unwrap().unwrap();
                result.unwrap();
            });
            control.unmap_from_guest();
        }
        drop(spawn);
        thread.join().unwrap();
    }

    #[test]
    fn partial_replace_and_unmap_preserve_unaffected_portions() {
        let (thread, spawn) = DefaultPool::spawn_on_thread("device-memory-test");
        {
            let mapping_manager = MappingManager::new_without_primary(&spawn, 0x20000, None);
            let region_manager = RegionManager::new(&spawn, mapping_manager.client().clone());
            let memory = GuestMemory::new(
                "test",
                block_on(mapping_manager.client().new_mapper(true)).unwrap(),
            );
            let (mut control, region) = DeviceMemoryMapper::new(region_manager.client().clone())
                .new_region(0x10000, "test".into())
                .unwrap();
            let original = sparse_mmap::alloc_shared_memory(0x10000, "test").unwrap();
            let replacement = sparse_mmap::alloc_shared_memory(0x10000, "test").unwrap();
            region.map(0, &original, 0, 0x10000, true).unwrap();
            control.map_to_guest(0, true).unwrap();
            let pattern: Vec<_> = (0..0x10000).map(|i| (i / 0x1000) as u8 + 1).collect();
            memory.write_at(0, &pattern).unwrap();

            region
                .map(0x4000, &replacement, 0x4000, 0x4000, true)
                .unwrap();
            let mut data = vec![0; pattern.len()];
            memory.read_at(0, &mut data).unwrap();
            assert_eq!(data[..0x4000], pattern[..0x4000]);
            assert!(data[0x4000..0x8000].iter().all(|&b| b == 0));
            assert_eq!(data[0x8000..], pattern[0x8000..]);

            // Unmap a range spanning the original and replacement mappings.
            region.unmap(0x2000, 0x4000).unwrap();
            let mut data = vec![0; 0x2000];
            memory.read_at(0, &mut data).unwrap();
            assert_eq!(data, pattern[..0x2000]);
            assert!(memory.read_at(0x2000, &mut [0]).is_err());
            assert!(memory.read_at(0x5fff, &mut [0]).is_err());
            memory.read_at(0x6000, &mut data).unwrap();
            assert!(data.iter().all(|&b| b == 0));
            let mut data = vec![0; 0x8000];
            memory.read_at(0x8000, &mut data).unwrap();
            assert_eq!(data, pattern[0x8000..]);
            control.unmap_from_guest();
        }
        drop(spawn);
        thread.join().unwrap();
    }
}
