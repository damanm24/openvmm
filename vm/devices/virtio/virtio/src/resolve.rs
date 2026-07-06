// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resource resolver definitions for virtio devices.

use crate::DynVirtioDevice;
use crate::VirtioDevice;
use std::sync::Arc;
use vm_resource::CanResolveTo;
use vm_resource::kind::VirtioDeviceHandle;
use vmcore::vm_task::VmTaskDriverSource;

pub use guestmem::MemoryReclaim as VirtioMemoryReclaim;

impl CanResolveTo<ResolvedVirtioDevice> for VirtioDeviceHandle {
    type Input<'a> = VirtioResolveInput<'a>;
}

/// A resolved virtio device.
pub struct ResolvedVirtioDevice(pub Box<dyn DynVirtioDevice>);

impl<T: 'static + VirtioDevice> From<T> for ResolvedVirtioDevice {
    fn from(value: T) -> Self {
        Self(Box::new(value))
    }
}

/// Resolver input for [`VirtioDeviceHandle`].
pub struct VirtioResolveInput<'a> {
    /// The VM driver source.
    pub driver_source: &'a VmTaskDriverSource,
    /// Host memory reclaim interface, available when the VM's RAM is
    /// backed by reclaimable private memory. Consumed by devices that
    /// return memory to the host (virtio-balloon).
    pub memory_reclaim: Option<Arc<dyn VirtioMemoryReclaim>>,
}
