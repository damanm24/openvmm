// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Defines the resource resolver for virtio-balloon devices.

use crate::VirtioBalloonDevice;
use virtio::resolve::ResolvedVirtioDevice;
use virtio::resolve::VirtioResolveInput;
use virtio_resources::balloon::VirtioBalloonHandle;
use vm_resource::ResolveResource;
use vm_resource::declare_static_resolver;
use vm_resource::kind::VirtioDeviceHandle;

/// Resolver for virtio-balloon devices.
pub struct VirtioBalloonResolver;

declare_static_resolver! {
    VirtioBalloonResolver,
    (VirtioDeviceHandle, VirtioBalloonHandle),
}

impl ResolveResource<VirtioDeviceHandle, VirtioBalloonHandle> for VirtioBalloonResolver {
    type Output = ResolvedVirtioDevice;
    type Error = anyhow::Error;

    fn resolve(
        &self,
        resource: VirtioBalloonHandle,
        input: VirtioResolveInput<'_>,
    ) -> Result<Self::Output, Self::Error> {
        let device = VirtioBalloonDevice::new(
            input.driver_source,
            resource.initial_target_bytes,
            resource.recv,
            input.memory_reclaim,
        );
        Ok(device.into())
    }
}
