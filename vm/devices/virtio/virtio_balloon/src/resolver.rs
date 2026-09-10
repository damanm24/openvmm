// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Defines the resource resolver for virtio-balloon devices.

use crate::VirtioBalloonDevice;
use anyhow::Context as _;
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
        let reclaim = input.memory_reclaim.context(
            "virtio-balloon requires MemoryReclaim support: use non-isolated x86_64 KVM (Linux) or WHP (Windows), without VTL2, with all RAM private anonymous and no pinning, aliases, or physical DMA; Windows also requires thp=off",
        )?;
        reclaim
            .enable()
            .context("failed to enable virtio-balloon memory reclaim")?;
        let device = VirtioBalloonDevice::new(
            input.driver_source,
            resource.initial_target_bytes,
            resource.recv,
            Some(reclaim),
        );
        Ok(device.into())
    }
}
