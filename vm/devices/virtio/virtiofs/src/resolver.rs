// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Defines the resource resolver for virtiofs devices.

use crate::VirtioFs;
use crate::virtio::VirtioFsDevice;
#[cfg(windows)]
use anyhow::Context as _;
use lxutil::LxVolumeOptions;
use virtio::resolve::ResolvedVirtioDevice;
use virtio::resolve::VirtioResolveInput;
use virtio_resources::fs::VirtioFsBackend;
use virtio_resources::fs::VirtioFsHandle;
use vm_resource::ResolveResource;
use vm_resource::declare_static_resolver;
use vm_resource::kind::VirtioDeviceHandle;

/// Resolver for virtiofs devices.
pub struct VirtioFsResolver;

declare_static_resolver! {
    VirtioFsResolver,
    (VirtioDeviceHandle, VirtioFsHandle),
}

impl ResolveResource<VirtioDeviceHandle, VirtioFsHandle> for VirtioFsResolver {
    type Output = ResolvedVirtioDevice;
    type Error = anyhow::Error;

    fn resolve(
        &self,
        resource: VirtioFsHandle,
        input: VirtioResolveInput<'_>,
    ) -> Result<Self::Output, Self::Error> {
        let VirtioFsHandle { tag, fs } = resource;
        let device = match fs {
            VirtioFsBackend::HostFs {
                root_path,
                mount_options,
                #[cfg(windows)]
                user_token,
            } => {
                #[cfg(windows)]
                let user_token = user_token
                    .as_ref()
                    .map(crate::impersonation::impersonation_token)
                    .transpose()
                    .context("failed to create virtio-fs impersonation token")?;

                let fs = {
                    // Open the root as the user so that access is checked
                    // against the user's token.
                    #[cfg(windows)]
                    let _impersonation = user_token
                        .as_ref()
                        .map(crate::impersonation::ImpersonationGuard::new)
                        .transpose()
                        .context("failed to impersonate virtio-fs user token")?;

                    VirtioFs::new(
                        &root_path,
                        Some(&LxVolumeOptions::from_option_string(&mount_options)),
                    )?
                };

                let device = VirtioFsDevice::new(input.driver_source, &tag, fs, 0, None);
                #[cfg(windows)]
                let device = match user_token {
                    Some(token) => device.with_user_token(token),
                    None => device,
                };
                device
            }
            #[cfg(windows)]
            VirtioFsBackend::SectionFs { root_path } => {
                VirtioFsDevice::new(
                    input.driver_source,
                    &tag,
                    crate::SectionFs::new(&root_path)?,
                    8 * 1024 * 1024 * 1024, // 8GB of shared memory,
                    None,
                )
            }
            #[cfg(not(windows))]
            VirtioFsBackend::SectionFs { .. } => {
                anyhow::bail!("section fs not supported on this platform")
            }
            VirtioFsBackend::Aggregate { children } => {
                let fs = VirtioFs::new_aggregate();
                for child in children {
                    fs.add_child(
                        &child.name,
                        &child.root_path,
                        Some(&LxVolumeOptions::from_option_string(&child.mount_options)),
                    )
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "failed to add virtiofs aggregate child '{}' (root_path='{}'): {e}",
                            child.name,
                            child.root_path
                        )
                    })?;
                }
                VirtioFsDevice::new(input.driver_source, &tag, fs, 0, None)
            }
        };
        Ok(device.into())
    }
}
