// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resource resolver for Minestrone endpoints.

use crate::MinestroneEndpoint;
use minestrone::MinestroneParams;
use net_backend::resolve::ResolveEndpointParams;
use net_backend::resolve::ResolvedEndpoint;
use net_backend_resources::minestrone::MinestroneHandle;
use thiserror::Error;
use vm_resource::ResolveResource;
use vm_resource::declare_static_resolver;
use vm_resource::kind::NetEndpointHandleKind;

/// Resolver for [`MinestroneHandle`].
pub struct MinestroneResolver;

declare_static_resolver! {
    MinestroneResolver,
    (NetEndpointHandleKind, MinestroneHandle),
}

/// An error resolving a [`MinestroneHandle`].
#[derive(Debug, Error)]
pub enum ResolveMinestroneError {
    /// The CIDR could not be parsed.
    #[error("invalid CIDR {1:?}")]
    InvalidCidr(#[source] minestrone::InvalidCidr, String),
}

impl ResolveResource<NetEndpointHandleKind, MinestroneHandle> for MinestroneResolver {
    type Output = ResolvedEndpoint;
    type Error = ResolveMinestroneError;

    fn resolve(
        &self,
        resource: MinestroneHandle,
        input: ResolveEndpointParams,
    ) -> Result<Self::Output, Self::Error> {
        let mut params = MinestroneParams::new();
        params.gateway.client_mac.0 = input.mac_address.to_bytes();
        if let Some(cidr) = resource.cidr {
            params
                .set_cidr(&cidr)
                .map_err(|err| ResolveMinestroneError::InvalidCidr(err, cidr.clone()))?;
        }
        Ok(MinestroneEndpoint::new(params).into())
    }
}
