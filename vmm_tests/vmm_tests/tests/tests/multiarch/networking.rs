// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Networking integration tests for virtio-net and netvsp (vmbus) NICs.

use petri::PetriVmBuilder;
use petri::openvmm::OpenVmmPetriBackend;
use petri::pipette::PipetteClient;
use petri::pipette::cmd;
use vmm_test_macros::openvmm_test;

/// Bring up the network interface and obtain an IP address via DHCP, then
/// run all networking validations: IP assignment, UDP (DNS), and TCP loopback.
async fn validate_nic_networking(agent: &PipetteClient) -> anyhow::Result<()> {
    let sh = agent.unix_shell();

    // Bring up the interface and obtain an IP address via DHCP.
    cmd!(sh, "ifconfig eth0 up").run().await?;
    cmd!(sh, "udhcpc -i eth0 -n -q").run().await?;

    // --- IP assignment validation ---
    let output = cmd!(sh, "ifconfig eth0").read().await?;
    tracing::info!(output, "ifconfig output");

    assert!(
        output.contains("inet addr:10.0.0.2"),
        "expected IPv4 10.0.0.2 not found in ifconfig output"
    );
    assert!(
        output.contains("inet6 addr:"),
        "expected unicast IPv6 address not found in ifconfig output"
    );

    // --- UDP validation via DNS query ---
    // Use nslookup to query the consomme gateway DNS forwarder.
    // This exercises a full UDP round-trip through the NIC and consomme.
    let output = cmd!(sh, "nslookup localhost 10.0.0.1").read().await?;
    tracing::info!(output, "nslookup output");

    assert!(
        output.contains("127.0.0.1"),
        "expected localhost to resolve to 127.0.0.1"
    );

    // --- TCP loopback validation ---
    // Start a TCP listener in the background, send data from a client,
    // and verify the exchange succeeds. The commands will fail if TCP
    // connectivity doesn't work.
    let output = cmd!(
        sh,
        "sh -c 'echo test_payload | nc -l -p 12345 &\nsleep 1\necho hello_from_client | nc -w 2 127.0.0.1 12345'"
    )
    .read()
    .await?;
    tracing::info!(output, "tcp loopback output");

    Ok(())
}

/// Validate networking with a virtio-net NIC: IP assignment, UDP (DNS query),
/// and TCP loopback.
#[openvmm_test(linux_direct_x64)]
async fn virtio_net_networking(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
) -> anyhow::Result<()> {
    let (vm, agent) = config
        .modify_backend(|b| b.with_virtio_net())
        .run()
        .await?;

    validate_nic_networking(&agent).await?;

    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

/// Validate networking with a netvsp (vmbus) NIC: IP assignment, UDP (DNS
/// query), and TCP loopback.
#[openvmm_test(linux_direct_x64)]
async fn netvsp_networking(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
) -> anyhow::Result<()> {
    let (vm, agent) = config
        .modify_backend(|b| b.with_nic())
        .run()
        .await?;

    validate_nic_networking(&agent).await?;

    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}