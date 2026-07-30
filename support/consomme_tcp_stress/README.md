# Consomme TCP stress tool

This standalone tool measures completed short-lived TCP connections through a
Consomme host-to-guest port forward. It does not depend on the OpenVMM test
harness.

Build the server on Linux, then expose the release binary to the guest through
virtio-fs:

```bash
cargo build --release -p consomme_tcp_stress
```

Inside the guest, start the server from the mounted virtio-fs share:

```bash
./consomme_tcp_stress server --listen 0.0.0.0:8080
```

Configure Consomme to forward a host TCP port to guest port 8080. On the host,
run the client against that forwarded port:

```bash
consomme_tcp_stress.exe client \
  --address 127.0.0.1:50000 \
  --connections 1000 \
  --concurrency 100
```

Use `--json` for machine-readable output. Compare identical client commands
with virtio-net configured for one queue pair and multiple queue pairs. Keep
the VM vCPU count, guest server worker count, and host workload unchanged.
