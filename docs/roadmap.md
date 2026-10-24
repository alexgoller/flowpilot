# Roadmap

What is planned, in rough order, and what is deliberately left out. Items here are plans, not promises. The decisions
below were taken on 2026-10-22.

## Where things stand

- Done: the standalone install (static binaries, `flowpilot install`, release workflow); the UDP collection and upload path (NetFlow, IPFIX, sFlow, text), the spool and uploader, and automatic
  unmanaged workload creation, tested against a mock PCE. Its flow counts are kept in hourly buckets, about one entry
  per unknown internal IP per hour of the window.
- Open: a run of unmanaged workload creation against a real PCE.
- Open: some verification from the original plan: unit tests with captured exporter traffic, a config accept/reject
  comparison against the original on edge cases, and a check that every feature of the original has a counterpart.

## Bidirectional byte counts

Next after unmanaged workloads. Today, as in the original, only one direction's bytes are reported per conversation.
This is a deliberate divergence from the original and will be listed as a fix:

- Read the IPFIX biflow reverse byte count (RFC 5103, enterprise number 29305, `reverseOctetDeltaCount`) into the
  reverse direction.
- Handle a missing direction field correctly. Today NetFlow v9 and IPFIX records without a direction (the default) have
  all bytes counted as one direction.
- Orient each conversation the same way every time: the server (well-known) port is the destination. Now, a reply that
  arrives before the request can flip source and destination and turn the ephemeral port into the destination port.
- Move the direction behaviour from "Preserved on purpose" to "Fixed quirks" in
  [differences-from-flowlink.md](differences-from-flowlink.md), and adjust the differential test,
  which currently expects identical output to the original.

## FlowPilot rename, install and packaging

Done (2026-10-24). The product is FlowPilot: the crate, binary, service, user, paths and log lines follow the name.
Static release binaries (musl, x86_64 and aarch64) are built and published by the release workflow with `SHA256SUMS`
and `install.sh`. `flowpilot install` is an interactive wizard that is also scriptable (`--yes`, flags,
`FLOWPILOT_*`), re-running it upgrades, and `upgrade`, `rollback`, `uninstall` and `status` exist. It is described in
[operations.md](operations.md#installing) and was verified in Rocky Linux 8 and 9 VMs with SELinux enforcing.

Decisions kept:

- **Distribution:** public GitHub releases (static binaries, `SHA256SUMS`, `install.sh`), Apache-2.0.
- **Minimum platform:** RHEL 8; other systemd distributions should work.
- **Firewall:** the installer prints the commands and never runs them.

Possible later channels, not planned: an RPM or .deb, a container image, taking over a host that runs FlowLink, and
network self-update. A run on an actual RHEL host is still open.

## CLI config wizard

Done as part of `flowpilot install` (see above).

## IPv6 unmanaged workloads

The unmanaged workload feature is IPv4-only: IPv6 CIDRs are refused and IPv6 addresses never become candidates.
IPv6 flows are collected and uploaded as usual. Support for IPv6 workloads is wanted later, but not now.

## Deferred connectors

These parts of FlowLink 2.0.1-2 were not reimplemented. The config schema still accepts them, and a config that uses
them fails to start the affected consumer with a clear message.

| Feature | Notes |
|---|---|
| Kafka connector (input) and Kafka output | Later. The output branch also changes the record format. |
| AWS CloudWatch Logs connector and parser | Later. |
| TCP connector | Much later. The text parser already has a partial-line path for it. |
| PCE Kafka / Integrations mode (`pce_kafka`) | Later. |

If you depend on one of these, keep running FlowLink for that data source for now.
