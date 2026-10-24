# FlowPilot

FlowPilot collects network flow records (NetFlow, IPFIX, sFlow or syslog-style text), summarises them over a time
window and uploads the summary to an Illumio PCE. It also creates unmanaged workloads in the PCE for busy internal IPs
that have none.

It is a Rust reimplementation of Illumio FlowLink 2.0.1-2. It reads the same `config.yaml`, writes the same data
files and sends the same upload requests, so it can replace FlowLink on a collector host. "Illumio PCE" and "FlowLink"
are named here only to say what FlowPilot is compatible with. FlowPilot is not an Illumio product and is not
supported by Illumio.

FlowPilot has its own version numbers, starting at 0.9.0. Each release is compatible with FlowLink 2.0.1.

## Status

- The collection and upload path is a complete reimplementation of the UDP part of FlowLink 2.0.1-2.
- Unmanaged workload creation is new. It is implemented and tested against a mock PCE. It has not yet been run
  against a real PCE.
- The crate and the binary are called `flowpilot`. The config keys are the original ones.
- Release binaries are static (Linux x86_64 and aarch64) and install themselves: `flowpilot install` sets up the
  service, user, config and key file. Install, upgrade, rollback and uninstall were run in Rocky Linux 8 and 9 VMs with
  SELinux enforcing (Rocky 8 as emulated x86_64). They have not been run on a RHEL host.
- The minimum platform is RHEL 8.

## Features

- Collectors on UDP: NetFlow v5, v7 and v9, IPFIX, sFlow v5, and a configurable text/syslog parser.
- Several consumers in one process, each with its own parser and one or more UDP ports, optionally restricted to
  listed exporter addresses.
- Aggregation per window (5 to 60 minutes), gzip-compressed protobuf upload to the PCE, with a persistent on-disk
  spool, retry with backoff, age and size limits, and five parallel senders.
- API key from a file or from a command, HTTP proxy settings, certificate verification switch.
- Unmanaged workload creation: IPs inside your networks that reach a flow threshold get a workload with labels from
  CIDR rules and a reverse-DNS hostname, with per-window and per-day caps and a dry run. See
  [docs/unmanaged-workloads.md](docs/unmanaged-workloads.md).
- Differential test harness that runs the original and this build on the same traffic and compares what they upload.

## Not supported yet

- Kafka connector (input) and Kafka output.
- TCP connector.
- AWS CloudWatch Logs connector and parser.
- PCE Kafka / Integrations mode (`pce_kafka`). The key is validated, but a config that sets `installation_id` makes
  the process log a message and exit.
- IPv6 workload creation. IPv6 flows are collected and uploaded; only the automatic workloads are IPv4-only.
- Bidirectional byte counts: like the original, only one direction's bytes per conversation are reported.

Configs that use an unsupported connector or parser type pass validation but that consumer does not start. See
[docs/differences-from-flowlink.md](docs/differences-from-flowlink.md).

## Build

You need a Rust toolchain that supports edition 2021. TLS is rustls, so OpenSSL is not required. The config schema is
FlowPilot's own (`src/config_schema.json`); it accepts exactly the configs FlowLink's schema accepts, which a unit test
checks against FlowLink's schema when `original/` is present (`make original` extracts it from the RPM; the test skips
without it). Nothing from `original/` is built into the binary.

```
cargo build --release
```

The binary is `target/release/flowpilot`; it links glibc dynamically, so build on a host no newer than the target.
Static binaries for both architectures, as released, come from `tools/build-static.sh` (musl, cargo-zigbuild). They land
in `dist/` as `flowpilot-<version>-{x86_64,aarch64}-linux` with a `SHA256SUMS` file.

## Quick start

On the collector host (Linux with systemd, run as a user who can use `sudo`). You need the PCE address, the
organization id and an API key (its `api_...` user name and secret), created in the PCE beforehand:

```
curl -fsSL https://github.com/alexgoller/flowpilot/releases/latest/download/install.sh | sh
```

The script picks the binary for the CPU, downloads it and `SHA256SUMS`, verifies the checksum and runs
`flowpilot install`. The wizard asks for the PCE, the API key and the collectors, checks the PCE and the key before it
writes anything, installs and starts the service, waits until it is healthy and prints the firewall commands for the
ports you chose. Arguments after `sh -s --` go to `flowpilot install`, for example
`... | sh -s -- --pce pce.example.com:8443 --org 1 --api-user api_1a2b3c --api-secret-file /root/pce-secret --netflow 2055 --yes`.
Under `curl | sh` stdin is the script, so the secret must be in a file (here `/root/pce-secret`, mode 0600), not `-`.
Run as a normal user, the script calls `sudo`, which drops `FLOWPILOT_*` variables from your shell; pass flags, run
it as root, or use `... | sudo -E sh -s -- ...` to keep them.

Set `FLOWPILOT_VERSION` to install a version other than the latest.

On a host that cannot reach GitHub, copy the binary over, check it against `SHA256SUMS` and run it:

```
sha256sum -c --ignore-missing SHA256SUMS
chmod +x flowpilot-0.9.0-x86_64-linux
sudo ./flowpilot-0.9.0-x86_64-linux install
```

Then check the result, and later upgrade, roll back or remove it:

```
flowpilot status
sudo ./flowpilot-<newer-version>-x86_64-linux install    # upgrade: keeps the config, keeps the old binary as .prev
sudo flowpilot rollback
sudo flowpilot uninstall                                  # --purge also removes config, data and the user
```

All of it, including unattended installs, layout and troubleshooting, is in [docs/operations.md](docs/operations.md).
To run the binary by hand without installing, set `CONFIG_FILE` to a config file ([docs/configuration.md](docs/configuration.md))
and start `./flowpilot`; logs go to stdout. Other command line flags: `-debug` (verbose logging), `-version` and
`-print-config`.

## Documentation

| Document | Contents |
|---|---|
| [docs/configuration.md](docs/configuration.md) | Every config key, default, range and validation rule; the API key formats |
| [docs/collectors.md](docs/collectors.md) | NetFlow, IPFIX, sFlow and text parsers: ports, options, fields used, limits |
| [docs/unmanaged-workloads.md](docs/unmanaged-workloads.md) | Automatic unmanaged workload creation |
| [docs/operations.md](docs/operations.md) | install, upgrade, rollback, uninstall, status, data directory, upload behaviour, signals, PCE permissions, troubleshooting |
| [docs/differences-from-flowlink.md](docs/differences-from-flowlink.md) | Every intentional difference from FlowLink 2.0.1-2 |
| [docs/testing.md](docs/testing.md) | Unit tests, clippy, the differential harness and the unmanaged scenario |
| [docs/compatibility.md](docs/compatibility.md) | How the decoders are checked against the specs and real exporters, results and open findings |
| [docs/roadmap.md](docs/roadmap.md) | What is planned and what is deferred |

## Testing

```
cargo test
cargo clippy --all-targets -- -D warnings
```

The end-to-end scripts in `tests/e2e` need Docker and are described in [docs/testing.md](docs/testing.md).

## Repository layout

| Path | Contents |
|---|---|
| `src/` | The program: config, collectors (`parsers/`), aggregator, spool, uploader, `unmanaged/` |
| `src/unmanaged/` | Unmanaged workload creation |
| `docs/` | These documents |
| `install.sh` | The one-line installer attached to each release |
| `.github/workflows/` | CI and the release workflow |
| `tests/vm/` | Lima Rocky Linux VM tests of install, upgrade, rollback and uninstall (see [docs/testing.md](docs/testing.md)) |
| `tests/e2e/` | Docker-based differential test and the unmanaged scenario with a mock PCE |
| `tests/fixtures/` | Sample files for unit tests |
| `tools/build-static.sh` | Static release builds (musl) |
| `original/` | Files extracted from the FlowLink RPM by `make original`, kept locally for reference; not in the repository |

## Licence and ownership

FlowPilot is licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE). It contains code ported from
the Go standard library (BSD-3-Clause) and rcrowley/go-metrics (BSD-2-Clause); see [NOTICE](NOTICE).

FlowPilot is an independent project. It is not affiliated with, endorsed by or supported by Illumio. Illumio and
FlowLink are trademarks of their owner and are used here only to say what FlowPilot is compatible with. No vendor
files are included in this repository.
