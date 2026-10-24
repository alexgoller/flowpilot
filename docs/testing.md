# Testing

There are six layers: unit tests that run anywhere, a differential test that compares FlowPilot with the original
FlowLink on the same traffic, a conformance run of the decoders against captures from real exporters, scenario tests
against a mock PCE (unmanaged workloads, and configuration from variables only), installer checks in Rocky Linux VMs,
and a decode benchmark for the cost of the stats counters. None of them talks to a real PCE.

What these checks found about decoder compatibility, and what is still open, is in
[compatibility.md](compatibility.md).

Last run 2026-10-22: differential RECORDS IDENTICAL (308 records); unmanaged scenario 28 PASS (A, B, C);
variables-only scenario 15 PASS; conformance 104 cases, 0 new mismatches; `cargo test` 304 pass, 1 ignored.

## Unit tests and lint

```
cargo test
cargo clippy --all-targets -- -D warnings
```

`cargo test` needs no network, no root and no Docker, and also runs on macOS. At the time of writing it runs 305 tests:
304 pass and 1 is ignored (`unmanaged::dns::tests::system_dns_localhost`, which needs a working system resolver; run
it with `cargo test -- --ignored`).

What they cover:

| Area | Examples |
|---|---|
| CLI and config | Flag parsing like Go's `flag` package; schema accept/reject cases; defaults; the error line format; the number and string conversions; the `unmanaged_workloads` rules |
| API key and start-up | File and `$command` sources, JSON keys, error texts; instance id layout; reported-IP files, including real gob files from the original in `tests/fixtures` |
| Collectors | NetFlow v5/v9, IPFIX and sFlow decoding from hand-built datagrams, template replay and the 120-second rule, the text parser's attribute matching, time layouts, `only_recs`, the fixes for the original's panics |
| Aggregation and spool | Merging forward and reverse flows, window reports, batch splitting, protobuf and gzip output, the size cap, retention, ordering |
| Uploader | A local HTTP server checks the request line, headers, basic auth, the 404 fallback and the status handling |
| Unmanaged workloads | Label rules, selection, caps and burst pause, DNS concurrency, PCE client against a local server, state files, the worker thread |
| Environment configuration | `FLOWPILOT_*` and `PCE_*` overlay, value forms, error texts naming the variable, `-print-config` and its secret masking, data directory creation |
| Stats | Collector and exporter counters, exporter table limits, status rules, upload and unmanaged counters, the log line, the JSON and Prometheus output, the HTTP endpoint's limits |

These tests show the pieces behave as written. They do not prove equivalence with the original; that is what the next
section is for.

The flow decoders also have cargo-fuzz targets (run in Docker, nightly) and a round-trip property test
(`tests/decode_roundtrip.rs`); see [fuzz/README.md](../fuzz/README.md).

## Differential test against the original

`tests/e2e/run.sh` runs the original binary and this build side by side in Docker, feeds both the same traffic, and
compares what each uploads to a mock PCE.

### What you need

- Docker with linux/amd64 support (on Apple silicon, emulation is used; it is slow).
- The original binary at `original/usr/local/bin/flowlink`. It is proprietary and not in the repository; extract it
  from the RPM with `make original`, which needs the vendor RPM in the repository root and `bsdtar`.
- The flow generator, [illumio-flowgen](https://github.com/alexgoller/illumio-flowgen), checked out at
  `../illumio-flowgen` (relative to this repository). Set
  `FLOWGEN_SRC` to use another path.

### Run

```
tests/e2e/run.sh          # 10 seconds of traffic per protocol
tests/e2e/run.sh 30       # 30 seconds
```

The script builds both Rust programs inside a `rust:1-bookworm` container (the cargo registry is cached in a Docker
volume), then `inside.sh` does the run. Artifacts (logs, uploaded files, decoded JSON) are written to `target/e2e`.

### What it does

1. Creates a throw-away certificate and starts two mock PCEs (`mock_pce.py`) that accept uploads over HTTPS and keep
   the bodies, one for each program.
2. Starts the original and FlowPilot with equivalent configs: a NetFlow, an IPFIX and a text consumer.
3. `udp_fanout.py` receives on the standard ports and copies every datagram to both programs, so they see byte-for-byte
   the same input.
4. The flow generator sends NetFlow v5, NetFlow v9 and IPFIX (preset `three-tier`, fixed seed, 50 flows per second),
   and a script sends about 48 syslog-style lines to the text consumer.
5. Both programs are stopped with SIGQUIT, which flushes the window, and their exit statuses are recorded (the original exits 1, FlowPilot 0).
6. `decode_posts.py` unpacks every uploaded body (gzip, protobuf) into sorted JSON records.

### What it proves

It prints the number of posts, the records and the `aggregation_seconds` of each side, and then
`RECORDS IDENTICAL` or `RECORDS DIFFER` with the records that appear on only one side. The script exits non-zero when
the two record sets differ or are empty. So a pass means: for NetFlow v5, v9, IPFIX and the text parser, on this
traffic, FlowPilot uploads the same flow records, with the same counts, bytes, times and ports, as the original.

It does not prove:

- sFlow equivalence, `remote_addrs`, or multiple ports (not exercised);
- that log lines are identical (logs are saved, not compared);
- behaviour under overload, long runs, retries or a real PCE;
- anything about unmanaged workloads, which the original does not have.

Window timing in the differential run is cut short by the SIGQUIT flush, not by waiting for `aggregation_minutes`.

## Decoder conformance against real exporters

`tests/conformance/run.sh` replays public captures from real NetFlow v5/v9, IPFIX and sFlow exporters (about 30
vendors) through the decoders and compares every record with tshark; see
[tests/conformance/README.md](../tests/conformance/README.md). It needs Docker and network access for the first
download, and writes `target/conformance/report.md`.

## Unmanaged workload scenario

```
tests/e2e/run.sh unmanaged
```

It needs Docker and the flow generator, but not the original binary. It takes about six minutes, because the shortest
allowed window, `aggregation_minutes: 5`, must pass once; the script polls for the result instead of sleeping, and
`UW_WAIT_SECS` (default 420) limits the wait. Artifacts go to `target/e2e-unmanaged`.

Three FlowPilot instances see the same generated NetFlow v5 traffic:

- **A** talks to a mock PCE that is seeded with one existing workload and one label, with `min_flows: 1`,
  `max_creates_per_window: 3`, DNS off and a set of label rules.
- **B** talks to a mock PCE that answers every REST call with 403 but still accepts flow uploads.
- **C** is like A with `max_creates_per_window: 100`, against a mock PCE that has a workload for one busy IP which
  the startup export does not list. Only the per-IP pre-create check can find it.

The script checks, and prints PASS or FAIL for each:

- A creates exactly three workloads; names, interface name `umw0`, `external_data_set` and
  `external_data_reference` are as documented; there is no hostname.
- The labels match the label rules, computed independently in the checker (longest prefix wins per type).
- The seeded IP gets no second workload, no label is duplicated, and the pre-create check ran for every created IP.
- The summary log line shows 3 created, some deferred, 0 errors, and that missing label values were created.
- The mock saw no malformed requests.
- C creates the other eligible IPs but not the hidden one, and its pre-create check queried that IP.
- B still gets flow uploads accepted (204), logs that the key needs permission, and creates no workloads.
- Every process exits with status 0 after SIGQUIT (a process that ignores it is killed and counts as a failure).

It ends with `RESULT: PASS` or `RESULT: FAIL`.

What this proves is that the PCE conversation (labels, export, pre-create check, `bulk_create`) works against a mock
that was written from the REST behaviour probed on a real PCE. It does not prove
the feature on a real PCE: that run is still open (see [roadmap.md](roadmap.md)).

## Variables-only scenario

```
tests/e2e/run.sh envonly
```

It needs Docker and the flow generator, but not the original binary. Like the unmanaged scenario it takes about six
minutes, because it waits for the first 5-minute window to be uploaded; `ENV_WAIT_SECS` (default 420) limits the wait.
Artifacts go to `target/e2e-envonly`.

FlowPilot starts with no `CONFIG_FILE`. Its whole configuration comes from variables: `FLOWPILOT_PCE_ADDR`,
`FLOWPILOT_API_USER`/`_SECRET`, `FLOWPILOT_VERIFY_PCE_CERT=false` (the mock's certificate is self-signed),
`FLOWPILOT_DATA_DIRECTORY` (a directory that does not exist yet), `FLOWPILOT_NETFLOW_PORTS`, `FLOWPILOT_IPFIX_PORTS`,
`FLOWPILOT_NETFLOW_REMOTE_ADDRS=127.0.0.1`, `FLOWPILOT_AGGREGATION_MINUTES=5`, `FLOWPILOT_STATS_INTERVAL_SECONDS=10`
and `FLOWPILOT_STATS_HTTP_LISTEN=127.0.0.1:9180`. The flow generator sends NetFlow v9 and IPFIX for 30 seconds, and
one NetFlow datagram is sent from `127.0.0.2`, which `remote_addrs` does not allow.

The script checks, and prints PASS or FAIL for each:

- the data directory was created;
- right after the traffic, `/healthz` answers 200 and `/stats` shows status `ok`, collectors `netflow` and `ipfix`
  with `flows_decoded > 0` and exporter `127.0.0.1`, and `rejected_datagrams >= 1` on `netflow` with no exporter row
  for the rejected sender;
- the `FLOWPILOT_STATS` lines parse as JSON;
- after the first window, the mock PCE received an upload (204) and the last `FLOWPILOT_STATS` line before SIGQUIT
  shows `uploads.succeeded >= 1`;
- no line of the FlowPilot log contains the API secret;
- the process exits with status 0 after SIGQUIT.

It ends with `RESULT: PASS` or `RESULT: FAIL`.

## Installer on a real host (Lima VMs)

```
tests/vm/run.sh rocky9                 # Rocky Linux 9, aarch64
tests/vm/run.sh rocky8                 # Rocky Linux 8, x86_64 under emulation
CHECKS=basic tests/vm/run.sh rocky9-x86  # Rocky Linux 9, x86_64 under emulation: install, status and uninstall only
```

The installer's own tests run against an in-memory host; these runs check it on a real systemd host with SELinux
enforcing. They need [Lima](https://lima-vm.io) (`brew install lima`; for the x86_64 VMs also
`brew install lima-additional-guestagents` and QEMU), `python3` and `openssl` on the Mac, and the static binaries from
`tools/build-static.sh`. No real PCE is contacted. Rocky 8 runs as x86_64 because its aarch64 kernel uses 64 KB pages,
which Apple silicon does not support ("This 64 KB granular kernel is not supported by your CPU").

`run.sh` creates the VM `flowpilot-rocky9`, `flowpilot-rocky8` or `flowpilot-rocky9-x86` from Lima's Rocky template
on first use, without host mounts or containerd, and reuses it later (delete one with `limactl delete -f <name>`). It makes a CA and
a certificate for `host.lima.internal` signed by it, starts two mock PCEs (`tests/e2e/mock_pce.py`) on the Mac, one
normal and one answering every API call with 401 (ports 18443 and 18444; `VM_PCE_PORT` moves them), copies the binary,
the CA, a canned NetFlow v5 datagram and `checks.sh` into the VM, and runs `checks.sh` there as root. The VM reaches the
mocks as `host.lima.internal`. Output goes to `target/vm/<vm>`: `checks.log`, `transcript` (the installer's output
per check) and the mock logs. A first run downloads the image; an emulated x86_64 VM takes several minutes to boot, and
a full run in it about ten minutes.

`checks.sh` first removes any earlier install, then prints PASS or FAIL for each check:

| Check | What it shows |
|---|---|
| `selinux_enforcing` | `getenforce` is `Enforcing` |
| `pce_cert_untrusted` | before the mock's CA is trusted, the unattended install exits 1 with the certificate error and creates nothing; the CA is then added with `update-ca-trust` |
| `install` | `install --yes --pce host.lima.internal:<port> --org 1 --api-user api_1 --api-secret-file - --netflow 2055` (secret on stdin) exits 0 and the service is `active` |
| `bin_t`, `modes` | `/usr/local/bin/flowpilot` is labelled `bin_t`; modes and owners of `/etc/flowpilot`, `config.yaml`, `api_key`, `/var/lib/flowpilot`, the unit and the binary, and the user's `nologin` shell |
| `status` | `flowpilot status` shows `Service:  active` (from `systemctl is-active`) |
| `rerun_unchanged` | the same install again prints `unchanged` |
| `netflow_in_stats`, `netflow_in_status` | a NetFlow v5 datagram sent to UDP 2055 shows exporter `127.0.0.1` in `/stats` and in `flowpilot status` |
| `upgrade` | `install --yes` from a newer build (the binary with bytes appended) replaces the binary, keeps the old one as `.prev`, and the service comes back `active` and `bin_t` |
| `rollback_installed_broken`, `rollback` | an upgrade to a script that exits 1: the installer switches back to the previous binary by itself, exits 1, and the service is active and healthy again |
| `auth_401_changes_nothing` | against the 401 mock the install exits 1 and binaries, config, key, unit, labels and the running process are as before |
| `text_binds_514` | adding a text collector on 514 restarts the service with `CAP_NET_BIND_SERVICE` and `ss -ulpn` shows it bound |
| `secret_not_in_ps`, `secret_not_in_journal` | the random secret never appears in `ps -eo args` (sampled during every install), in `journalctl -u flowpilot` or in the whole journal |
| `uninstall_keeps_config`, `purge` | `uninstall` removes service, unit and binary and keeps `/etc/flowpilot`; `uninstall --purge --yes` removes everything and the user |

`CHECKS=basic` runs `selinux_enforcing`, `pce_cert_untrusted`, `install`, `bin_t`, `modes`, `status`, the secret
checks, `uninstall_keeps_config` and `purge`. The script ends with `RESULT: PASS` or `RESULT: FAIL`, and `run.sh` exits
non-zero on a failure.

How the broken upgrade is made: a script cannot run the installer, and the installer installs the file at the path it
was started from. So a good binary is started from `/tmp/fpvm/inst` and, while it waits for the secret on stdin, the
script is bind-mounted over that path; the installer then installs the script, restarts the service, sees no health,
and switches back. `rollback_installed_broken` checks that the script really was installed.

Last run 2026-10-24: Rocky 9.8 aarch64 18 PASS, Rocky 8.10 x86_64 18 PASS, Rocky 9.8 x86_64 (`CHECKS=basic`) 10 PASS.

## Stats overhead

```
cargo run --release --example decode_bench [-- ITERATIONS]
```

Decodes one NetFlow v9 and one IPFIX data message of 10 records each (the unit tests' record layouts) 1 000 000 times
through `decode_datagram`, once with registered `CollectorStats` and once with `CollectorStats::default()`, and prints
flows per second for both. Counting is always on, so both runs count. To measure against no counting at all, build the
same loop with the stats counters removed (`ParserContext` reduced to `{ meter, sink }`). On 2026-10-22 (Apple silicon host, release build, median of 3 runs of 20 million flows):
1 862 914 flows/s with stats, 1 859 787 without, a difference of +0.2%, which is noise.

## Running a trial against a real PCE

Use `dry_run: true` first, or a separate `external_data_set` such as `flowpilot-test`. Creating workloads changes the
PCE, so do it only on a PCE where that is acceptable. The helper `tests/e2e/pce_key.sh ENV_FILE` prints `API_KEY API_SECRET`
from an env file, so a config can say `api_key: "$tests/e2e/pce_key.sh /path/to/env"` without storing the key in the
config.

## Static release binaries

```
tools/build-static.sh
```

Builds fully static Linux binaries for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` with
`cargo zigbuild --release --locked` inside Docker (`rust:1.97.1-bookworm`, zig 0.14.1, cargo-zigbuild 0.19.8; the
container runs natively on the host architecture and zig cross-compiles, so no emulation is needed). It writes
`dist/flowpilot-<version>-<arch>-linux` (version from `Cargo.toml`) and `dist/SHA256SUMS`. `dist/` is not committed.
The cargo registry and the zig toolchain are cached in the Docker volumes `flowpilot-cargo-registry` and
`flowpilot-build-tools`; the first run downloads them, later runs take about a minute per target.

Check the result with `file dist/flowpilot-*` (both must say "statically linked") and run it in a bare container:

```
docker run --rm --platform linux/arm64 -v $PWD/dist:/d alpine /d/flowpilot-<version>-aarch64-linux -version
docker run --rm --platform linux/amd64 -v $PWD/dist:/d alpine /d/flowpilot-<version>-x86_64-linux -version
```

On musl, TLS roots are read at run time from the system certificate files (`/etc/ssl/certs/ca-certificates.crt`,
`SSL_CERT_FILE`), so the host needs a CA bundle to verify a PCE certificate; `-print-config` and `-version` need none.
