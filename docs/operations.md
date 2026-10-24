# Operations guide

How to install FlowPilot as a service, what it writes to disk, how it talks to the PCE, and what to check when
something is wrong.

## Installing

`flowpilot install` sets everything up on a Linux host with systemd. The quick start in the [README](../README.md) shows
the one-liner (`install.sh`) and the air-gapped path: copy the release binary to the host and run
`sudo ./flowpilot-<version>-<arch>-linux install`. Run `flowpilot install --help` for all flags.

What the wizard does, in order:

1. Checks that it runs as root on a systemd host.
2. Asks for the PCE address (`host:port`), organization id, the API user (`api_...`) and secret (not echoed), the
   collectors (NetFlow, IPFIX, sFlow, text: port and optional allowed exporter addresses), optionally unmanaged
   workloads, and whether to verify the PCE certificate.
3. Checks the PCE before writing anything: it connects, validates the certificate and makes a read-only authenticated
   call with the key. A failure names the step and lets you correct the answer. The rendered config is validated as the
   daemon validates it at start.
4. Shows a summary and asks to confirm.
5. Copies itself to `/usr/local/bin/flowpilot` and restores the SELinux label, creates the user and directories, writes
   the config, key file and unit, and runs `systemctl enable --now flowpilot`.
6. Waits until `/healthz` on the local stats endpoint answers (`no_flows` counts as healthy), then prints the firewall
   commands for the chosen ports and how to run `flowpilot status`.

### Host layout

| What | Where |
|---|---|
| Binary | `/usr/local/bin/flowpilot`; the previous one is kept as `/usr/local/bin/flowpilot.prev` |
| Config | `/etc/flowpilot/config.yaml` (root:flowpilot 0640), directory 0750 |
| API key | `/etc/flowpilot/api_key` (root:flowpilot 0640), `user secret` format, referenced from the config |
| Data | `/var/lib/flowpilot` (flowpilot:flowpilot 0750) |
| Service | `/etc/systemd/system/flowpilot.service`, running as the system user `flowpilot` (no login shell) |

Logs go only to the journal: `journalctl -u flowpilot -f`. There are no log files and no logrotate. The stats endpoint
listens on `127.0.0.1:9180`, or the next free port up to 9189; an existing `stats.http_listen` in the config is kept.
If a collector port is below 1024 (text on 514, for example) the unit gets `AmbientCapabilities=CAP_NET_BIND_SERVICE`.

### Unattended installs

With `--yes` nothing is prompted. `--pce` and an API key are required; the others default (organization 1, certificate
verification on). With no collector flag the installer defaults to NetFlow on 2055. A missing answer exits 2 and a
failed check exits 1; either way nothing is changed. There is no flag that carries the secret: pass
`--api-secret-file PATH`, or `-` to read it from stdin, or `--api-key-file PATH` for the JSON file the PCE offers
for download. Each flag also has a `FLOWPILOT_*` variable (for example `FLOWPILOT_PCE_ADDR`, `FLOWPILOT_API_USER`,
`FLOWPILOT_API_SECRET`, `FLOWPILOT_NETFLOW_PORTS`); the flag wins.

```
printf '%s\n' "$SECRET" | sudo flowpilot install --yes --pce pce.example.com:8443 --org 1 \
  --api-user api_1a2b3c --api-secret-file - --netflow 2055@192.0.2.10 --ipfix 4739
```

`--skip-pce-check` skips the live check for a host that is provisioned before the PCE is reachable; it prints a
warning that the key was not checked. `--no-verify-pce-cert` turns certificate verification off.

`--proxy URL` (or `FLOWPILOT_HTTPS_PROXY`; the wizard asks too, default none) writes `proxy_config.https_proxy`. The
live check goes through exactly that proxy, or direct when there is none. It ignores `HTTPS_PROXY` and `ALL_PROXY`
in your shell, because the service does not inherit them either; when one is set and no proxy is given, the installer
says so. An upgrade keeps the `proxy_config` of the existing config.

Run it again with the same answers and it reports `unchanged` and changes nothing; Ansible can run it on every play.
A re-run still checks the service (the same health wait, or `systemctl is-active` when the config has no
`stats.http_listen`) and exits 1 when it is not healthy, so a broken install does not turn green on the next play.

### Upgrade, rollback, status, uninstall

- **Upgrade:** run `install` (or `upgrade`, the same command) from the newer binary. Without answers or `--reconfigure`
  the existing config and key are kept and not even asked about; the binary is replaced when it differs from the
  installed one, the old one is kept as `flowpilot.prev`, the unit is rewritten if it differs and the service is restarted. If it does
  not come up healthy, or a later step fails (a file write, `daemon-reload`, the restart), the installer switches back
  to `flowpilot.prev` by itself, says so and exits 1. Only the binary goes back: a config the same run rewrote is
  kept, and the message names the backup of the previous one.
- **Reconfigure:** `install --reconfigure`, or an unattended run with different answers, replaces the config. The
  wizard offers the installed answers as defaults; only the API secret is asked for again. The old
  file is first saved as `/etc/flowpilot/config.yaml.<timestamp>.bak` and the installer names it. The file is rewritten
  whole; comments and hand edits are not merged, so copy them over from the backup.
- **Rollback:** `sudo flowpilot rollback` swaps `flowpilot.prev` back in and restarts. A second rollback undoes the first.
- **Status:** `flowpilot status` shows the service state, the health, the version and uptime, the last successful
  upload and error, and for each collector the exporters sending and when each last sent. `--json` prints the same
  as JSON. It exits 1 when the service is not active or the stats report `unhealthy`. It reads the stats endpoint, so
  it needs `stats.http_listen` in the config.
- **Uninstall:** `sudo flowpilot uninstall` stops and disables the service and removes the unit and the binaries. It
  keeps `/etc/flowpilot` and `/var/lib/flowpilot`. `--purge` also removes both and the `flowpilot` user; it asks first,
  or needs `--yes`.

### Firewall commands

The installer never changes the firewall. It prints the commands for the ports you chose, for the firewall that is
active (firewalld, ufw or nftables); for firewalld, for example:

```
firewall-cmd --permanent --add-port=2055/udp
firewall-cmd --reload
```

With no active firewall it prints a comment naming the UDP ports. To limit a port to one exporter, use a rich rule as in
the [Firewall](#firewall) section below.

### Where the installer was tested

Install, upgrade, automatic rollback, uninstall and `--purge` ran in Lima VMs with SELinux enforcing: Rocky Linux 9
(aarch64) and Rocky Linux 8, the latter as emulated x86_64 because aarch64 Rocky 8 needs 64 KB pages, which Apple
silicon does not support. Not tested on RHEL itself. See [testing.md](testing.md#installer-on-a-real-host-lima-vms).

## Running under systemd by hand

The installer does all of this. Use the manual path on a host where you cannot run the installer, or to see what it
sets up. The names below use the same layout as the installer. The unit is the installer's with one extra line,
`ProtectHome=yes`, and `NoNewPrivileges=yes` where the installer sets `NoNewPrivileges=no` (an `api_key: $command` may
need it).

Create a service user and directories:

```
useradd --system --user-group --no-create-home --home-dir / --shell /sbin/nologin flowpilot
install -d -m 0750 -o root -g flowpilot /etc/flowpilot
install -d -m 0700 -o flowpilot -g flowpilot /var/lib/flowpilot/data
install -m 0755 target/release/flowpilot /usr/local/bin/flowpilot
```

Put `config.yaml` and the API key file in `/etc/flowpilot`, readable by the group `flowpilot`. The user needs no
privileges when all UDP ports are above 1023.

`/etc/systemd/system/flowpilot.service`:

```ini
[Unit]
Description=FlowPilot flow collector
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=flowpilot
Group=flowpilot
Environment=CONFIG_FILE=/etc/flowpilot/config.yaml
ExecStart=/usr/local/bin/flowpilot
Restart=always
RestartSec=10
# On a signal FlowPilot waits 5 s to drain, up to 5 s more for unmanaged workloads to save their state,
# and up to about 32 s more to send the last file.
TimeoutStopSec=60
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/flowpilot

[Install]
WantedBy=multi-user.target
```

```
systemctl daemon-reload
systemctl enable --now flowpilot
journalctl -u flowpilot -f
```

This unit is a template written for these docs. It has not been tested on a RHEL host in this repository. Note that
a stop by signal exits 0, while a config error exits 1 and shows as a failed unit; the service restarts every 10
seconds, and after five tries in five minutes systemd stops trying. If the service seems to flap, read the journal for the config
errors.

If `api_key` uses a `$command`, that program runs as the service user with the same restrictions, so it must be
executable and its files readable under `ProtectSystem=strict`.

### Firewall

The collector only receives UDP. Open the ports you configured to the exporters. On a host with firewalld, for
example for NetFlow on 2055 from one exporter:

```
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.0.2.10" port port="2055" protocol="udp" accept'
firewall-cmd --reload
```

FlowPilot does not change firewall settings. Outbound, it needs HTTPS to the PCE (and to the proxy, if you use one),
and DNS if `unmanaged_workloads.dns` uses the system resolver.

### Time and certificates

- Keep the host clock correct (chrony). Flow times from the text parser without a zone, and the sFlow flow time, use
  the host clock.
- PCE certificate checking uses the operating system's trust store. To trust a private CA on RHEL, copy the CA
  certificate to `/etc/pki/ca-trust/source/anchors/` and run `update-ca-trust`. Setting `verify_pce_cert: false`
  disables the check and should be a temporary measure.

## Logging

All output goes to standard output, one line per event, prefixed with a local timestamp such as
`2026-10-22T14:57:07.549374+02:00`. Under systemd that is the journal. There is no log file, no log level setting and
no rotation to configure. `-debug` adds per-packet and per-record detail. Do not use it in production: it prints very
large volumes, and in debug mode a processing error makes the process exit.

Lines to know:

| Line | Meaning |
|---|---|
| `******************** Starting FlowPilot version: 0.9.0` | Start. |
| `Starting Data Consumer: <name>` | A consumer from the config is being started. |
| `Listening for <type> messages on udp port: <port>` | A port is open. `from remote addresses: [...]` is added when `remote_addrs` is set. |
| `Reporting flows every N minutes` | The window loop has started. |
| `Reporting Flows`, `Flow count: N` | A window ended and N aggregated records were produced. |
| `No flows to report` | A window ended with nothing received. |
| `***** Following new IP addresses found in flows: [...]` | IPs seen for the first time since the reported-IP list began. |
| `Sending file: <path> kafkaSync: false` | An upload attempt. |
| `Response Code 204` | Upload accepted. |
| `Response Code <other>` and `Response body: ...` | Upload refused, will be retried. |
| `Sleeping N seconds before retrying send of files.` | Backoff. |
| `Dropping unwanted UDP flows from <ip>` | A sender not in `remote_addrs` (once per address). |
| `No template for ... Storing data for later processing.` | v9 or IPFIX data arrived before its template. |
| `Discarding flow, due to bad data:` | An ICMP flow with a destination port. |
| `Unmanaged workloads: ...` | Summary and warnings of the workload feature. |
| `Got signal`, `Writing flows` | Shutdown, see [Signals](#signals-and-shutdown). |
| `FLOWPILOT_STATS {...}` | The stats, as one JSON object, every `stats.interval_seconds`. See [stats.md](stats.md). |
| `Error: stats HTTP endpoint <addr>: <error>` | The stats endpoint could not bind its address; FlowPilot exits 1. |

### Metrics lines

Every `metrics_print_seconds` each consumer prints a block:

```
meter netflow
  count:              1520
  1-min rate:         25.31
  5-min rate:         24.80
  15-min rate:        12.07
  mean rate:          10.12
```

`count` is the number of records the parser has handled since start (for sFlow, the number of flow records in the
samples; for text, the number of non-empty lines). The rates are per second. A consumer whose count stays at 0
is not receiving usable data.

## The data directory

`data_directory` holds all state. It must be writable by the service user. Nothing in it is needed to start, but
removing files loses the data they contain.

| File | Purpose |
|---|---|
| `traffic_flows_<microseconds>.pb.gz` | The spool: one gzip-compressed protobuf upload per file, mode 0640. Created at each window, deleted after the PCE accepts it. Sent oldest first. |
| `<pce_addr>-org<org_id>-reported_ips.json` | Every IP ever seen in flows, as a sorted JSON array, mode 0640, rewritten atomically after a window that found new IPs. It only grows. It makes the "new IP" log line fire once per IP. |
| `<pce_addr>-org<org_id>-reported_ips.dat` | If a file of this name from FlowLink exists and the `.json` file does not, it is imported once. It is never written or deleted by FlowPilot. |
| `restart_info.yml` | The highest flow sequence number seen per exporter and transport. Written after each window with flows, for compatibility. FlowPilot does not read it. |
| `.uuid` | The instance id, mode 0600, created at first start. It is sent in every upload so the PCE can tell collectors apart. Keep it when you move a collector to a new host if the PCE should see the same one. |
| `<pce_addr>-org<org_id>-uw_known.json` | Unmanaged workloads: IPs known to have workloads, and creation times for the daily cap. |
| `<pce_addr>-org<org_id>-uw_candidates.json` | Unmanaged workloads: flow counts per candidate IP. |

`pce_addr` includes the port, so the names contain a colon (for example `pce.example.com:8443-org1-uw_known.json`).
If the same directory is used for two PCEs or organisations, the name keeps their state apart, but the spool files
are shared, so use one directory per collector.

## What is uploaded

At the end of each window FlowPilot merges the flows it collected and writes them to the spool.

- **Merging.** Flows are keyed by source IP, destination IP, destination port, protocol, ICMP type and code, MAC
  addresses and prefix lengths. When a flow arrives whose reverse is already in the window, it is added to the existing
  record. Per record the upload carries: the earliest start time, the number of flows, the destination port,
  protocol, ICMP type/code for ICMP, and two byte counters (`dst_dbi`, bytes towards the destination, and `dst_dbo`,
  bytes back from it) that are only present when not zero. Which counter the bytes land in depends on the exporter and
  the port rule in [collectors.md](collectors.md#common-behaviour); it is not a full two-way count.
- **Window length field.** `aggregation_seconds` in the upload is the spread between the earliest and latest flow
  times seen in the window, not `aggregation_minutes`. It is 0 if all flows have the same timestamp.
- **Splitting.** At most `max_flows_per_post` records go in one file.
- **Window timing.** The timer sleeps `aggregation_minutes` and then flushes, so the period is a little longer than
  the setting. The first upload happens after one full window.
- **Instance id.** Every upload carries the content of `.uuid`.

## Upload behaviour

- **Endpoint.** `POST https://<pce_addr>/api/v2/orgs/<org_id>/traffic_data/flowlink`. If the PCE answers 404 for
  that path, all senders switch for the rest of the run to `/api/v2/orgs/<org_id>/traffic_data` (for older PCEs) and
  repeat the request. A 404 on the older path deletes the file without sending it.
- **Request.** HTTP/1.1, one connection per request (`Connection: close`), HTTP basic authentication with the API key
  user and secret, `Content-Type: application/x-protobuf`, `Content-Encoding: gzip`. The body is the spool file as is.
  Timeout 60 seconds per request.
- **Success** is status 204 only. Any other status (including 200 and 202) is a failure.
- **Retry.** After a failure (network error, TLS error or any status except 204) the sender waits 10 seconds, then
  20, 30, and so on up to 120 seconds, and tries the same file again, with no limit on attempts. The response body is
  logged. Retention is checked before every attempt: once the file is older than `file_retention_hours` it is deleted.
- **Senders.** Five senders work in parallel, each on a different file. After every file a sender pauses one second,
  so the PCE sees at most about five uploads per second.
- **Start-up.** On start, existing `traffic_flows*` files are queued oldest first. Files older than the retention
  and empty files are deleted. The size cap is not applied at that moment.
- **Retention.** Age is counted from the file's creation (its modification time after a restart).
- **Size cap.** When a new file would take the spool above `data_directory_size_mb`, the oldest queued files are
  deleted first, without a log line. A file that is being sent is not evicted. If the PCE is unreachable for long, the
  oldest flow data is the first to go.
- **Unmanaged workload calls** are separate from this. They use their own REST requests and never block uploads.

### PCE API key permissions

For flow upload, the API key must be accepted by the PCE for the traffic data endpoint above. The PCE role this needs
has not been verified for this build; use the same kind of key you used for FlowLink. A refused key shows as
`Response Code 401` or `403` in the log, and the files stay in the spool and are retried.

For unmanaged workloads (when enabled), the key needs permission to read labels, create labels, read workloads and
create workloads. FlowPilot logs which one is missing on a 401 or 403. See
[unmanaged-workloads.md](unmanaged-workloads.md#pce-access).

### Proxies

Set `proxy_config` (`flowpilot install --proxy URL` writes its `https_proxy`) or the standard environment variables
(`HTTPS_PROXY`, `NO_PROXY`). See [configuration.md](configuration.md#proxy_config). Use `NO_PROXY` for the PCE host if it must be reached directly.

## Signals and shutdown

`SIGINT`, `SIGTERM` and `SIGQUIT` all do the same. Only the first one counts; later ones are ignored.

1. `Got signal`. The sockets stop reading (`udp exiting` per reader), and the metrics are removed.
2. A 5-second pause lets the parsers finish what they hold (`Allowing parsers to drain`).
3. `Writing flows`: the window in progress is flushed. If nothing else is queued and everything fits one file, that
   file is sent before exit and FlowPilot waits for the senders for up to about 32 seconds
   (`Waiting for file senders to drain`). Otherwise the files stay in the data directory and are sent at the next start.
4. The unmanaged workload worker gets the last window to count (nothing is created at shutdown) and up to 5 seconds
   to save its state.
5. The process exits with status **0**, so systemd does not count a stop as a failure. FlowLink exits 1 here.

Nothing is lost on a stop: unsent files stay on disk. A `kill -9` loses the flows of the current window that were
not yet written.

There is no reload signal. Restart the service to apply a config change.

## Is it working?

On an installed host, `flowpilot status` answers this (see [Installing](#upgrade-rollback-status-uninstall)). To read the raw
statistics, take the last `FLOWPILOT_STATS` line (one per `stats.interval_seconds`, by default every 60 seconds):

```
journalctl -u flowpilot -o cat | grep ' FLOWPILOT_STATS ' | tail -n 1 | sed 's/^[^ ]* FLOWPILOT_STATS //' \
  | jq '{status, last_flow_at, uploads: .uploads | {succeeded, failed, last_success_at, last_error}}'
```

Or, with the HTTP endpoint on (`stats.http_listen: 127.0.0.1:9180`), ask the running process:

```
curl -s http://127.0.0.1:9180/stats | jq '{status, last_flow_at}'
```

- `status` is `ok`: flows arrive and uploads succeed.
- `starting`: wait one stats interval.
- `no_flows`: nothing decoded for `stats.idle_warn_seconds`. Check each collector's `datagrams`: 0 means no
  traffic reaches the port; a rising `rejected_datagrams` means `remote_addrs` drops it; rising `decode_errors` means
  the exporter sends a format the collector does not read.
- `upload_failing`: uploads fail for longer than one window. `uploads.last_error` and `uploads.failed` say why; see
  the table below.

Per exporter, `collectors[].exporters[]` shows who sends, what protocol, how many flows and when they were last seen.
Flows that arrive but are filtered show in `flows_dropped`. All fields are described in [stats.md](stats.md).

For a supervisor's health check use `/healthz`. It fails only when a core thread has stopped, not for `no_flows` or
`upload_failing`, which a restart would not fix ([stats.md](stats.md#what-healthz-checks)).

## Troubleshooting

Start by reading the log from the start of the run: `journalctl -u flowpilot --since "10 min ago"`.

| Symptom | Likely cause and fix |
|---|---|
| `flowpilot install` stops with a PCE check error | It names the step: name resolution, connection, certificate or the API key. Fix the answer and run it again; nothing was written. Use `--skip-pce-check` only when the PCE cannot be reached yet. |
| An upgrade ends with `exit 1` and the old version is running | The new binary did not become healthy and the installer switched back to `flowpilot.prev`. Read `journalctl -u flowpilot` for the reason. |
| `flowpilot status` says `FlowPilot is not running` | `journalctl -u flowpilot` shows why, usually a config error. |
| Exits right away after `Starting FlowPilot` with `No config file provided` | `CONFIG_FILE` is not set in the service environment. |
| `The FlowPilot configuration file is not valid` followed by `- [...]` lines | Fix the named keys. A `ports` number needs quotes. Unknown keys are rejected. See [configuration.md](configuration.md). |
| `Data directory: ... is not writable.` | The directory is missing or not writable for the service user. It is not created automatically. |
| `Command failed: ...` or `Unable to obtain api key information` | The `$command` failed or the key text is not `user secret` / JSON. Run the command as the service user. |
| Process exits with status 1 and no message after the `Starting Data Consumer` lines | No consumer started. Look for `Error: listen udp :<port>: bind: address already in use` or `permission denied`, `Unsupported connector:`, or `parser not supported.` lines above it. |
| `Listening for ...` is logged but metrics `count` stays 0 | No traffic arrives. Check the exporter's target IP and port, the host firewall, and the path with `tcpdump -ni any udp port 2055`. Check `remote_addrs` and look for `Dropping unwanted UDP flows from`. |
| Count rises, but `Flow count` is small or 0 | Records are filtered (multicast, missing addresses, ICMP with ports). Use `-debug` briefly on a test host to see `Discarding flow` reasons. |
| NetFlow v9 or IPFIX logs `No template for` | Data arrived before the template. It resolves when the exporter resends templates; check the exporter's template refresh interval. After a collector restart expect a gap. |
| Text parser logs `Discarding flow due to ...` | The field names or numbers do not match your log lines. Compare with [collectors.md](collectors.md#how-a-line-is-read). |
| `Response Code 401` or `403` | The API key is wrong, expired, or lacks permission. |
| `Error sending request:` | The PCE cannot be reached or the TLS handshake fails (name, port, proxy, firewall, untrusted certificate). Test with `curl -v https://<pce_addr>/`. Files are kept and retried. |
| `Response Code 404` for the old path too | The PCE does not know either upload path. Check `pce_addr` and `org_id`. The file is deleted. |
| Uploads work but nothing appears in the PCE | The PCE shows reported flows when at least one side is a managed or unmanaged workload. Enable [unmanaged workloads](unmanaged-workloads.md) or create workloads for the IPs. |
| `traffic_flows_*` files pile up | The PCE rejects or cannot be reached; see the lines above. They are deleted by age and by the size cap. |
| Old flows seem to vanish | The retention or size cap evicted them. Check `file_retention_hours` (also stay at or below 546) and `data_directory_size_mb`. |
| `Unmanaged workloads: ... errors` | See [unmanaged-workloads.md](unmanaged-workloads.md#log-lines). |

## Cutting a release

1. Bump `version` in `Cargo.toml` (and let `Cargo.lock` follow with `cargo build`), commit, and run `tests/e2e/run.sh`
   locally; it must report `RECORDS IDENTICAL` before you tag. The release workflow's e2e job always skips on GitHub
   (it logs a `SKIPPED` line and succeeds), because the original FlowLink binary it compares against is never
   committed and so never present in CI. That local run is the only differential test a release gets.
2. Tag the commit and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`. The tag must equal the `Cargo.toml`
   version; the workflow fails otherwise.
3. The `Release` workflow (`.github/workflows/release.yml`) then runs `cargo test` and clippy, the e2e step (a skip, see step 1),
   `tools/build-static.sh` (static musl binaries for x86_64 and aarch64), a smoke test of both binaries (`-version`,
   `-print-config`; the aarch64 one under QEMU), and creates the GitHub release with
   `flowpilot-<version>-x86_64-linux`, `flowpilot-<version>-aarch64-linux`, `SHA256SUMS` and `install.sh`.
   Only that last job has write permission.

Users install with the one-liner, which verifies the checksum before running `flowpilot install`:

```
curl -fsSL https://github.com/alexgoller/flowpilot/releases/latest/download/install.sh | sh
curl -fsSL .../install.sh | FLOWPILOT_VERSION=0.9.0 sh -s -- <flowpilot install flags>
```

Everything after `sh -s --` is passed to `flowpilot install`. `GITHUB_TOKEN` (or a logged-in `gh`) is used when set, for
example to avoid GitHub's anonymous rate limit.

Run as a normal user, `install.sh` re-runs the installer with `sudo`, which drops the environment: `FLOWPILOT_*`
answers set in your shell do not arrive, and `--yes` then stops with `Missing with --yes`. Pass the answers as flags
after `sh -s --`, run the script as root, or keep the variables with `sudo -E`:

```
curl -fsSL .../install.sh | sudo -E sh -s -- --yes --api-secret-file /root/pce-secret
```
