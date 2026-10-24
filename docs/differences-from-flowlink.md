# Differences from FlowLink 2.0.1-2

FlowPilot is meant to be a drop-in replacement: same config file, same data files, same upload requests. This page
lists where it is not. It describes observable behaviour only: what FlowLink 2.0.1-2 does with a given config,
traffic or signal, and what FlowPilot does. Where FlowLink behaves oddly, FlowPilot either copies it on purpose so
output stays comparable ([Preserved on purpose](#preserved-on-purpose)) or deliberately does better
([Fixed quirks](#fixed-quirks)).

## Additions

- **`unmanaged_workloads`** is a new top-level config key. The original's schema rejects unknown top-level keys, so
  a config that has this key cannot be loaded by FlowLink. Remove the key to go back. See
  [unmanaged-workloads.md](unmanaged-workloads.md).
- **`stats`** is a new optional top-level key (stats output; same rule: FlowLink rejects the key).
- **The `FLOWPILOT_STATS` log line.** Every `stats.interval_seconds` (default `metrics_print_seconds`) FlowPilot logs
  one extra line: the marker `FLOWPILOT_STATS` and a JSON object with counters per collector and exporter, the
  aggregation, the uploads and the unmanaged workloads. It is on by default and only adds to the log; `stats.log:
  false` turns it off. See [stats.md](stats.md).
- **An HTTP endpoint** with `/healthz`, `/stats` and `/metrics` (Prometheus). It is off unless `stats.http_listen` is
  set. See [stats.md](stats.md#http-endpoint).
- **`stats.legacy_metrics`** switches the original per-collector metrics lines (`meter <name>` blocks). They stay on by
  default, as in FlowLink.
- **Environment variables.** `FLOWPILOT_*` variables set any setting, with plugger's `PCE_*` as a fallback ([plugger](https://github.com/illumio-community/illumio-plugger), a plugin host for the Illumio PCE, passes `PCE_*` variables to plugins), and can
  replace the config file. See [configuration.md](configuration.md#environment-variables). With no such variable the
  behaviour is that of the original.
- **`-print-config`**, a new command line flag: prints the effective configuration with the origin of each value and
  exits. See [configuration.md](configuration.md#seeing-the-effective-configuration).

## Not implemented

These were left out on purpose and are on the [roadmap](roadmap.md#deferred-connectors). The config schema still
accepts them.

| Feature | What FlowPilot does |
|---|---|
| Kafka connector (input) | The connector is rejected with `Unsupported connector: kafka`; the consumer does not start. |
| TCP connector | Same, `Unsupported connector: tcp`. The original starts it. |
| AWS CloudWatch Logs connector and `aws` parser | `Unsupported connector: aws` or `aws parser not supported.` |
| Kafka output | Not available; uploads always go to the PCE REST endpoint. |
| PCE Kafka / Integrations mode (`pce_kafka`) | If `installation_id` is set, FlowPilot logs `PCE Kafka (Integrations) mode is not supported in this build` and exits 1. |
| Wrapper scripts and init script | The RPM of the original ships control and monitor scripts and a SysV script. FlowPilot is the bare program; run it with systemd ([operations.md](operations.md)). |

A consumer with several connectors keeps the ones that start. If no consumer starts at all, the process exits 1
silently, as the original does.

## Known divergences

- **Validation messages.** The original uses a Go JSON-schema library; FlowPilot uses a Rust one and ports the
  original's wording for the keywords the schema uses. Accept and reject decisions match; the text and the
  order of several errors at once can differ. Line format (`\t- [field: message]`) and the exit code are the same.
- **YAML 1.2.** FlowPilot parses the config as YAML 1.2. The original's YAML library follows YAML 1.1 rules, so
  scalars such as `yes`, `no`, `on` and `off` that were booleans there are strings here, and a duplicate key is an
  error. YAML syntax error messages differ. Quote values to be safe.
- **HTTP headers.** Flow uploads send the same request line, body, basic authentication and the headers that matter
  (`Content-Type: application/x-protobuf`, `Content-Encoding: gzip`, `Connection: close`). The HTTP client is
  different, so minor headers that the PCE does not use can differ (for example the original sent Go's default
  `User-Agent` and `Accept-Encoding`). The e2e harness compares uploaded bodies, not headers.
- **Reported IPs are stored as JSON.** The original appended a Go "gob" stream to
  `<pce_addr>-org<org>-reported_ips.dat`. FlowPilot writes `<pce_addr>-org<org>-reported_ips.json`, a sorted array,
  replaced atomically. If the `.json` file does not exist but the old `.dat` exists, the IPs are imported from it
  once and the `.dat` is left untouched. Going back to FlowLink after running FlowPilot means the original reads an
  old `.dat` (or none) and announces some IPs again; that is harmless, as it only changes a log line.
- **Debug output.** Go stack dumps and some of FlowLink's debug dumps are not reproduced. In debug mode an error
  logs `Exiting.` and exits 1, as in the original, without the stack.
- **Error lines.** An error is logged as `Error: <message>`, as in FlowLink, but without the `Line:` line that
  follows it in FlowLink: FlowPilot's log does not carry FlowLink's source file and line locations.
- **Version text.** `-version` prints `FlowPilot version: 0.9.0`; the original printed `FlowLink version:`.
- **Shutdown of idle sockets.** UDP readers check for shutdown once a second. The original only noticed after the next
  datagram arrived.

## Fixed quirks

Bugs in the original that FlowPilot does not copy. None of them changes the data a well-formed exporter produces.

| Area | Original | FlowPilot |
|---|---|---|
| Proxy credentials in the log | `Detected http(s) Proxy:` and `HTTP(S) Proxy configured:` print the proxy URL with its user and password. | The user and password are shown as `***` (`http://***@proxy:3128`); the rest of the line is unchanged. |
| Exit status after a stop by signal | Exits 1. | Exits 0, so systemd does not mark a stopped unit as failed. |
| Empty `$` in `api_key` | Crashes with a Go panic, exit 2. | Logs `Command failed: ` and exits 1. |
| Unreadable data directory at start | Silent hang: nothing is ever uploaded. | Logs the error and exits 1. |
| Spool size cap with an empty queue | Panics, for example with a single file larger than the cap. | Evicts what it can and still writes the file. |
| Unparsable IP in a record | The whole batch fails to encode and is lost. | Only that record is dropped; `Discarding flow with invalid IP address:` is logged. |
| `reported_ips` and `restart_info.yml` writes | Opened without truncation; `restart_info.yml` can keep stale trailing bytes and break; one file descriptor leaks per window. | Truncated or replaced atomically, closed. |
| Memory and CPU over time | Memory grows with every upload, and a stopped component can leave a thread spinning. | Neither happens. |
| Data before its template | Held without limit. | Capped at 10 000 records and about 32 MiB per store, oldest dropped first. The 120-second replay rule is unchanged. |
| Template map | No limit and no expiry; spoofed datagrams can fill memory with templates (279 MiB from 200 datagrams). | About 32 MiB of templates per store (IPFIX, NetFlow v9). Past that, the template defined longest ago is dropped and counted in `template_store_evicted`. A normal deployment uses a few MiB, so nothing is dropped. |
| Template replay | Other NetFlow v9 datagrams wait while data held for a new template is decoded and sent. | They do not wait. |
| `IN_BYTES` or `FLOWS` with an odd width | The whole process crashes on an exporter's template. | Treated as malformed; no crash. |
| Padding after the last template in a template set | Read as another template, which also misreads the sets that follow. | Skipped; parsing continues at the set boundary. A template whose field list runs past its set is not learned. |
| Byte counts in other fields than IE 1 | Only `octetDeltaCount`/`IN_BYTES` (IE 1) is read, so Cisco ASA (NSEL `initiatorOctets`, IE 231) and exporters sending only `octetTotalCount` (IE 85) upload 0 bytes. | IE 231, then IE 85, is used when IE 1 is absent, at any width from 1 to 8 bytes. `responderOctets` (IE 232) waits for bidirectional byte counts. |
| Variable-length fields (IPFIX and NetFlow v9) | A variable-length field is treated as longer than the rest of the datagram: the record is sent with only the fields before it, and the rest of the message is lost. NetScaler, YAF, Procera/Sandvine, Barracuda, Ixia, Huawei, H3C and Nokia BRAS send such fields. | The field is decoded per RFC 7011 section 7 and its value skipped, so the whole record and the rest of the message are decoded. A field running past its data set drops the rest of that set as one decode error. Templates without variable-length fields decode as before. |
| Template that consumes no bytes | Loops forever and, on replay, freezes all IPFIX parsers. | Stops at the first empty record. |
| FIRST_SWITCHED after a negative 8-byte flow start | The time wraps around to a huge positive value. | The time stays at the smallest value instead of wrapping. Both are garbage; only the overflow differs. |
| ICMP type/code in the destination port | Exporters that send ICMP type and code in the destination port instead of an ICMP field (nProbe, softflowd, Cisco IPFIX, Procera, and NetFlow v5 exporters, which have no ICMP field) have their ICMP flows dropped by the filter as "ICMP with a port". | For an ICMP or ICMPv6 record without field 32, 139 or 176 to 179, type and code are read from the port (`type * 256 + code`, or the type alone below 256) and the port is set to 0. Records with an ICMP field are unchanged; any ICMP flow still left with a port is dropped as before. |
| Sets in the last 32 bytes of an IPFIX message | Not parsed: a small template set (6 fields or fewer) or a small final data set is lost, and with a lost template all its data. | Every set header that fits is read. Fewer than 4 bytes left, or an all-zero set header, end the message without a decode error. |
| Data set with a length below 4 or past the end of the datagram | With a known template, the last partial record is sent again and again: one small datagram gives about 65 500 records and log lines. | The rest of the datagram is dropped and counted as one decode error; sets before it are decoded as usual. |
| sFlow raw header shorter than 16 bytes | Tries to allocate about 4 GiB, then fails. | Treated as a read error. |
| sFlow datagram longer than the buffer | Panic. | Clamped. |
| Text parser, random processing order | Whether numeric `protocol: 1` becomes ICMPv6 for IPv6 sources, whether `timestamp_format` sees `field_separator`, and the first discard reason all depend on random order. | Fixed order: `protocol` is read first, so `1` with an IPv6 source is always 58, and the field separator rule applies after all properties are read. |
| Text parser, timestamp spanning past the last field | Panic, process exits. | Logs `Invalid time:` and uses the current time. |
| Parser workers after their input stops | Workers spin, logging in a loop. | Workers stop. |
| Debug lines for config defaults | Logged in random order. | Logged in schema order. |

## Preserved on purpose

These look like bugs but match the original, so output and operations stay the same. They are listed so nobody is
surprised.

- No consumer started exits 1 without a message.
- `Detected https Proxy:` prints the HTTP proxy value, and the lower-case `https_proxy` variable receives the
  HTTP proxy value.
- The API key source is read twice unless the text contains `key_id` (a `$command` runs twice); for JSON keys the user
  is `auth_username` and the password is `secret`. The instance id file is used without trimming.
- Only status 204 is success for an upload. A 404 on the `/flowlink` path permanently switches to the older path.
  Each file is followed by a one-second pause.
- `aggregation_seconds` is the spread of flow times in the window. MAC addresses and prefix lengths are part of the
  record key, so identical-looking records can appear twice in one upload.
- Only one direction's bytes are counted, and bytes with an unknown direction and a zero port count as outgoing.
  This is planned to change, see [roadmap.md](roadmap.md#bidirectional-byte-counts).
- Retention minutes and the size cap are 16-bit, so `file_retention_hours` above 546 and `data_directory_size_mb`
  above 32767 misbehave. Integers that overflow their field read as 0.
- Config validation runs before defaults, the `Unable to read config file` message hides the OS error, and numbers in
  parser properties become decimal strings.
- NetFlow: the v9 header record count limits how many sets are read; options templates are ignored; v10
  on the NetFlow port is decoded as IPFIX; sFlow reports zero bytes and no sampling scaling.
- Text parser: `||` in `only_recs` is not an OR; a failed timestamp falls back
  to the current time.
- `-debug` makes processing errors fatal, so it is for test hosts only.
