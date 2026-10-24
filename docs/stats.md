# Stats

FlowPilot counts what it receives, decodes, aggregates and uploads, and reports those counts in two ways:

- **A log line.** Every `stats.interval_seconds` it logs one line, `FLOWPILOT_STATS` followed by a JSON object. This is
  on by default.
- **An HTTP endpoint.** `/healthz`, `/stats` (the same JSON) and `/metrics` (Prometheus). This is off until
  `stats.http_listen` is set.

Counting itself is always on. The settings only switch the outputs. They are listed in
[configuration.md](configuration.md#stats).

## Reading the log line

The line goes through the normal log, behind FlowPilot's own timestamp:

```
2026-10-22T14:10:00.004211+02:00 FLOWPILOT_STATS {"schema":"flowpilot.stats/v1","time":"2026-10-22T12:10:00Z",...}
```

To print the last one as formatted JSON:

```
journalctl -u flowpilot -o cat | grep ' FLOWPILOT_STATS ' | tail -n 1 | sed 's/^[^ ]* FLOWPILOT_STATS //' | jq .
```

Or just the status and the flows per collector:

```
journalctl -u flowpilot -o cat | grep ' FLOWPILOT_STATS ' | tail -n 1 | sed 's/^[^ ]* FLOWPILOT_STATS //' \
  | jq '{status, collectors: [.collectors[] | {name, flows_decoded, flows_forwarded}]}'
```

The log line lists, per collector, at most 50 exporters: the 50 that sent the most flows since the previous line.
`exporters_omitted` gives the number left out. `/stats` always lists every exporter.

With many collectors and exporters a line can grow past 16 KiB. Docker's default `json-file` log driver splits log
lines longer than 16 KiB into several parts, and some log shippers do not join them again, so the JSON arrives cut in
pieces. Where that matters, read `/stats` instead: it is always one complete object.

The existing per-collector metrics lines (`meter <name>`, see
[operations.md](operations.md#metrics-lines)) are still printed. Set `stats.legacy_metrics: false` to turn them off.

## Conventions

- Field names are snake_case.
- Times are RFC 3339 in UTC, to the second, for example `2026-10-22T12:09:59Z`. A time that has not happened yet (no
  upload so far, for example) is `null`.
- Counters are totals since the process started. They start again at 0 after a restart. To get a rate, subtract two
  readings.
- Rates are per second.
- The object carries `"schema": "flowpilot.stats/v1"`. Fields may be added within `v1`. A field will not be renamed
  or have its meaning changed without a new schema name.

## Status

`status` is one of:

| Status | Meaning |
|---|---|
| `starting` | Less than one stats interval (`stats.interval_seconds`) has passed since the start. |
| `upload_failing` | Uploads have failed, with no success in between, for longer than one aggregation window (`aggregation_minutes`). |
| `no_flows` | No flow was decoded for `stats.idle_warn_seconds` (default 300). The time is counted from the last flow, or from the start if there has been no flow yet. |
| `ok` | None of the above: flows arrive and the last upload attempt, if any, succeeded or has not been failing for long. |

The rules are checked in this order, so `upload_failing` beats `no_flows`. "Decoded" means a datagram that carried at
least one flow record. Records the filter then drops still count, so a collector that receives only filtered traffic
is `ok`, not `no_flows`. Check `flows_forwarded` for that case.

## HTTP endpoint

Set `stats.http_listen` (or `FLOWPILOT_STATS_HTTP_LISTEN`) to a literal `ip:port`, for example `127.0.0.1:9180` to
listen on the loopback interface only, or `0.0.0.0:9180` to listen on all IPv4 interfaces (`[::]:9180` for IPv6).
Host names such as `localhost:9180` are rejected by the config check. The address is bound at start-up, before any
collector starts. If that fails (the port is in use, or the address is not on this host), FlowPilot logs
`Error: stats HTTP endpoint <addr>: <error>` and exits 1.

The endpoint has no authentication and no TLS. Bind it to the loopback interface or a management network, or put a
firewall in front of it. It reveals exporter addresses and flow counts, but no credentials.

Only `GET` is answered:

| Path | Response |
|---|---|
| `/healthz` | `200` with `{"status":"<status>"}` (the status above) while the process and its core threads run. `503` with `{"status":"unhealthy","reason":"..."}` if one has stopped. |
| `/stats` | `200`, `application/json`: the full object, with every exporter. |
| `/metrics` | `200`, `text/plain; version=0.0.4`: the same data in the Prometheus text format. |
| other paths | `404` |
| other methods | `405` |

Each response closes the connection (`Connection: close`). A query string is ignored.

### What /healthz checks

`/healthz` is meant for a container or service supervisor (plugger, Docker, Kubernetes) that restarts the process
when the check fails. It answers `503` with `{"status":"unhealthy",...}` only when restarting can help:

- a core thread has ended outside shutdown, by returning or by a panic. Core threads are the aggregator, the parser
  workers, the UDP readers and the window loop. The `reason` names them, for example
  `core thread ended: udp reader`;
- the window loop has not run for longer than twice `aggregation_minutes` plus 60 seconds, for example
  `aggregation loop stalled: last heartbeat 1300 s ago`.

It does **not** fail for `no_flows` or `upload_failing`. Those are usually caused outside FlowPilot: an exporter that
stopped sending, a firewall, a PCE that cannot be reached, or a wrong API key. A restart fixes none of them. A restart
would also throw away the current aggregation window and drop flows while the process starts again. Watch `status` in
the body (or `flowpilot_status` in `/metrics`) to alert on those conditions instead.

### Limits

A slow or silent client cannot hold up flow collection:

- each connection is closed at the latest 5 seconds after it was accepted, reading the request and writing the answer
  included. This is a bound on the whole request, not on each read: a client that sends nothing, or trickles a byte at
  a time, is disconnected after 5 seconds;
- at most 8 connections are served at once. While all 8 are busy, a new connection is answered at once with `503` and
  the body `{"status":"busy"}`, then closed. This `503` means the endpoint is busy, not that FlowPilot is unhealthy
  (that body is `{"status":"unhealthy","reason":"..."}`); a supervisor that probes `/healthz` should retry rather than
  restart on `busy`. Because of the 5 second bound, slots free up within 5 seconds;
- the request head (request line and headers) may be at most 8 KiB, otherwise the answer is `431`;
- the answer is built before it is written, so no lock that the collectors use is held while a client reads.

## Fields

### Process

| Field | Unit | Meaning |
|---|---|---|
| `schema` | | Always `flowpilot.stats/v1`. |
| `time` | time | When this object was made. |
| `version` | | FlowPilot version. |
| `started_at` | time | Process start. |
| `uptime_seconds` | seconds | `time` − `started_at`. |
| `instance_id` | | The instance id kept in the data directory. The same id goes into the uploaded files. |
| `status` | | See [Status](#status). |
| `last_flow_at` | time | The last datagram that carried flow records, on any collector. `null` if none yet. |

### `collectors[]`

One entry per consumer in the configuration, in config order.

| Field | Unit | Meaning |
|---|---|---|
| `name` | | Consumer name. |
| `parser` | | Parser type: `netflow`, `ipfix`, `sflow` or `text`. |
| `datagrams` | count | UDP datagrams accepted, after the `remote_addrs` check. |
| `bytes` | bytes | Payload bytes of those datagrams. |
| `flows_decoded` | count | Flow records the parser handed to the flow filter. This counts the same way for all parsers: NetFlow/IPFIX data records, sFlow flow records, text lines that parsed as flows. For sFlow it can differ from the `count` of the old metrics line, which counts the records the samples declare. |
| `flows_forwarded` | count | Flows that passed the filter and went on to aggregation. |
| `flows_dropped.empty_address` | count | Flows dropped because the source or destination address or the IP version is missing. |
| `flows_dropped.special_address` | count | Flows dropped for a special source or destination address, such as multicast. |
| `flows_dropped.ipv6_extension` | count | IPv6 flows dropped for protocol 0, 43 or 44 (extension headers). |
| `flows_dropped.icmp_with_port` | count | ICMP and ICMPv6 flows dropped because they carry a destination port. A NetFlow/IPFIX record without an ICMP type/code field has them taken from the port first (see [collectors.md](collectors.md)), so this counts records whose ICMP field and port disagree, such as Cisco ASA, and text input. |
| `decode_errors` | count | Failure points, not datagrams: each error found while decoding counts once, and so does a datagram of an unknown version. A text datagram with 3 bad lines counts 3. |
| `rejected_datagrams` | count | Datagrams from senders not in `remote_addrs`. They are counted here only: rejected senders get no exporter row, so they cannot push real exporters out of the table. |
| `templates` | count | Templates known for this collector's exporters. Only for `netflow` and `ipfix` collectors, 0 for the others. |
| `waiting_for_template` | count | Data sets from this collector's exporters waiting for their template. |
| `template_store_evicted` | count | Data sets dropped from the template wait store (10 000 data sets or about 32 MiB per store) plus templates dropped by the template memory cap (about 32 MiB per store), since the start. A normal deployment never reaches the template cap. The NetFlow and IPFIX stores are shared by the whole process, so this is a process-wide figure: every `netflow` and `ipfix` collector shows the same number. Do not add it up across collectors. |
| `rate.m1`, `rate.m5`, `rate.m15` | flows/s | Moving averages over 1, 5 and 15 minutes from the meter behind the old metrics line, so they count what that line counts (for sFlow, declared records). |
| `exporters[]` | | See below. |
| `exporters_omitted` | count | Exporters left out by the 50-exporter limit of the log line. Always 0 in `/stats`. |

### `collectors[].exporters[]`

One entry per exporter (source address of the datagrams) of the collector. At most 10 000 exporters are kept per
collector; when the table is full the one seen least recently is dropped. An exporter that has sent nothing for 24
hours is dropped. In the log line the list is ordered by flows since the previous line; in `/stats`, by flows since
the start.

| Field | Unit | Meaning |
|---|---|---|
| `address` | | Source IP of the datagrams. IPv6 addresses are written without brackets, for example `2001:db8::1`. |
| `protocols` | | Protocols and versions seen, in the order first seen: `netflow_v5`, `netflow_v7`, `netflow_v9`, `ipfix`, `sflow`, `text`. |
| `datagrams` | count | Datagrams from this exporter. |
| `flows` | count | Flow records decoded from them (as `flows_decoded`). |
| `decode_errors` | count | Decode failure points in its datagrams (as `decode_errors`). |
| `first_seen`, `last_seen` | time | First and last datagram. A dropped and later returning exporter starts again. |
| `flows_per_second` | flows/s | Flows in the last complete UTC minute, divided by 60. |
| `templates` | count | Templates known for this exporter (NetFlow and IPFIX stores added together). |
| `waiting_for_template` | count | Its data sets waiting for their template. |

### `aggregation`

| Field | Unit | Meaning |
|---|---|---|
| `window_flows` | count | Flow records merged into the current window so far. |
| `window_keys` | count | Distinct aggregation keys in the current window, which is the number of records the window will produce. |
| `last_flush_at` | time | End of the last window. `null` before the first one. |
| `last_window_records` | count | Aggregated records the last window produced. |
| `last_window_new_ips` | count | IPs seen for the first time in the last window (the `Following new IP addresses` log line). |

### `uploads`

| Field | Unit | Meaning |
|---|---|---|
| `succeeded` | count | Files the PCE accepted. |
| `failed` | count by kind | Failed attempts, by HTTP status (`"503"`) or `"error"` when there was no response. Each retry counts. |
| `records_uploaded` | count | Records in the accepted files. Files left over from an earlier run count 0, because their record count is not known. |
| `last_success_at` | time | Last accepted upload. |
| `last_error` | | Status line or transport error of the last failure. Credentials in a URL are replaced by `***`, and headers are never included. |
| `last_error_at` | time | Last failure. |
| `first_failure_since_success_at` | time | First failure after the last success. `null` while uploads succeed. Drives `upload_failing`. |
| `removed_by_size_cap` | count | Files deleted unsent to keep `data_directory_size_mb`. |
| `removed_by_retention` | count | Files deleted unsent because they were older than `file_retention_hours`. |
| `queued_files` | count | Files waiting in the data directory, queued or being sent. |
| `queued_bytes` | bytes | Their size. |

### `unmanaged_workloads`

`null` when [unmanaged workloads](unmanaged-workloads.md) are off.

| Field | Unit | Meaning |
|---|---|---|
| `dry_run` | | `true` in dry run. |
| `known_ips` | count | IPs that have a workload on the PCE: the last refresh, plus the workloads created since. |
| `last_refresh_at` | time | Last attempt to load the workload list. At start, the time of the saved list. |
| `last_refresh_ok` | | Whether that attempt succeeded. `null` before the first. |
| `last_window.candidates` | count | IPs inside the networks being counted in the last window. |
| `last_window.eligible` | count | IPs that had reached `min_flows`. |
| `last_window.created` | count | Workloads created. 0 in dry run. |
| `last_window.deferred` | count | Eligible IPs held back by a cap. |
| `last_window.errors` | count | Errors in the window. |
| `last_window.labels_created` | count | Label values created. |
| `created_total` | count | Workloads created since the start. |
| `created_today` | count | Creations in the last 24 hours, which is what `max_creates_per_day` is checked against. Creations that failed in a way that might still have created the workload count too. |
| `would_create_total` | count | Dry run: IPs listed as "would create", summed over windows. An IP that stays eligible for 3 windows counts 3. |
| `deferred_total` | count | Eligible IPs deferred by a cap, summed over windows. An IP deferred in 3 windows counts 3. |
| `failed_total` | count | Errors summed over windows: failed PCE calls and creations, and also failed refreshes and failed saves of the state files. |
| `daily_cap` | count | `max_creates_per_day`. |
| `per_window_cap` | count | `max_creates_per_window`. |
| `burst_paused_since` | time | When the current burst pause started. `null` when there is none. |
| `disabled_reason` | | Why creation is disabled (a label rule uses a label type the PCE lacks). `null` otherwise. |

## Prometheus metrics

`/metrics` renders the same object. All names start with `flowpilot_`. Counters end in `_total`. Times are gauges in
Unix seconds (`_timestamp_seconds`). A series whose value is `null` in the JSON is left out. Collector series have a
`collector` label, and exporter series have `collector` and `exporter` labels.

| Metric | Type | Labels | JSON field |
|---|---|---|---|
| `flowpilot_info` | gauge (1) | `version`, `instance_id` | `version`, `instance_id` |
| `flowpilot_start_time_seconds` | gauge | | `started_at` |
| `flowpilot_uptime_seconds` | gauge | | `uptime_seconds` |
| `flowpilot_status` | gauge (1 or 0) | `status` (all four values) | `status` |
| `flowpilot_last_flow_timestamp_seconds` | gauge | | `last_flow_at` |
| `flowpilot_collector_info` | gauge (1) | `collector`, `parser` | `parser` |
| `flowpilot_datagrams_total` | counter | `collector` | `datagrams` |
| `flowpilot_received_bytes_total` | counter | `collector` | `bytes` |
| `flowpilot_flows_decoded_total` | counter | `collector` | `flows_decoded` |
| `flowpilot_flows_forwarded_total` | counter | `collector` | `flows_forwarded` |
| `flowpilot_flows_dropped_total` | counter | `collector`, `reason` | `flows_dropped.*` |
| `flowpilot_decode_errors_total` | counter | `collector` | `decode_errors` |
| `flowpilot_rejected_datagrams_total` | counter | `collector` | `rejected_datagrams` |
| `flowpilot_templates` | gauge | `collector` | `templates` |
| `flowpilot_waiting_for_template` | gauge | `collector` | `waiting_for_template` |
| `flowpilot_template_store_evicted_total` | counter | `collector` | `template_store_evicted` (process-wide) |
| `flowpilot_flows_per_second` | gauge | `collector`, `window` (`1m`, `5m`, `15m`) | `rate.*` |
| `flowpilot_exporters` | gauge | `collector` | number of exporters tracked |
| `flowpilot_exporter_protocol_info` | gauge (1) | `collector`, `exporter`, `protocol` | `protocols` |
| `flowpilot_exporter_datagrams_total` | counter | `collector`, `exporter` | `datagrams` |
| `flowpilot_exporter_flows_total` | counter | `collector`, `exporter` | `flows` |
| `flowpilot_exporter_decode_errors_total` | counter | `collector`, `exporter` | `decode_errors` |
| `flowpilot_exporter_first_seen_timestamp_seconds` | gauge | `collector`, `exporter` | `first_seen` |
| `flowpilot_exporter_last_seen_timestamp_seconds` | gauge | `collector`, `exporter` | `last_seen` |
| `flowpilot_exporter_flows_per_second` | gauge | `collector`, `exporter` | `flows_per_second` |
| `flowpilot_exporter_templates` | gauge | `collector`, `exporter` | `templates` |
| `flowpilot_exporter_waiting_for_template` | gauge | `collector`, `exporter` | `waiting_for_template` |
| `flowpilot_aggregation_window_flows` | gauge | | `aggregation.window_flows` |
| `flowpilot_aggregation_window_keys` | gauge | | `aggregation.window_keys` |
| `flowpilot_aggregation_last_flush_timestamp_seconds` | gauge | | `aggregation.last_flush_at` |
| `flowpilot_aggregation_last_window_records` | gauge | | `aggregation.last_window_records` |
| `flowpilot_aggregation_last_window_new_ips` | gauge | | `aggregation.last_window_new_ips` |
| `flowpilot_uploads_succeeded_total` | counter | | `uploads.succeeded` |
| `flowpilot_uploads_failed_total` | counter | `kind` | `uploads.failed` |
| `flowpilot_uploaded_records_total` | counter | | `uploads.records_uploaded` |
| `flowpilot_upload_last_success_timestamp_seconds` | gauge | | `uploads.last_success_at` |
| `flowpilot_upload_last_error_timestamp_seconds` | gauge | | `uploads.last_error_at` |
| `flowpilot_upload_failing_since_timestamp_seconds` | gauge | | `uploads.first_failure_since_success_at` |
| `flowpilot_upload_files_removed_total` | counter | `reason` (`size_cap`, `retention`) | `uploads.removed_by_*` |
| `flowpilot_upload_queued_files` | gauge | | `uploads.queued_files` |
| `flowpilot_upload_queued_bytes` | gauge | | `uploads.queued_bytes` |
| `flowpilot_unmanaged_dry_run` | gauge (1 or 0) | | `unmanaged_workloads.dry_run` |
| `flowpilot_unmanaged_known_ips` | gauge | | `known_ips` |
| `flowpilot_unmanaged_last_refresh_timestamp_seconds` | gauge | | `last_refresh_at` |
| `flowpilot_unmanaged_last_refresh_ok` | gauge (1 or 0) | | `last_refresh_ok` |
| `flowpilot_unmanaged_last_window` | gauge | `count` (`candidates`, `eligible`, `created`, `deferred`, `errors`, `labels_created`) | `last_window.*` |
| `flowpilot_unmanaged_created_total` | counter | | `created_total` |
| `flowpilot_unmanaged_created_today` | gauge | | `created_today` |
| `flowpilot_unmanaged_would_create_total` | counter | | `would_create_total` |
| `flowpilot_unmanaged_deferred_total` | counter | | `deferred_total` |
| `flowpilot_unmanaged_failed_total` | counter | | `failed_total` |
| `flowpilot_unmanaged_daily_cap` | gauge | | `daily_cap` |
| `flowpilot_unmanaged_per_window_cap` | gauge | | `per_window_cap` |
| `flowpilot_unmanaged_burst_paused` | gauge (1 or 0) | | `burst_paused_since` is set |
| `flowpilot_unmanaged_disabled` | gauge (1 or 0) | | `disabled_reason` is set |

The `flowpilot_unmanaged_*` metrics are left out when unmanaged workloads are off. `last_error` and
`disabled_reason` are text and appear only in the JSON.

Example alerts: `flowpilot_status{status="upload_failing"} == 1`, or
`rate(flowpilot_flows_forwarded_total[10m]) == 0` for a collector that stopped getting usable flows.

A scrape configuration:

```yaml
scrape_configs:
  - job_name: flowpilot
    static_configs:
      - targets: ["flowpilot-host:9180"]
```

## Example

A full object, from a collector with one NetFlow consumer, an IPv4 and an IPv6 exporter, and unmanaged workloads on.
The log line carries the same object on one line.

```json
{
  "schema": "flowpilot.stats/v1",
  "time": "2026-10-22T12:10:00Z",
  "version": "0.9.0",
  "started_at": "2026-10-22T08:00:00Z",
  "uptime_seconds": 15000,
  "instance_id": "3f2c9a1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b",
  "status": "ok",
  "last_flow_at": "2026-10-22T12:09:59Z",
  "collectors": [
    {
      "name": "netflow-dc1",
      "parser": "netflow",
      "datagrams": 182340,
      "bytes": 255276000,
      "flows_decoded": 5470200,
      "flows_forwarded": 5401876,
      "flows_dropped": {
        "empty_address": 12,
        "special_address": 68210,
        "ipv6_extension": 0,
        "icmp_with_port": 102
      },
      "decode_errors": 3,
      "rejected_datagrams": 41,
      "templates": 4,
      "waiting_for_template": 0,
      "template_store_evicted": 0,
      "rate": { "m1": 364.8, "m5": 361.2, "m15": 358.9 },
      "exporters": [
        {
          "address": "10.1.0.1",
          "protocols": ["netflow_v9"],
          "datagrams": 121560,
          "flows": 3646800,
          "decode_errors": 0,
          "first_seen": "2026-10-22T08:00:03Z",
          "last_seen": "2026-10-22T12:09:59Z",
          "flows_per_second": 243.2,
          "templates": 2,
          "waiting_for_template": 0
        },
        {
          "address": "2001:db8::1",
          "protocols": ["ipfix"],
          "datagrams": 60780,
          "flows": 1823400,
          "decode_errors": 3,
          "first_seen": "2026-10-22T08:00:05Z",
          "last_seen": "2026-10-22T12:09:58Z",
          "flows_per_second": 121.6,
          "templates": 2,
          "waiting_for_template": 0
        }
      ],
      "exporters_omitted": 0
    }
  ],
  "aggregation": {
    "window_flows": 218004,
    "window_keys": 9120,
    "last_flush_at": "2026-10-22T12:00:00Z",
    "last_window_records": 9875,
    "last_window_new_ips": 4
  },
  "uploads": {
    "succeeded": 25,
    "failed": { "503": 1 },
    "records_uploaded": 241800,
    "last_success_at": "2026-10-22T12:00:02Z",
    "last_error": "HTTP 503 Service Unavailable",
    "last_error_at": "2026-10-22T09:30:01Z",
    "first_failure_since_success_at": null,
    "removed_by_size_cap": 0,
    "removed_by_retention": 0,
    "queued_files": 0,
    "queued_bytes": 0
  },
  "unmanaged_workloads": {
    "dry_run": false,
    "known_ips": 1840,
    "last_refresh_at": "2026-10-22T12:00:05Z",
    "last_refresh_ok": true,
    "last_window": {
      "candidates": 6,
      "eligible": 2,
      "created": 2,
      "deferred": 0,
      "errors": 0,
      "labels_created": 0
    },
    "created_total": 31,
    "created_today": 9,
    "would_create_total": 0,
    "deferred_total": 0,
    "failed_total": 0,
    "daily_cap": 100,
    "per_window_cap": 20,
    "burst_paused_since": null,
    "disabled_reason": null
  }
}
```
