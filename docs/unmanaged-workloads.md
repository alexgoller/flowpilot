# Unmanaged workloads

FlowPilot can create unmanaged workloads in the PCE for busy internal IPs. Without a workload, such an IP shows up
as an unknown IP in Explorer and on the traffic map, and you cannot write policy for it.

The feature is off by default. When it is on, FlowPilot counts flows per IP, and once an IP inside your networks has
enough flows it creates a workload with:

- the IP as the name, and the reverse DNS name as the hostname when there is one;
- labels from your label rules (missing label values are created);
- `external_data_set` set to `flowpilot` and `external_data_reference` set to the IP, so you can find the workloads
  again.

FlowPilot only creates. It never updates or deletes workloads, and it never creates label types (the `role`, `app`,
`env`, `loc` kind of thing). Only IPv4 is supported. Flow collection and upload never wait for this feature: a slow or
failing PCE API or DNS server is logged and retried in the next window.

A config that uses `unmanaged_workloads` cannot be loaded by the original Go FlowLink.

## Configuration

Add a top-level `unmanaged_workloads` key to the config. All values shown are the defaults, except `label_rules`.

```yaml
unmanaged_workloads:
  enabled: false
  dry_run: false
  networks: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
  exclude_networks: []
  allow_broad_networks: false
  min_flows: 10
  flow_window_hours: 24
  max_creates_per_window: 100
  max_creates_per_day: 500
  refresh_hours: 24
  external_data_set: flowpilot
  # api_key: "$/usr/local/bin/get-pce-key"
  dns:
    enabled: true
    servers: []
    timeout_ms: 2000
    concurrency: 8
  label_rules:
    - cidr: 10.0.0.0/8
      labels: { loc: dc1 }
    - cidr: 10.20.0.0/16
      labels: { env: prod, app: billing }
```

| Key | Meaning |
|---|---|
| `enabled` | Turns the feature on. |
| `dry_run` | Does everything except write to the PCE. See [Dry run](#dry-run). |
| `networks` | Only IPs inside these networks are candidates. |
| `exclude_networks` | IPs inside these are never candidates, even when inside `networks`. |
| `allow_broad_networks` | Allows a network or label CIDR broader than /8. |
| `min_flows` | Flows an IP needs within `flow_window_hours` before it gets a workload. Each flow counts for both its source and its destination IP. |
| `flow_window_hours` | The sliding window the flows are counted over. Counts survive a restart. |
| `max_creates_per_window` | Most workloads created per aggregation window. |
| `max_creates_per_day` | Most workloads created in any rolling 24 hours. |
| `refresh_hours` | How often the known workload IPs and labels are reloaded from the PCE. |
| `external_data_set` | Value set on every created workload. |
| `api_key` | Optional API key for this feature only, in the same formats as the main `api_key` (file, `$<command>`, and so on). The default is the main `api_key`. |
| `dns.enabled` | Look up the hostname by reverse DNS. |
| `dns.servers` | DNS servers to ask. Empty means the system resolver. |
| `dns.timeout_ms` | Timeout per lookup. |
| `dns.concurrency` | Lookups in parallel. |
| `label_rules` | CIDR to labels rules, see below. |

The PCE host, org and proxy settings are the same as for the flow upload.

### Validation

FlowPilot refuses to start, with a message naming the key, when:

- a CIDR is invalid or IPv6;
- a CIDR is broader than /8 and `allow_broad_networks` is not true;
- `min_flows` is below 1;
- `flow_window_hours` is shorter than one aggregation window (`flow_window_hours x 60 < aggregation_minutes`);
- `max_creates_per_window` is not between 1 and 1000;
- `max_creates_per_day` is below `max_creates_per_window`;
- a label rule has no labels;
- `refresh_hours`, `dns.timeout_ms` or `dns.concurrency` is below 1, or a `dns.servers` entry is not an IP address.

### Label rules

Every rule whose CIDR contains the IP applies. For each label type, the value from the most specific rule (longest
prefix) wins, and broader rules fill the types the specific ones leave out. If two rules have the same prefix length,
the one listed first wins. An IP that matches no rule gets no labels.

With the example above, 10.20.1.5 gets `loc=dc1`, `env=prod` and `app=billing`.

Label values that do not exist yet are created once and cached. A label type that does not exist in the PCE is never
created: FlowPilot logs one error naming the rule and the type, and creates no workloads until you fix the rule and
restart. Flow collection carries on.

## What gets created

For each IP that qualifies, one workload:

| Field | Value |
|---|---|
| `name` | the IP |
| `hostname` | reverse DNS name, without the trailing dot. Left out when there is none |
| `interfaces` | `[{"name": "umw0", "address": "<ip>"}]` |
| `labels` | from the label rules |
| `external_data_set` | `external_data_set` from the config |
| `external_data_reference` | the IP |

An IP qualifies when it is inside `networks`, not inside `exclude_networks`, has no workload in the PCE yet (whoever
created that workload, on any interface), and has reached `min_flows` within `flow_window_hours`.

Reverse DNS is asked only for IPs about to be created. If several names come back, the first is used. A name that is
just the IP is ignored, and a failed or timed-out lookup means no hostname; the workload is still created. The
hostname is set at creation and never updated.

## Safety limits

- **Per window.** At most `max_creates_per_window` workloads are created per aggregation window. The rest are
  deferred to the next window, busiest first.
- **Per day.** At most `max_creates_per_day` workloads in any rolling 24 hours, also across restarts. When the cap is
  reached, creation waits until it frees up and one warning is logged.
- **Burst pause.** If more IPs become eligible in a single window than `max_creates_per_day`, nothing is created that
  window and a warning names the networks involved. Only IPs that reach `min_flows` in that window count; IPs that were
  already eligible and are waiting for the caps do not, so a backlog drains through the caps without pausing. A burst
  means a network is likely misconfigured. Fix `networks` or `exclude_networks`.
- **Broad networks.** A network or label CIDR broader than /8 (for example `0.0.0.0/0`) is refused at startup unless
  `allow_broad_networks: true`.
- **No creation without a known set.** Nothing is created until the existing workload IPs have been loaded from the PCE
  (or a saved list younger than `refresh_hours` has been read). If a later refresh fails, the last list loaded by the
  running FlowPilot is used for up to twice `refresh_hours`; after that creation pauses until a refresh succeeds. A
  list stamped in the future (the clock moved back) is never trusted.
- **Clock changes.** Creation times in the future still count toward the daily cap, so moving the clock back does not
  free it.
- **Shutdown.** The last window, and any window still queued, is counted when FlowPilot stops, but nothing is created.

## Dry run

With `dry_run: true`, FlowPilot counts, resolves DNS and reads from the PCE, but writes nothing. Each IP it would
create is logged:

```
Unmanaged workloads (dry run): would create workload 10.20.1.5 hostname=app01.example.com labels=app=billing,env=prod,loc=dc1
```

Dry-run IPs are not remembered, so switching `dry_run` off creates them.

## Log lines

Every line starts with `Unmanaged workloads`. After each aggregation window there is one summary line:

```
Unmanaged workloads: 37 candidates, 4 eligible, 4 created, 0 deferred, 3/4 resolved, 1 label created, 0 errors
```

Candidates are IPs inside your networks that FlowPilot is counting. Eligible have reached `min_flows`. Deferred were
eligible but held back by a cap. Resolved is hostnames found out of lookups made.

## PCE access

The API key needs permission to read labels, create labels, read workloads and create workloads. If the PCE answers
401 or 403, FlowPilot logs once per window which permission is missing, for example `the API key needs permission to
create workloads`. Flow uploads are not affected, and the call is tried again in the next window.

What FlowPilot asks the PCE:

- At startup and then every `refresh_hours`: the label types, all labels and all workload IPs (as asynchronous
  exports, so large orgs are not cut off).
- Per window: a check for each IP about to be created, `GET /workloads?ip_address=<ip>`, because other tools may have
  created a workload since the last load. An IP that already has one is skipped. This costs at most
  `max_creates_per_window` requests per window and never grows with flow volume.
- Then any missing labels (`POST /labels`) and one `PUT /workloads/bulk_create` per 1000 workloads.

If a pre-create check fails, nothing is created in that window. 429 and 5xx answers are retried in the next window.

State is kept in the data directory, as `<pce_addr>-org<org>-uw_known.json` (known IPs, creation times) and
`<pce_addr>-org<org>-uw_candidates.json` (flow counts). A damaged file is logged and ignored. The known list is saved
right after each create call, so an unclean stop does not lose the daily cap.

Flow counts are kept in hourly buckets: memory and the candidates file hold about one entry per unknown internal IP
per hour of `flow_window_hours`. Because of the buckets, the effective window can be up to `flow_window_hours + 1`
hours.

## Several collectors on one PCE

If several FlowPilot instances feed the same PCE, give them all the same `external_data_set`. The PCE refuses a second
workload with the same `external_data_set` and `external_data_reference` (the IP), so that also blocks duplicates
between collectors, even when two of them pick the same IP at the same time.

## Finding and removing the created workloads

All workloads FlowPilot creates have `external_data_set` set (default `flowpilot`) and `external_data_reference` set to
the IP.

List them through the API:

```
GET /api/v2/orgs/<org>/workloads?external_data_set=flowpilot
```

To remove them, delete those workloads in the PCE, or with `DELETE /api/v2/orgs/<org>/workloads/<uuid>` for each one
returned by the list above. FlowPilot itself never deletes.

What happens to a deleted IP that still has traffic has not been verified yet. The PCE keeps a deleted workload as a
tombstone (`"deleted": true`), and that tombstone may keep its `external_data_reference` reserved. So after the next
refresh (`refresh_hours`) one of two things happens:

- the PCE accepts a new workload with the same reference, and FlowPilot creates a new workload for the IP; or
- the PCE reports the reference as already used, FlowPilot treats the IP as known, and it never creates it again.

To be sure an IP is not created again, add it or its network to `exclude_networks`, or set `enabled: false`.

Use a different `external_data_set` (for example `flowpilot-test`) for trial runs, so test workloads are easy to find
and remove.
