# Configuration reference

The config is one YAML file. Its path comes from the environment variable `CONFIG_FILE`; there is no command line
option for it. The keys are those of FlowLink 2.0.1-2, plus the new top-level keys `unmanaged_workloads` and `stats` and the new key `pce_kafka.gateway`. All settings can also be given as
[environment variables](#environment-variables).

`flowpilot install` writes `/etc/flowpilot/config.yaml` and the key file `/etc/flowpilot/api_key` for you, from the
wizard's answers or from flags (see [operations.md](operations.md#installing)). The installed service starts with
`CONFIG_FILE=/etc/flowpilot/config.yaml` and `api_key` pointing at that key file. The file is the installer's: with
`--reconfigure`, or an unattended run with different answers, the old file is saved as
`config.yaml.<timestamp>.bak` and the new one is written whole. Comments and hand edits are not carried over. An
upgrade without answers leaves the file as it is. After a hand edit, run `systemctl restart flowpilot`; a re-run of
`install` with no answers keeps your edit.

```
CONFIG_FILE=/etc/flowpilot/config.yaml ./flowpilot
```

A relative `CONFIG_FILE`, `data_directory` or `api_key` file path is resolved against the working directory of the
process. Use absolute paths in a service.

## How the file is checked

1. The file is read. If `CONFIG_FILE` is unset or empty, FlowPilot logs `No config file provided` and exits with
   status 1 (unless `FLOWPILOT_*` variables build the configuration, see [Environment variables](#environment-variables)). If the file cannot be read it logs `Unable to read config file: <absolute path>` (without the OS error)
   and exits 1. An empty file gives `Config file: <absolute path> is empty.`
2. Only the first YAML document is used. The file is parsed as YAML 1.2, so `yes`, `no` and `on` are strings, and a
   duplicate key is an error. Anchors and merge keys (`<<`) work.
3. The document is validated, as written, against a JSON schema (draft 4). The schema is FlowPilot's own
   (`src/config_schema.json`). It accepts the same configs as FlowLink, plus the new keys `unmanaged_workloads` and
   `stats`. Top-level keys that are not in the schema are rejected. Validation errors
   are logged and the process exits 1:

   ```
   The FlowPilot configuration file is not valid. see errors :
   	- [aggregation_minutes: Must be greater than or equal to 5]
   	- [consumers.0.connectors.0.properties.ports: Invalid type. Expected: string, given: integer]
   ```

   Field names are paths such as `consumers.0.connectors.0.properties`. The wording is close to the original's but not
   guaranteed identical, and the order of the lines can differ. See
   [differences-from-flowlink.md](differences-from-flowlink.md).
4. Defaults are filled in for keys that are absent. Explicit values are never clamped.
5. `unmanaged_workloads` gets its own checks (see [Unmanaged workloads](#unmanaged_workloads)).
6. `data_directory` must exist and be writable by the process (an `access(2)` check). FlowPilot does not create it (a directory from `FLOWPILOT_DATA_DIRECTORY` or the default is created, see below).
   Otherwise: `Data directory: <absolute path> is not writable.` and exit 1.

Because validation runs on the raw file, a value that violates its range is an error even when a default would exist.

### Number handling

Integer keys must be YAML integers (`10`, not `"10"`; `10.0` is accepted). `aggregation_minutes`,
`data_directory_size_mb`, `file_retention_hours` and `metrics_print_seconds` are stored in 16 bits, and `org_id` in
32 bits. A value that does not fit is silently read as `0`. The schema has no maximum for some of these, so see the
notes in the table.

## Environment variables

Every setting can also come from an environment variable, so a container needs no config file. The variables are
`FLOWPILOT_*`; plugger's `PCE_*` variables are used as a fallback. [plugger](https://github.com/illumio-community/illumio-plugger), a plugin host for the Illumio PCE, passes `PCE_*` variables to plugins.

### Precedence

1. If `CONFIG_FILE` is set, the file is read as described above.
2. `FLOWPILOT_*` variables are applied on top, setting or replacing single values. A variable always beats the file.
3. Plugger's `PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`, `PCE_API_KEY` (the API user) and `PCE_API_SECRET` only fill a value
   that neither a `FLOWPILOT_*` variable nor the file sets.
4. With no `CONFIG_FILE`, the configuration is built from the variables alone. The required settings are the same as
   for a file: PCE address, API credentials, a data directory (default below) and at least one collector.
5. With neither a file nor any `FLOWPILOT_*` variable, FlowPilot behaves as before: `No config file provided`, exit 1.
   `PCE_*` alone do not count.

Where the API credentials come from, highest first: `FLOWPILOT_API_USER` with `FLOWPILOT_API_SECRET`; then
`api_user` with `api_secret_command` (from the variables or the file); then `api_key`; then plugger's `PCE_API_KEY` and
`PCE_API_SECRET`, used only when none of the others is set.

The merged result goes through the same schema validation and checks as a file. When a rejected value came from a
variable, the error names it:

```
The FlowPilot configuration file is not valid. see errors :
	- [FLOWPILOT_ORG_ID (org_id): Must be greater than or equal to 1]
```

### Value formats

- Integers in decimal. Booleans: `true`/`false`, `1`/`0`, `yes`/`no`, case-insensitive. Anything else is an error that
  names the variable.
- Lists: comma-separated, spaces around items ignored.
- An empty variable counts as unset.
- A `FLOWPILOT_*` variable that is not one of the variables below (a misspelling such as `FLOWPILOT_NETFLOW_PORT`) is
  ignored, and the start logs `Unknown variable ignored: <NAME>` for it (never its value). `-print-config` lists the
  same lines first, as YAML comments.

### General settings

| Variable | Config key | Notes |
|---|---|---|
| `FLOWPILOT_PCE_ADDR` | `pce_addr` | Fallback: `PCE_HOST`, with `:PCE_PORT` when that is set |
| `FLOWPILOT_ORG_ID` | `org_id` | Fallback: `PCE_ORG_ID` |
| `FLOWPILOT_API_KEY` | `api_key` | Same forms as in the file: a path, or `$command` |
| `FLOWPILOT_API_USER`, `FLOWPILOT_API_SECRET` | | The credentials themselves, instead of `api_key`. Both or neither. Fallback: `PCE_API_KEY`, `PCE_API_SECRET`. If both forms are given, these win |
| `FLOWPILOT_API_USER`, `FLOWPILOT_API_SECRET_COMMAND` | `api_user`, `api_secret_command` | A command that prints the secret, instead of `api_key`. `FLOWPILOT_API_USER` pairs with either `FLOWPILOT_API_SECRET` or `FLOWPILOT_API_SECRET_COMMAND`; setting both of those is an error (`set only one of ...`). `FLOWPILOT_API_USER` alone also fills `api_user` for an `api_secret_command` in the file |
| `FLOWPILOT_VERIFY_PCE_CERT` | `verify_pce_cert` | |
| `FLOWPILOT_DATA_DIRECTORY` | `data_directory` | See the data directory rule below |
| `FLOWPILOT_DATA_DIRECTORY_SIZE_MB` | `data_directory_size_mb` | |
| `FLOWPILOT_FILE_RETENTION_HOURS` | `file_retention_hours` | |
| `FLOWPILOT_AGGREGATION_MINUTES` | `aggregation_minutes` | |
| `FLOWPILOT_MAX_FLOWS_PER_POST` | `max_flows_per_post` | |
| `FLOWPILOT_METRICS_PRINT_SECONDS` | `metrics_print_seconds` | |
| `FLOWPILOT_HTTPS_PROXY`, `FLOWPILOT_HTTP_PROXY`, `FLOWPILOT_NO_PROXY` | `proxy_config.*` | The standard `HTTP_PROXY` etc. keep working as before |

**Data directory.** Without a config file the default is `/var/lib/flowpilot`. When the directory comes from
`FLOWPILOT_DATA_DIRECTORY` or from that default and does not exist, FlowPilot creates it (with parents, mode 0750) and
logs `Created data directory: <path>`; if that fails, the usual `is not writable` error and exit 1 follow. A directory
that comes from a config file is never created.

### Collectors

One variable turns a collector on: its ports. Each defines a consumer named `netflow`, `ipfix`, `sflow` or `text` with
a UDP connector.

| Variable | Effect |
|---|---|
| `FLOWPILOT_NETFLOW_PORTS` | NetFlow collector on these UDP ports, e.g. `2055` |
| `FLOWPILOT_IPFIX_PORTS` | IPFIX collector, e.g. `4739` |
| `FLOWPILOT_SFLOW_PORTS` | sFlow collector, e.g. `6343` |
| `FLOWPILOT_TEXT_PORTS` | Text/syslog collector, e.g. `514` |
| `FLOWPILOT_<C>_REMOTE_ADDRS` | Optional, for `<C>` = `NETFLOW`, `IPFIX`, `SFLOW` or `TEXT`: only accept data from these exporters |

- `_PORTS` is a comma-separated list of ports from 0 to 65535. `_REMOTE_ADDRS` items must be IP addresses (no CIDR, no
  host names). A bad item is a configuration error that names the variable.
- **Merge, not replace.** If the file has a consumer of the same name, the variables are applied over it value by
  value. `_PORTS` and `_REMOTE_ADDRS` patch the `ports` and `remote_addrs` of that consumer's first `udp` connector (an
  error if it has none). Everything the variables do not set keeps the file's value. Other consumers are untouched.
- **Without `_PORTS`.** `_REMOTE_ADDRS` or a `FLOWPILOT_TEXT_*` variable patches the file's consumer of that name. If
  the file has none, it is an error: `FLOWPILOT_TEXT_SRC_IP is set but FLOWPILOT_TEXT_PORTS is missing`.
- Only one consumer per collector kind can be set up through variables; more need a file.

**Text parser properties.** One variable per property of the text parser, `FLOWPILOT_TEXT_<PROPERTY>`:
`SRC_IP`, `DST_IP`, `DST_PORT`, `PROTOCOL` (these four are required when `FLOWPILOT_TEXT_PORTS` is set, as in a
file), `ICMP_TYPE`, `ICMP_CODE`, `OCTETS`, `TIMESTAMP`, `TIMESTAMP_FORMAT`, `ONLY_RECS`, `FIELD_SEPARATOR`,
`ATTRIBUTE_SEPARATOR`. A value that is all digits is a field number, as when a YAML number is used; anything else is an
attribute name. The string-only properties `TIMESTAMP_FORMAT`, `ONLY_RECS`, `FIELD_SEPARATOR` and
`ATTRIBUTE_SEPARATOR` are never converted to integers. The value is not trimmed, so
`FLOWPILOT_TEXT_FIELD_SEPARATOR=" "` is a single space. Missing required properties are reported with the variable
names when the text consumer came from variables, and with the config keys otherwise.

### Unmanaged workloads

`FLOWPILOT_UNMANAGED_<KEY>` for every key of [`unmanaged_workloads`](#unmanaged_workloads), the key in upper case with
dots as underscores: `ENABLED`, `DRY_RUN`, `NETWORKS`, `EXCLUDE_NETWORKS`, `ALLOW_BROAD_NETWORKS`, `MIN_FLOWS`,
`FLOW_WINDOW_HOURS`, `MAX_CREATES_PER_WINDOW`, `MAX_CREATES_PER_DAY`, `REFRESH_HOURS`, `EXTERNAL_DATA_SET`, `API_KEY`,
`LABEL_RULES`, `DNS_ENABLED`, `DNS_SERVERS`, `DNS_TIMEOUT_MS`, `DNS_CONCURRENCY`. `NETWORKS`, `EXCLUDE_NETWORKS` and
`DNS_SERVERS` are comma-separated lists. Setting any of them adds the `unmanaged_workloads` key with the defaults for the rest; the
feature stays off unless `FLOWPILOT_UNMANAGED_ENABLED` is true.

`FLOWPILOT_UNMANAGED_LABEL_RULES` takes one of two forms:

- Compact: rules separated by `;`, each `cidr=key:value,key:value`.
  Example: `10.1.0.0/16=app:web,env:prod;10.2.0.0/24=app:db`.
- JSON: a value starting with `[` is the same array as in YAML,
  `[{"cidr":"10.1.0.0/16","labels":{"app":"web"}}]`.

### Stats

The key `stats` has the same settings as variables:

| Variable | Config key | Default |
|---|---|---|
| `FLOWPILOT_STATS_INTERVAL_SECONDS` | `stats.interval_seconds` | `metrics_print_seconds` |
| `FLOWPILOT_STATS_LOG` | `stats.log` | `true` |
| `FLOWPILOT_STATS_LEGACY_METRICS` | `stats.legacy_metrics` | `true` |
| `FLOWPILOT_STATS_HTTP_LISTEN` | `stats.http_listen` | unset (HTTP endpoint off) |
| `FLOWPILOT_STATS_IDLE_WARN_SECONDS` | `stats.idle_warn_seconds` | `300` |

`stats.http_listen` / `FLOWPILOT_STATS_HTTP_LISTEN` must be a literal `ip:port`, for example `127.0.0.1:9180` or
`0.0.0.0:9180`. Host names such as `localhost` are rejected. What the log line and the endpoint report is described in
[stats.md](stats.md).

### Seeing the effective configuration

`-print-config` loads the configuration exactly as a start would (file, variables, fallbacks), validates it, prints it
as YAML and exits 0. On an error it prints the validation lines and exits 1. It does not print the start-up banner. It has no side effects: if the data
directory comes from a variable or the default and is missing, it is not created; the `data_directory` line is marked
`(will be created at start)`.

Each value has a trailing comment with its origin: `file`, the variable name, `<VAR> (plugger)` for a fallback, or
`default`. The API secret is shown as `'********'`; an `api_key` that is a path or `$command`, and an
`api_secret_command`, are shown as given, and what they read or print never is (`-print-config` does not run them). A user and password in a proxy URL are shown as `***`
(`http://***@proxy:3128`). This is the tool for "why is it doing that".

```
$ FLOWPILOT_PCE_ADDR=pce.example:8443 FLOWPILOT_API_USER=api_1 FLOWPILOT_API_SECRET=s3cret \
  FLOWPILOT_NETFLOW_PORTS=2055 FLOWPILOT_DATA_DIRECTORY=/var/lib/flowpilot ./flowpilot -print-config
pce_addr: pce.example:8443  # FLOWPILOT_PCE_ADDR
api_user: api_1  # FLOWPILOT_API_USER
api_secret: '********'  # FLOWPILOT_API_USER
org_id: 1  # default
verify_pce_cert: true  # default
aggregation_minutes: 10  # default
data_directory: /var/lib/flowpilot  # FLOWPILOT_DATA_DIRECTORY
data_directory_size_mb: 500  # default
file_retention_hours: 24  # default
metrics_print_seconds: 60  # default
max_flows_per_post: 10000  # default
consumers:
  - name: netflow  # FLOWPILOT_NETFLOW_PORTS
    parser:
      type: netflow  # FLOWPILOT_NETFLOW_PORTS
    connectors:
      - type: udp  # FLOWPILOT_NETFLOW_PORTS
        properties:
          ports: '2055'  # FLOWPILOT_NETFLOW_PORTS
stats:
  interval_seconds: 60  # default
  log: true  # default
  legacy_metrics: true  # default
  idle_warn_seconds: 300  # default
```

## Example

```yaml
pce_addr: pce.example.com:8443
api_key: /etc/flowpilot/api_info          # or "$/usr/local/bin/get-pce-key"
org_id: 1
verify_pce_cert: true
aggregation_minutes: 10
data_directory: /var/lib/flowpilot/data
data_directory_size_mb: 500
file_retention_hours: 24
metrics_print_seconds: 60
max_flows_per_post: 10000

proxy_config:
  https_proxy: http://proxy.example.com:3128
  no_proxy: localhost,127.0.0.1

consumers:
  - name: netflow
    parser: { type: netflow }
    connectors:
      - type: udp
        properties:
          ports: "2055"
          remote_addrs: "192.0.2.10,192.0.2.11"

  - name: ipfix
    parser: { type: ipfix }
    connectors:
      - { type: udp, properties: { ports: "4739" } }

  - name: sflow
    parser: { type: sflow }
    connectors:
      - { type: udp, properties: { ports: "6343" } }

  - name: firewall-syslog
    parser:
      type: text
      properties:
        src_ip: src
        dst_ip: dst
        dst_port: dport
        protocol: proto
        timestamp: "date_time, 1"
        timestamp_format: "mmm dd yyyy HH:MM:SS"
    connectors:
      - { type: udp, properties: { ports: "6514" } }

unmanaged_workloads:
  enabled: true
  dry_run: true
  label_rules:
    - cidr: 10.20.0.0/16
      labels: { env: prod, loc: dc1 }
```

## Top-level keys

Required keys: `pce_addr`, `api_key`, `data_directory`, `consumers`. `api_key` is not required when `api_user` and
`api_secret_command` are set.

| Key | Type | Default | Allowed | Meaning |
|---|---|---|---|---|
| `pce_addr` | string | required | | PCE host and port, for example `pce.example.com:8443`. Used as `https://<pce_addr>/api/...`. |
| `api_key` | string | required | | Where to get the API key: a file or a `$command`. See [API key](#api_key). |
| `api_user` | string | none | | The API user, with `api_secret_command`. New in FlowPilot. See [api_user and api_secret_command](#api_user-and-api_secret_command). |
| `api_secret_command` | string | none | | A command that prints the API secret, with `api_user`. New in FlowPilot. |
| `org_id` | integer | `1` | at least 1 | Organisation id in the PCE. |
| `verify_pce_cert` | boolean | `true` | | Verify the PCE TLS certificate against the system trust store. `false` accepts any certificate. |
| `aggregation_minutes` | integer | `10` | 5 to 60 | Length of the aggregation window. One upload batch is produced per window. |
| `data_directory` | string | required | existing, writable directory | Spool and state files, see [operations.md](operations.md#the-data-directory). |
| `data_directory_size_mb` | integer | `500` | at least 100 | Size cap for queued upload files. Keep it at or below 32767; larger values read as 0. |
| `file_retention_hours` | integer | `24` | at least 4 | Queued upload files older than this are deleted unsent. **Keep it at or below 546.** Higher values overflow a 16-bit minute count and give a wrong, possibly negative, retention. |
| `metrics_print_seconds` | integer | `60` | at least 15 | How often per-consumer rates are logged. Above 32767 it reads as 0 and nothing is logged. |
| `max_flows_per_post` | integer | `10000` | 2500 to 20000 | Most flow records in one upload file. A larger window is split into several files. |
| `proxy_config` | object | none | | HTTP proxy settings. |
| `pce_kafka` | object | none | | PCE Kafka (Integrations) mode: flows go to Illumio's Kafka instead of the PCE. See [pce_kafka](#pce_kafka). |
| `consumers` | list | required | at least 1 entry | Parsers and their connectors. |
| `unmanaged_workloads` | object | see below | | Automatic unmanaged workload creation. New in FlowPilot. |

### api_key

`api_key` says where the key is, not what it is. There is no way to put the key itself in the config.

- **A file.** Any value that does not start with `$` is a file path. The content is trimmed.
- **A command.** A value that starts with `$` is run. `"$/usr/local/bin/get-pce-key"` or `"$cat /etc/flowpilot/api_info"`.
  The text after `$` is split on whitespace into program and arguments. There is no shell, so no quoting, pipes or
  redirects. The program is found through `PATH` or given with a path. Standard input is empty. Standard output,
  trimmed, is the key. If the command fails, FlowPilot logs `Command failed: <the command's stderr>` and exits 1.
  Quote the YAML value, since `$` and spaces can confuse a plain scalar.

The key text must be in one of these forms:

- **Two words**, user then secret: `api_1a2b3c4d4e5f secret-value`.
- **JSON** as downloaded from the PCE when an API key is created: an object with `key_id`, `auth_username` and
  `secret`. The text is treated as JSON when it contains the string `key_id`. The user is `auth_username` and the
  password is `secret`. If it does not parse, FlowPilot logs `Invalid API key json file`.

Anything else logs `Unable to obtain api key information` and exits 1. For the two-word form the source is read twice,
so a command is run twice at start-up.

When the PCE answers 401, the source is read again; see [Re-reading after a 401](#re-reading-after-a-401).

### api_user and api_secret_command

New in FlowPilot. For key stores whose command line prints one field, such as Vault:

```yaml
api_user: api_1a2b3c4d4e5f
api_secret_command: vault kv get -field=secret secret/flowpilot
```

- Both keys or neither; one alone is a validation error (`api_user and api_secret_command must be set together`).
  With both set, `api_key` is not required, and is ignored if present. `FLOWPILOT_API_USER` and
  `FLOWPILOT_API_SECRET` still win over them.
- The value is the command itself, with no leading `$`. It runs like an `api_key` `$command`: split on whitespace, no
  shell (no quoting, pipes or redirects), the program found through `PATH` or given with a path, standard input
  empty. It inherits FlowPilot's environment, so `VAULT_ADDR`, `VAULT_TOKEN` or `VAULT_CACERT` set for the service
  reach it (see [operations.md](operations.md#api-secret-from-a-key-store)).
- It runs once at start-up. Its standard output, trimmed, is the secret. Output that is empty or contains whitespace
  logs `API secret command printed no usable secret` and exits 1. A failing command logs
  `Command failed: <the command's stderr>` and exits 1. A command still running after 30 seconds is killed, and
  FlowPilot logs `Command timed out after 30 seconds: <program>` and exits 1. The output is never logged.

### Re-reading after a 401

When the PCE answers a request with 401, FlowPilot reads the credentials again: it runs `api_secret_command` again, or
reads the `api_key` file or runs its `$command` again. A secret rotated in the key store, or a key file rewritten by
Vault Agent, is picked up without a restart. Credentials given as `FLOWPILOT_API_USER` and `FLOWPILOT_API_SECRET`, or
by plugger's variables, are not re-read.

- At most one read per 60 seconds. Senders that get a 401 at the same time wait for that one read.
- The log shows `PCE answered 401, reading the API credentials again`, then `API credentials changed` or
  `API credentials unchanged`. A read that fails logs the usual message (`Command failed: ...`,
  `Command timed out after 30 seconds: ...`) and keeps the old credentials; FlowPilot keeps running. A re-read
  `$command` in `api_key` is also killed after 30 seconds.
- Flow uploads: when the credentials changed, the file is sent again at once with the new ones. Otherwise the usual
  backoff applies. The 401 counts as one failed upload either way.
- Unmanaged workloads use the new credentials from their next PCE call, unless `unmanaged_workloads.api_key` overrides
  them; an override is read once at start-up only.
- The PCE Kafka bootstrap reads the credentials at start-up only.

### proxy_config

All three keys are strings and optional.

| Key | Effect |
|---|---|
| `http_proxy` | Sets `HTTP_PROXY` and `http_proxy` for the process. |
| `https_proxy` | Sets `HTTPS_PROXY` for the process. Sets the lower-case `https_proxy` too, but to the value of `http_proxy`, as the original does. |
| `no_proxy` | Sets `NO_PROXY` and `no_proxy`. |

The variables are set before the API key command runs, so a `$command` inherits them. A value given here replaces an
environment variable of the same name. Connections to the PCE use HTTPS, so `https_proxy` is the one that matters in
practice. FlowPilot also reads `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` from its environment (for example from a
systemd `Environment=` line) and logs `Detected ...` lines for them. The proxy applies to flow uploads and to the
unmanaged workload API calls.

### pce_kafka

```yaml
pce_kafka:
  installation_id: "..."                    # required inside this object; not empty turns the mode on
  env_override: stage                       # optional: dev or stage
  kafka_info: /etc/flowpilot/kafka_info     # optional: a file, or "$command", with the Kafka settings
  gateway: integrations.example.com         # optional, FlowPilot only: the Integrations gateway host
```

With a non-empty `installation_id`, FlowPilot runs in PCE Kafka (Integrations) mode, as FlowLink does: each upload
file goes as one message to a Kafka topic that Illumio runs for the PCE, instead of to the PCE's REST endpoint. What
is sent and how is in [operations.md](operations.md#pce-kafka-mode). An empty `installation_id` is the normal REST
mode.

| Key | Type | Meaning |
|---|---|---|
| `installation_id` | string | Required in the object. Put in the header of every message. |
| `env_override` | string | `dev` or `stage`: use that environment of the Integrations gateway instead of production (see below). |
| `kafka_info` | string | Where to find the Kafka settings when the gateway has none for this PCE (status 404). A file path or a `$command`, read like [`api_key`](#api_key). It holds the same JSON as the gateway's answer. |
| `gateway` | string | The Integrations gateway host, optionally with `:port`. New in FlowPilot; FlowLink ignores the key. It wins over the built-in gateway and over `env_override`. |

**Start-up.** After the API key and the instance id are read, and before the stats endpoint and the collectors start,
FlowPilot logs `Getting integrations kafka config` and asks Illumio's Integrations gateway for the Kafka settings:

- `GET https://<gateway>/integrations/api/v1/config/flowlink-kafka?pceHost=<host>&orgId=<org_id>`. `<host>` is
  `pce_addr` up to its first `:`, without the port. Nothing is URL-encoded.
- HTTP basic authentication with the PCE API user and secret, `Accept: application/json`, timeout 60 seconds.
- The proxy settings apply ([proxy_config](#proxy_config), `HTTPS_PROXY`, `NO_PROXY`), as for the PCE.
- The gateway's certificate is checked against the system trust store unless `verify_pce_cert: false`.
- `Response Code <status>` is logged.

**Which gateway.** `gateway` when it is set. Otherwise the gateway built into release binaries, or, with
`env_override`, `<env_override>-<staging domain>` with the staging domain built into the binary. These names are
given at build time through the variables `FLOWPILOT_BUILD_GATEWAY` and `FLOWPILOT_BUILD_GATEWAY_STAGING_DOMAIN`; they
are not in the source. `flowpilot -version` prints `Built-in Integrations gateway: yes` or `no`, without the name. A
build without a built-in gateway (a plain `cargo build`, for example), with no `gateway` set, logs
`this build has no built-in Integrations gateway; set pce_kafka.gateway` and exits 1. The same happens with
`env_override` on a build without a staging domain.

**The answer.**

- Status 200: the body is the Kafka settings.
- Status 404: the settings come from `kafka_info`. If `kafka_info` is empty, `No valid Integrations kafka config` is
  logged and the process exits 1.
- Any other status: `Invalid Integrations kafka config response: <body>` and exit 1.

The settings are a JSON object:

```json
{"bootstrapServers": "broker1:9093,broker2:9093", "topic": "...", "connectionString": "...", "maxObjectsPerMessage": 5000}
```

- Keys are matched without regard to case, as Go does. Unknown keys are ignored, `null` leaves a value unset, and
  when a key appears twice the last one wins.
- `bootstrapServers`: comma-separated `host:port` list of brokers. If it is empty, `No Integrations kafka Servers
  configured` and exit 1.
- `topic`: the topic to write to.
- `connectionString`: the SASL password. It is never logged.
- `maxObjectsPerMessage`: an integer. It replaces `max_flows_per_post` without the 2500 to 20000 check, as in
  FlowLink. 0, absent or negative means one message per window, with no limit on the records in it.

Invalid JSON gives `Unable to process Integrations Kafka config: <error>` (status 200) or
`Unable to process Integrations kafka config: <404 body>` followed by the error (from `kafka_info`), and exit 1. The
error text says where the JSON is wrong, never what the values are.

**Connecting.** FlowPilot then connects to the brokers (see [operations.md](operations.md#pce-kafka-mode)) and logs
`KafkaProducer setup`. If the brokers cannot be reached, the login fails or the topic does not exist, it logs
`Unable to create Kafka Producer: <error>` and exits 1, with no retry; systemd restarts the service.

**Variables.** Each key has a variable:

| Variable | Config key |
|---|---|
| `FLOWPILOT_PCE_KAFKA_INSTALLATION_ID` | `pce_kafka.installation_id` |
| `FLOWPILOT_PCE_KAFKA_ENV_OVERRIDE` | `pce_kafka.env_override` |
| `FLOWPILOT_PCE_KAFKA_KAFKA_INFO` | `pce_kafka.kafka_info` |
| `FLOWPILOT_PCE_KAFKA_GATEWAY` | `pce_kafka.gateway` |

As for every object, a setting without `installation_id` is an error that names the variable
(`FLOWPILOT_PCE_KAFKA_INSTALLATION_ID`). `-print-config` shows the section when `installation_id` is set. It prints
`kafka_info` as given (the path or `$command`) and never runs or reads it; the connection string is never printed.

### consumers

Each entry is one data source: a parser, and the connectors that feed it. Required per entry: `name`, `parser`,
`connectors` (at least one).

| Key | Type | Meaning |
|---|---|---|
| `name` | string | Label for logs and for the metrics lines. Entries with the same name share one meter. |
| `parser.type` | string | `netflow`, `ipfix`, `sflow` or `text`. `aws` passes validation but is not supported. |
| `parser.properties` | object | Parser options. Only the `text` parser has any. |
| `connectors[].type` | string | `udp`, or `kafka` with the `text` parser. `tcp` and `aws` pass validation, but the connector is rejected at start-up with `Unsupported connector: <type>`. A `kafka` connector on another parser logs `Parser <type> does not support connector kafka`. |
| `connectors[].properties` | object | Connector options, see below. |

A consumer that cannot start any of its connectors is skipped. If no consumer starts, the process exits 1 without a
log line. A consumer whose connectors partly fail keeps the ones that started.

**Do not give `properties` to `netflow`, `ipfix` or `sflow` parsers.** The schema requires the four text keys
whenever a parser has `properties`, and the parsers ignore them anyway (an `Unsupported <type> parser property:` line
is logged).

#### UDP connector properties

| Key | Type | Default | Meaning |
|---|---|---|---|
| `ports` | string | the parser's default port | Comma-separated UDP ports, for example `"2055,2056"`. **It must be a quoted string**: an unquoted number fails validation. |
| `remote_addrs` | string | all senders | Comma-separated exporter IP addresses. Datagrams from other sources are dropped, with one log line per source address. Exact IP addresses only: no CIDR, no host names. |

Default ports: NetFlow 2055, IPFIX 4739, sFlow 6343, text 6514. Details in [collectors.md](collectors.md). An unknown
property is logged (`Unsupported udp connector property: <key>`) and ignored. An invalid port or address stops that
connector from starting. If several ports are listed and one fails to bind, the earlier ports keep running and the
connector counts as failed.

The aws property set is accepted by the schema but unused (see [roadmap.md](roadmap.md#deferred-connectors)).

#### Kafka connector properties

Only with `parser.type: text`. The connector joins a Kafka consumer group and hands each message to the parser as
one datagram; see [collectors.md](collectors.md#kafka-input). Kafka connectors can only be set in the config file,
not through variables.

```yaml
  - name: firewall-kafka
    parser:
      type: text
      properties: { src_ip: src, dst_ip: dst, dst_port: dport, protocol: proto }
    connectors:
      - type: kafka
        properties:
          brokers: "kafka1:9094,kafka2:9094"
          version: "2.8.1"
          group: flowpilot
          topics: firewall-logs
          broker_certs: /etc/flowpilot/kafka-client.pem
          broker_keys: /etc/flowpilot/kafka-client.key
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `brokers` | string | required | Comma-separated `host:port` list. Spaces around entries are ignored. The first entry, as written, is the exporter address of every message. |
| `version` | string | required | The brokers' Kafka version. Format: `a.b.c`, or `0.a.b.c` when it starts with `0`; digits only, at least 5 characters. Any such version is accepted. Below `0.10.2.0` consumer groups are refused (see below). |
| `group` | string | required | The consumer group. A new group starts at the oldest message of each partition. |
| `topics` | string | required | Comma-separated topics. Spaces around entries are ignored. |
| `instances` | integer | the number of `brokers` entries | Consumers started for this connector, each a member of the group. 0 means the default. |
| `client_id` | string | `Illumio-flowlink` | Client id sent to the brokers. With more than one instance, each gets the suffix `-<n>`, starting at `-0`. |
| `broker_certs` | string | none | A file, or a `$command`, giving the client certificate in PEM. Setting it turns on TLS. |
| `broker_keys` | string | none | A file, or a `$command`, giving the matching private key in PEM. Required with `broker_certs`. |

Without `broker_certs` the connection is plain TCP. With it, the connection uses TLS, the brokers' certificates are
checked against the system trust store with a host name check (`verify_pce_cert` does not apply here), and the client
certificate is offered. To trust a private broker CA, add it to the system trust store (`update-ca-trust` on RHEL) or
point `SSL_CERT_FILE` at a bundle that contains it. There is no SASL for the input connector.

The PEM text is cut into blocks at each `-----BEGIN`. The certificate and key blocks are paired in order. The first
pair is the one offered; any others must load too but are not used. If neither holds a PEM block, TLS is used
without a client certificate. PEM content is never logged.

Errors:

| Log line | Effect |
|---|---|
| `Missing kafka property: <key>` | The connector does not start. |
| ``Error: invalid version `<version>` `` | The connector does not start. With `-debug` the process exits. |
| `Invalid kafka instances value: <n>` | A negative `instances`; the connector does not start. |
| `Invalid kafka instances value, must be numeric. Using default instances.` | A non-numeric `instances`; the default is used. |
| `Missing script for broker certificate keys.` | `broker_certs` without `broker_keys`; exit 1. |
| `Number of broker certs doesn't match number of broker keys.` | Exit 1. |
| `Error: <error>` | A certificate or key does not load, or a key does not match its certificate; exit 1. |
| `kafka: invalid configuration (consumer groups require Version to be >= V0_10_2_0)` | `version` is below 0.10.2.0. Handled like a connection error: retried every 60 seconds, exit 1 after 20 minutes. |

#### Text parser properties

Only for `parser.type: text`. All values are strings; a YAML number is converted to a decimal string, so
`src_ip: 3` means "field 3".

| Key | Required | Default | Meaning |
|---|---|---|---|
| `src_ip` | yes | | Source IP. |
| `dst_ip` | yes | | Destination IP. |
| `dst_port` | yes | | Destination port, 0 to 65535. |
| `protocol` | yes | | `tcp`, `udp`, `icmp` (lower or upper case) or a number 0 to 255. |
| `icmp_type` | no | | ICMP type, 0 to 255. |
| `icmp_code` | no | | ICMP code, 0 to 255. |
| `octets` | no | 0 | Byte count. |
| `timestamp` | no | field 1 | Where the time is. |
| `timestamp_format` | no | `yyyy-mm-ddTHH:MM:SS-HH:MM` | Layout of the time. Also `unix` for epoch seconds. |
| `only_recs` | no | all lines | Keep only lines that contain given text. |
| `field_separator` | no | one space | Splits a line into fields. |
| `attribute_separator` | no | `=` | Splits a field into `name=value`. |

The schema also rejects `src_mac` and `dst_mac`, so they cannot be configured, as with FlowLink. How lines are matched, the time layout tokens and the `only_recs` syntax are in
[collectors.md](collectors.md#text-and-syslog).

### unmanaged_workloads

Optional. The feature is off unless `enabled: true`. A config with this key cannot be loaded by the original FlowLink.
The full description, with the log lines, safety limits and the PCE calls, is in
[unmanaged-workloads.md](unmanaged-workloads.md). This table is the short form.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | boolean | `false` | |
| `dry_run` | boolean | `false` | Log what would be created, write nothing. |
| `networks` | list of CIDR | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | Only IPs inside are candidates. IPv4 only. |
| `exclude_networks` | list of CIDR | empty | Never candidates. |
| `allow_broad_networks` | boolean | `false` | Needed for any CIDR broader than /8. |
| `min_flows` | integer | `10` | At least 1. |
| `flow_window_hours` | integer | `24` | Not shorter than one aggregation window. |
| `max_creates_per_window` | integer | `100` | 1 to 1000. |
| `max_creates_per_day` | integer | `500` | At least `max_creates_per_window`. |
| `refresh_hours` | integer | `24` | At least 1. |
| `external_data_set` | string | `flowpilot` | Set on every workload created. |
| `api_key` | string | main `api_key` | Same formats as the main key. |
| `dns.enabled` | boolean | `true` | |
| `dns.servers` | list of IP | empty (system resolver) | |
| `dns.timeout_ms` | integer | `2000` | At least 1. |
| `dns.concurrency` | integer | `8` | At least 1. |
| `label_rules` | list | empty | Items: `cidr` and `labels` (a map of label type to value), both required. |

Errors from these checks are logged in the same format as schema errors, for example
`unmanaged_workloads.min_flows: must be at least 1`, and the process exits 1.
