# Collectors

A collector is a consumer in `consumers`: a parser plus one or more UDP connectors. This page describes what each
parser reads and what it cannot do. For the config keys see [configuration.md](configuration.md).

## Common behaviour

- **Transport.** UDP only. Each configured port is bound dual-stack (IPv6 wildcard that also accepts IPv4), with a
  256000-byte receive buffer request. The kernel limits that to `net.core.rmem_max`; if exporters send in bursts and
  you see drops, raise the sysctl.
- **Threads.** Each port gets twice as many reader threads and parser threads as the host has CPUs. Readers block when
  the parser queue is full, so overload shows up as dropped datagrams in the kernel, not as memory growth.
- **Sender address.** The address a datagram arrives from identifies the exporter. For NetFlow v9 and IPFIX it is part
  of the template key, so exporters behind one NAT address share templates. Use `remote_addrs` to accept only listed
  exporters. IPv6 addresses in `remote_addrs` must be written in the compressed lower-case form (`2001:db8::1`),
  because they are compared as text.
- **Filtering.** All parsers hand their flows to the same filter. A flow is dropped when the source or destination is
  missing, the IP version is 0, an IPv6 flow has protocol 0, 43 or 44 (extension headers), either address is
  multicast or broadcast (224.0.0.0/3, `ff00::/8`, or a multicast/broadcast Ethernet address), or an ICMP flow carries
  a destination port. Loopback and link-local addresses are not filtered.
- **ICMP type and code in the port.** Many exporters put the ICMP type and code into the destination port instead of
  an ICMP field. For an ICMP or ICMPv6 record from NetFlow v5, v9 or IPFIX that has no ICMP type/code field (32, 139,
  176 to 179), FlowPilot reads them from the destination port and sets the port to 0: `type * 256 + code`, or, below
  256, the type alone with code 0 (Cisco IPFIX and Procera captures show this). The original dropped these flows.
  A record that has an ICMP field keeps its values and its port, so if the port is not 0 it is still dropped (Cisco
  ASA sends fields 176/177 and another value in the port).
- **Direction.** When the exporter does not say which side is the client and both ports are known, the flow is turned
  around if the source port is a low port and the destination is a high port (above 32768). The result is the usual
  "client to server" orientation.
- **Aggregation.** Flows with the same source, destination, destination port, protocol and ICMP type/code in one window
  are merged. The reverse direction of a known conversation is folded into it. See
  [operations.md](operations.md#what-is-uploaded).
- **Bytes.** The PCE record has two byte counters, one per direction. For every conversation FlowPilot reports the
  bytes of **one direction only**, the one the exporter reported. This is the same as the original. A fix is planned
  ([roadmap.md](roadmap.md#bidirectional-byte-counts)).
- **Metrics.** Each consumer has a meter that counts records. It is logged every `metrics_print_seconds`.

## NetFlow

| | |
|---|---|
| Parser type | `netflow` |
| Default port | 2055/udp |
| Versions | 5, 7, 9. Version 10 (IPFIX) datagrams on this port are decoded as IPFIX. Anything else is dropped, with one log line per parser thread. |
| Connector options | `ports`, `remote_addrs` |
| Parser options | none |

**Version 5 and 7** (fixed 48-byte records). Used: source and destination address, source and destination port,
protocol, byte count, the two prefix lengths, and the start time (export time minus the age of the flow). Not used:
packet count, TCP flags, next hop, interfaces, AS numbers, ToS and the end time. Each record counts as one flow and the
bytes are reported as the incoming direction. NetFlow v5 has no ICMP type/code field; the exporter puts them in the
destination port, and FlowPilot reads them from there (see the ICMP rule above). The original dropped every v5 ICMP
record except echo replies.

**Version 9.** Templates are learned per exporter address, source id and template id. Fields used:

| Field | v9 name |
|---|---|
| 1 | IN_BYTES (4 or 8 bytes wide) |
| 231, 85 | initiatorOctets (Cisco ASA NSEL), then octetTotalCount: used for the bytes only when field 1 is absent; 1 to 8 bytes wide. Not read by the original FlowLink, where ASA flows had 0 bytes |
| 3 | FLOWS |
| 4 | PROTOCOL |
| 7, 11 | L4 source and destination port (also 180/181/182/183) |
| 8, 12 | IPv4 source and destination address |
| 27, 28 | IPv6 source and destination address |
| 9, 13, 29, 30 | prefix lengths |
| 22 | FIRST_SWITCHED, with the packet's uptime, for the flow start time |
| 32, 139 | combined ICMP type/code |
| 56, 57 | source and destination MAC (used only for the multicast filter) |
| 60 | IP version |
| 61 | direction (0 = ingress, 1 = egress) |
| 225-228, 281, 282 | post-NAT addresses and ports |

All other fields are skipped. If both post-NAT addresses are present, a second flow with the translated addresses is
reported as well.

Limits and behaviour to know:

- A data record that arrives before its template is kept (up to 10 000 records and about 32 MiB per store, oldest
  dropped first) and decoded when the template arrives, if that happens within 120 seconds. Otherwise it is lost.
  Expect a gap after a restart until the exporter resends templates.
- Options templates (set id 1) are ignored, so options data is never decoded.
- Padding after the last template in a template FlowSet is skipped. The original read it as another template.
- A datagram is ignored if its header record count is 0, and sets beyond that count are not read.
- Without field 61, a flow has direction "unknown" and the port rule above applies.
- Fields 1 and 3 with an unusual width (for example a 3-byte byte counter) are skipped; the original crashed on them.

## IPFIX

| | |
|---|---|
| Parser type | `ipfix` |
| Default port | 4739/udp |
| Connector options | `ports`, `remote_addrs` |
| Parser options | none |

IPFIX (version 10) uses the same field table as NetFlow v9, with the IANA information element numbers (the numbers
above are the same). Extra elements understood: 150 and 152 (flow start in seconds or milliseconds), 154 and 156
(flow start in NTP time), 158 (flow start delta in microseconds), 176 to 179 (ICMP type and code, IPv4 and IPv6). The
observation domain id takes the role of the v9 source id. Version 9 datagrams sent to the IPFIX port are decoded as v9.

Limits:

- Templates are learned per exporter, observation domain and template id. They do not expire by age; past about 32 MiB of templates per store, the one defined longest ago is dropped (counted in `template_store_evicted`).
- Packets that arrive before their template follow the same 120-second rule as in NetFlow v9.
- Every set in a message is read, also a small one at the end. Fewer than 4 bytes left, or an all-zero set header
  (padding), end the message. The original ignored the last 32 bytes, so a small template set (6 fields or fewer) or
  a small final data set could be lost.
- Variable-length information elements (RFC 7011 section 7, also in v9 from H3C) are skipped: the rest of the record
  and of the message is decoded, but none of their values is used. A variable-length element that runs past its data
  set drops the rest of that set and counts as one decode error.
- Template withdrawals are stored as empty templates. Data for an empty template is not decoded.
- Packet counts, interfaces, VLAN, flow end time and other elements are ignored.
- Biflow (RFC 5103) elements such as `reverseOctetDeltaCount` are not read, which is why only one direction's bytes
  appear. Reading them is planned.

## sFlow

| | |
|---|---|
| Parser type | `sflow` |
| Default port | 6343/udp |
| Connector options | `ports`, `remote_addrs` |
| Parser options | none |

Version 5 datagrams only (others are logged and dropped). Flow samples (standard and expanded) are decoded; counter
samples are skipped.

Flows come from:

- **Raw packet header records** whose header protocol is Ethernet (optionally with one 802.1Q tag) or IPv4. Source and
  destination address, protocol, and TCP/UDP ports or ICMP type/code are read from the sampled packet header. Bare
  IPv6 headers (header protocol 12) and other link types produce no flow.
- **Sampled IPv4 data records** (format 3), which carry addresses, ports and protocol directly.
- Ethernet frame records set the MAC addresses used for the multicast filter.

Limits:

- **No byte counts and no sampling-rate scaling.** Every sampled packet counts as one flow with zero bytes. The
  `count` in the PCE is therefore the number of sampled packets, not an estimate of real flows or traffic. The bytes
  fields stay empty.
- The flow time is the time the datagram was received, not a time from the sample.
- IPv6 flows are only produced from Ethernet raw headers. The IPv6 extension-header length is mis-computed, as in the
  original, so ports can be wrong when extension headers are present.
- An error in one sample ends the processing of the rest of that datagram.
- The agent address in the datagram header is not used. The sender address is the exporter.
- In `-debug` mode, a malformed datagram makes the process exit. Do not run a production collector with `-debug`.

## Text and syslog

| | |
|---|---|
| Parser type | `text` |
| Default port | 6514/udp |
| Connector options | `ports`, `remote_addrs` |
| Parser options | see [configuration.md](configuration.md#text-parser-properties) |

Each datagram is plain ASCII text with one or more lines (a datagram with any byte above 0x7F is dropped, with one log
line per parser thread). A line that ends the datagram without a newline is processed too. Every non-empty line is one
flow with a count of 1.

### How a line is read

1. If `only_recs` is set, the line must pass it (below).
2. The line is split into fields on `field_separator` (default: one space). Consecutive separators make empty fields,
   and they count.
3. Each configured attribute (`src_ip`, `dst_port`, ...) has a list of names, separated by commas. For each name,
   FlowPilot looks through the fields:
   - If a field has exactly one `attribute_separator` (default `=`), it is `name=value`. It matches when `name` equals
     the configured name.
   - Otherwise the field is a bare value, and it matches when the configured name is its 1-based position as a decimal
     number (`3` for the third field).
4. The first match supplies the value.

So `src_ip: src` reads `src=10.0.0.1` anywhere in the line, and `src_ip: 4` reads the fourth field whatever it
contains. `timestamp: "date_time, 1"` means: use `date_time=...` if present, otherwise the first field.

A line is discarded, with two log lines (`Discarding flow due to <reason>` and the line itself), when:

- the source or destination is not a valid IP address (`invalid source IP:` and so on), or one is IPv4 and the other
  IPv6;
- the port, protocol, ICMP type, ICMP code or byte count is not a valid number in range (`octets` may be negative);
- source IP, destination IP or IP version are missing (`missing data:`).

Other details:

- `protocol` accepts `tcp`, `udp`, `icmp`, `TCP`, `UDP`, `ICMP` or a number. `icmp` becomes protocol 58 if the
  source address is IPv6. Mixed case such as `Tcp` is rejected.
- An address is IPv4 if it contains a dot, so `::ffff:10.0.0.1` counts as IPv4.
- The source port is not read, so it is always 0. Direction is "unknown", and because the source port is 0, bytes
  from `octets` are reported as the outgoing direction.
- If the line has no timestamp, or it cannot be parsed, the current time is used (an `Invalid time:` line is logged for
  unparsable values).

### Time layout

`timestamp_format` describes the time in a record. It is a list of space-separated words, and each word is made of the
tokens below. `timestamp` picks the field where the first word starts; the layout's other words are read from the
fields that follow.

| Token | Meaning |
|---|---|
| `yyyy`, `yy` | four- and two-digit year |
| `mm`, `mmm`, `mmmm` | month as number, short name, full name |
| `dd`, `ddd`, `dddd` | day of month, short weekday name, full weekday name |
| `_d` | day of month, space padded |
| `HH`, `MM`, `SS` | hour, minute, second |
| `.0`, `.00`, `.000` ... | fraction of a second, after `SS` (the fraction is not stored) |
| `ZZZ` | zone abbreviation |
| `Z`, `ZHH:MM`, `ZHHMM`, `-HH:MM`, `-HHMM` | `Z` for UTC or a UTC offset |
| `T` `,` `-` `:` | literal characters |
| `unix` (the whole value) | seconds since 1970 |

Examples: `mmm dd yyyy HH:MM:SS`, `yyyy-mm-ddTHH:MM:SS.000ZHH:MM`, `ddd, dd mmm yyyy HH:MM:SS -HHMM`.

- Times without a zone are read in the host's local time zone (the `TZ` variable or `/etc/localtime`).
- **A layout without a year gives year 0**, so classic syslog times (`mmm dd HH:MM:SS`) produce meaningless
  timestamps. Use a layout with a year, or `unix`.
- Anything outside the table (a `/`, AM/PM, a bare `.`) is an error: the process logs `Unrecognized element:` and exits.
- With a `field_separator` other than a single space, the time must be inside one field.

### only_recs

A comma-separated list of clauses. A clause is one or more search words joined by `&&` (or `||`), with spaces around
the operators. A line is kept when **every** clause matches. Words are case-sensitive substrings of the whole line and
cannot contain spaces.

- `only_recs: "ACCEPT,eth0"` keeps lines containing both `ACCEPT` and `eth0`.
- `only_recs: "ACCEPT && eth0"` is the same.
- `||` does not work as an OR. As in the original, `A || B` behaves like `B` alone.

An invalid expression (an operator in the wrong place) makes the consumer fail to start.

### Start-up errors

A missing required attribute logs `Missing required text parser attribute: <name>` for each one, and the process
exits 1. An invalid `timestamp_format` also exits.

## What is not collected

- NetFlow/IPFIX over TCP, Kafka-delivered flows and AWS flow logs (not yet supported).
- Packet and byte counters from sFlow.
- Anything the exporter does not put on the wire; FlowPilot does not enrich or resolve addresses.
