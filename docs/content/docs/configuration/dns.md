---
title: DNS
weight: 4
---

Use DNS settings when you want domains in a list to be resolved through a specific DNS server, usually the same VPN that will carry the matching traffic.

On package-based router installs, keen-pbr normally takes care of dnsmasq integration for you. Most users only need to define:

- `system_resolver` (keep the defaults)
- `servers`
- `rules`
- `fallback`

## Configuration

Local Alpha connects optional DNS / TLS SNI / HTTP Host / QUIC Initial learning
to the daemon's firewall lifecycle. It is **off by default**. Settings → Advanced
has two independent switches. Editing only changes the draft; Save and Apply are
required. dnsmasq remains required and active. DNS enforcement is a separate option.

The JSON keys are `dns.learning.dns` and `dns.learning.l7`. A missing or null
key inherits legacy `dns.passive_learning` (default false). For example,
`"dns": {"learning": {"dns": false, "l7": true}}` enables only L7. Unrelated saves
preserve the previous representation.

On the overview, expand the learning diagnostics below the DNS check. It shows
each listener's state, interfaces, counters and technical reasons. Active means
configured capture and a live listener, not verified site routing or VPN health.
Missing observations and zero counters are not failures. Counters reset when the
listener is recreated; disconnected live updates are explicitly labelled stale.
Viewing the panel sends no probes and changes no routes.

Capture uses domain lists from active routing rules. Its scope includes explicit
`route.inbound_interfaces` and enabled native-VPN clients with verified runtime
ingress. For pooled services, each rule matches both the exact interface and the
client prefix; a firmware LAN binding or an unverified saved pool is insufficient.
IPv4 and IPv6 pools are separate; global IPv6 disablement also disables IPv6 capture.
An empty LAN allowlist never becomes a WAN wildcard: only verified enabled native
ingress can then participate.

Native-VPN bypasses are matched before capture, by source for L7 and destination
for DNS replies. A disabled VPN pool on a shared bridge no longer excludes other
LAN clients. On a bridge, the entire excluded pool is skipped rather than relying
on an ingress physical-port match that cannot be reused on replies. Bridged VPN
clients currently require that bridge to be explicitly selected. DNS REDIRECT
exceptions on addressless ingress do not disable passive learning or change the
existing resolver path.

DNS replies use queue 43053 with bypass, only when the kernel confirms FAIL_OPEN.
On older kernels, DNS holding stays disabled; dnsmasq and available passive L7
continue. Rate-limited TCP 80/443 and UDP 443 copies use NFLOG group 43054.
Busy bindings belonging to another program, including nfqws, are never reclaimed.

STOP removes owned capture rules before closing listeners. The learner neither
changes VPN health nor restarts services. ECH or traffic without a visible domain may
remain unidentified. This is not a dnsmasq replacement or hardware acceptance;
this local version has not been installed on routers.

Cleanup hints preserve the observed client's address family: an AAAA answer over
IPv4 can teach the IPv6 set, but cannot identify that client's IPv6 address for
conntrack cleanup (and vice versa). After successful learning, the existing routing
owner may remove up to four exact conntrack entries per request so that the client
can reconnect through the selected route. It checks the committed generation,
rule priority, addresses, protocol and ports, live kernel-set membership and
confirmed learning writes. Direct, blocking and per-device VPN rules retain their
priority. Correctly routed connections, foreign marks, DNAT and other conntrack
zones are left alone. Work is time-bounded; busy, unknown, stopped or superseded
requests are skipped without retries. There is no global flush. This is not a
seamless migration: the application may need to reconnect. Hardware offload has
not yet been validated on a router. Setting
`daemon.reconnect_unmarked_flows_on_routing_change` to `false` also disables this
cleanup; DNS/L7 learning itself remains active.

```json { filename="config.json" }
{
  "dns": {
    "system_resolver": {
      "address": "127.0.0.1"
    },
    "servers": [...],
    "rules": [...],
    "fallback": ["google_dns", "quad9"]
  }
}
```

| Field | Type | Description |
|---|---|---|
| `system_resolver` | object | How keen-pbr refreshes dnsmasq on the system |
| `servers` | array | DNS server definitions |
| `rules` | array | Rules mapping lists to DNS servers |
| `fallback` | array of string | Ordered DNS server tags for queries that match no rule |
| `bootstrap` | array of string | Up to eight plain DNS server tags used to find DoH server addresses, not a fallback for website queries. |
| `dns_test_server` | object | Optional built-in DNS probe listener for advanced troubleshooting |
| `client_dns_enforcement` | object | Force LAN clients to use the router DNS: `{"enabled": true}` transparently redirects plain DNS (port 53) from inbound interfaces to the local resolver and blocks DNS-over-TLS (port 853, disable with `"block_dot": false`). DoH on port 443 cannot be blocked generically. |

## Browser Secure DNS signal

`dns.firefox_doh_canary` controls the Firefox network-DNS signal; omitted/null
means true, preserving existing configurations. Set false to remove the generated
`address=/use-application-dns.net/` directive. It is also available beside the
client-DNS checkbox in General settings and uses normal Save/Apply.

Firefox honors the signal for automatic DoH, not a manually enabled resolver.
[Mozilla documentation](https://support.mozilla.org/en-US/kb/canary-domain-use-application-dnsnet).
It does not configure Chrome, Edge or Yandex Browser or block HTTPS DNS providers.
Router upstream DNS and port 53/853 enforcement are independent.

## System Resolver

`dns.system_resolver` tells keen-pbr how to check dnsmasq state after configuration changes.

On normal router package installs, you usually should not change these settings.

| Field | Type | Required | Description |
|---|---|---|---|
| `address` | string | yes | Resolver address used for integration and TXT health checks, for example `"127.0.0.1"` or `"127.0.0.1:5353"` |

## DNS Test Server

`dns.dns_test_server` is optional. It is mainly useful when you are troubleshooting DNS and want keen-pbr to expose a simple test DNS listener.

| Field | Type | Required | Description |
|---|---|---|---|
| `listen` | string | yes | IPv4 listen address in `host:port` form, for example `"127.0.0.88:53"` |
| `answer_ipv4` | string | no | IPv4 address returned in the DNS probe answer (`nslookup check.keen.pbr`). Defaults to the host part of `listen`. |

```json
{
  "dns": {
    "dns_test_server": {
      "listen": "127.0.0.88:53"
    }
  }
}
```

When the HTTP API is enabled, you can verify if your DNS works or not via Web UI.

## DNS Servers

Each server has a tag, optional `type`, optional `address`, and optional `detour`.
DNS server `tag` values must match `^[a-z][a-z0-9_]*$`, be at most 24 characters, and must be unique.

| Field | Type | Required | Description |
|---|---|---|---|
| `tag` | string | yes | Unique identifier for this DNS server |
| `type` | string | no | `static` (plain DNS, default), `keenetic` (router DNS), or `doh` (DNS over HTTPS) |
| `address` | string | for `static` and `doh` | Plain DNS: an IP with an optional port, such as `"10.8.0.1:5353"` or `"[2001:4860:4860::8888]:5353"`. DoH: an HTTPS URL, such as `"https://dns.example/dns-query"`. |
| `ips` | array of string | no, `doh` only | Up to 16 fixed IPv4/IPv6 addresses of the DoH server, without ports. When supplied, bootstrap is not used. |
| `detour` | string | no | Outbound to use when contacting this DNS server |

The `detour` field is useful when a DNS server must be reached through a specific connection, usually the same VPN that will carry the matching traffic.

```json { filename="config.json" }
{
  "dns": {
    "servers": [
      {
        "tag": "vpn_dns",
        "type": "static",
        "address": "10.8.0.1:5353",
        "detour": "vpn"
      },
      {
        "tag": "google_dns",
        "address": "8.8.8.8"
      },
      {
        "tag": "google_dns_v6",
        "address": "[2001:4860:4860::8888]:53"
      },
      {
        "tag": "keenetic_dns",
        "type": "keenetic"
      }
    ]
  }
}
```

### `type: keenetic` (built-in router DNS via RCI)

On Keenetic routers, `type: "keenetic"` tells keen-pbr to reuse the router's current built-in DNS settings automatically.

Rules and behavior:

- At most one `dns.servers` entry may use `type: "keenetic"`.
- `address` must not be set for `type: "keenetic"` (resolved from RCI).
- keen-pbr reads unscoped `dns_server = ...` entries from the **System** proxy policy.
- If unscoped encrypted upstreams (DoH/DoT) are present, all of them are used in order.
- Otherwise, all unscoped plaintext upstreams are used in order.
- `static_a` / `static_aaaa` entries from the System policy are also propagated to generated dnsmasq config.

### How `detour` works

For plain DNS, `detour` creates a firewall rule for the DNS IP and port, including queries originating on the router. It can also affect clients contacting that IP and port directly. For DoH, the forwarder's HTTPS socket carries the outbound mark; no broad port 443 rule is created. The existing routing policy of that outbound determines what happens when it is unavailable.

For example, if `vpn_dns` has `detour: "vpn"`, then the DNS requests to `vpn_dns` will also go through `vpn`.

## DNS Rules

Rules map lists to one or more DNS servers. The editor displays aliases and stores stable server tags.

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | boolean | no | Whether this rule is active. `false` disables it. `true`, omitted, or `null` all mean enabled. |
| `list` | array of string | yes | List names whose domains should be resolved by this server |
| `servers` | array of string | yes, for new rules | Non-empty list of unique DNS server tags |
| `server` | string | no | Legacy single-server alternative to `servers` |

```json { filename="config.json" }
{
  "dns": {
    "rules": [
      {
        "enabled": true,
        "list": ["my_domains", "remote_list"],
        "servers": ["vpn_dns", "vpn_dns_backup"]
      }
    ]
  }
}
```

If `enabled` is omitted or set to `null`, the DNS rule is still treated as enabled.

Every selected server must exist. Each retains its own `detour`, so select VPN-routed servers, including additional servers, when DNS must not use the provider connection.

In local Alpha, multiple servers share one keen-pbr DNS forwarder group, which can mix plain DNS and DoH. The forwarder rotates the starting server between queries; a timeout, refusal or SERVFAIL tries the next server and temporarily skips the failing one. NXDOMAIN is a valid negative answer, not a reason to ask another server. This is not strict primary-to-backup failover. A single plain DNS server remains a direct dnsmasq target. Existing first-enabled-rule priority for overlapping lists is preserved. Direct domain bindings still take precedence over list rules.

Legacy `server` documents remain readable without mandatory rewriting. The editor saves `servers`. When both fields are present, `server` must equal the first `servers` entry. An empty array is invalid, not a fallback to the old server. Deleting one server preserves the rule with its remaining servers; deleting its last server removes the dependent rule after confirmation.

## Native DNS-over-HTTPS (local Alpha)

Choose **DNS-over-HTTPS (DoH)** in the DNS server editor, enter your provider's HTTPS URL and select an outbound. Assign the server to a list or to the default DNS chain. Creating a server alone does not make it the resolver for all websites.

For a URL containing a hostname, configure either fixed IPs (up to 16 numeric IPv4/IPv6 addresses without ports) or bootstrap (up to eight installed plain DNS servers). Bootstrap is shared by all DoH entries and tries its servers in order using their own outbounds. The DoH connection uses its separately selected outbound.

Bootstrap resolves only the DoH server hostname, not website queries as a fallback. Do not use the router's local resolver: this can loop back into the same DoH service. An empty bootstrap never falls back to the system resolver. Fixed IPs or a numeric URL host need no bootstrap.

Trusted CA certificates are required (`ca-bundle` on Entware). TLS verifies the URL hostname even with fixed IPs. Credentials and URL fragments are not supported. DNS failures do not change VPN health or restart tunnels.

Nothing is changed before Save. Existing entries remain plain DNS until explicitly edited. Advanced configuration uses `type: "doh"`, `address: "https://…/dns-query"`, optional `ips`, and the shared `dns.bootstrap` tag array.

dnsmasq forwards to managed UDP/TCP listeners at `127.0.0.89`, ports `5355–5386` (up to 32 distinct ordered groups). Identical groups share a port across default DNS and list rules; unused DoH definitions do not start listeners. Plain-only groups do not require CA certificates. Listeners are prepared before dnsmasq switches; a failed apply restores the previous forwarder configuration. STOP cancels bootstrap and retains only real plain DNS servers without a VPN detour, never the local proxy, as direct fallback.

Additional DNS NFQUEUE/L7 learning is separately opt-in through `passive_learning`; dnsmasq is still required. HTTPS connections are currently fresh per request to prevent reuse across different outbounds or pinned IPs. Router performance and hardware acceptance remain unverified. Keenetic DNS settings are not switched automatically.

## dnsmasq Integration

On packaged router installs, you usually do not need to configure dnsmasq manually.

{{% details title="Manual dnsmasq integration (advanced)" closed="true" %}}
keen-pbr provides the `generate-resolver-config` subcommand that prints dnsmasq configuration to stdout.

Two resolver types are supported:

| Resolver type | Directive style | Use with |
|---|---|---|
| `dnsmasq-ipset` | `ipset=` | iptables/ipset backend |
| `dnsmasq-nftset` | `nftset=` | nftables backend |

Example dnsmasq integration:

```text
conf-script=/usr/sbin/keen-pbr generate-resolver-config dnsmasq-nftset
```

Restart dnsmasq after adding this line.
{{% /details %}}

## Complete Example

```json { filename="config.json" }
{
  "dns": {
    "servers": [
      {
        "tag": "vpn_dns",
        "address": "10.8.0.1:5353",
        "detour": "vpn"
      },
      {
        "tag": "vpn_dns_backup",
        "address": "1.1.1.1",
        "detour": "vpn"
      },
      {
        "tag": "google_dns",
        "address": "8.8.8.8"
      },
      {
        "tag": "google_dns_v6",
        "address": "[2001:4860:4860::8888]:53"
      }
    ],
    "rules": [
      {
        "list": ["my_domains", "remote_list"],
        "servers": ["vpn_dns", "vpn_dns_backup"]
      }
    ],
    "fallback": ["google_dns", "google_dns_v6"],
    "system_resolver": { "address": "127.0.0.1" }
  }
}
```

{{% details title="Under the hood: how domain-based routing works" closed="true" %}}
When a domain in a matched list is resolved, dnsmasq adds the resulting IP address to an internal set used by keen-pbr. Traffic to that IP can then be routed through the correct outbound.
{{% /details %}}
