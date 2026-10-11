# certbot-dns documentation

The `certbot-dns` utility issues and renews Let's Encrypt TLS certificates using **DNS-01** challenges, managing TXT records through one or more DNS providers (**FastVPS FastDNS**, **Alibaba Cloud DNS**). Optional zone mirroring copies records from a master provider or a BIND `.zone` file to slave providers.

## Table of contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Domain expansion and output layout](#domain-expansion-and-output-layout)
5. [DNS-01 and providers](#dns-01-and-providers)
6. [Zone sync](#zone-sync)
7. [Renewal and daemon mode](#renewal-and-daemon-mode)
8. [Obtain checkpoint](#obtain-checkpoint)
9. [Docker](#docker)
10. [Logging](#logging)
11. [Tests](#tests)
12. [Troubleshooting](#troubleshooting)

## Requirements

- Go 1.25+ (or Docker)
- Credentials for at least one supported DNS provider
- Domains delegated to DNS where TXT records for DNS-01 can be created
- Contact email for ACME registration

| Provider | Credentials |
|----------|-------------|
| `fastdns` | FastVPS FastDNS API token |
| `alibabacloud` | Alibaba Access Key ID + Secret (AliDNS), optional `region_id` |

## Installation

### install.sh (recommended, Linux + systemd)

```bash
curl -fsSL https://github.com/raidkon/certbot-dns/raw/master/install.sh -o get-certbot-dns.sh
sudo sh ./get-certbot-dns.sh --dry-run
sudo sh ./get-certbot-dns.sh
```

The release tarball includes the binary, `certbot-dns.service`, `config.example.toml`, `env.example`, and `example.com.zone`.

```bash
sudo nano /etc/certbot-dns/config.toml
sudo nano /etc/certbot-dns/env
sudo systemctl restart certbot-dns
journalctl -u certbot-dns -f
```

Options: `--version v1.0.0`, `--no-start`. Uninstall: `uninstall.sh` (`--purge`).

### From source

```bash
git clone https://github.com/raidkon/certbot-dns.git
cd certbot-dns
sudo cp config.example.toml /etc/certbot-dns/config.toml

export FASTDNS_API_TOKEN="your-token"

cd src
go test ./...
go build -o certbot-dns .
./certbot-dns -config /etc/certbot-dns/config.toml
```

Default config path: `/etc/certbot-dns/config.toml`.

## Configuration

Full example: [`config.example.toml`](../config.example.toml). Systemd packaging: [`packaging/config.example.toml`](../packaging/config.example.toml).

Secrets: `/etc/certbot-dns/env` — see `packaging/env.example` (`FASTDNS_API_TOKEN`, `ALIBABA_ACCESS_KEY_ID`, `ALIBABA_ACCESS_KEY_SECRET`, optional `ALIBABA_REGION_ID`).

### `[acme]` section

| Parameter | Description |
|-----------|-------------|
| `email` | ACME account email (required) |
| `directory` | `production` or `staging` |
| `state_dir` | `account.key` and `registration.json` (default `.acme-state`) |
| `user_agent` | Optional; default `certbot-dns/1` |

### `[[providers]]` blocks

| `type` | Fields |
|--------|--------|
| `fastdns` | `api_token`, optional `api_url` |
| `alibabacloud` | `access_key_id`, `access_key_secret`, optional `region_id` |

Type aliases: `alidns`, `ali-dns`, `alicloud`.

**Backward compatibility:** `[fastdns]` without `[[providers]]` creates provider `name = "default"`. Omitted `provider` on a certificate block uses `default`.

### `[dns_challenge]` section

| Parameter | Description |
|-----------|-------------|
| `propagation_timeout` | Max wait for TXT (e.g. `24h`) |
| `propagation_interval` | Delay between checks (e.g. `10m`) |
| `recursive_resolvers` | `host:port` list for pre-check; default `8.8.8.8:53`, `1.1.1.1:53` |

### `[[certificates]]` blocks

| Parameter | Description |
|-----------|-------------|
| `id` | Optional log label |
| `provider` | **String or array** of `[[providers]]` names — DNS-01 TXT is written to **every** listed provider |
| `domains` | See [domain expansion](#domain-expansion-and-output-layout) |
| `output_dir` | Base output directory |
| `key_type` | Default `ec256` |
| `renew_before_days` | Default `25` |

```toml
[[certificates]]
id = "sites"
provider = ["fv-main"]
domains = ["*.example.com"]
output_dir = "/var/lib/certbot-dns/certs/sites"
```

No `zone` field: apex zone is derived from the last two labels of the FQDN.

### `[sync]` section

| Parameter | Description |
|-----------|-------------|
| `enabled` | `true` — mirror master → slaves after ACME in the same cycle |
| `interval` | **`onstart`** (default) — sync once at startup; or a duration (`5m`) — repeat in daemon and cap sleep |
| `record_types` | Record types to copy (default: A, AAAA, CNAME, MX, TXT, NS, SRV) |
| `exclude_names` | Glob exclusions; default skips `_acme-challenge*` on sync |

`[[sync.zones]]`: `zone`, `master` (provider name or `file:///path/to.zone`), `slaves` (provider names). Master file: BIND `.zone` export; `$ORIGIN` must match `zone`. Sample: [`packaging/example.com.zone`](../packaging/example.com.zone).

### `[runtime]` section

| Parameter | Description |
|-----------|-------------|
| `mode` | `once` or `daemon` |
| `poll_when_ok` | Max sleep when all certs are fresh |
| `loglevel` | `debug` … `fatal` |

Use `${VAR}` for environment expansion in config strings.

## Domain expansion and output layout

- `*.example.com` → SAN includes apex; dir `wc-example-com/`
- Standalone apex → `apex-*`
- `www.example.com` with `*.example.com` in the same block → same wildcard cert

On disk: `output_dir/.../YYYY-MM-DD/*.pem`, symlink `live/`, optional `.obtain-checkpoint.json`.

## DNS-01 and providers

Startup checks `GetRecords` per (provider, zone).

- Multiple `provider` entries → TXT on each provider for one ACME order
- **FastDNS:** purge conflicting TXT; sequential challenges
- **Alibaba Cloud DNS:** standard libdns client

Zone name heuristic: last two labels of apex (limitations for some ccTLDs).

## Zone sync

When enabled, after ACME each zone block:

1. Read master (API or file)
2. Filter by types and exclusions
3. `SetRecords` on each slave to match master, preserving excluded names on the slave

**Warning:** sync rewrites the slave zone (except exclusions). Test carefully.

```toml
[sync]
enabled = true
interval = "onstart"

[[sync.zones]]
zone = "example.com"
master = "file:///etc/certbot-dns/example.com.zone"
slaves = ["ali-dns"]
```

## Renewal and daemon mode

**once:** single pass, exit 0 on success.

**daemon:** loop ACME → sync (per `interval`) → sleep until renewal (capped by `poll_when_ok` and sync interval when set).

## Obtain checkpoint

`.obtain-checkpoint.json` stores order URI, TXT record IDs (`challenge_key|provider` when multiple providers), and key PEM. Resumes the same order; removed on success.

## Docker

See [README.md](../README.md#docker).

## Logging

Levels: `debug`, `verbose`, `info`, `warning`, `error`, `fatal`. lego logs go to slog.

## Tests

```bash
cd src && go test ./...
cd src && go test ./... -cover
```

## Troubleshooting

| Issue | Action |
|-------|--------|
| Zone API error | Check credentials, delegation, zone name in logs |
| FastDNS empty AppendRecords error | Stale TXT; check panel |
| Sync damaged slave zone | Disable sync; restore backup; review master/exclusions |
| TXT propagation | Increase timeout; set `recursive_resolvers` |
| First tests | `directory = "staging"` |

Exit codes: `0` success, `1` runtime/obtain/sync, `2` config.

---

Russian: [docs/ru.md](ru.md) · all languages: [docs/README.md](README.md)
