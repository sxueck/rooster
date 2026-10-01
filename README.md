# Rooster

[![docker-image](https://github.com/sxueck/rooster/actions/workflows/docker-image.yml/badge.svg)](https://github.com/sxueck/rooster/actions/workflows/docker-image.yml)

Port protection agent + management hub for Linux nodes, in a single Rust
binary (`rooster agent` / `rooster hub`). No external middleware: the agent
is a 80/443 reverse proxy with WAF, GeoIP, ACME and nftables-backed banning;
the hub is the management plane agents stay connected to over WebSocket,
serving a Vue 3 panel from the same binary.

## Features

Agent:

- 80/443 reverse proxy — TLS termination (static certs or ACME HTTP-01 with
  cache/renewal) or TCP passthrough via ClientHello SNI peeking; PROXY
  protocol v1/v2 toward upstreams; trusted-proxy real-IP resolution.
- WAF — ModSecurity SecLang subset with an OWASP CRS v4 PL1 subset (624
  rules, 0 skipped; see `rules/`), anomaly scoring, paranoia levels, live
  rule inventory and explain-where-rules-came-from diagnostics.
- GeoIP country filtering (MaxMind-compatible `.mmdb`), fail-closed with
  periodic refresh.
- TCP/UDP port forwarding with per-rule CIDR ACLs, per-IP rate limits,
  concurrency caps, live stats; DNS forwarding.
- nftables ban manager over raw netlink, ssh-guard, HTTP brute-force
  lockout, ban degradation is observable via `/v0/management/stats`.
- `config.yaml` as single source of truth: layered `local`/`managed`
  merge, comment-preserving edits, atomic writes with history, inotify
  hot reload, confirm/rollback for critical sections; loopback-only
  management API.

Hub:

- mTLS PKI, one-time-token node registration, persistent WebSocket control
  channel, management-API passthrough to agents.
- Node labels + config templates → diff preview → batch rollout with
  auto-confirm and offline replay.
- Cluster-wide bans: manual plus policy engine (min-nodes or
  threshold+window), broadcast and full re-sync on reconnect.
- Remote upgrades: Ed25519-signed binaries, staged rollout with observation
  window, automatic rollback on failure.
- Vue 3 panel, audit log, `backup`/`restore` subcommands.

WASM plugins: wasmtime host (no WASI, memory cap, epoch timeout,
fail-open/fail-closed per plugin) with a guest SDK and an example plugin
(`crates/rooster-plugin-sdk/`).

## Layout

```text
crates/
├── rooster/            # single binary entry: `rooster agent` / `rooster hub`
├── rooster-config/     # config schema, layered merge, comment-preserving writer, hot reload
├── rooster-agent/      # proxy, WAF/GeoIP/ACME, forwarding, nftables, hub client, upgrades
├── rooster-hub/        # PKI, registry, passthrough, templates, rollouts, policies, panel
├── rooster-proto/      # hub<->agent frame types + MessagePack codec
├── rooster-waf/        # SecLang subset engine
├── rooster-nft/        # nftables/netlink ban manager interface
└── rooster-plugin-sdk/ # WASM guest SDK + example plugin
web/                    # Vue 3 panel (served by the hub from web/dist)
rules/                  # built-in CRS subset, embedded into the agent at build time
```

## Quick deploy

```sh
curl -fsSL https://raw.githubusercontent.com/sxueck/rooster/main/deploy.sh | bash

# or clone first:
git clone https://github.com/sxueck/rooster.git
cd rooster && bash deploy.sh
```

`deploy.sh` walks you through, with prompts and defaults:

- **hub** — Docker (pulls `ghcr.io/sxueck/rooster`, auto-generates a
  self-signed TLS cert + CA, writes `hub.yaml`, health-checks the endpoint),
  native build + systemd unit, or behind an existing nginx/TLS terminator
  (plaintext loopback mode + a ready-to-paste nginx server block);
- **agent** — enrolls a node against an existing hub via the hub's own
  `install.sh` (one-time token from the panel), or runs it in Docker.
  Signed releases are required by default; installing the hub's own unsigned
  binary requires an explicit choice and a matching CPU architecture.

The helper refuses to overwrite existing hub configuration or TLS files.
Hostname/IP prompts accept a comma-separated list, so a future
port-forward or reverse-proxy address can be baked into the same
certificate; agents and browsers verify the address they dial against
it. Upgrade an existing deployment manually, preserving its CA and data; a new
CA requires updating the trust anchor on existing nodes. Native deployment
installs frontend dependencies and copies the panel to
`/usr/share/rooster/web/dist`. Health checks require `/healthz` to return
`200` and `ok`, with certificate and hostname verification for TLS.

Deployment regression tests (Python 3, Bash, curl and OpenSSL):
`python3 tests/test_deploy.py -v`.

## Build & run

```sh
make all        # cargo release build + panel build (Node 22) → target/release/rooster
cargo test      # workspace tests
./target/release/rooster hub --config hub.yaml
./target/release/rooster agent --config config.yaml   # first start writes a commented template
```

The hub serves the panel from `panel-dir` (default `web/dist`). Add nodes
from the panel (one-time token + `install.sh` command); a registration
token only adds a node. TLS `static` mode is required for any non-loopback
hub `listen`, so agents have a CA to trust.

## Container image

CI builds a combined agent+hub image to `ghcr.io/sxueck/rooster` on pushes
to `main` and on `v*` tags. The hub role (or just run `bash deploy.sh`):

```sh
docker run -d --name rooster-hub -p 9443:9443 \
  -v "$PWD/hub.yaml:/etc/rooster/hub.yaml" \
  -v rooster-data:/var/lib/rooster-hub \
  ghcr.io/sxueck/rooster
```

The agent role bans via nftables on the host kernel — run it with
`--network host --cap-add NET_ADMIN`, or enroll real nodes with
`install.sh` (see `deploy.sh` option 3).

## Toolchain

Rust stable + Node 22 (panel build only). No external services required at
runtime. The nftables integration test needs root on a real Linux host:
`sudo ROOSTER_NFT_ITEST=1 cargo test -p rooster-nft --test integration`.

## Credits

- WAF rule set: OWASP Core Rule Set subset, Apache-2.0 (`rules/CRS-LICENSE`).
- Test fixture GeoIP database: DB-IP Country Lite (dbip.com), CC BY 4.0.
