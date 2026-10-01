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

Docker hub deployment requires the Docker Compose plugin (`docker compose`).
The helper downloads `compose.yaml` (or `compose.host.yaml` for upstream TLS
termination) into the chosen config directory as `compose.yaml`, and writes
`.env` with the selected port and a stable project name. It validates the
Compose configuration, pulls the image, then starts the hub.

Overwrite installation is supported. Before replacing files, the helper creates
an `install-backup.*` directory with private permissions. Hub reinstalls preserve
existing `hub.yaml`, TLS/CA and data; prompted password/TLS settings only apply to
new installations. Compose files are refreshed and the image remains `latest`.
Compose download, validation and image pull happen in a temporary directory,
so failures before activation leave the existing installation untouched and can
be retried. Native reinstalls back up installed artifacts and explicitly restart
the service.
Hostname/IP prompts accept a comma-separated list, so a future
port-forward or reverse-proxy address can be baked into the same
certificate; agents and browsers verify the address they dial against
it. Replacing a CA requires updating the trust anchor on existing nodes. Native deployment
installs frontend dependencies and copies the panel to
`/usr/share/rooster/web/dist`. Health checks require `/healthz` to return
`200` and `ok`, with certificate and hostname verification for TLS.

Deployment regression tests (Python 3, Bash, curl and OpenSSL):
`python3 tests/test_deploy.py -v`.
Agent overwrite/readiness tests: `python3 tests/test_install.py -v`.
First-download trust tests: `python3 tests/test_enroll.py -v`.
Node registration regression tests (after `npm --prefix web ci`):
`node --test tests/test_node_registration.mjs`.

### Agent enrollment and trust

The panel enrollment command downloads `enroll.sh` over GitHub's verified HTTPS,
then fetches the hub installer over verified TLS. For private/self-signed CAs,
it includes `--ca-sha256` from the hub's configured `tls.ca`. Confirm the panel
and that fingerprint through a trusted channel before copying the command.
Only the public CA certificate is fetched with relaxed verification; its SHA-256
fingerprint is checked before any executable is downloaded. Subsequent requests
use that CA and enforce certificate chain and hostname verification. A locally
provisioned CA can instead be supplied with `--ca-file /path/to/ca.crt`.
`--insecure` is refused; it cannot bypass installer or binary verification.

For a hub behind a TLS-terminating proxy, set `public-url` to its external HTTPS
origin (for example `https://hub.example.com:8443`). Fresh deployments set this
automatically; existing configurations retained on reinstall must add it manually.
Neither internal plaintext mode nor untrusted forwarded headers determine the
external protocol when `public-url` is set.

Signed agent installation requires an Ed25519 signing key kept outside the hub.
Set `upgrade-public-key: "ed25519:<base64-public-key>"` in `hub.yaml`, restart the
hub, then upload a signed `rooster-VERSION-ARCH` package through the panel
(`ARCH` matches `uname -m`). Missing key/package errors explain these steps.
`--allow-unsigned` remains an explicit same-architecture development option.

Agent reinstalls back up the overwritten binary, config, server CA and systemd
unit, write `config.yaml` with mode `0600`, and retain node data/client PKI.
The generated config replaces local settings; restore any required custom rules
from the printed backup directory. Changing the hub/name with existing client
PKI is refused rather than silently reusing another identity. The installer
explicitly restarts the service and reports success only after the authenticated
local readiness endpoint confirms a live Hub connection. If readiness fails,
installation exits nonzero with a journal/backup hint.

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
hub `listen`, so agents have a CA to trust. The registration modal closes
when its token expires. While it is open, the panel checks nodes every two
seconds; a new online node closes the modal and refreshes the node list without
reloading the whole page. Readiness is detected against the node list captured
when opening the modal, not token consumption; concurrent registrations can
therefore also trigger completion.

## Container image

CI builds a combined agent+hub image to `ghcr.io/sxueck/rooster` on pushes
to `main` and on `v*` tags. Run `bash deploy.sh` to initialize a hub, then
manage it from the config directory selected during deployment:

```sh
cd /path/to/rooster-hub
docker compose up -d       # start
docker compose down        # stop and remove the container, keeping data
docker compose logs -f hub
docker compose pull && docker compose up -d   # upgrade
```

`compose.yaml` maps `${ROOSTER_PORT:-9443}` to the hub's TLS port 9443.
`compose.host.yaml` uses host networking for plaintext loopback mode behind a
TLS terminator; the selected backend port is written into `hub.yaml`.
Both mount the config directory at `/etc/rooster` and retain the existing
`rooster-hub-data` Docker volume. Do not use `docker compose down -v` unless
intentionally deleting hub data, including its node registry and PKI.

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
