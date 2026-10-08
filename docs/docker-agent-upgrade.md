# Docker agent packaging and upgrades

The image contains one executable supporting both `hub` and `agent`. Hub runs
`/usr/local/bin/rooster` directly. The agent entrypoint seeds a mutable copy at
`/var/lib/rooster/bin/rooster` on first start, then runs that copy. A named volume
retains the executable, `rooster.prev`, upgrade marker and client PKI across
restarts and container recreation. Pulling a newer image does **not** overwrite
an agent version already installed in that volume.

## Build and package

```sh
docker build --build-arg ROOSTER_VERSION=0.2.2 -t rooster:0.2.2 .
docker run --rm rooster:0.2.2 --version
id=$(docker create rooster:0.2.2)
docker cp "$id:/usr/share/rooster/agents" ./agents
docker rm -v "$id"
(cd agents && sha256sum -c SHA256SUMS)
```

`/usr/share/rooster/agents` contains the raw `rooster-VERSION-ARCH`, gzip and xz
variants, `manifest.json` and `SHA256SUMS`. `ARCH` is `x86_64` or `aarch64` and
matches the image architecture. `scripts/package-agent.sh` is used by both the
Dockerfile and the dual-architecture release workflow. Version injection is
shared by CLI `--version` and Agent Hello so release names and rollout version
checks agree. Without `ROOSTER_VERSION`, builds use the Cargo package version.
The current image workflow builds the runner's native x86_64 image; it does not
publish a multi-architecture image index. The release workflow packages both
x86_64 and aarch64 binaries.

## Sign and publish

Builds do not carry a deployment signing key. Keep your Ed25519 private key
outside the repository, Docker build context, images and Hub. Configure the
matching `upgrade-public-key: "ed25519:<base64-raw-public-key>"` on the Hub and
pin it in each agent's `local.security.upgrade-public-key`.

```sh
# Generate once in a private directory; retain this key for future releases.
(umask 077; openssl genpkey -algorithm ed25519 -out /secure/upgrade.key)
python3 scripts/publish-agent.py agents/rooster-0.2.2-x86_64 \
  --key /secure/upgrade.key
```

The script prints the **public** key and writes a raw `.sig` and JSON metadata
alongside the artifact. Sign raw executable bytes, not gzip/xz bytes. You can
upload the executable and base64 signature through the panel, using version
`0.2.2-x86_64`, or use an existing panel session token in a private file:

```sh
chmod 600 /secure/hub-session-token
python3 scripts/publish-agent.py agents/rooster-0.2.2-x86_64 \
  --key /secure/upgrade.key \
  --hub https://hub.example.com:9443 \
  --ca-file /secure/hub-ca.crt \
  --token-file /secure/hub-session-token
```

No insecure TLS or unsigned upload mode is provided. The Hub verifies the
signature before storing the package. Signed packages then become available
through the existing `/v0/downloads/rooster-ARCH` bootstrap resolution and
`install.sh`; there is no automatic trust in an unsigned image artifact. Select
nodes of the matching architecture and trigger a targeted or staged rollout in
the panel. Observe each node's reported version and rollout result.

## Run the agent

Use an enrolled config directory containing `config.yaml` and the trust files it
references. Certificate/key paths must be accessible inside the container. When
migrating a native installation, provision its existing client PKI into the new
volume at the configured paths, or explicitly re-enroll the node; mounting only
`config.yaml` does not move its identity. Stop the native agent first to avoid
port conflicts. `bash deploy.sh` option 4 preserves the volume on recreation.

```sh
docker run -d --name rooster-agent --init --restart unless-stopped \
  --network host --cap-add NET_ADMIN \
  -v /path/to/enrolled-config:/etc/rooster \
  -v rooster-agent-data:/var/lib/rooster \
  rooster:0.2.2 agent --config /etc/rooster/config.yaml
```

The entrypoint always uses runtime overrides `--data-dir /var/lib/rooster` and
`--upgrade-method exit`, including after config reload. It does not rewrite the
enrolled config. An alternative volume path requires `ROOSTER_AGENT_DATA_DIR`
and a matching mount. Each start invokes the immutable image's `upgrade-guard`
with the explicit mutable binary path, so even a non-starting new executable can
be restored. Guard failures refuse startup rather than resetting the volume.

A valid upgrade atomically records a pending marker, replaces the executable
and exits. Docker restarts the container with the installed version. The new
agent must connect to the Hub within 60 seconds to clear its marker; otherwise
it restores the previous binary and exits. An executable that cannot start is
rolled back by the pre-start guard once the 90-second grace expires. Restarts
and Docker's backoff add to these timings.

This is a recoverable **restart upgrade**, not a zero-downtime handover. Existing
proxy connections may be interrupted. Do not run two agents sharing the same
volume. Do not delete the volume or run `docker compose down -v` to upgrade.
The image's immutable guard must remain CLI-compatible with versions you deploy.

## End-to-end verification

A Linux Docker daemon with host networking is required. The test builds no
images and never skips to success if Docker is unavailable:

```sh
docker build --build-arg ROOSTER_VERSION=0.0.0-e2e-old -t rooster:e2e-old .
docker build --build-arg ROOSTER_VERSION=0.2.2 -t rooster:e2e-new .
python3 scripts/test-docker-upgrade.py \
  --old-image rooster:e2e-old --new-image rooster:e2e-new
```

It creates unique containers and volumes, a temporary TLS CA/server certificate
and an offline signing key. It checks embedded artifact checksums, real TLS
registration, old-to-new Hub-triggered upgrade, executable/backup digests,
identity preservation, marker clearance, bad-signature rejection, rollback of
a correctly signed corrupt executable and persistence after container
recreation. Test resources are removed on exit; `--keep` retains them for
investigation and includes private test keys, so remove that directory later.

The Docker CI workflow runs these checks before publishing an image. Local
focused checks without Docker:

```sh
python3 -m unittest tests.test_container_entrypoint tests.test_docker_upgrade tests.test_agent_package
cargo test --locked -p rooster-agent --lib -p rooster
sh -n docker/entrypoint.sh scripts/package-agent.sh
bash -n deploy.sh
```
