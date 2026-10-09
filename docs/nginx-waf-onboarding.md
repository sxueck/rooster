# Nginx site discovery and WAF onboarding

The node's **Sites** tab scans the local Nginx instance through its Agent. It
shows domains, listen directives, configuration source files, upstreams,
compatibility reasons and managed WAF mode. It does not send complete Nginx
configuration files to the Hub.

Choose **Enable WAF**, then **Monitor** or **Block**. Requests follow:

```
client -> Nginx (existing TLS termination) -> loopback Rooster -> original HTTP upstream
```

Nginx continues to own certificates and external ports. Rooster uses
`127.0.0.1:18080` by default. If a dedicated HTTP-only loopback HTTP guard is
already enabled, its fixed port is reused. Configure another loopback port if
18080 is occupied. The shortcut preserves existing global WAF/CRS settings; it
does not enable CRS for other sites. WAF body inspection currently covers the
first 128 KiB; larger bodies are streamed onward after that inspection prefix.

## First-version compatibility

The Agent discovers one running host Nginx master, including absolute `-c` and
`-p` arguments and trailing `-g` globals. When Nginx is installed but stopped,
configuration discovery is available and mutation is disabled. Multiple
masters, containers and ambiguous/relative startup arguments require manual
integration.

All parsed HTTP server blocks appear in the discovery table. Automatic
onboarding supports exactly one `location /` (or `location ^~ /`) with one
`proxy_pass` without a URI suffix. The proxy target may be a literal
`http://host:port` (and `https://host:port`, attached with upstream TLS
verification skipped to match Nginx's default of not verifying upstream
certificates) or a named `upstream` group — but only when the group contains
exactly one non-`backup`, non-`down` `server` entry, because forwarding through
Rooster would otherwise silently change load-balancing or failover semantics.
Resolved groups keep Nginx's `$proxy_host` semantics: `Host` and implicit
`proxy_redirect` continue to use the group name. Variable upstreams, upstream
groups with several servers, FastCGI, static serving, extra or nested
locations, includes inside a server/location, rewrites, caches and module
hooks are displayed with an unsupported reason. Ambiguous inherited
HTTP-level proxy settings in included server files are also declined.

The table folds server blocks without a `proxy_pass` (port-80 redirect/ACME
blocks) into their domain group's first row, so a certificate-split pair of
80/443 blocks occupies one actionable row.

Inherited `proxy_set_header` directives are materialized when a location-level
injection would otherwise suppress inheritance. Original Host behavior and
implicit proxy redirect mapping are retained. Existing location-level X-Forwarded-For using `$remote_addr` or
`$proxy_add_x_forwarded_for`, and X-Forwarded-Proto using `$scheme` or a literal
http/https value, are retained without duplicates. Custom source expressions
and the reserved X-Rooster-Site header require manual integration. Inherited
source headers are replaced by the managed forwarding metadata. The injected client address comes from Nginx's
`$remote_addr`; configure Nginx real-IP handling first when it is behind a CDN
or load balancer. Header expressions using `$proxy_host`/`$proxy_port` are
rejected because their values change when proxy_pass changes.

The internal X-Rooster-Site routing header is honored only from a configured
trusted loopback peer, is overwritten by Nginx, and is stripped before reaching
the business upstream. Forwarded HTTPS is honored only from configured trusted
proxies. This also works with multiple virtual hosts sharing a file or port.

## Validation, restore and recovery

The browser sends the configuration fingerprint from its scan. The Agent
re-scans before onboarding and rejects stale fingerprints. It writes a private
complete-file backup and transaction journal under `<data-dir>/nginx`, applies
the Rooster site, verifies its listener and (in block mode) a blocked probe,
then updates only the original proxy_pass span with a marked fragment. It runs
`nginx -t`, signals reload and waits for a new worker before reporting success.
Nginx operations use a longer Hub timeout and do not block the session heartbeat.
Configuration commits use brief locks and content comparison so concurrent edits
are preserved; verified internal probes do not feed automatic ban policies.

Immediate failure rolls back Rooster and any changed Nginx fragment. Rollback
failures are returned explicitly and the journal remains available. **Close and
restore** restores only that marked fragment, retains unrelated edits and
other attached sites, reloads Nginx, then removes the Rooster site. Global guard
settings remain configured, allowing other or future sites to reuse them.
Generic JSON editing/deletion is blocked for journal-managed sites; use their
Nginx controls instead.

After an interrupted transaction, a journal/config mismatch appears as
**Needs recovery**. The restore operation can recover an exact managed fragment
or a prepared transaction with an unchanged original-file fingerprint. If the
managed fragment itself was edited, removed or duplicated, automatic recovery
refuses to overwrite it; reconcile against the private `.conf.backup` file.
External edits still require coordination with the Agent, especially during
validation/reload. Container/config-management systems should use manual
integration until they have a dedicated adapter.

Monitor mode records WAF verdicts in Agent logs and forwards traffic; it does
not currently produce Hub Block events. Block mode runs a built-in XSS probe
before touching Nginx; a custom ruleset that does not block that probe must be
reviewed or used in monitor mode. The probe verifies the local WAF path and new
Nginx workers, not every business route. Existing WebSocket support inspects the
upgrade request and tunnels frames afterwards.

## API and verification

- `GET /v0/management/nginx/sites`: `{running, sites}`.
- `PUT /v0/management/nginx/sites/{id}/waf`: `{mode, fingerprint}`; mode is
  `detect`, `block` or `off`. A fingerprint is required for initial onboarding.
- Hub forwards these through `/v0/nodes/{node}/management/nginx/...` using the
  existing authenticated Agent connection.

Parser and injection tests run with `cargo test -p rooster-agent --lib nginx`.
The opt-in lifecycle test starts a temporary Nginx and business upstream,
checks POST-body blocking, header preservation, two virtual hosts, idempotency,
stale scans, monitor mode, failed self-test rollback and fragment restore:

```
ROOSTER_TEST_NGINX=1 cargo test -p rooster-agent --lib nginx -- --test-threads=1
npm ci --prefix web
npm run build --prefix web
```

Run the lifecycle test on an isolated Linux host with `/usr/sbin/nginx` and no
other Nginx master. It does not target a production node.
