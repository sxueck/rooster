# Nginx site discovery and WAF onboarding

The node's **Sites** tab scans the local Nginx instance through its Agent. It shows domains, listen directives, configuration source files, upstreams, compatibility reasons and managed WAF mode. It does not send complete Nginx configuration files to the Hub.

Choose **Enable WAF**, then **Monitor** or **Block**. Requests follow:

```
client -> Nginx (existing TLS termination) -> loopback Rooster -> original HTTP upstream
```

Nginx continues to own certificates and external ports. Rooster uses `127.0.0.1:18080` by default. If a dedicated HTTP-only loopback HTTP guard is already enabled, its fixed port is reused. Configure another loopback port if 18080 is occupied. The shortcut preserves existing global WAF/CRS settings; it does not enable CRS for other sites. WAF body inspection currently covers the first 128 KiB; larger bodies are streamed onward after that inspection prefix.

## First-version compatibility

The Agent discovers one running host Nginx master, including absolute `-c` and `-p` arguments and trailing `-g` globals. When Nginx is installed but stopped, configuration discovery is available and mutation is disabled. Multiple masters, containers and ambiguous/relative startup arguments require manual integration.

All parsed HTTP server blocks appear in the discovery table. Automatic onboarding classifies every `location` in a server block individually:

- a location with exactly one static `proxy_pass` and only proxy-safe directives is **onboarded**: its `proxy_pass` is rewritten to the loopback guard with a per-location `X-Rooster-Site` id, so `location /` and `location /api` (even to different upstreams) are each protected;
- a location without a dynamic handler or nested block (static file serving, internal redirects, ACME answers) stays in Nginx and is reported as a bypass count in the row; FastCGI, gRPC, uWSGI, SCGI, module hooks and nested locations decline the whole server rather than being counted as static bypasses;
- anything else (variables, unsafe directives, unresolvable groups) declines the whole server block with a reason naming the location.

The proxy target may be a literal `http://host:port` (and `https://host:port`, attached with upstream TLS verification skipped to match Nginx's default of not verifying upstream certificates) or a named `upstream` group — but only when the group contains exactly one non-`backup`, non-`down` `server` entry, because forwarding through Rooster would otherwise silently change load-balancing or failover semantics. A `proxy_pass` URI prefix (`location /app/ { proxy_pass http://127.0.0.1:3006/api/; }`) is kept on the loopback hop, so Nginx still performs the same path rewrite and Rooster forwards the path it receives. The original implicit response redirect mapping is made explicit (`proxy_redirect http://127.0.0.1:3006/api/ /app/;`); `proxy_redirect off` remains off. Resolved groups keep Nginx's `$proxy_host` semantics: `Host` and implicit `proxy_redirect` continue to use the group name. Variable upstreams, upstream groups with several servers, FastCGI, nested locations, rewrites, caches and module hooks are displayed with an unsupported reason. Server-level timeout/buffering directives — the same hop-quality set a location may carry (`proxy_http_version`, the three proxy timeouts, buffering, `proxy_request_buffering`, `proxy_redirect off`) — are accepted: after onboarding they govern the Nginx→Rooster hop. The effective location/server `proxy_connect_timeout` is also stored as the Rooster site's `upstream-connect-timeout` for origin TCP connections and TLS handshakes (Nginx default: 60s; non-onboarded Rooster sites retain their 10s default). Read/send timeouts and buffering remain enforced by Nginx; onboarding adds a forwarding hop and does not guarantee identical timing. Semantic proxy directives (`proxy_cache*`, `proxy_next_upstream`, `proxy_intercept_errors`, …) and server-level routing directives (`return`, `rewrite`, `try_files`, …) still require manual integration; a declining reason names the offending directive.

## Inheritance and includes

A standalone `sites-enabled` file has no `http{}` block of its own, so the Agent reconstructs the HTTP context from the `nginx -T` dump: the `http{}` children of the main configuration plus every file reached from it through `include` (absolute, relative to the main configuration directory, or POSIX glob including character classes, always resolved against the dump itself — never against a caller-supplied path). Empty glob matches are valid, and glob expansion has no 16-file limit; a missing literal include still declines. Those `proxy_set_header` directives are the value a location inherits when neither the location nor its server defines one. Only one `http{}` context can be resolved this way; a dump with several `http{}` blocks declines. HTTP-level `proxy_*` directives other than `proxy_set_header` also decline, because after onboarding they would apply to the Nginx→Rooster hop instead of the origin hop.

`include` inside a server or location block is recursively expanded from the same dump, in configuration order, and its directives are classified as if written inline. Cycles, chains deeper than 64 levels and expansion beyond 4 MiB decline. An include that cannot be resolved from the dump, contains a nested block, or supplies the `proxy_pass` itself declines. Expansion into the site file happens only when a directive must be rewritten (see below); otherwise the include line is left untouched.

`$proxy_host` and `$proxy_port` change value the moment `proxy_pass` changes, so any effective `proxy_set_header` using them is rewritten to the pre-onboarding literal (`Host g;` for a group, `Host 127.0.0.1:3001;` for a literal). `$proxy_port` comes from the original `proxy_pass`, not the physical server address: `http://g` uses 80 and `https://g` uses 443 even when the group's server listens on another port. When that directive lives in a shared include, the include line in the site file is replaced by its expanded contents with the value literalized — shared files such as `proxy_params` are never edited. The rewrite is journaled next to the `proxy_pass` fragment and is undone by the same restore. `$proxy_host` in any other directive (`add_header`, …) still requires manual integration.

The table folds server blocks without a `proxy_pass` (port-80 redirect/ACME blocks) into their domain group's first row, so a certificate-split pair of 80/443 blocks occupies one actionable row.

Inherited `proxy_set_header` directives are materialized when a location-level injection would otherwise suppress inheritance — including directives inherited from another file. Existing location-level X-Forwarded-For using `$remote_addr` or `$proxy_add_x_forwarded_for`, and X-Forwarded-Proto using `$scheme` or a literal http/https value, are retained without duplicates. Custom source expressions and the reserved X-Rooster-Site header require manual integration. Inherited source headers are replaced by the managed forwarding metadata. The injected client address comes from Nginx's `$remote_addr`; configure Nginx real-IP handling first when it is behind a CDN or load balancer. Header expressions using `$proxy_host`/`$proxy_port` are rewritten to their pre-onboarding literal, as described above.

The internal X-Rooster-Site routing header is honored only from a configured trusted loopback peer, is overwritten by Nginx, and is stripped before reaching the business upstream. ACME challenge paths on this managed route are forwarded to the origin, not intercepted by Rooster's local challenge responder; ordinary direct requests retain local ACME handling. Forwarded HTTPS is honored only from configured trusted proxies. This also works with multiple virtual hosts sharing a file or port.

## Validation, restore and recovery

The browser sends a fingerprint covering the complete configuration dump, including inherited snippets and upstream definitions. The Agent re-scans before onboarding, rejects stale fingerprints and rechecks all dumped files before writing Nginx. It writes a private complete-file backup and transaction journal under `<data-dir>/nginx`, applies the Rooster sites (one per onboarded location; the catch-all uses the block id, extra locations use `<block-id>-l<n>`), verifies its listener and (in block mode) a blocked probe per location, then updates only the original proxy_pass spans with marked fragments. It runs `nginx -t`, signals reload and waits for a new worker before reporting success. Nginx operations use a longer Hub timeout and do not block the session heartbeat. Configuration commits use brief locks and content comparison so concurrent edits are preserved; verified internal probes do not feed automatic ban policies.

Immediate failure rolls back Rooster and any changed Nginx fragments. Rollback failures are returned explicitly and the journal remains available. **Close and restore** restores only the marked fragments, retains unrelated edits and other attached sites, reloads Nginx, then removes the Rooster sites. Global guard settings remain configured, allowing other or future sites to reuse them. Generic JSON editing/deletion is blocked for journal-managed sites (including the `-l<n>` sub-sites); use their Nginx controls instead.

Consistency checks restore the target journal's fragments under their original dump path in a copy of the complete dump, preserving includes, upstream groups and other attached servers. Dump-path identity remains separate from canonical write targets, so `sites-enabled` symlinks remain intact. Checks compare location ids and current upstream addresses; new journals also fingerprint effective headers, URI/redirect settings and connect timeouts. Changes to these dependencies require recovery rather than silently retaining an obsolete route. After an interrupted transaction, a journal/config mismatch appears as **Needs recovery**. The restore operation can recover an exact managed fragment or a prepared transaction with an unchanged original-file fingerprint. If the managed fragment itself was edited, removed or duplicated, automatic recovery refuses to overwrite it; reconcile against the private `.conf.backup` file. External edits still require coordination with the Agent, especially during validation/reload. Container/config-management systems should use manual integration until they have a dedicated adapter.

Monitor mode records WAF verdicts in Agent logs and forwards traffic; it does not currently produce Hub Block events. Block mode runs a built-in XSS probe before touching Nginx; a custom ruleset that does not block that probe must be reviewed or used in monitor mode. The probe verifies the local WAF path and new Nginx workers, not every business route. Existing WebSocket support inspects the upgrade request and tunnels frames afterwards.

## API and verification

- `GET /v0/management/nginx/sites`: `{running, sites}`.
- `PUT /v0/management/nginx/sites/{id}/waf`: `{mode, fingerprint}`; mode is `detect`, `block` or `off`. A fingerprint is required for initial onboarding.
- Hub forwards these through `/v0/nodes/{node}/management/nginx/...` using the existing authenticated Agent connection.

Parser and injection tests run with `cargo test -p rooster-agent --lib nginx`. The opt-in lifecycle test starts a temporary Nginx and business upstream, checks POST-body blocking, header preservation, two virtual hosts, idempotency, stale scans, monitor mode, failed self-test rollback and fragment restore:

```
ROOSTER_TEST_NGINX=1 cargo test -p rooster-agent --lib nginx -- --test-threads=1
npm ci --prefix web
npm run build --prefix web
```

Run the lifecycle test on an isolated Linux host with `/usr/sbin/nginx` and no other Nginx master. It does not target a production node.

## Fixture-backed end-to-end check

`tests/nginx-fixtures/` is a set of real-world-shaped Nginx configurations (TLS + ACME + named upstream + `include proxy_params`, WebSocket, multi-server upstream group, HTTPS origin, `proxy_pass` URI prefix, `$proxy_host` snippet, two vhosts in one file) with echo origins that report the headers they received. `scripts/nginx-waf-e2e.sh` installs them into a live Nginx, runs a standalone Agent against them, attaches every supported block, and asserts per site: benign traffic reaches the right origin, query and POST-body attacks return 403, `Host` keeps its pre-onboarding value, and closing restores the fixture files byte-for-byte.

```sh
scripts/nginx-waf-e2e.sh setup && scripts/nginx-waf-e2e.sh check
scripts/nginx-waf-e2e.sh teardown
```

The check returns nonzero for failed discovery, attach, traffic assertions, detach, file restoration or final `nginx -t`. An exit trap attempts restoration even after an earlier failure or interruption. Its status does not replace the need to inspect a failed restoration before reusing the host. Exit-status regressions run without Nginx or root: `sh tests/nginx-waf-e2e-status.sh`.

Root on an isolated Linux host with nginx, python3 and openssl. Sites that must stay manual (multi-server upstream groups, `proxy_ssl_*` origins) are asserted as declined, so a classifier that starts accepting unsafe shapes fails the check too.
