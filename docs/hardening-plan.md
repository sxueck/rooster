# Low-Cost Hardening Plan — L4 Guard + L7 Audit

Planned protection measures that reuse existing building blocks (`rooster-nft`
ban sets, `sshguard`, `httpguard`, forward-rule stats). Scope: items whose
implementation cost is rated **very low** or **low**. No code yet — this
document is the design baseline for the first two batches.

Current coverage (for context): 80/443 via reverse proxy with WAF (CRS v4
subset, anomaly scoring), GeoIP, HTTP throttling, HTTP brute-force lockout;
22 via ssh-guard; nftables `inet rooster` table with cluster-wide ban sync;
per-rule CIDR ACLs / rate limits / concurrency caps for forwarding rules.

## Batch 1 — L4 layer (nftables + guard reuse)

### 1. Honeypot ports → instant ban *(cost: very low)*

Any packet destined to a known-high-risk port (23, 445, 1433, 3306, 3389,
6379, 27017, 9200, …) inserts the source IP directly into the existing nft
ban set. Highly effective against scanners/worms, near-zero false positives.

- Port list is a config item; ports actually listened on by the host or by
  forwarding rules must be excluded (validation at config load).
- Pure nftables rules in the existing `inet rooster` table; no new data path.

### 2. Generalized port-scan detection → ban *(cost: low)*

Generalize `sshguard`: count closed-port hits per source IP in a sliding
window; N distinct closed ports within the window → auto-ban. Effectively a
"port-guard" reusing the sshguard pattern and the ban manager.

- Threshold and window are config items.
- Shared-egress IPs (CDN/NAT): single-node bans may over-block. Mitigation is
  hub-side — reuse the cluster-ban min-nodes policy rather than tightening
  local thresholds.

### 3. Drop invalid states + TCP flag anomalies *(cost: very low)*

Explicit nftables rules: `ct state invalid drop`, plus drop of NULL/FIN/XMAS
combinations (e.g. `tcp flags & (fin|syn|rst|ack) == 0`, `== fin|syn`).
Covers stealth scanning and malformed packets before they reach listeners.

### 4. Global L4 new-connection rate limit *(cost: low)*

`ct state new limit rate over N/second` per source IP (nft meter) —
offenders go to the ban set. Protects the host control plane (conntrack,
CPU) from SYN floods and connection floods across all ports, not just
per-forward-rule as today.

### 5. Kernel sysctl baseline *(cost: very low)*

Document (and optionally verify in `deploy.sh`) a host baseline:
`net.ipv4.tcp_syncookies=1`, `rp_filter=1`, ICMP rate limits, conntrack
table sizing. Defensive floor for L3/L4 floods; no rooster code required.

## Batch 2 — L7 layer (audits and caps in `httpguard`)

### 6. Slowloris audit *(cost: low)*

Verify and make explicit: request-header read timeout, request-body read
timeout, minimum read rate, and a per-IP concurrent-connection cap on the
listener. Today these rely on library defaults; slow attacks (slowloris,
slow read, slow body) need explicit, configurable limits.

### 7. TLS ClientHello rate/size caps *(cost: low)*

`clienthello.rs` already peeks ClientHello for SNI passthrough. Add: per-IP
ClientHello rate limit and maximum ClientHello record size → handshake-flood
and oversized-hello exhaustion protection at the cheapest possible point.

### 8. Global request-body size hard cap *(cost: very low)*

A hard global maximum request body size in front of the WAF, independent of
CRS rules. Prevents large-POST resource exhaustion for all sites by default,
with per-site override.

## Boundaries and cautions

- **Volumetric DDoS is out of scope at host level.** Bandwidth saturation
  requires upstream scrubbing/CDN. These measures protect the host control
  plane only — the docs and README must keep that expectation explicit.
- **False positives.** Honeypot/scan-detection rules must exclude real
  listening ports; prefer hub-side aggregation (min-nodes) over tightening
  local thresholds when shared egress IPs are a concern.
- Items 9–11 from the original gap analysis (UDP amplification-factor
  monitoring, credential-stuffing heuristics, egress filtering) are rated
  medium/medium-low cost and are intentionally deferred to a later plan.

## Implementation and verification notes

- Every hardening section is opt-in. Site `max-body-size` only overrides an
  enabled global body cap; it is not a separate enable switch.
- Honeypot and scan detection inspect incoming, original-direction TCP
  connection attempts. Linux TCP listeners are enumerated at validation and
  apply time; services started later require a configuration reapply.
- Scan detection records `(source IP, destination port)` tuples with a
  sliding expiry, rather than counting SYN retransmissions. The promoter
  checks distinct live ports periodically; `find-time` must be at least
  500 ms, and the polling interval is at most half the configured window
  (capped at 2 seconds).
- L4 meter state is separate from the over-limit hit queue. Consuming a hit
  does not reset the source's token bucket. Netlink limit units are seconds;
  element timeouts are milliseconds.
- Slowloris enforcement covers header deadlines, request-body frame idle
  timeouts (including WAF-off and streamed remainder paths), and per-IP
  connection caps. A minimum sustained read-rate policy is not implemented.
- ClientHello caps exclude application records coalesced after a complete
  hello. With the section disabled, reaching the peek ceiling retains the
  previous passthrough behavior.

Focused verification:

```sh
cargo test --workspace --locked
npm --prefix web run build
ROOSTER_NFT_HOST_NETNS="$(readlink /proc/self/ns/net)" \
  unshare -Urn env ROOSTER_NFT_KTEST=1 \
  cargo test -p rooster-nft --test hardening_kernel -- --ignored --test-threads=1
```

The explicit kernel suite refuses the host network namespace. It exercises
below/above-rate traffic, distinct IPv4/IPv6 port tuples, normal ACK delivery,
outbound honeypot replies, repeated apply, and cleanup with missing legacy
sets. These tests do not replace deployment-specific VM or frontend checks.
