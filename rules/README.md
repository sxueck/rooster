# rules

Built-in WAF signatures and the OWASP CRS (Paranoia Level 1–2) subset
consumed by `rooster-waf`. This directory is embedded into the agent binary
at build time (see `crates/rooster-agent/build.rs`) and materialized on
nodes when no operator-provided rule directory exists.
