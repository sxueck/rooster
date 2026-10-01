# syntax=docker/dockerfile:1

# --- web panel ---
FROM node:22-alpine AS panel
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# --- backend: single binary that serves both `agent` and `hub` ---
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
# rules/ is embedded into the binary by crates/rooster-agent/build.rs
COPY rules/ rules/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --bin rooster \
    && cp target/release/rooster /usr/local/bin/rooster

FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="rooster"
LABEL org.opencontainers.image.description="port protection agent + management hub"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/rooster /usr/local/bin/rooster
# hub's default panel-dir is `web/dist`, resolved relative to the workdir
COPY --from=panel /src/web/dist /usr/share/rooster/web/dist
WORKDIR /usr/share/rooster
VOLUME /var/lib/rooster-hub
# 80/443: agent proxy; 9443: hub (API + panel + agent WebSocket)
EXPOSE 80 443 9443
ENTRYPOINT ["/usr/local/bin/rooster"]
CMD ["hub", "--config", "/etc/rooster/hub.yaml"]
