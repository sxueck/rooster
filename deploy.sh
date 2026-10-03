#!/usr/bin/env bash
# Interactive deployment helper for Rooster (https://github.com/sxueck/rooster).
# Deploys the management hub (Docker or native+systemd) or enrolls an agent node.
set -euo pipefail

IMAGE="ghcr.io/sxueck/rooster"
REPO_URL="https://github.com/sxueck/rooster"
HUB_CONTAINER="rooster-hub"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  B="\033[1m"; DIM="\033[2m"; G="\033[32m"; Y="\033[33m"; R="\033[31m"; N="\033[0m"
else
  B=""; DIM=""; G=""; Y=""; R=""; N=""
fi

say()  { printf "%b\n" "$*"; }
die()  { printf "%b\n" "${R}error:${N} $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

STEP_NO=0
step() { STEP_NO=$((STEP_NO + 1)); say "\n${B}[${STEP_NO}] $*$N"; }

# fetch URL OUTPUT [extra curl args...] -> visible download with timeouts and
# a cause hint on failure; returns curl's exit code so callers keep control
fetch() {
  local url="$1" out="$2" rc=0
  shift 2
  say "${DIM}downloading $url ...${N}"
  curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 "$@" "$url" -o "$out" || rc=$?
  if [ "$rc" -ne 0 ]; then
    case "$url" in
      https://raw.githubusercontent.com/*)
        say "${Y}hint: raw.githubusercontent.com is blocked or DNS-poisoned on some networks${N}" >&2
        say "${Y}(404/reset). Retry with 'export https_proxy=...' set, or download the script${N}" >&2
        say "${Y}manually and run it from a local file.${N}" >&2 ;;
      *)
        say "${Y}hint: could not download $url (curl exit $rc).${N}" >&2 ;;
    esac
  fi
  return "$rc"
}

# prompts must not read stdin: under `curl ... | bash` stdin is the script
# pipe itself, so interactive answers come from the terminal instead
read_tty() {
  if [ -t 0 ]; then read "$@"
  elif read "$@" 2>/dev/null </dev/tty; then :
  else read "$@"
  fi
}

# ask PROMPT [DEFAULT] -> prints the answer
ask() {
  local p="$1" d="${2:-}" a
  if [ -n "$d" ]; then p="$p ${DIM}[$d]${N}"; fi
  printf "%b" "$p: " >&2
  read_tty -r a
  echo "${a:-$d}"
}

# ask_secret PROMPT -> prints the answer; empty input generates a random secret
ask_secret() {
  local a
  printf "%b" "$1 ${DIM}(empty = autogenerate)${N}: " >&2
  read_tty -rs a; printf "\n" >&2
  if [ -z "$a" ]; then
    a="$(openssl rand -base64 18)"
    say "${DIM}password generated; it will be saved to .env.passwd${N}" >&2
  fi
  echo "$a"
}

# choose PROMPT OPT1 OPT2... -> prints the chosen option string
choose() {
  local p="$1" i=1 opt
  shift
  say "$B$p$N" >&2
  for opt in "$@"; do say "  $i) $opt" >&2; i=$((i + 1)); done
  local n sel
  n=$#
  while :; do
    printf "%b" "select ${DIM}[1-$n]${N}: " >&2
    read_tty -r sel
    sel="${sel:-1}"
    case "$sel" in (*[!0-9]*|'') ;; (*) [ "$sel" -ge 1 ] && [ "$sel" -le "$n" ] && break ;; esac
    say "${Y}invalid choice${N}" >&2
  done
  i=1
  for opt in "$@"; do [ "$i" -eq "$sel" ] && { echo "$opt"; return; }; i=$((i + 1)); done
}

as_root() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

detect_ip() {
  hostname -I 2>/dev/null | awk '{print $1}'
}

save_password() (
  umask 077
  printf 'ROOSTER_ADMIN_PASSWORD=%q\n' "$2" > "$1"
  chmod 600 "$1"
)

# gen_tls DIR HOSTS [reuse] -> SANs belong to the server certificate, not the CA.
gen_tls() (
  umask 077
  local dir="$1" host="$2" reuse="${3:-new}" san name cn=""
  san="DNS:localhost,IP:127.0.0.1"
  # SANs come only from the prompt: hosts may be comma-separated so later
  # forward/proxy addresses end up on the same certificate — agents and
  # browsers verify the address they dial
  local -a names
  IFS=',' read -r -a names <<< "$host"
  for name in "${names[@]}"; do
    name="${name//[[:space:]]/}"
    name="${name#[}"; name="${name%]}"
    [[ "$name" =~ ^[a-zA-Z0-9.*:-]+$ ]] || die "invalid SAN: use bare DNS names or IPs, comma-separated"
    [ -n "$cn" ] || cn="$name"
    if [[ "$name" = *:* || "$name" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      san="$san,IP:$name"
    else
      san="$san,DNS:$name"
    fi
  done
  [ -n "$cn" ] || die "at least one SAN is required"
  mkdir -p "$dir"
  if [ "$reuse" = reuse ]; then
    [ -f "$dir/ca.key" ] && [ -f "$dir/ca.crt" ] || die "existing CA certificate and private key required"
  else
    openssl ecparam -name prime256v1 -genkey -noout -out "$dir/ca.key" 2>/dev/null
    openssl req -x509 -new -key "$dir/ca.key" -subj "/CN=rooster-hub-ca" -days 3650 -out "$dir/ca.crt" 2>/dev/null
  fi
  openssl ecparam -name prime256v1 -genkey -noout -out "$dir/hub.key" 2>/dev/null
  openssl req -new -key "$dir/hub.key" -subj "/CN=$cn" -out "$dir/hub.csr" 2>/dev/null
  openssl x509 -req -in "$dir/hub.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
    -days 825 -extfile <(printf "subjectAltName=%s" "$san") -out "$dir/hub.crt" 2>/dev/null
  rm -f "$dir/hub.csr" "$dir/ca.srl"
  chmod 600 "$dir/ca.key" "$dir/hub.key"
  openssl verify -CAfile "$dir/ca.crt" "$dir/hub.crt" >/dev/null
)

# gen_release_key DIR -> prints the `ed25519:<base64>` upgrade public key.
# Writes release-ed25519.key (0600, kept next to hub.yaml) for offline
# package signing. Whoever holds this key can push binaries to every agent,
# so it must stay on the operator machine — never in git or on the hub's
# panel-visible surface.
gen_release_key() (
  umask 077
  local dir="$1" raw
  # 不能与 dir 同行声明:set -u 下同一 local 语句的展开先于赋值
  local key="$dir/release-ed25519.key"
  [ -f "$key" ] || openssl genpkey -algorithm ed25519 -out "$key" 2>/dev/null
  chmod 600 "$key"
  # raw 32-byte public key: DER drops the fixed 12-byte SPKI prefix
  raw="$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0)"
  [ -n "$raw" ] || die "release keypair generation failed"
  printf 'ed25519:%s' "$raw"
)

certificate_host() {
  openssl x509 -in "$1" -noout -ext subjectAltName |
    awk -F ',[[:space:]]*' '/DNS:|IP Address:/ {for (i=1; i<=NF; i++) {
      sub(/^[[:space:]]*/, "", $i)
      if ($i ~ /^DNS:/ && $i !~ /\*/) {sub(/^DNS:/, "", $i); print $i; exit}
      if ($i ~ /^IP Address:/) {sub(/^IP Address:/, "", $i); print $i; exit}
    }}'
}

write_hub_config() {
  local file="$1" secret="$2" mode="${3:-static}" port="${4:-9443}"
  local panel="${5:-web/dist}" ca="${6:-yes}" public="${7:-}" upgrade_pub="${8:-}" agent="${9:-}" s
  # YAML double-quoted style: escape backslash and quote (printf, not heredoc,
  # so the secret never undergoes shell expansion)
  s=${secret//\\/\\\\}; s=${s//\"/\\\"}
  {
    printf '%s\n' '# rooster hub configuration, generated by deploy.sh'
    if [ "$mode" = "plain" ] || [ "$mode" = "plain-docker" ]; then
      if [ "$mode" = "plain-docker" ]; then
        # bridge network: published ports cannot reach a loopback bind, so
        # the in-container listen is 0.0.0.0:9443; host exposure stays bounded
        # by compose's 127.0.0.1 publish + ROOSTER_ALLOW_PLAIN_NON_LOOPBACK
        printf '%s\n' 'listen: 0.0.0.0:9443'
      else
        printf 'listen: 127.0.0.1:%s\n' "$port"
      fi
      printf '%s\n' 'data-dir: /var/lib/rooster-hub'
      printf '%s\n' 'tls:'
      printf '%s\n' '  mode: none'
    else
      printf 'listen: 0.0.0.0:%s\n' "$port"
      printf '%s\n' 'data-dir: /var/lib/rooster-hub'
      printf '%s\n' 'tls:'
      printf '%s\n' '  mode: static'
      printf '%s\n' '  cert: /etc/rooster/tls/hub.crt'
      printf '%s\n' '  key: /etc/rooster/tls/hub.key'
      if [ "$ca" = "yes" ]; then printf '%s\n' '  ca: /etc/rooster/tls/ca.crt'; fi
    fi
    [ -z "$public" ] || printf 'public-url: "%s"\n' "$public"
    [ -z "$agent" ] || printf 'agent-url: "%s"\n' "$agent"
    printf 'secret-key: "%s"\n' "$s"
    printf '%s\n' 'session-ttl: 12h'
    printf 'panel-dir: %s\n' "$panel"
    printf '%s\n' 'auto-confirm-delay-secs: 10'
    printf '%s\n' 'audit-retention: 180d'
    [ -z "$upgrade_pub" ] || printf 'upgrade-public-key: "%s"\n' "$upgrade_pub"
  } > "$file"
  chmod 600 "$file"
}

# static 模式下 Agent 必须拨 Hub 自己的 TLS 端口(客户端证书得端到端到达
# hub);L7 反代的 Host 头不带端口,推不出这个地址。这里的 port 是宿主机侧
# 暴露的端口(docker 映射后的 host 端口,不是容器内 9443)。plain 模式不写:
# 那里 TLS 在上游终止,origin 本就该跟着请求走。
agent_origin() {
  local mode="$1" host="$2" port="$3"
  [ "$mode" = "static" ] || return 0
  printf 'https://%s:%s' "$host" "$port"
}

wait_hub() {
  local port="$1" mode="$2" host="$3" ca="$4" i response url error rc
  host="${host//[[:space:]]/}"
  host="${host#[}"; host="${host%]}"
  error="$(mktemp)"
  local -a args=(--silent --show-error --fail --noproxy '*' --connect-timeout 1 --max-time 2)
  url="http://127.0.0.1:$port/healthz"
  if [ "$mode" = "static" ]; then
    [[ "$host" = *:* ]] && host="[$host]"
    url="https://$host:$port/healthz"
    args+=(--connect-to "$host:$port:127.0.0.1:$port")
    [ -n "$ca" ] && args+=(--cacert "$ca")
  fi
  say "${DIM}waiting for the hub to come up (30 probes, up to ~90s) ...${N}"
  for i in $(seq 1 30); do
    rc=0
    response="$(curl "${args[@]}" -w '\n%{http_code}' "$url" 2>"$error")" || rc=$?
    # Some TLS backends report EOF (56) after a complete HTTP/1.0 response.
    if { [ "$rc" -eq 0 ] || [ "$rc" -eq 56 ]; } && [ "$response" = $'ok\n200' ]; then
      rm -f "$error"
      say "${G}hub is up.${N}"; return 0
    fi
    printf '%b' "${DIM}.${N}"
    sleep 1
  done
  say ""
  [ ! -s "$error" ] || while IFS= read -r response; do printf '%s\n' "$response" >&2; done < "$error"
  rm -f "$error"
  die "hub health check failed after 30 probes: $url via 127.0.0.1:$port (check: docker logs $HUB_CONTAINER / journalctl -u rooster-hub)"
}

join_hint() {
  local host="$1" port="$2" selfsigned="$3"
  [[ "$host" = *:* ]] && host="[$host]"
  local hub="https://$host:$port" ca_arg=""
  [ "$selfsigned" != yes ] || ca_arg=" --ca-sha256 CA_SHA256_FROM_TRUSTED_PANEL"
  say ""
  say "$B>Add agent nodes$N"
  say "  1. open the panel -> ${B}节点 → 添加节点${N} -> copy the one-time token"
  say "  2. on the node run:"
  say "     curl -fsSL https://raw.githubusercontent.com/sxueck/rooster/main/enroll.sh -o /tmp/rooster-enroll.sh"
  say "     sudo sh /tmp/rooster-enroll.sh --hub $hub --token TOKEN$ca_arg"
  say "  ${DIM}note: until you upload a signed release package, the hub can only serve its"
  say "  own unsigned binary — add --allow-unsigned for same-arch dev installs.${N}"
}

nginx_hint() {
  local host="$1" port="${2:-9443}" pubport="${3:-443}"
  say ""
  say "$B>nginx server block (TLS termination)$N"
  say "  server {"
  say "      listen $pubport ssl;"
  say "      server_name $host;"
  say "      ssl_certificate     /path/to/fullchain.pem;"
  say "      ssl_certificate_key /path/to/privkey.pem;"
  say "      location / {"
  say "          proxy_pass http://127.0.0.1:$port;"
  say "          proxy_http_version 1.1;"
  say "          proxy_set_header Upgrade \$http_upgrade;"
  say "          proxy_set_header Connection \"upgrade\";"
  say "          proxy_set_header Host \$host;"
  say "          proxy_read_timeout 3600s; ${DIM}# keep agent WebSockets alive${N}"
  say "      }"
  say "  }"
  say "  ${DIM}alternative — use a static-TLS hub for L4 passthrough + client-cert auth:${N}"
  say "  ${DIM}  stream { server { listen $pubport; proxy_pass 127.0.0.1:$port; } }${N}"
}

# ---------------- hub: docker ----------------
deploy_hub_docker() (
  umask 077
  local stage
  stage="$(mktemp -d)"
  trap 'rm -rf "$stage"' EXIT
  have docker || die "docker not found (https://docs.docker.com/engine/install/)"
  docker compose version >/dev/null 2>&1 || die "docker compose plugin not found (https://docs.docker.com/compose/install/)"
  have openssl || die "openssl not found"
  have curl || die "curl not found"
  step "checking prerequisites (docker, compose plugin, openssl, curl)"

  local ip host hosts port pubport secret dir selfsigned tlsdir hubmode ca="" names recreate=no plain_migrate=no
  ip="$(detect_ip)"
  hosts="$(ask "public hostname(s)/IP(s) agents and the panel will use (comma-separated)" "${ip:-127.0.0.1}")"
  host="${hosts%%,*}"
  port="$(ask "listen port" 9443)"
  [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || die "invalid listen port"
  secret="$(ask_secret "panel admin password")"
  dir="$(ask "config directory (created if missing)" "$PWD/rooster-hub")"
  names="$(docker ps -a --format '{{.Names}}')"
  if grep -qx "$HUB_CONTAINER" <<< "$names"; then
    [ "$(choose "container '$HUB_CONTAINER' exists" "abort" "overwrite installation (back up and retain configuration/data)")" = "abort" ] && die "aborted"
    recreate=yes
  fi
  local existing=no
  [ ! -f "$dir/hub.yaml" ] || existing=yes
  if [ "$existing" = yes ]; then
    cp -a "$dir/hub.yaml" "$stage/hub.yaml"
    [ ! -d "$dir/tls" ] || cp -a "$dir/tls" "$stage/tls"
    hubmode=static; selfsigned=yes
    grep -Eq '^[[:space:]]*mode:[[:space:]]*none' "$stage/hub.yaml" && { hubmode=plain; selfsigned=nginx; }
    pubport="$port"
    if [ "$hubmode" = plain ]; then
      port="$(awk '/^listen:/ {n=split($2,a,":"); print a[n]}' "$stage/hub.yaml")"
      [[ "$port" =~ ^[0-9]{1,5}$ ]] || die "cannot read existing hub listen port"
      plain_migrate=yes
      pubport="$(ask "public HTTPS port at the TLS terminator" 443)"
    elif [ ! -f "$stage/tls/ca.crt" ]; then
      selfsigned=no
    fi
    say "${DIM}Retaining existing hub.yaml, admin password and TLS; prompt values do not replace them.${N}"
  else
  selfsigned="$(choose "TLS certificate" \
    "auto-generate self-signed (agents verify the panel's CA fingerprint)" \
    "use my own cert/key (entered next)" \
    "upstream TLS termination (nginx etc.) — hub serves plain HTTP on loopback")"

  mkdir -p "$stage/tls"
  tlsdir="$stage/tls"
  hubmode="static"
  case "$selfsigned" in
    "use my own cert/key (entered next)")
      local cert key ca
      cert="$(ask "server certificate path")"; key="$(ask "server key path")"
      ca="$(ask "CA certificate path served to agents (empty = public CA)")"
      cp "$cert" "$tlsdir/hub.crt"; cp "$key" "$tlsdir/hub.key"; chmod 600 "$tlsdir/hub.key"
      if [ -n "$ca" ]; then cp "$ca" "$tlsdir/ca.crt"; else rm -f "$tlsdir/ca.crt"; fi
      selfsigned="no"
      ;;
    "upstream TLS termination (nginx etc.) — hub serves plain HTTP on loopback")
      selfsigned="nginx"; hubmode="plain"
      rm -f "$tlsdir/ca.crt" "$tlsdir/hub.crt" "$tlsdir/hub.key"
      pubport="$(ask "public HTTPS port at the TLS terminator (agents use it too)" 443)"
      ;;
    *)
      gen_tls "$tlsdir" "$hosts"
      selfsigned="yes"
      ;;
  esac

  local bindport=9443 ca_config=no
  # plain mode runs under compose.host.yaml's bridge network: the in-container
  # listen is fixed at 0.0.0.0:9443 (published ports cannot reach a loopback
  # bind); the selected port stays on the host side via ROOSTER_PORT
  if [ -f "$tlsdir/ca.crt" ]; then ca="$tlsdir/ca.crt"; ca_config=yes; fi
  local publichost="$host" publicport="$port"
  [[ "$publichost" != *:* ]] || publichost="[$publichost]"
  [ "$hubmode" != plain ] || publicport="$pubport"
  local cfg_mode="$hubmode"
  [ "$hubmode" = "plain" ] && cfg_mode="plain-docker"
  local rel_pub
  rel_pub="$(gen_release_key "$stage")"
  write_hub_config "$stage/hub.yaml" "$secret" "$cfg_mode" "$bindport" web/dist "$ca_config" "https://$publichost:$publicport" "$rel_pub" "$(agent_origin "$cfg_mode" "$publichost" "$port")"
  fi
  tlsdir="$stage/tls"
  [ ! -f "$tlsdir/ca.crt" ] || ca="$tlsdir/ca.crt"
  local compose_file=compose.yaml
  [ "$hubmode" = "plain" ] && compose_file=compose.host.yaml
  step "fetching $compose_file from the repository"
  fetch "https://raw.githubusercontent.com/sxueck/rooster/main/$compose_file" "$stage/compose.yaml" \
    || die "failed to download Compose file; existing container was not removed"
  printf 'COMPOSE_PROJECT_NAME=rooster-hub\nROOSTER_PORT=%s\n' "$port" > "$stage/.env"
  docker compose --project-directory "$stage" config --quiet
  step "pulling image $IMAGE (layer progress below)"
  docker compose --project-directory "$stage" pull
  mkdir -p "$dir"
  dir="$(cd "$dir" && pwd -P)"
  local backup file
  backup="$(mktemp -d "$dir/install-backup.XXXXXXXX")"
  for file in hub.yaml tls compose.yaml .env .env.passwd; do
    [ ! -e "$dir/$file" ] || cp -a "$dir/$file" "$backup/"
  done
  for file in compose.yaml .env; do install -m600 "$stage/$file" "$dir/.$file.new"; mv -f "$dir/.$file.new" "$dir/$file"; done
  if [ "$existing" = no ]; then
    install -m600 "$stage/hub.yaml" "$dir/.hub.yaml.new"
    mv -f "$dir/.hub.yaml.new" "$dir/hub.yaml"
    cp -a "$stage/tls" "$dir/"
    install -m600 "$stage/release-ed25519.key" "$dir/release-ed25519.key"
    save_password "$dir/.env.passwd" "$secret"
    say "  password: $dir/.env.passwd (keep private)"
  else
    # pre-keyed installs keep their existing release keypair; older
    # deployments upgrade in place by appending the line once
    if ! grep -q '^upgrade-public-key:' "$dir/hub.yaml"; then
      local rel_pub
      rel_pub="$(gen_release_key "$dir")"
      printf 'upgrade-public-key: "%s"\n' "$rel_pub" >> "$dir/hub.yaml"
    fi
  fi
  tlsdir="$dir/tls"; ca=""
  [ ! -f "$tlsdir/ca.crt" ] || ca="$tlsdir/ca.crt"
  if [ "$plain_migrate" = yes ]; then
    # old plain installs bound 127.0.0.1 on the host network; bridge compose
    # needs an in-container 0.0.0.0 bind for the published port (host exposure
    # stays loopback-only via the 127.0.0.1 publish)
    sed -i 's#^listen:[[:space:]].*#listen: 0.0.0.0:9443#' "$dir/hub.yaml"
  fi
  if [ "$recreate" = "yes" ]; then docker rm -f "$HUB_CONTAINER" >/dev/null; fi
  step "starting the hub container"
  docker compose --project-directory "$dir" up -d

  local probe_host="$host"
  if [ "$existing" = yes ] && [ "$hubmode" = static ] && [ -f "$tlsdir/hub.crt" ]; then
    probe_host="$(certificate_host "$tlsdir/hub.crt")"
    [ -n "$probe_host" ] || probe_host="$host"
  fi
  wait_hub "$port" "$hubmode" "$probe_host" "$ca"

  say ""
  say "$B>Hub deployed (Docker Compose)$N"
  printf '  start:    cd %q && docker compose up -d\n' "$dir"
  printf '  stop:     cd %q && docker compose down\n' "$dir"
  printf '  upgrade:  cd %q && docker compose pull && docker compose up -d\n' "$dir"
  say "  ${DIM}docker compose down keeps data; do not use down -v unless deleting hub data.${N}"
  if [ "$hubmode" = "plain" ]; then
    say "  panel:    https://$host:$pubport/   (served through your TLS terminator)"
    say "  hub:      http://127.0.0.1:$port (plain mode, loopback only, host network)"
    say "  config:   $dir/hub.yaml"
    say "  data:     docker volume rooster-hub-data"
    say "  logs:     docker logs -f $HUB_CONTAINER"
    say "  backup:   docker exec $HUB_CONTAINER rooster hub --config /etc/rooster/hub.yaml backup --out /tmp/backup"
    nginx_hint "$host" "$port" "$pubport"
    say "  ${Y}note: TLS ends at the terminator — the agent control channel loses its"
    say "  ${Y}TLS-layer client-cert auth. For internet-facing hubs prefer the static${N}"
    say "  ${Y}path, or make nginx an L4 stream passthrough.${N}"
    join_hint "$host" "$pubport" "no"
  else
    say "  panel:    https://$host:$port/   (login with the admin password you set)"
    say "  config:   $dir/hub.yaml        (hashed on first start)"
    say "  tls:      $tlsdir"
    say "  data:     docker volume rooster-hub-data"
    say "  logs:     docker logs -f $HUB_CONTAINER"
    say "  backup:   docker exec $HUB_CONTAINER rooster hub --config /etc/rooster/hub.yaml backup --out /tmp/backup"
    [ "$selfsigned" = "yes" ] && say "  ${DIM}self-signed CA: use the panel's fingerprint-verified enrollment command.${N}"
    join_hint "$host" "$port" "$selfsigned"
  fi
  say "  ${DIM}Release keypair: $dir/release-ed25519.key (keep private, offline). Sign packages with:${N}"
  say "  ${DIM}  openssl pkeyutl -sign -inkey $dir/release-ed25519.key -rawin -in rooster-VERSION-ARCH -out sig.raw${N}"
  say "  ${DIM}then upload package + base64 signature in the panel. Never use --allow-unsigned implicitly.${N}"
)

# ---------------- hub: source + systemd ----------------
deploy_hub_native() (
  umask 077
  have cargo || die "cargo not found (https://rustup.rs)"
  have npm || die "npm not found (Node 22: https://nodejs.org)"
  have openssl || die "openssl not found"
  have curl || die "curl not found"
  have make || die "make not found"
  step "checking prerequisites (cargo, npm, openssl, curl, make)"

  local ip host hosts port pubport secret dir="/etc/rooster" selfsigned tlsdir hubmode work ca=""
  local existing=no
  if as_root test -f "$dir/hub.yaml"; then
    existing=yes
    say "${DIM}Existing hub config/TLS and data will be retained; installed artifacts will be backed up.${N}"
  fi
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  ip="$(detect_ip)"
  hosts="$(ask "public hostname(s)/IP(s) agents and the panel will use (comma-separated)" "${ip:-127.0.0.1}")"
  host="${hosts%%,*}"
  port="$(ask "listen port" 9443)"
  secret="$(ask_secret "panel admin password")"
  selfsigned="$(choose "TLS certificate" \
    "auto-generate self-signed (recommended)" \
    "use my own cert/key (entered next)" \
    "upstream TLS termination (nginx etc.) — hub serves plain HTTP on loopback")"

  step "cloning + building from source (npm/cargo output below; this takes several minutes)"
  if [ ! -f Cargo.toml ]; then
    have git || die "git not found"
    # clone into the scratch dir: `curl | bash` usually starts in a
    # non-empty directory where `git clone ... .` would fail
    git clone --depth 1 "$REPO_URL.git" "$work/src"
    cd "$work/src"
  fi
  npm --prefix web ci --no-audit --no-fund
  make all

  tlsdir="$work/tls"
  mkdir -p "$tlsdir"
  hubmode="static"
  case "$selfsigned" in
    "use my own cert/key (entered next)")
      local cert key ca
      cert="$(ask "server certificate path")"; key="$(ask "server key path")"
      ca="$(ask "CA certificate path served to agents (empty = public CA)")"
      cp "$cert" "$tlsdir/hub.crt"; cp "$key" "$tlsdir/hub.key"
      chmod 600 "$tlsdir/hub.key"
      if [ -n "$ca" ]; then cp "$ca" "$tlsdir/ca.crt"; fi
      selfsigned="no"
      ;;
    "upstream TLS termination (nginx etc.) — hub serves plain HTTP on loopback")
      selfsigned="nginx"; hubmode="plain"
      rm -f "$tlsdir/ca.crt" "$tlsdir/hub.crt" "$tlsdir/hub.key"
      pubport="$(ask "public HTTPS port at the TLS terminator (agents use it too)" 443)"
      ;;
    *)
      gen_tls "$tlsdir" "$hosts"
      selfsigned="yes"
      ;;
  esac
  local ca_config=no
  if [ -f "$tlsdir/ca.crt" ]; then ca="$tlsdir/ca.crt"; ca_config=yes; fi
  local publichost="$host" publicport="$port" backup
  [[ "$publichost" != *:* ]] || publichost="[$publichost]"
  [ "$hubmode" != plain ] || publicport="$pubport"
  local rel_pub
  rel_pub="$(gen_release_key "$work")"
  write_hub_config "$work/hub.yaml" "$secret" "$hubmode" "$port" /usr/share/rooster/web/dist "$ca_config" "https://$publichost:$publicport" "$rel_pub" "$(agent_origin "$hubmode" "$publichost" "$port")"
  step "installing binary, panel and systemd service (existing files backed up)"
  as_root mkdir -p "$dir"
  backup="$(as_root mktemp -d "$dir/install-backup.XXXXXXXX")"
  for file in "$dir/hub.yaml" "$dir/tls" "$dir/.env.passwd" /usr/local/bin/rooster /usr/share/rooster/web/dist /etc/systemd/system/rooster-hub.service; do
    if as_root test -e "$file"; then as_root cp -a "$file" "$backup/"; fi
  done
  as_root install -Dm755 target/release/rooster /usr/local/bin/rooster
  as_root mkdir -p "$dir" /var/lib/rooster-hub /usr/share/rooster/web/dist
  as_root cp -a web/dist/. /usr/share/rooster/web/dist/
  if [ "$hubmode" = "static" ] && [ "$existing" = no ]; then
    as_root mkdir -p "$dir/tls"
    as_root cp -r "$tlsdir/." "$dir/tls/"
  fi
  if [ "$existing" = no ]; then
    as_root install -m600 "$work/hub.yaml" "$dir/hub.yaml"
    save_password "$work/.env.passwd" "$secret"
    as_root install -m600 "$work/.env.passwd" "$dir/.env.passwd"
    as_root install -m600 "$work/release-ed25519.key" "$dir/release-ed25519.key"
    say "  password: $dir/.env.passwd (keep private)"
  else
    as_root cp "$dir/hub.yaml" "$work/hub.yaml"
    as_root chown "$(id -u)" "$work/hub.yaml"
    if ! as_root grep -q '^upgrade-public-key:' "$dir/hub.yaml"; then
      local rel_pub
      rel_pub="$(gen_release_key "$work")"
      printf 'upgrade-public-key: "%s"\n' "$rel_pub" | as_root tee -a "$dir/hub.yaml" >/dev/null
    fi
    hubmode=static
    grep -Eq '^[[:space:]]*mode:[[:space:]]*none' "$work/hub.yaml" && hubmode=plain
    port="$(awk '/^listen:/ {n=split($2,a,":"); print a[n]}' "$work/hub.yaml")"
    ca=""
    if as_root test -f "$dir/tls/ca.crt"; then as_root cp "$dir/tls/ca.crt" "$work/existing-ca.crt"; as_root chown "$(id -u)" "$work/existing-ca.crt"; ca="$work/existing-ca.crt"; fi
  fi

  as_root tee /etc/systemd/system/rooster-hub.service >/dev/null <<'EOF'
[Unit]
Description=Rooster management hub
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/rooster hub --config /etc/rooster/hub.yaml
Restart=on-failure
RestartSec=3
StateDirectory=rooster-hub
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/etc/rooster /var/lib/rooster-hub

[Install]
WantedBy=multi-user.target
EOF
  step "starting the rooster-hub service"
  as_root systemctl daemon-reload
  as_root systemctl enable rooster-hub
  as_root systemctl restart rooster-hub
  say "${DIM}Release keypair: $dir/release-ed25519.key (keep private, offline); upgrade-public-key is in hub.yaml. Sign with${N}"
  say "${DIM}openssl pkeyutl -sign -inkey $dir/release-ed25519.key -rawin, then upload in the panel.${N}"

  wait_hub "$port" "$hubmode" "$host" "$ca"

  say ""
  say "$B>Hub deployed (native + systemd)$N"
  if [ "$hubmode" = "plain" ]; then
    say "  panel:    https://$host:$pubport/   (served through your TLS terminator)"
    say "  hub:      http://127.0.0.1:$port (plain mode, loopback only)"
    say "  config:   $dir/hub.yaml"
    say "  service:  systemctl status rooster-hub"
    say "  upgrade:  rebuild + reinstall the binary and panel, then sudo systemctl restart rooster-hub"
    nginx_hint "$host" "$port" "$pubport"
    say "  ${Y}note: TLS ends at the terminator — the agent control channel loses its"
    say "  ${Y}TLS-layer client-cert auth. For internet-facing hubs prefer the static${N}"
    say "  ${Y}path, or make nginx an L4 stream passthrough.${N}"
    join_hint "$host" "$pubport" "no"
  else
    say "  panel:    https://$host:$port/"
    say "  config:   $dir/hub.yaml"
    say "  service:  systemctl status rooster-hub"
    say "  upgrade:  rebuild + reinstall the binary and panel, then sudo systemctl restart rooster-hub"
    join_hint "$host" "$port" "$selfsigned"
  fi
)

# ---------------- agent: join a hub ----------------
deploy_agent_join() (
  have curl || die "curl not found"
  local hub token selfsigned script policy
  local -a args=()
  hub="$(ask "hub URL (as shown by the panel)" "https://$(detect_ip):9443")"
  selfsigned="$(choose "hub certificate" "self-signed / private CA (verify CA fingerprint from trusted panel)" "public CA (no extra flag)")"
  say "get the one-time token: panel -> ${B}节点 → 添加节点${N}"
  token="$(ask "one-time token")"
  [ -n "$token" ] || die "token required"
  [ "$(id -u)" -eq 0 ] || have sudo || die "need root or sudo to install"

  policy="$(choose "binary verification" "require a signed release (recommended)" "allow the hub's unsigned binary (same-arch only)")"
  [ "$policy" = "allow the hub's unsigned binary (same-arch only)" ] && args+=(--allow-unsigned)
  script="$(mktemp)"
  trap 'rm -f "$script"' EXIT
  if [ "$selfsigned" = "self-signed / private CA (verify CA fingerprint from trusted panel)" ]; then
    local fingerprint
    fingerprint="$(ask "CA SHA-256 fingerprint from the trusted panel enrollment command")"
    [[ "$fingerprint" =~ ^[0-9a-fA-F]{64}$ ]] || die "invalid CA SHA-256 fingerprint"
    args+=(--ca-sha256 "$fingerprint")
  fi
  step "fetching enroll.sh"
  fetch "https://raw.githubusercontent.com/sxueck/rooster/main/enroll.sh" "$script" \
    || die "could not download enroll.sh"
  step "running the agent installer (installs /usr/local/bin/rooster + the rooster systemd service)"
  as_root sh "$script" --hub "$hub" --token "$token" "${args[@]}"

  say ""
  say "$B>Agent enrolled$N"
  say "  service:  systemctl status rooster"
  say "  config:   /etc/rooster/config.yaml"
  say "  ${DIM}the registration token can be removed from the config once the node shows online in the panel${N}"
)

# ---------------- agent: docker ----------------
deploy_agent_docker() {
  have docker || die "docker not found"
  say "${Y}the agent bans via nftables on the HOST kernel — it needs host networking"
  say "and NET_ADMIN; for production prefer the install.sh enrollment.${N}"
  local dir
  dir="$(ask "directory containing an enrolled config.yaml" "/etc/rooster")"
  [ -f "$dir/config.yaml" ] || die "no config.yaml in $dir (enroll via install.sh first, or write one)"
  dir="$(cd "$dir" && pwd -P)"
  step "pulling image $IMAGE:latest (layer progress below)"
  docker pull "$IMAGE:latest"
  step "starting the agent container (host network + NET_ADMIN)"
  docker rm -f rooster-agent >/dev/null 2>&1 || true
  docker run -d --name rooster-agent --restart unless-stopped \
    --network host --cap-add NET_ADMIN \
    -v "$dir:/etc/rooster" \
    "$IMAGE" agent --config /etc/rooster/config.yaml >/dev/null
  say ""
  say "$B>Agent container started$N — logs: docker logs -f rooster-agent"
}

renew_hub_tls() (
  umask 077
  have openssl || die "openssl not found"
  have curl || die "curl not found"
  local target dir work hosts host port publicport policy backup file
  target="$(choose "existing hub installation" "Docker Compose" "native + systemd")"
  if [ "$target" = "Docker Compose" ]; then
    dir="$(ask "config directory" "$PWD/rooster-hub")"
    have docker || die "docker not found"
  else
    dir="$(ask "config directory" /etc/rooster)"
  fi
  tls_cmd() {
    if [ "$target" = "Docker Compose" ]; then "$@"; else as_root "$@"; fi
  }
  tls_cmd test -f "$dir/hub.yaml" || die "no hub.yaml in $dir"
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  tls_cmd cp "$dir/hub.yaml" "$work/hub.yaml"
  tls_cmd chown "$(id -u)" "$work/hub.yaml"
  grep -Eq '^[[:space:]]*mode:[[:space:]]*static' "$work/hub.yaml" || die "renewal requires static TLS"
  grep -Eq '^[[:space:]]*cert:[[:space:]]*/etc/rooster/tls/hub.crt[[:space:]]*$' "$work/hub.yaml" &&
    grep -Eq '^[[:space:]]*key:[[:space:]]*/etc/rooster/tls/hub.key[[:space:]]*$' "$work/hub.yaml" || die "renewal only supports deploy.sh-managed TLS paths"
  port="$(awk '/^listen:/ {n=split($2,a,":"); print a[n]}' "$work/hub.yaml")"
  if [ "$target" = "Docker Compose" ]; then
    port="$(awk -F= '/^ROOSTER_PORT=/ {print $2}' "$dir/.env")"
    port="${port:-9443}"
  fi
  [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || die "invalid existing listen port"
  hosts="$(ask "all SAN hostname(s)/IP(s) to retain or add (comma-separated)")"
  host="${hosts%%,*}"; host="${host//[[:space:]]/}"
  host="${host#[}"; host="${host%]}"
  publicport="$(ask "public HTTPS port (may differ behind a proxy)" "$port")"
  [[ "$publicport" =~ ^[0-9]{1,5}$ ]] && ((10#$publicport >= 1 && 10#$publicport <= 65535)) || die "invalid public HTTPS port"
  policy="$(choose "certificate renewal" "retain CA; reissue server certificate with new SANs (recommended)" "REBUILD CA; existing agents must trust the new CA and re-enroll")"
  mkdir -p "$work/tls"
  if [ "$policy" = "retain CA; reissue server certificate with new SANs (recommended)" ]; then
    tls_cmd cp "$dir/tls/ca.crt" "$dir/tls/ca.key" "$work/tls/"
    tls_cmd chown -R "$(id -u)" "$work/tls"
    gen_tls "$work/tls" "$hosts" reuse
  else
    say "${Y}WARNING: rebuilding the server CA changes its fingerprint; existing agents must trust the new CA and re-enroll.${N}"
    [ "$(ask "type REBUILD to confirm CA replacement")" = REBUILD ] || die "aborted"
    gen_tls "$work/tls" "$hosts"
  fi
  local publichost="$host"
  [[ "$publichost" != *:* ]] || publichost="[$publichost]"
  awk -v url="https://$publichost:$publicport" '
    /^[^[:space:]#]/ {in_tls=($0 ~ /^tls:/)}
    /^public-url:/ {next}
    in_tls && /^[[:space:]]*ca:/ {next}
    {print}
    in_tls && /^[[:space:]]*mode:/ {print "  ca: /etc/rooster/tls/ca.crt"}
    END {printf "public-url: \"%s\"\n", url}
  ' "$work/hub.yaml" > "$work/new-hub.yaml"
  [ "$(choose "apply new certificates and restart the hub?" "abort" "apply and restart")" = "apply and restart" ] || die "aborted"
  backup="$(tls_cmd mktemp -d "$dir/tls-backup.XXXXXXXX")"
  tls_cmd cp -a "$dir/tls" "$dir/hub.yaml" "$backup/"
  for file in ca.crt ca.key hub.crt hub.key; do
    tls_cmd install -m600 "$work/tls/$file" "$dir/tls/.$file.new"
    tls_cmd mv -f "$dir/tls/.$file.new" "$dir/tls/$file"
  done
  tls_cmd install -m600 "$work/new-hub.yaml" "$dir/.hub.yaml.new"
  tls_cmd mv -f "$dir/.hub.yaml.new" "$dir/hub.yaml"
  restart_hub() {
    if [ "$target" = "Docker Compose" ]; then
      docker compose --project-directory "$dir" restart hub
    else
      as_root systemctl restart rooster-hub
    fi
  }
  if restart_hub && (wait_hub "$port" static "$host" "$work/tls/ca.crt"); then
    say "${G}SANs updated; backup: $backup${N}"
    say "  panel: https://$publichost:$publicport/"
  else
    tls_cmd cp -a "$backup/tls/." "$dir/tls/"
    tls_cmd cp -a "$backup/hub.yaml" "$dir/hub.yaml"
    restart_hub || true
    die "renewal failed; previous TLS/config restored from $backup"
  fi
)

menu() {
  say "$B== Rooster deploy ==  $DIM$REPO_URL$N"
  case "$(choose "what do you want to deploy?" \
    "hub - Docker (recommended)" \
    "hub - build from source + systemd" \
    "agent node - join an existing hub (install.sh)" \
    "agent node - Docker (advanced/testing)" \
    "hub - renew TLS SANs / rebuild CA")" in
    "hub - Docker (recommended)")                        deploy_hub_docker ;;
    "hub - build from source + systemd")                 deploy_hub_native ;;
    "agent node - join an existing hub (install.sh)")    deploy_agent_join ;;
    "agent node - Docker (advanced/testing)")            deploy_agent_docker ;;
    "hub - renew TLS SANs / rebuild CA")                  renew_hub_tls ;;
  esac
}

# BASH_SOURCE is unset when the script is piped into bash (curl | bash)
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then menu; fi
