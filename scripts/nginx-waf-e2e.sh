#!/bin/sh
# Rooster Nginx -> WAF end-to-end fixture runner.
#
# Installs tests/nginx-fixtures into a live Nginx, starts echo origins, runs a
# standalone Agent against them, and drives the management API. Root on an
# isolated Linux host with nginx installed. Never point this at production.
#
#   scripts/nginx-waf-e2e.sh setup      # fixtures + origins + agent
#   scripts/nginx-waf-e2e.sh discover   # discovery table (onboardable / reason)
#   scripts/nginx-waf-e2e.sh attach <stem> [detect|block]
#   scripts/nginx-waf-e2e.sh detach <stem>
#   scripts/nginx-waf-e2e.sh check      # attach every case, assert, restore
#   scripts/nginx-waf-e2e.sh teardown   # restore nginx, stop agent + origins
set -eu

REPO=${REPO:-$(pwd)}
FIX=$REPO/tests/nginx-fixtures
AGENT_BIN=${AGENT_BIN:-$REPO/target/release/rooster}
MGMT=${MGMT:-127.0.0.1:9873}
SECRET=${SECRET:-rooster-e2e-secret}
CONF=${CONF:-/etc/rooster-e2e/config.yaml}
DATA=${DATA:-/var/lib/rooster-e2e}
ORIGINS="3001 3002 3003 3004 3005 3006 3007 3008 3009"
TLS_ORIGIN=3443
NGX=/usr/sbin/nginx
STEMS="api.demo.test chat.demo.test default legacy.demo.test multi-vhost.demo.test plan.demo.test shop.demo.test sonar.demo.test"

# check cases: <stem> <scheme> <port> <host> <path> <expected origin> <expect_host>
CASES="
api.demo.test|https|443|api.demo.test|/|origin-3001|-
api.demo.test|https|443|api.demo.test|/api/|origin-3002|-
chat.demo.test|http|80|chat.demo.test|/|origin-3003|-
chat.demo.test|http|80|chat.demo.test|/ws|origin-3003|-
legacy.demo.test|http|80|legacy.demo.test|/app/x|origin-3006|-
multi-vhost.demo.test|http|80|blue.demo.test|/|origin-3007|-
multi-vhost.demo.test|http|80|green.demo.test|/internal/|origin-3008|-
shop.demo.test|http|80|shop.demo.test|/|origin-3009|127.0.0.1:3009
"
# sites that must stay manual are asserted in check_declines.

say() { printf '%s\n' "$*"; }

mgmt() { # mgmt <method> <path> [json-body]
  m=$1; p=$2; body=${3:-}
  if [ -n "$body" ]; then
    curl -fsS -X "$m" -H "Authorization: Bearer $SECRET" -H 'content-type: application/json' \
      -d "$body" "http://$MGMT$p"
  else
    curl -fsS -X "$m" -H "Authorization: Bearer $SECRET" "http://$MGMT$p"
  fi
}

py() { python3 -c "$@"; }

req() { # req <scheme> <port> <host> <path> -> body
  scheme=$1; port=$2; host=$3; path=$4
  curl -sk -m 8 --resolve "$host:$port:127.0.0.1" "$scheme://$host:$port$path" || true
}

start_origins() {
  mkdir -p "$DATA/log"
  for port in $ORIGINS; do
    if ! ss -ltn "sport = :$port" 2>/dev/null | tail -n +2 | grep -q .; then
      nohup python3 "$FIX/backends/backend.py" "$port" "origin-$port" \
        >>"$DATA/log/origin-$port.log" 2>&1 &
    fi
  done
  if ! ss -ltn "sport = :$TLS_ORIGIN" 2>/dev/null | tail -n +2 | grep -q .; then
    nohup python3 "$FIX/backends/backend.py" "$TLS_ORIGIN" "origin-tls" \
      --tls /etc/nginx/e2e/wildcard.crt /etc/nginx/e2e/wildcard.key \
      >>"$DATA/log/origin-tls.log" 2>&1 &
  fi
  sleep 1
}

write_agent_config() {
  mkdir -p "$DATA" "$(dirname "$CONF")"
  cat >"$CONF" <<EOF
local:
  agent:
    node-name: 'e2e-nginx'
    data-dir: '$DATA'
    log-level: 'info'
  management:
    listen: $MGMT
    secret-key: '$SECRET'
managed:
  waf:
    crs:
      enabled: true
      paranoia-level: 1
      inbound-anomaly-threshold: 5
EOF
}

start_agent() {
  if curl -fsS -m 2 "http://$MGMT/healthz" >/dev/null 2>&1; then return; fi
  write_agent_config
  nohup "$AGENT_BIN" agent --config "$CONF" >>"$DATA/log/agent.log" 2>&1 &
  i=0
  until curl -fsS -m 2 "http://$MGMT/healthz" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -gt 50 ] && { say "agent did not come up"; tail -30 "$DATA/log/agent.log"; exit 1; }
    sleep 0.2
  done
}

install_fixtures() {
  mkdir -p /etc/nginx/e2e /var/www/acme /var/www/static /var/www/chat /var/www/legacy /var/www/html
  echo rooster-e2e > /var/www/html/index.html
  [ -f /etc/nginx/e2e/wildcard.crt ] || openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /etc/nginx/e2e/wildcard.key -out /etc/nginx/e2e/wildcard.crt \
    -days 30 -subj '/CN=*.demo.test' >/dev/null 2>&1
  # Keep a pristine copy of the pre-fixture config so teardown can restore it.
  if [ ! -d /etc/nginx/e2e/backup ]; then
    mkdir -p /etc/nginx/e2e/backup
    cp -a /etc/nginx/nginx.conf /etc/nginx/e2e/backup/nginx.conf
    for d in sites-enabled conf.d snippets; do
      [ -d "/etc/nginx/$d" ] && cp -a "/etc/nginx/$d" "/etc/nginx/e2e/backup/$d"
    done
  fi
  rm -f /etc/nginx/sites-enabled/*
  cp "$FIX"/conf.d/*.conf /etc/nginx/conf.d/
  cp "$FIX"/sites-enabled/*.conf /etc/nginx/sites-enabled/
  cp "$FIX"/snippets/*.conf /etc/nginx/snippets/
  "$NGX" -t
  "$NGX" -s reload || { systemctl start nginx; "$NGX" -s reload; }
}

setup() {
  [ "$(id -u)" = 0 ] || { say "run as root"; exit 1; }
  install_fixtures
  start_origins
  start_agent
  say "setup done"
}

sites_json() { mgmt GET /v0/management/nginx/sites; }

discover() {
  sites_json | py '
import json,sys
d=json.load(sys.stdin)
print("running:", d.get("running"))
for s in sorted(d.get("sites", []), key=lambda s: (s["file"], s["id"])):
    f=s["file"].rsplit("/",1)[-1]
    print("%-30s %-18s onboard=%-5s mode=%-7s status=%-14s bypass=%s extra=%s :: %s" % (
        f, ",".join(s["domains"])[:18], s.get("reason") is None, s.get("mode"), s.get("status"),
        s.get("bypassed_locations"), len(s.get("extra_locations") or []), s.get("reason") or "-"))
'
}

# One row per block; status distinguishes untouched manual sites from recovery records.
site_rows() {
  sites_json | py "
import json,sys
for s in json.load(sys.stdin)['sites']:
    if s['file'].endswith('/$1.conf'):
        print(s['id'], s.get('reason') is None, s['fingerprint'], s['file'], s['status'])
"
}

attach() ( # Re-read per block: attaching another server invalidates its fingerprint.
  stem=$1; mode=${2:-block}; failed=0
  rows=$(site_rows "$stem") || return 1
  [ -n "$rows" ] || { say "  FAIL missing fixture $stem"; return 1; }
  for id in $(printf '%s\n' "$rows" | awk '$2 == "True" {print $1}'); do
    rows=$(site_rows "$stem") || { failed=1; continue; }
    fp=$(printf '%s\n' "$rows" | awk -v want="$id" '$1 == want {print $3}')
    [ -n "$fp" ] || { say "  FAIL missing fingerprint $id"; failed=1; continue; }
    out=$(mgmt PUT "/v0/management/nginx/sites/$id/waf" "{\"mode\":\"$mode\",\"fingerprint\":\"$fp\"}" 2>&1) \
      || { say "  FAIL $id: $out"; failed=1; continue; }
    say "  ok $id $out"
  done
  return "$failed"
)

detach() (
  stem=$1; failed=0
  rows=$(site_rows "$stem") || return 1
  [ -n "$rows" ] || { say "  FAIL missing fixture $stem"; return 1; }
  while read -r id _ok _fp _file status; do
    [ -n "$id" ] || continue
    [ "$status" != discovered ] || continue
    if mgmt PUT "/v0/management/nginx/sites/$id/waf" '{"mode":"off"}' >/dev/null 2>&1; then
      say "  detached $id"
    else
      say "  detach failed $id"
      failed=1
    fi
  done <<EOF
$rows
EOF
  return "$failed"
)

probe() {
  for host in api.demo.test chat.demo.test plan.demo.test sonar.demo.test legacy.demo.test blue.demo.test green.demo.test shop.demo.test; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' -m 5 --resolve "$host:80:127.0.0.1" "http://$host/")
    say "$host benign=$code"
  done
}

# decline expectations: <stem> must stay manual and its reason must contain a
# substring (guards against the classifier silently accepting unsafe shapes).
check_declines() (
  failed=0
  for pair in "plan.demo.test|上游组" "sonar.demo.test|复杂指令"; do
    stem=${pair%%|*}; want=${pair#*|}
    rows=$(site_rows "$stem") || { failed=1; continue; }
    why=$(sites_json | py "
import json,sys
for s in json.load(sys.stdin)['sites']:
    if s['file'].endswith('/$stem.conf') and s.get('reason'): print(s['reason'])
" | head -1)
    if printf '%s' "$rows" | grep -q ' False ' && printf '%s' "$why" | grep -q "$want"; then
      say "PASS decline $stem ($why)"
    else
      say "FAIL decline $stem: expected a manual-integration reason containing '$want' (got '$why')"
      failed=1
    fi
  done
  return "$failed"
)

check_traffic() (
  failed=0
  while IFS='|' read -r stem scheme port host path origin want_host; do
    [ -n "$stem" ] || continue
    benign=$(req "$scheme" "$port" "$host" "$path")
    got_origin=$(printf '%s' "$benign" | py '
import json,sys
try: print(json.load(sys.stdin).get("origin","-"))
except Exception: print("-")
')
    got_host=$(printf '%s' "$benign" | py '
import json,sys
try:
    d=json.load(sys.stdin)
    print([v for k,v in d["header_pairs"] if k=="host"][0])
except Exception: print("-")
')
    attack=$(curl -sk -o /dev/null -w '%{http_code}' -m 8 --resolve "$host:$port:127.0.0.1" \
      "$scheme://$host:$port${path}%3Cscript%3Ealert(1)%3C/script%3E?id=1%27%20UNION%20SELECT%20password%20FROM%20users--") || attack=000
    post=$(curl -sk -o /dev/null -w '%{http_code}' -m 8 -X POST --resolve "$host:$port:127.0.0.1" \
      -d 'evil=<script>document.cookie</script>' "$scheme://$host:$port$path") || post=000
    status=PASS
    [ "$got_origin" = "$origin" ] || status=FAIL
    [ "$attack" = 403 ] || status=FAIL
    [ "$post" = 403 ] || status=FAIL
    if [ "$want_host" != "-" ] && [ "$got_host" != "$want_host" ]; then status=FAIL; fi
    say "$status $host$path origin=$got_origin(want $origin) host=$got_host(want $want_host) attack=$attack post=$post"
    [ "$status" = PASS ] || failed=1
  done <<EOF
$CASES
EOF
  return "$failed"
)

restore_checks() (
  failed=0
  say "--- restore ---"
  for stem in $STEMS; do
    detach "$stem" >/dev/null || failed=1
    after=$(md5sum "/etc/nginx/sites-enabled/$stem.conf") || { failed=1; continue; }
    want=$(md5sum "$FIX/sites-enabled/$stem.conf") || { failed=1; continue; }
    after=${after%% *}; want=${want%% *}
    if [ "$after" = "$want" ]; then
      say "PASS restore $stem"
    else
      say "FAIL restore $stem ($after != $want)"
      failed=1
    fi
  done
  if "$NGX" -t -q; then
    say "PASS nginx -t after restore"
  else
    say "FAIL nginx -t after restore"
    failed=1
  fi
  return "$failed"
)

check() (
  # Restore even after an early error or interruption; restoration failures also fail the run.
  trap 'restore_checks || exit 1' 0
  trap 'exit 1' HUP INT TERM
  failed=0
  say "--- discovery ---"
  discover || failed=1
  check_declines || failed=1
  say "--- attach ---"
  for stem in $STEMS; do attach "$stem" block || failed=1; done
  say "--- traffic ---"
  check_traffic || failed=1
  exit "$failed"
)

teardown() {
  for stem in $STEMS; do detach "$stem" >/dev/null 2>&1 || true; done
  pkill -f 'rooster.*agent --config /etc/rooster-e2e' 2>/dev/null || true
  pkill -f 'backend.py' 2>/dev/null || true
  if [ -d /etc/nginx/e2e/backup ]; then
    cp -a /etc/nginx/e2e/backup/nginx.conf /etc/nginx/nginx.conf
    for d in sites-enabled conf.d snippets; do
      [ -d "/etc/nginx/e2e/backup/$d" ] || continue
      rm -rf "/etc/nginx/$d" && cp -a "/etc/nginx/e2e/backup/$d" "/etc/nginx/$d"
    done
    "$NGX" -t && "$NGX" -s reload || true
  fi
  say "teardown done"
}

case ${1:-help} in
  setup) setup ;;
  discover) discover ;;
  attach) attach "${2:?site stem}" "${3:-block}" ;;
  detach) detach "${2:?site stem}" ;;
  probe) probe ;;
  check) check ;;
  teardown) teardown ;;
  *) sed -n '2,15p' "$0" ;;
esac
