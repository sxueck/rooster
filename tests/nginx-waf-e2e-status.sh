#!/bin/sh
# Isolate the runner's control flow from root, Nginx and the management API.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' 0
trap 'exit 1' HUP INT TERM
awk '/^case \$\{1:-help\} in/ {exit} {print}' "$ROOT/scripts/nginx-waf-e2e.sh" > "$TMP/functions.sh"

run() {
  name=$1; expected=$2; scenario=$3
  : > "$TMP/calls"
  if ( . "$TMP/functions.sh"; eval "$scenario" ) > "$TMP/output" 2>&1; then
    actual=0
  else
    actual=$?
  fi
  if [ "$actual" != "$expected" ]; then
    printf 'FAIL %s: status %s, expected %s\n' "$name" "$actual" "$expected"
    cat "$TMP/output"
    exit 1
  fi
  printf 'PASS %s\n' "$name"
}

run discover-api-failure 1 'mgmt() { return 7; }; discover'
run site-rows-api-failure 1 'mgmt() { return 7; }; site_rows app'

run decline-failure 1 '
  site_rows() { echo "a True fp /fixture/app.conf discovered"; }
  sites_json() { echo "{}"; }
  py() { echo ""; }
  check_declines
'
run decline-success 0 '
  site_rows() { echo "a False fp /fixture/app.conf discovered"; }
  sites_json() { echo "{}"; }
  py() { echo "上游组 复杂指令"; }
  check_declines
'

attach_common='
  site_rows() { printf "a True fp /fixture/app.conf discovered\nb True fp /fixture/app.conf discovered\n"; }
'
run attach-failure 1 "$attach_common"'
  mgmt() { echo "$2" >> "$TMP/calls"; [ "$2" != /v0/management/nginx/sites/a/waf ]; }
  attach app
'
[ "$(wc -l < "$TMP/calls")" -eq 2 ]
run attach-success 0 "$attach_common"'
  mgmt() { return 0; }
  attach app
'
run attach-discovery-failure 1 'site_rows() { return 1; }; attach app'
run attach-missing-fixture 1 'site_rows() { return 0; }; attach app'

detach_common='
  site_rows() { printf "a False fp /fixture/app.conf attached\nb False fp /fixture/app.conf needs-recovery\nc False fp /fixture/app.conf discovered\n"; }
'
run detach-failure 1 "$detach_common"'
  mgmt() { echo "$2" >> "$TMP/calls"; [ "$2" != /v0/management/nginx/sites/a/waf ]; }
  detach app
'
[ "$(wc -l < "$TMP/calls")" -eq 2 ]
run detach-success 0 "$detach_common"'
  mgmt() { echo "$2" >> "$TMP/calls"; }
  detach app
'
[ "$(wc -l < "$TMP/calls")" -eq 2 ]
run detach-discovery-failure 1 'site_rows() { return 1; }; detach app'

traffic_common='
  CASES="app|http|80|app.test|/|origin|app.test"
  req() { printf "{\"origin\":\"origin\",\"header_pairs\":[[\"host\",\"app.test\"]]}"; }
  curl() { printf 403; }
'
run traffic-success 0 "$traffic_common"'check_traffic'
run traffic-origin-failure 1 "$traffic_common"'req() { echo "{}"; }; check_traffic'
run traffic-host-failure 1 "$traffic_common"'CASES="app|http|80|app.test|/|origin|wrong.test"; check_traffic'
run traffic-waf-failure 1 "$traffic_common"'curl() { printf 200; }; check_traffic'
run traffic-network-failure 1 "$traffic_common"'curl() { return 7; }; check_traffic'

restore_common='
  STEMS="app other"
  NGX=fake_nginx
  detach() { echo "$1" >> "$TMP/calls"; }
  md5sum() { echo "same  $1"; }
  fake_nginx() { return 0; }
'
run restore-success 0 "$restore_common"'restore_checks'
run restore-detach-failure 1 "$restore_common"'detach() { echo "$1" >> "$TMP/calls"; return 1; }; restore_checks'
[ "$(wc -l < "$TMP/calls")" -eq 2 ]
run restore-file-failure 1 "$restore_common"'md5sum() { return 1; }; restore_checks'
run restore-mismatch 1 "$restore_common"'md5sum() { echo "$1  $1"; }; restore_checks'
run restore-nginx-failure 1 "$restore_common"'fake_nginx() { return 1; }; restore_checks'

check_common='
  STEMS="app"
  discover() { return 0; }
  check_declines() { return 0; }
  attach() { return 0; }
  check_traffic() { return 0; }
  restore_checks() { echo restore >> "$TMP/calls"; }
'
run check-success 0 "$check_common"'check'
[ "$(wc -l < "$TMP/calls")" -eq 1 ]
for phase in discover check_declines attach check_traffic; do
  run "check-$phase-failure" 1 "$check_common $phase() { return 1; }; check"
  [ "$(wc -l < "$TMP/calls")" -eq 1 ]
done
run check-early-exit 2 "$check_common"'check_traffic() { exit 2; }; check'
[ "$(wc -l < "$TMP/calls")" -eq 1 ]
run check-restore-failure 1 "$check_common"'restore_checks() { echo restore >> "$TMP/calls"; return 1; }; check'
[ "$(wc -l < "$TMP/calls")" -eq 1 ]
printf 'All exit-status regressions passed.\n'
