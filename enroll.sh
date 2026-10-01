#!/bin/sh
# Fetch the hub installer only after authenticating its TLS identity.
set -eu
umask 077

HUB="" TOKEN="" NAME="" CA_FILE="" CA_SHA256="" ALLOW_UNSIGNED=0
fail() { echo "error: $*" >&2; exit 1; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --hub|--token|--name|--ca-file|--ca-sha256)
      [ "$#" -ge 2 ] && [ -n "$2" ] || fail "missing value for $1"
      case "$1" in
        --hub) HUB="$2";; --token) TOKEN="$2";; --name) NAME="$2";;
        --ca-file) CA_FILE="$2";; --ca-sha256) CA_SHA256="$2";;
      esac
      shift 2;;
    --allow-unsigned) ALLOW_UNSIGNED=1; shift;;
    --insecure) fail "--insecure is no longer supported; use --ca-file or --ca-sha256 from the trusted panel";;
    *) fail "unknown argument: $1";;
  esac
done
[ "$(id -u)" = 0 ] || fail "run as root"
[ -n "$HUB" ] && [ -n "$TOKEN" ] || fail "--hub and --token are required"
case "$HUB" in
  https://*) PROTO='=https';;
  http://localhost:*|http://127.0.0.1:*|http://\[::1\]:*) PROTO='=http';;
  *) fail "hub must use HTTPS (HTTP is allowed only on loopback)";;
esac
HUB="${HUB%/}"
command -v curl >/dev/null 2>&1 || fail "curl is required"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
trap 'exit 1' HUP INT TERM

if [ -n "$CA_SHA256" ]; then
  [ -z "$CA_FILE" ] || fail "choose --ca-file or --ca-sha256, not both"
  command -v openssl >/dev/null 2>&1 || fail "openssl is required for CA fingerprint verification"
  EXPECTED="$(printf '%s' "$CA_SHA256" | tr 'A-F' 'a-f')"
  case "$EXPECTED" in *[!0-9a-f]*) fail "invalid CA SHA-256 fingerprint";; esac
  [ "${#EXPECTED}" = 64 ] || fail "CA SHA-256 fingerprint must have 64 hex digits"
  [ "$PROTO" = '=https' ] || fail "CA fingerprint requires HTTPS"
  # Only public CA bytes may cross an unverified connection, never executable code.
  curl -kfsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 60 \
    "$HUB/v0/ca.crt" -o "$WORK/ca.crt"
  openssl x509 -in "$WORK/ca.crt" -outform DER -out "$WORK/ca.der"
  ACTUAL="$(openssl dgst -sha256 -r "$WORK/ca.der" | awk '{print $1}')"
  [ "$ACTUAL" = "$EXPECTED" ] || fail "hub CA fingerprint mismatch; installer was not downloaded"
  # Drop any extra certificates appended to the verified PEM certificate.
  openssl x509 -inform DER -in "$WORK/ca.der" -out "$WORK/ca.crt"
  CA_FILE="$WORK/ca.crt"
fi
set -- --hub "$HUB" --token "$TOKEN"
[ -z "$NAME" ] || set -- "$@" --name "$NAME"
[ "$ALLOW_UNSIGNED" = 0 ] || set -- "$@" --allow-unsigned
if [ -n "$CA_FILE" ]; then
  [ -f "$CA_FILE" ] || fail "CA file not found"
  curl -fsSL --proto "$PROTO" --proto-redir "$PROTO" --cacert "$CA_FILE" \
    --connect-timeout 10 --max-time 120 "$HUB/install.sh" -o "$WORK/install.sh"
  set -- "$@" --ca-file "$CA_FILE"
else
  curl -fsSL --proto "$PROTO" --proto-redir "$PROTO" --connect-timeout 10 --max-time 120 \
    "$HUB/install.sh" -o "$WORK/install.sh"
fi
sh "$WORK/install.sh" "$@"
