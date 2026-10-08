#!/bin/sh
# Keep the image binary immutable so it can guard a non-starting signed upgrade.
# Installed agents live in the data volume; image pulls must not overwrite them.
# One container per volume: first-start seeding is not a multi-writer protocol.

set -eu

IMAGE_BIN="${ROOSTER_IMAGE_BINARY:-/usr/local/bin/rooster}"
DATA_DIR="${ROOSTER_AGENT_DATA_DIR:-/var/lib/rooster}"

log() { printf 'rooster-entrypoint: %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

[ -x "$IMAGE_BIN" ] || die "image binary $IMAGE_BIN is missing or not executable"

# Anything that is not `agent` (hub, --version, ...) goes straight to the
# immutable binary: no data-dir assumptions, no guard run, no seeding.
if [ "${1:-}" != agent ]; then
  exec "$IMAGE_BIN" "$@"
fi
shift  # drop the leading "agent"

# --- classify the agent invocation, keeping "$@" intact --------------------
END=__rooster_entrypoint_sentinel__
SUB=""
HELP=0
CLI_DATA=""
CLI_METHOD=""

set -- "$@" "$END"
while [ "$1" != "$END" ]; do
  arg="$1"; shift
  if [ -n "$SUB" ]; then                    # subcommand args are opaque
    set -- "$@" "$arg"
    continue
  fi
  case "$arg" in
    -h|--help)
      HELP=1
      set -- "$@" "$arg"
      ;;
    --config)
      [ "$1" != "$END" ] || die "--config requires a value"
      set -- "$@" "$arg" "$1"; shift
      ;;
    --data-dir)
      [ "$1" != "$END" ] || die "--data-dir requires a value"
      CLI_DATA="$1"
      set -- "$@" "$arg" "$1"; shift
      ;;
    --upgrade-method)
      [ "$1" != "$END" ] || die "--upgrade-method requires a value"
      CLI_METHOD="$1"
      set -- "$@" "$arg" "$1"; shift
      ;;
    --data-dir=*)       CLI_DATA="${arg#--data-dir=}"; set -- "$@" "$arg" ;;
    --upgrade-method=*) CLI_METHOD="${arg#--upgrade-method=}"; set -- "$@" "$arg" ;;
    -*)                 set -- "$@" "$arg" ;;   # other flags: clap validates
    *)                  SUB="$arg"; set -- "$@" "$arg" ;;
  esac
done
shift  # drop the sentinel; "$@" is the original agent argument list again

# Help and subcommands (only `upgrade-guard` exists — the immutable guard
# CLI) are inspection: forwarded verbatim, no normalization, no seeding.
if [ "$HELP" = 1 ] || [ -n "$SUB" ]; then
  exec "$IMAGE_BIN" agent "$@"
fi

# The entrypoint owns the data dir and the upgrade method: CLI values may not
# disagree with them (identical values are normalized away below).
if [ -n "$CLI_DATA" ] && [ "$CLI_DATA" != "$DATA_DIR" ]; then
  die "agent --data-dir '$CLI_DATA' disagrees with the container data dir '$DATA_DIR' (unset the flag or set ROOSTER_AGENT_DATA_DIR)"
fi
if [ -n "$CLI_METHOD" ] && [ "$CLI_METHOD" != exit ]; then
  die "agent --upgrade-method '$CLI_METHOD' is not allowed here; the container supervisor requires 'exit'"
fi

# --- strip the two override flags so ours are appended exactly once --------
set -- "$@" "$END"
while [ "$1" != "$END" ]; do
  arg="$1"; shift
  case "$arg" in
    --data-dir|--upgrade-method) shift ;;   # drop flag + validated value
    --data-dir=*|--upgrade-method=*) ;;     # drop flag
    *) set -- "$@" "$arg" ;;
  esac
done
shift

AGENT_BIN="$DATA_DIR/bin/rooster"
MARKER="$DATA_DIR/upgrade-pending.json"

# --- upgrade-guard on EVERY start ------------------------------------------
# Rolls a failed signed upgrade back to <binary>.prev and clears the marker
# before anything else runs. A marker whose target binary is missing is also
# handled here — the entrypoint never re-seeds over a pending upgrade.
log "running upgrade-guard for $DATA_DIR"
if ! "$IMAGE_BIN" agent upgrade-guard --data-dir "$DATA_DIR" --binary "$AGENT_BIN"; then
  die "upgrade-guard failed for $DATA_DIR; refusing to start the agent"
fi

# --- seed the mutable agent binary (first start / wiped volume) ------------
# Never overwrites a persisted — possibly hub-upgraded — binary.
if [ ! -e "$AGENT_BIN" ] && [ ! -e "$MARKER" ]; then
  mkdir -p "$DATA_DIR/bin" || die "cannot create $DATA_DIR/bin"
  tmp="$DATA_DIR/bin/.rooster.seed.$$"
  if cp "$IMAGE_BIN" "$tmp" && chmod 0755 "$tmp" && mv "$tmp" "$AGENT_BIN"; then
    log "seeded $AGENT_BIN from image binary $IMAGE_BIN"
  else
    rm -f "$tmp"
    die "failed to seed $AGENT_BIN from $IMAGE_BIN"
  fi
fi

[ -x "$AGENT_BIN" ] || die "agent binary $AGENT_BIN is missing or not executable (left in place; inspect the rooster-agent-data volume)"

# --- exec: the mutable agent replaces this shell (PID 1 semantics) ---------
exec "$AGENT_BIN" agent "$@" --data-dir "$DATA_DIR" --upgrade-method exit
