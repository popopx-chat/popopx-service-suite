#!/usr/bin/env bash
# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
# POPOPX Service Suite — one-click development launch on macOS.
#
#   ./start_macos.sh                # venv gateway + local node, both on this Mac
#   ./start_macos.sh --no-node      # attach to a node you already run
#   ./start_macos.sh --docker       # compose path (caveat: see the note below)
#
# Why the default is a venv and not Docker: this suite talks to the node over
# the node's WebSocket API, which binds 127.0.0.1 and nothing else. `network_mode:
# host` is a Linux-only kernel feature — in Docker Desktop a container's "host"
# is the linuxvm, whose loopback is not this Mac's. So a gateway in a container
# and a node on the Mac cannot see each other at 127.0.0.1, and no amount of
# `ports:` fixes it. Running both natively makes the loopback hop real.
#
# Portable shell on purpose: /bin/bash on macOS is 3.2 (GPLv2, frozen) and this
# script must run there without a brew-installed bash 5.

set -eu

SUITE_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly SUITE_DIR
VENV_DIR="${SUITE_DIR}/.venv"
RUN_DIR="${SUITE_DIR}/.run"
ENV_FILE="${SUITE_DIR}/.env"
readonly VENV_DIR RUN_DIR ENV_FILE

GATEWAY_PORT="${POPOPX_GATEWAY_PORT:-8080}"
NODE_PORT="${POPOPX_NODE_PORT:-5225}"
NODE_BIN="${POPOPX_NODE_BIN:-}"
# Only used when the node reports it has no user profile at all (see
# start_node); an existing profile is never renamed, so this is a
# first-run convenience, not an identity decision made on the operator's
# behalf. Overridable without editing the script, like everything else here.
NODE_DISPLAY_NAME="${POPOPX_NODE_DISPLAY_NAME:-POPOPX Service}"
NODE_WS="${POPOPX_NODE_WS_URL:-ws://127.0.0.1:${NODE_PORT}}"
USE_DOCKER=0
START_NODE=1
SHOW_TOKEN=0
FORCED_HOST="${POPOPX_BIND_HOST:-}"
CHECK_ONLY=0

log()  { printf '\033[1;36m[popopx]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fatal]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  # Print the file's own leading comment block rather than a hardcoded line
  # range: a range silently starts leaking code the first time the header moves.
  # Also SIGPIPE-tolerant, so `--help | head` stays a clean help screen.
  trap - ERR 2>/dev/null || true
  set +e
  awk 'NR > 1 { if (!/^#/) exit; sub(/^# ?/, ""); print }' "$0"
  cat <<'USAGE'

Options:
  --docker              Run the gateway through docker compose instead of a venv.
                        Needs Docker Desktop with "Enable host networking", and it
                        only makes sense if the node is containerised too — see
                        the note at the top of this file.
  --no-node             Do not start a node; attach to one already listening.
  --node-bin PATH       Node executable to start (default: discover).
  --node-port N         Node WebSocket API port (default 5225).
  --port N              Gateway port (default 8080).
  --host IP             Bind address (default 0.0.0.0, so an iPhone can reach it).
  --show-token          Print POPOPX_ADMIN_TOKEN instead of only its location.
  --check               Preflight and report; start nothing.
  -h, --help            This text.

Python: requires 3.11 exactly. Nothing falls back to 3.10 silently — the suite is
written and typed against 3.11, and the failure mode of a wrong interpreter is a
SyntaxError inside a request handler at 3 a.m., not at install time.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --docker) USE_DOCKER=1; shift ;;
    --no-node) START_NODE=0; shift ;;
    --node-bin) [ $# -ge 2 ] || die "--node-bin needs a path"; NODE_BIN="$2"; shift 2 ;;
    --node-port) [ $# -ge 2 ] || die "--node-port needs a value"; NODE_PORT="$2"; NODE_WS="ws://127.0.0.1:${NODE_PORT}"; shift 2 ;;
    --port) [ $# -ge 2 ] || die "--port needs a value"; GATEWAY_PORT="$2"; shift 2 ;;
    --host) [ $# -ge 2 ] || die "--host needs an address"; FORCED_HOST="$2"; shift 2 ;;
    --show-token) SHOW_TOKEN=1; shift ;;
    --check) CHECK_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

[ "$(uname -s)" = "Darwin" ] || die "start_macos.sh is for macOS; on Linux use install_ubuntu22.sh"

# ───────────────────────────── port validation ──────────────────────────────

# Both numbers end up in a socket() call — the gateway's port and the node's
# --chat-server-port — and neither failure mode is an error message you would
# connect to the argument: a port above 65535 either dies in bind() with text
# that reads like a firewall problem, or, where the platform truncates modulo
# 65536, binds something else entirely while this script prints URLs for the
# number you typed. Checked here because the cost of catching it is one line.
require_port() { # $1 = what to name, $2 = the value
  case "$2" in
    '' | *[!0-9]*) die "$1 must be a decimal port number, got '${2}' (try --help)" ;;
  esac
  [ "$2" -ge 1 ] && [ "$2" -le 65535 ] \
    || die "$1 must be between 1 and 65535, got ${2}"
}
require_port "--port / POPOPX_GATEWAY_PORT" "${GATEWAY_PORT}"
require_port "--node-port / POPOPX_NODE_PORT" "${NODE_PORT}"

ARCH="$(uname -m)"
log "macOS ${ARCH}, suite at ${SUITE_DIR}"

# ────────────────────────────── interpreter ─────────────────────────────────

find_python() {
  # Order: explicit env, PATH, then the two Homebrew prefixes and the python.org
  # framework. Apple's /usr/bin/python3 is deliberately last and version-gated:
  # it is whatever the SDK ships (3.9 on older CLTs) and cannot satisfy 3.11.
  if [ -n "${POPOPX_PYTHON:-}" ] && [ -x "${POPOPX_PYTHON}" ]; then
    printf '%s' "${POPOPX_PYTHON}"; return 0
  fi
  for cand in \
    "$(command -v python3.11 2>/dev/null || true)" \
    /opt/homebrew/bin/python3.11 \
    /usr/local/bin/python3.11 \
    /Library/Frameworks/Python.framework/Versions/3.11/bin/python3.11 \
    "$(brew --prefix python@3.11 2>/dev/null)/bin/python3.11"
  do
    [ -n "${cand}" ] && [ -x "${cand}" ] && { printf '%s' "${cand}"; return 0; }
  done
  return 1
}

python_ok() { # $1 = interpreter path
  [ -n "${1}" ] && [ -x "${1}" ] || return 1
  "${1}" -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 11) else 1)' 2>/dev/null
}

# ─────────────────────────────── LAN address ────────────────────────────────

lan_ip() {
  # en0/en1 cover Wi-Fi and Thunderbolt Ethernet on Apple Silicon; the order is
  # not a guess about which is "primary", it is the first interface that actually
  # has an IPv4 lease.
  for iface in en0 en1 en2 en3 en4 en5 en6 bridge0 utun0; do
    ip="$(ipconfig getifaddr "${iface}" 2>/dev/null || true)"
    [ -n "${ip}" ] && { printf '%s' "${ip}"; return 0; }
  done
  iface="$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')"
  [ -n "${iface}" ] && ipconfig getifaddr "${iface}" 2>/dev/null && return 0
  printf '127.0.0.1'
}

port_listening() { # $1 = port
  lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

# ───────────────────────────────── .env ─────────────────────────────────────

ensure_env() {
  if [ ! -f "${ENV_FILE}" ]; then
    [ -f "${SUITE_DIR}/.env.example" ] || die "neither .env nor .env.example is present"
    cp "${SUITE_DIR}/.env.example" "${ENV_FILE}"
    log "created .env from .env.example"
  fi
  # Only fill a token that is literally empty — a developer who set one by hand
  # must never have it swapped under them mid-project.
  if ! grep -q '^POPOPX_ADMIN_TOKEN=..*' "${ENV_FILE}"; then
    token="$(/usr/bin/openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    # Rewrite in place through a temp file: sed -i on macOS needs the '' argument
    # and a failed in-place edit of a file holding a token is not worth it.
    awk -v t="${token}" '{ if ($0 ~ /^POPOPX_ADMIN_TOKEN=/) print "POPOPX_ADMIN_TOKEN=" t; else print }' \
      "${ENV_FILE}" > "${ENV_FILE}.tmp" && mv "${ENV_FILE}.tmp" "${ENV_FILE}"
    chmod 600 "${ENV_FILE}"
    log "generated a development POPOPX_ADMIN_TOKEN in .env (not printed)"
  fi
}

read_token() { grep '^POPOPX_ADMIN_TOKEN=..*' "${ENV_FILE}" 2>/dev/null | head -1 | cut -d= -f2-; }

# ──────────────────────────── official voucher key ──────────────────────────

DEV_KEYRING="${RUN_DIR}/official_keys"
readonly DEV_KEYRING

official_pubkey_from_file() {
  # A placeholder is not a key: the shipped .env.example ships the line empty, and
  # an operator who pastes CHANGE_ME would otherwise be told the gateway started
  # with a valid official key until the first redeem said "signature invalid".
  local value
  value="$(grep '^POPOPX_OFFICIAL_ED25519_PUBLIC_KEY=..*' "${ENV_FILE}" 2>/dev/null | head -1 | cut -d= -f2- || true)"
  case "${value}" in
    '' | *CHANGE_ME*) return 1 ;;
  esac
  printf '%s' "${value}"
}

# Whether this deployment insists on a POPX-CP voucher. Mirrors
# app/config.py:_as_bool exactly, including the default: an absent or empty
# value is FALSE, because a self-hosted instance is expected to work the moment
# it starts. A value that is neither truthy nor falsy is left alone — the
# gateway reports it itself, in the one place the grammar of these booleans is
# defined.
voucher_required() {
  local value
  value="${POPOPX_BILLING_REQUIRE_VOUCHER:-}"
  [ -n "${value}" ] || value="$(grep '^POPOPX_BILLING_REQUIRE_VOUCHER=..*' "${ENV_FILE}" 2>/dev/null | head -1 | cut -d= -f2- || true)"
  case "$(printf '%s' "${value}" | tr '[:upper:]' '[:lower:]')" in
    1 | true | yes | on) return 0 ;;
  esac
  return 1
}

# Resolve the official Ed25519 PUBLIC key for this run, in this order: the
# environment (an operator who knows what they want wins), .env, then a
# throwaway development keyring under .run/.
#
# The throwaway exists for the one deployment that asks for it: with
# POPOPX_BILLING_REQUIRE_VOUCHER=1 a missing public half means no code can ever be
# verified, so an account could never leave DRAFT, and the operator would only
# discover that in production. On a laptop the same rule reads as "I cannot run
# the thing I am writing", because the DRAFT -> ONLINE path is exactly what needs
# testing and it needs a minted voucher. So generate a keyring here — the private
# half stays inside .run/official_keys on this machine, which is the same property
# the production ceremony holds for the real one, and the gateway only ever
# learns the public half: no code path in this suite reads an official private key.
#
# It is created only when vouchers are actually required: minting a keyring nobody
# asked for leaves an operator with a file that looks like a secret.
ensure_official_key() {
  if [ -n "${POPOPX_OFFICIAL_ED25519_PUBLIC_KEY:-}" ]; then
    printf '%s' "${POPOPX_OFFICIAL_ED25519_PUBLIC_KEY}"; return 0
  fi
  if official_pubkey_from_file; then return 0; fi
  voucher_required || return 1
  if [ ! -f "${DEV_KEYRING}/official_ed25519.secret.json" ]; then
    log "no official public key configured; creating a development voucher keyring in ${DEV_KEYRING}"
    # No POPX_KEYRING_PASSPHRASE on purpose: a passphrase would be asked for on a
    # tty this script has already sent the gateway's output away from.
    install -d -m 700 "${DEV_KEYRING}" \
      && "${VENV_DIR}/bin/python" "${SUITE_DIR}/official_tools/gen_voucher.py" --gen-keyring --keyring "${DEV_KEYRING}" \
      || die "could not create the development keyring (is 'cryptography' installed? install gateway/requirements.txt into ${VENV_DIR} and re-run)"
  fi
  # The `base64` line is the one spelling the gateway's config parser takes, and
  # it is a single token on that line — no separator gymnastics needed.
  "${VENV_DIR}/bin/python" "${SUITE_DIR}/official_tools/gen_voucher.py" --show-pubkey --keyring "${DEV_KEYRING}" \
    | awk '/^base64/ { print $2; exit }'
}

# ────────────────────────────────── node ────────────────────────────────────

find_node_bin() {
  if [ -n "${NODE_BIN}" ]; then
    [ -x "${NODE_BIN}" ] || die "--node-bin ${NODE_BIN} is not executable"
    printf '%s' "${NODE_BIN}"; return 0
  fi
  if found="$(command -v popopx-chat 2>/dev/null)"; then [ -n "${found}" ] && { printf '%s' "${found}"; return 0; }; fi
  for cand in /usr/local/bin/popopx-chat /opt/homebrew/bin/popopx-chat "${HOME}/.local/bin/popopx-chat"; do
    [ -x "${cand}" ] && { printf '%s' "${cand}"; return 0; }
  done
  # The cabal build tree of a sibling checkout, newest match first. This is the
  # path that actually exists on a developer machine that has built the client.
  for repo in "${SUITE_DIR}/../popopx-chat" "${HOME}/popopx-chat/popopx-chat" "${HOME}/src/popopx-chat"; do
    [ -d "${repo}" ] || continue
    newest="$(find "${repo}/dist-newstyle/build" -type f -name popopx-chat -perm +111 2>/dev/null | sort | tail -1)"
    [ -n "${newest}" ] && { printf '%s' "${newest}"; return 0; }
  done
  return 1
}

# Start the node in the background. With one argument it also answers the
# first-run display-name question; without one it does not touch the identity.
node_launch() {
  if [ $# -gt 0 ]; then
    "${local_bin}" --chat-server-port "${NODE_PORT}" -y --user-display-name "$1" </dev/null >"${RUN_DIR}/node.log" 2>&1 &
  else
    # -y so a first run does not block on the database-migration confirmation with
    # nobody attached to answer it. No -d: the node's own default profile prefix
    # (~/.popopx/popopx_v1) is the identity already paired with the iPhone, and
    # inventing a fresh one would silently create a different service account.
    # stdin is /dev/null deliberately: the alternative is the terminal, and a node
    # that decides to ask a question while its output goes to a log file waits
    # forever for an input this script never tells you to give it.
    "${local_bin}" --chat-server-port "${NODE_PORT}" -y </dev/null >"${RUN_DIR}/node.log" 2>&1 &
  fi
  NODE_PID=$!
  echo "${NODE_PID}" > "${RUN_DIR}/node.pid"
}

# Poll for the API port. 0 = listening, 1 = the process died, 2 = still alive
# but not answering yet; keeping the three apart is what lets the caller retry
# for a missing profile without mistaking it for a broken binary.
node_wait() {
  local i=0
  while [ ${i} -lt 40 ]; do
    port_listening "${NODE_PORT}" && return 0
    kill -0 "${NODE_PID}" 2>/dev/null || return 1
    i=$((i + 1)); sleep 0.5
  done
  return 2
}

start_node() {
  if port_listening "${NODE_PORT}"; then
    log "a node already listens on 127.0.0.1:${NODE_PORT} — reusing it, no second node started"
    NODE_PID=""
    return 0
  fi
  local_bin="$(find_node_bin || true)"
  if [ -z "${local_bin}" ]; then
    cat >&2 <<HINT
[fatal] no popopx-chat node found, and none is listening on ${NODE_PORT}.

  Build it from the node checkout, then re-run:
     cd <popopx-chat checkout> && cabal build popopx-chat
     cabal list-bin popopx-chat            # prints the binary path
  ...or start your own node and use:  ./start_macos.sh --no-node
  ...or point at a binary directly:   ./start_macos.sh --node-bin /path/to/popopx-chat

  The suite cannot work without a node: the WebSocket JSON API on loopback is the
  only way out of this codebase to a real device.
HINT
    exit 4
  fi

  install -d -m 755 "${RUN_DIR}"
  log "starting node: ${local_bin} --chat-server-port ${NODE_PORT} -y"
  # First pass deliberately omits --user-display-name. The flag is NOT a no-op on
  # a machine that already has a profile: the node compares it against the active
  # user's display name and exits when they differ (src/Popopx/Chat/Core.hs:79-82
  # — "Active user display name ... does not match --user-display-name"), so
  # passing ours unconditionally would break the very setup this launcher exists
  # to serve. Only if the node says it has no profile do we create one, with a
  # name the operator can override.
  node_launch
  node_wait
  rc=$?
  if [ ${rc} -eq 1 ] && grep -q "No user profiles found" "${RUN_DIR}/node.log"; then
    log "the node has no user profile yet — creating one as '${NODE_DISPLAY_NAME}' (override with POPOPX_NODE_DISPLAY_NAME)"
    node_launch "${NODE_DISPLAY_NAME}"
    node_wait
    rc=$?
  fi
  case ${rc} in
    0) log "node up (pid ${NODE_PID}) on 127.0.0.1:${NODE_PORT}"; return 0 ;;
    1)
      warn "node exited immediately; last lines of ${RUN_DIR}/node.log:"
      tail -20 "${RUN_DIR}/node.log" >&2 || true
      exit 4 ;;
    *)
      warn "node process ${NODE_PID} is alive but ${NODE_PORT} is not listening yet — check ${RUN_DIR}/node.log" ;;
  esac
}

# ─────────────────────────────── gateway: venv ──────────────────────────────

ensure_venv() {
  PY="$(find_python || true)"
  if ! python_ok "${PY:-}"; then
    cat >&2 <<HINT
[fatal] Python 3.11 not found.

  Install it and re-run:
     brew install python@3.11
  or, if it lives somewhere unusual:
     POPOPX_PYTHON=/path/to/python3.11 ./start_macos.sh

  Checked: \$PATH, /opt/homebrew/bin, /usr/local/bin,
  /Library/Frameworks/Python.framework/Versions/3.11/bin, brew --prefix python@3.11.
HINT
    exit 3
  fi
  log "interpreter: ${PY} ($("${PY}" -V 2>&1))"

  if [ ! -x "${VENV_DIR}/bin/python" ]; then
    log "creating ${VENV_DIR}"
    "${PY}" -m venv "${VENV_DIR}" || die "python -m venv failed (is the venv module available? brew python@3.11 includes it)"
  fi
  # Install when the venv is new or when the locked set no longer resolves, but
  # never on every launch: `pip install -r` on a warm venv costs 20s of network
  # for an answer we already have.
  if [ ! -f "${VENV_DIR}/.deps-ok" ] || [ "${SUITE_DIR}/gateway/requirements.txt" -nt "${VENV_DIR}/.deps-ok" ]; then
    log "installing dependencies (first run only; ~1 min)"
    "${VENV_DIR}/bin/pip" install --quiet --upgrade pip wheel || die "pip upgrade failed"
    "${VENV_DIR}/bin/pip" install --quiet -r "${SUITE_DIR}/gateway/requirements.txt" \
      || die "dependency install failed. If compiling cryptography from source, accept the Command Line Tools: xcode-select --install"
    : > "${VENV_DIR}/.deps-ok"
  else
    log "dependencies already installed in ${VENV_DIR}"
  fi
}

run_gateway_native() {
  ensure_env
  ensure_venv
  install -d -m 755 "${RUN_DIR}"

  HOST_BIND="${FORCED_HOST:-0.0.0.0}"
  IP="$(lan_ip)"
  # The shipped defaults are the Linux FHS paths (/var/lib/popopx-service-suite),
  # which a developer cannot write without sudo. Keep the file untouched for
  # production and relocate state into the repo for this session only.
  install -d -m 700 "${SUITE_DIR}/.data"

  # Resolved BEFORE the subshell so a failure is a sentence on the terminal and
  # not a line in a log file nobody opened, and so an empty result can never be
  # exported: `POPOPX_OFFICIAL_ED25519_PUBLIC_KEY=` in the environment beats the
  # real key in .env, which would take a working deployment offline for a bug in
  # this script.
  OFFICIAL_PUB="$(ensure_official_key || true)"
  if [ -z "${OFFICIAL_PUB}" ] && voucher_required; then
    die "no official POPX-CP public key, and POPOPX_BILLING_REQUIRE_VOUCHER is on. Either set POPOPX_OFFICIAL_ED25519_PUBLIC_KEY in ${ENV_FILE}, or create a development keyring:
     ${VENV_DIR}/bin/python official_tools/gen_voucher.py --gen-keyring --keyring ${DEV_KEYRING}
     ${VENV_DIR}/bin/python official_tools/gen_voucher.py --show-pubkey --keyring ${DEV_KEYRING}"
  fi
  if [ -n "${OFFICIAL_PUB}" ]; then
    log "official voucher key: ${OFFICIAL_PUB:0:12}… (public half; this run only)"
  else
    log "voucher admission off (the default): the account starts ONLINE, no official key needed"
  fi

  log "gateway: python -m app.main on ${HOST_BIND}:${GATEWAY_PORT} (1 process: the node link's pending-correlation table is per-process)"
  (
    cd "${SUITE_DIR}/gateway" || exit 1
    # The values below are exported for this command only, so the file stays
    # untouched and `git diff` after a development run shows nothing. They are
    # written as a prefix to `exec`, NOT as a standalone assignment list: a
    # `VAR=x \` line followed by a comment line and then the command is a
    # comment-swallowed continuation, the assignment binds to the subshell
    # instead of the child, and uvicorn starts with .env's port and the Linux
    # FHS database path while the script cheerfully reports the dev one.
    #
    # `python -m app.main`, not `app.main:app`: building the ASGI object at import
    # time would need a configured .env and a writable database before anything
    # could run, and the main entrypoint reads the host/port/log level from the
    # same Config as the rest of the suite — a --host/--port here would be a
    # second source of truth about one socket and the flag would silently win.
    POPOPX_NODE_WS_URL="${NODE_WS}" \
    POPOPX_GATEWAY_HOST="${HOST_BIND}" \
    POPOPX_GATEWAY_PORT="${GATEWAY_PORT}" \
    POPOPX_DB_PATH="${SUITE_DIR}/.data/gateway.db" \
    POPOPX_PUBLIC_BASE_URL="http://${IP}:${GATEWAY_PORT}" \
    POPOPX_OFFICIAL_ED25519_PUBLIC_KEY="${OFFICIAL_PUB}" \
    exec "${VENV_DIR}/bin/python" -m app.main
  ) >"${RUN_DIR}/gateway.log" 2>&1 &
  GW_PID=$!
  echo "${GW_PID}" > "${RUN_DIR}/gateway.pid"

  i=0
  while [ ${i} -lt 40 ]; do
    if curl -fsS "http://127.0.0.1:${GATEWAY_PORT}/healthz" >/dev/null 2>&1; then
      log "gateway healthy (pid ${GW_PID})"
      return 0
    fi
    kill -0 "${GW_PID}" 2>/dev/null || { warn "gateway exited; ${RUN_DIR}/gateway.log:"; tail -30 "${RUN_DIR}/gateway.log" >&2 || true; return 1; }
    i=$((i + 1)); sleep 0.5
  done
  warn "gateway did not answer /healthz within 20s — see ${RUN_DIR}/gateway.log"
}

# ─────────────────────────────── gateway: docker ────────────────────────────

run_gateway_docker() {
  command -v docker >/dev/null 2>&1 || die "--docker requested but docker is not on PATH"
  docker info >/dev/null 2>&1 || die "docker is installed but the daemon is not running (open Docker Desktop and retry)"
  docker compose version >/dev/null 2>&1 || die "this docker has no compose v2 plugin"

  # Stated plainly because it is the trap this whole script exists to avoid:
  # docker-compose.yml sets network_mode: host, which is correct for Linux and a
  # no-op-to-worse on Docker Desktop unless "Host networking" is enabled in
  # Settings (4.26+). Without it, the gateway cannot reach a node on this Mac.
  warn "Docker Desktop: 'network_mode: host' needs Settings → Resources → Network → Enable host networking."
  warn "Without it a containerised gateway cannot reach a node running on macOS. Use the default venv path instead."
  # The container takes its configuration from .env through compose's env_file,
  # so the development keyring that the venv path creates under .run/ is not
  # reachable from it — and a gateway that cannot verify a POPX-CP code refuses
  # to boot at all, which in compose looks like a container that restarts.
  official_pubkey_from_file >/dev/null || {
    warn "no official POPX-CP public key in ${ENV_FILE}: the container will refuse to start."
    warn "Add the key, or use the default venv path, which creates a throwaway development"
    warn "keyring in ${DEV_KEYRING} and passes only its public half to the gateway."
  }
  if [ ${START_NODE} -eq 1 ]; then
    warn "--docker implies the node is containerised too (profile 'node'); a host node stays unreachable"
    ( cd "${SUITE_DIR}" && docker compose --profile node up -d --build gateway node )
  else
    ( cd "${SUITE_DIR}" && docker compose up -d --build gateway )
  fi
  ( cd "${SUITE_DIR}" && docker compose ps ) || true
  log "logs:  docker compose logs -f gateway"
  log "stop:  docker compose down"
}

# ───────────────────────────────── pairing ──────────────────────────────────

print_pairing() {
  IP="$(lan_ip)"
  TOKEN_LINE="located in ${ENV_FILE} (./start_macos.sh --show-token to display)"
  if [ ${SHOW_TOKEN} -eq 1 ]; then
    t="$(read_token || true)"
    [ -n "${t}" ] && TOKEN_LINE="${t}"
  fi
  cat <<PAIR

────────────────────────────────────────────────────────────────────────────
 POPOPX Service Suite — development endpoints
────────────────────────────────────────────────────────────────────────────
 Admin console   http://127.0.0.1:${GATEWAY_PORT}/
 Bearer token    ${TOKEN_LINE}
 From your phone http://${IP}:${GATEWAY_PORT}   (same Wi-Fi; the launcher
                 accepts http, PopopxH5Launcher.swift:52)
 Node API        ${NODE_WS}  (loopback, no authentication — keep it that way)
 H5 origin       http://${IP}:${GATEWAY_PORT}  (pushed into this run only)

 Before you trust any of it, the two suites that are NOT on the boot path:
   cd ${SUITE_DIR}/gateway && ${VENV_DIR}/bin/python -m app.main --self-test
   cd ${SUITE_DIR}/gateway && ${VENV_DIR}/bin/python -m app.main --check-routes
 The first requests every declared route against the real ASGI app; the second
 is the one gate `create_app()` does run before the socket is bound.

 If the iPhone cannot reach that address, in order of likelihood:
   1. macOS firewall:  System Settings → Network → Firewall → allow
      python3 (or turn stealth mode off).  Check with:
        /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
   2. The AP has client isolation on — very common on guest and corporate
      Wi-Fi. Use the Mac's hotspot or a different network; no setting here fixes it.
   3. The node's contact address was generated for another host — re-share it
      from the console; the relay address, not the LAN IP, is what the phone dials.

 Pairing needs no code edit, but it does need the two halves to be the same
 process group: the service account the node holds and the pairwise session the
 gateway records. Reset the gateway state (.data/) if you switch nodes, otherwise
 old pairwise_uid values will be signed with secrets the new node never issued.

 Ctrl-C stops the gateway and any node this script started. Nothing is installed
 system-wide; the venv is ${VENV_DIR}, deletable.
────────────────────────────────────────────────────────────────────────────
PAIR
}

shutdown() {
  trap - INT TERM EXIT
  echo
  log "shutting down"
  if [ -n "${GW_PID:-}" ] && kill -0 "${GW_PID}" 2>/dev/null; then
    kill -INT "${GW_PID}" 2>/dev/null || true
    # Uvicorn drains on SIGINT; give it the same grace the containers get.
    i=0
    while kill -0 "${GW_PID}" 2>/dev/null && [ ${i} -lt 20 ]; do i=$((i + 1)); sleep 0.25; done
    kill -TERM "${GW_PID}" 2>/dev/null || true
  fi
  if [ -n "${NODE_PID:-}" ] && kill -0 "${NODE_PID}" 2>/dev/null; then
    # Only a node THIS script started is ever stopped — a pre-existing node is
    # the developer's own process and may hold the paired identity.
    kill -TERM "${NODE_PID}" 2>/dev/null || true
  fi
  rm -f "${RUN_DIR}/gateway.pid" "${RUN_DIR}/node.pid" 2>/dev/null || true
  exit 0
}

# ─────────────────────────────────── main ───────────────────────────────────

[ ${CHECK_ONLY} -eq 1 ] && {
  PY="$(find_python || true)"
  python_ok "${PY:-}" && log "python: ${PY}" || warn "python 3.11: NOT FOUND (brew install python@3.11)"
  nb="$(find_node_bin || true)"
  [ -n "${nb}" ] && log "node: ${nb}" || warn "node binary: not found (a running node on ${NODE_PORT} is enough)"
  port_listening "${NODE_PORT}" && log "node already listening on 127.0.0.1:${NODE_PORT}" || log "nothing on ${NODE_PORT}"
  command -v docker >/dev/null 2>&1 && log "docker: $(docker --version 2>/dev/null)" || log "docker: absent (fine — the venv path does not need it)"
  # Configuration, reported without creating anything: the two values that make
  # the gateway refuse to boot are decided by a script run, and an operator who
  # asks "why did it exit 3" deserves the answer before the first run, not in a
  # log file after it.
  if [ -f "${ENV_FILE}" ]; then
    log "config: ${ENV_FILE} present"
    if grep -q '^POPOPX_ADMIN_TOKEN=..*' "${ENV_FILE}"; then
      log "  admin token: set"
    else
      warn "  admin token: empty — the gateway will not boot. A real run generates one here."
    fi
    if official_pubkey_from_file >/dev/null 2>&1; then
      log "  official POPX-CP public key: configured"
    elif voucher_required; then
      warn "  official POPX-CP public key: absent — a real run creates a development keyring in ${DEV_KEYRING}"
    else
      log "  official POPX-CP public key: absent, and admission is off (default: starts ONLINE)"
    fi
  else
    log "config: no ${ENV_FILE} yet — a real run copies .env.example and generates the token into it"
  fi
  log "gateway entry: python -m app.main (host ${FORCED_HOST:-0.0.0.0}, port ${GATEWAY_PORT}, database ${SUITE_DIR}/.data/gateway.db)"
  log "LAN address: $(lan_ip)"
  exit 0
}

install -d -m 755 "${RUN_DIR}"
GW_PID=""; NODE_PID=""

if [ ${USE_DOCKER} -eq 1 ]; then
  ensure_env
  run_gateway_docker
  print_pairing
  exit 0
fi

[ ${START_NODE} -eq 1 ] && start_node || log "--no-node: expecting a node on ${NODE_WS}"

if ! run_gateway_native; then
  warn "gateway failed to start; the node (if started here) is left running so you can retry"
  [ -n "${NODE_PID:-}" ] && kill -TERM "${NODE_PID}" 2>/dev/null || true
  exit 1
fi

print_pairing
trap 'shutdown' INT TERM EXIT
# `wait` on the uvicorn pid keeps the script in the foreground with the gateway's
# own lifetime; tail -f is only the log view, and losing it must not end the run.
tail -f "${RUN_DIR}/gateway.log" &
TAIL_PID=$!
wait "${GW_PID}" 2>/dev/null || true
kill "${TAIL_PID}" 2>/dev/null || true
shutdown
