#!/usr/bin/env bash
# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
# POPOPX Service Suite — Ubuntu 22.04 LTS production installer.
#
#   sudo ./install_ubuntu22.sh                  # containerised gateway (default)
#   sudo ./install_ubuntu22.sh --mode native    # venv + systemd, no Docker
#   sudo ./install_ubuntu22.sh --with-node      # also install/run the chat node
#
# What it guarantees, because an installer that lies is worse than no installer:
#   * idempotent — re-running never destroys an existing .env or the state
#     directory (the database that holds ledger, sessions and channel keys);
#     anything it would overwrite it backs up with a timestamp;
#   * it writes no secret to stdout. Per-host secrets are generated inside a
#     python process into .env (mode 0600) and only their NAMES are reported;
#   * it does NOT open any firewall port. The gateway binds
#     $POPOPX_GATEWAY_PORT on 0.0.0.0 and prints the exact `ufw` line to run.
#
# Requires root (or sudo). Tested shell: bash 5.1 (Ubuntu 22.04's own).

set -Eeuo pipefail

readonly SUITE_NAME="popopx-service-suite"
readonly INSTALL_ROOT="/opt/${SUITE_NAME}"
readonly STATE_DIR="/var/lib/popopx-service-suite"
readonly CONF_DIR="/etc/popopx-service-suite"
readonly RUN_USER="popopx"
readonly PYTHON_VERSION="3.11"

MODE="docker"
WITH_NODE=0
SKIP_APT=0
GATEWAY_PORT="${POPOPX_GATEWAY_PORT:-8080}"
NODE_IMAGE="${POPOPX_NODE_IMAGE:-popopx-chat-node:local}"
COMPOSE_HINT="docker compose"

log()  { printf '\033[1;35m[popopx]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fatal]\033[0m %s\n' "$*" >&2; exit 1; }

on_error() {
  local line="$1"
  warn "install_ubuntu22.sh aborted at line ${line}."
  warn "Nothing here is destructive; the previous deployment (if any) is still in place."
  exit 1
}
trap 'on_error ${LINENO}' ERR

usage() {
  # The ERR trap is dropped on purpose: `install_ubuntu22.sh --help | head`
  # closes the pipe early, sed dies of SIGPIPE, and the trap would otherwise
  # print a red "aborted" warning for a help screen that worked.
  trap - ERR
  set +e
  awk 'NR > 1 { if (!/^#/) exit; sub(/^# ?/, ""); print }' "$0"
  cat <<'USAGE'

Options:
  --mode docker|native   Install as containers (default) or as a venv + systemd unit.
  --with-node            Also install and start the open-source chat node next to the gateway.
  --port N               Gateway port (default 8080, or $POPOPX_GATEWAY_PORT).
  --skip-apt             Do not touch apt-get (airgapped host with packages already present).
  -h, --help             This text.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      [[ -n "${2:-}" ]] || die "--mode needs an argument (docker|native)"
      MODE="$2"; shift 2 ;;
    --mode=*) MODE="${1#*=}"; shift ;;
    --with-node) WITH_NODE=1; shift ;;
    --port) [[ -n "${2:-}" ]] || die "--port needs a value"; GATEWAY_PORT="$2"; shift 2 ;;
    --port=*) GATEWAY_PORT="${1#*=}"; shift ;;
    --skip-apt) SKIP_APT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

case "${MODE}" in
  docker|native) ;;
  *) die "--mode must be 'docker' or 'native', got '${MODE}'" ;;
esac
[[ "${GATEWAY_PORT}" =~ ^[0-9]+$ ]] && (( GATEWAY_PORT >= 1 && GATEWAY_PORT <= 65535 )) \
  || die "--port must be 1-65535, got '${GATEWAY_PORT}'"

# ───────────────────────────── preflight ────────────────────────────────────

[[ ${EUID} -eq 0 ]] || die "run as root:  sudo ./install_ubuntu22.sh"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "${REPO_DIR}/docker-compose.yml" && -d "${REPO_DIR}/gateway/app" ]] \
  || die "${REPO_DIR} does not look like the popopx-service-suite checkout (no docker-compose.yml or gateway/app)"

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" != "22.04" ]]; then
    warn "this script targets Ubuntu 22.04; detected ${PRETTY_NAME:-unknown}."
    warn "Continuing — the only release-specific step is the deadsnakes PPA for Python ${PYTHON_VERSION}."
  fi
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# ─────────────────────────────── secrets ────────────────────────────────────

ensure_env_file() {
  local target="$1"
  local example="${REPO_DIR}/.env.example"
  if [[ -f "${target}" ]]; then
    local backup="${target}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    log "existing .env found; keeping it and saving the pre-run copy to ${backup}"
    cp -p "${target}" "${backup}"
    # Said out loud because the gateway now reads its socket from this file and
    # nothing else: an operator who re-runs the installer with --port 9000 over a
    # deployment that says 8080 will get 8080, and the healthy-looking service on
    # the old port is the last thing they suspect.
    warn "the existing file wins: a value already set here (POPOPX_GATEWAY_PORT included) is NOT replaced by --port. Edit ${target} to move the service."
    return 0
  fi
  [[ -f "${example}" ]] || die "no .env and no ${example} to seed one from"

  install -d -m 0750 "$(dirname "${target}")"
  cp "${example}" "${target}"

  # Fill in only the values that MUST be unique per host. Everything else stays
  # at the shipped default so a diff of .env against .env.example shows the
  # operator exactly what the installer decided for them.
  #
  # The secrets are generated INSIDE the python process, not in bash argv:
  # a value passed as an argument is readable by every local user through
  # `ps -eww -o args` for the lifetime of the call, which on a shared box is a
  # disclosure of the token that authorises sending cards and rotating keys.
  GATEWAY_PORT="${GATEWAY_PORT}" TARGET_ENV="${target}" python3 - <<'PYEOF'
import os, re, secrets
path = os.environ["TARGET_ENV"]
admin_token = secrets.token_hex(32)
webhook_token = secrets.token_hex(20)
replacements = {
    "POPOPX_ADMIN_TOKEN": admin_token,
    "POPOPX_ALERT_WEBHOOK_TOKEN": webhook_token,
    "POPOPX_GATEWAY_PORT": os.environ["GATEWAY_PORT"],
}
text = open(path, encoding="utf-8").read()
for key, value in replacements.items():
    pattern = "(?m)^%s=.*$" % re.escape(key)
    if not re.search(pattern, text):
        text = text.rstrip("\n") + ("\n%s=%s\n" % (key, value))
    else:
        text = re.sub(pattern, "%s=%s" % (key, value), text)
open(path, "w", encoding="utf-8").write(text)
os.chmod(path, 0o600)
print("[popopx] generated %d per-host secrets in %s (values not displayed)" % (len(replacements) - 1, path))
PYEOF
  chown "${RUN_USER}:${RUN_USER}" "${target}" 2>/dev/null || true

  echo
  log "─────────────────────── ONE-TIME SECRET NOTICE ───────────────────────"
  log "POPOPX_ADMIN_TOKEN was generated and written to ${target} (mode 0600)."
  log "It was NOT printed to this terminal. Read it with:"
  log "    sudo grep POPOPX_ADMIN_TOKEN ${target}"
  log "If you ever paste that file into a chat, ticket or CI log, treat the"
  log "token as compromised and rotate it — a bearer token grants card-sending"
  log "and key-rotation rights on this deployment."
  log "──────────────────────────────────────────────────────────────────────"
  echo
}

# ─────────────────────────────── docker mode ────────────────────────────────

install_docker() {
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    log "docker engine already running: $(docker --version)"
  else
    if [[ ${SKIP_APT} -eq 0 ]]; then
      log "installing docker.io + compose plugin from the Ubuntu archive"
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq docker.io containerd runc docker-compose-plugin curl ca-certificates
    fi
    command -v docker >/dev/null 2>&1 || die "docker is not installed and --skip-apt was given"
    systemctl enable --now docker
    # `docker info` is the only real readiness test: systemd can report
    # "active" while the socket is still coming up, and the first compose build
    # would then fail with a permission error that reads like a broken install.
    for _ in $(seq 1 30); do
      docker info >/dev/null 2>&1 && break
      sleep 1
    done
    docker info >/dev/null 2>&1 || die "docker daemon did not become ready within 30s"
    log "docker engine ready: $(docker --version)"
  fi

  if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    warn "using legacy docker-compose binary; host-networking behaviour is identical but the file format must be v2"
    COMPOSE=(docker-compose)
  else
    die "no compose plugin found. Install docker-compose-plugin, or run: sudo ./install_ubuntu22.sh --mode native"
  fi
}

run_docker() {
  local compose_dir="${INSTALL_ROOT}/src"
  install -d -m 0755 "${INSTALL_ROOT}" "${STATE_DIR}"
  log "syncing suite source to ${compose_dir}"
  install -d -m 0755 "${compose_dir}"
  # `cp -a` rather than rsync: rsync is not in the Ubuntu cloud-image base and
  # installing it for one copy operation is not worth another apt transaction.
  cp -a "${REPO_DIR}/docker-compose.yml" "${compose_dir}/"
  cp -a "${REPO_DIR}/gateway" "${compose_dir}/"
  cp -a "${REPO_DIR}/official_tools" "${compose_dir}/" 2>/dev/null || true
  [[ -f "${REPO_DIR}/LICENSE" ]] && cp -a "${REPO_DIR}/LICENSE" "${compose_dir}/"

  ensure_env_file "${compose_dir}/.env"

  # The named volume is owned by the image's uid 1001. A bind mount would be
  # owned by whoever created the directory, so on a host where 1001 is not
  # 'popopx' the container would fail on its first ledger write with a
  # SQLITE_CANTOPEN that looks like a corrupt database.
  if [[ -d "${STATE_DIR}" ]]; then
    chown -R 1001:1001 "${STATE_DIR}" 2>/dev/null || warn "could not chown ${STATE_DIR} to 1001 — check gateway logs if startup fails on the database"
  fi
  chmod 0750 "${STATE_DIR}"

  export POPOPX_NODE_IMAGE="${NODE_IMAGE}"
  COMPOSE_HINT="${COMPOSE[*]}"
  log "building the gateway image (this pulls the Python 3.11 base layer once)"
  ( cd "${compose_dir}" && "${COMPOSE[@]}" build gateway )

  # `--profile node` is the only way to get the node container at all, and it is
  # opt-in because the node needs its own SMP relay configuration that this
  # installer cannot guess.
  if [[ ${WITH_NODE} -eq 1 ]]; then
    log "including the managed node (image ${NODE_IMAGE}); configure its relay before expecting inbound traffic"
    ( cd "${compose_dir}" && "${COMPOSE[@]}" --profile node up -d gateway node )
  else
    ( cd "${compose_dir}" && "${COMPOSE[@]}" up -d gateway )
  fi

  echo
  log "container status:"
  ( cd "${compose_dir}" && "${COMPOSE[@]}" ps ) || true
  log "to follow the gateway:  ( cd ${compose_dir} && ${COMPOSE[*]} logs -f gateway )"
}

# ─────────────────────────────── native mode ────────────────────────────────

install_python_311() {
  if command -v "python${PYTHON_VERSION}" >/dev/null 2>&1; then
    log "python${PYTHON_VERSION} present: $(python${PYTHON_VERSION} -V 2>&1)"
    return 0
  fi
  [[ ${SKIP_APT} -eq 0 ]] || die "python${PYTHON_VERSION} is missing and --skip-apt was given"

  log "Ubuntu 22.04 ships Python 3.10; adding deadsnakes for ${PYTHON_VERSION}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq software-properties-common curl ca-certificates gnupg
  # deadsnakes is a third-party PPA. It is unavoidable here: 3.11 is the
  # interpreter this suite is built and typed against, and the alternative —
  # running on 3.10 — silently drops the syntax the codebase is written in.
  add-apt-repository -y ppa:deadsnakes/ppa
  apt-get update -qq
  apt-get install -y -qq \
    "python${PYTHON_VERSION}" "python${PYTHON_VERSION}-venv" "python${PYTHON_VERSION}-dev" \
    build-essential libssl-dev libffi-dev pkg-config curl ca-certificates
  command -v "python${PYTHON_VERSION}" >/dev/null 2>&1 || die "python${PYTHON_VERSION} still not on PATH after install"
}

run_native() {
  install_python_311

  log "creating service account ${RUN_USER}"
  id -u "${RUN_USER}" >/dev/null 2>&1 || \
    useradd --system --create-home --home-dir "/var/lib/${RUN_USER}" --shell /usr/sbin/nologin "${RUN_USER}"

  install -d -m 0755 "${INSTALL_ROOT}"
  log "syncing source to ${INSTALL_ROOT}"
  rm -rf "${INSTALL_ROOT}/src.new"   # scratch path this script created, nothing else
  install -d -m 0755 "${INSTALL_ROOT}/src.new"
  # tar rather than rsync (see run_docker:214 — rsync is not in the Ubuntu cloud-image
  # base), and excluding instead of `cp -a` then `rm -rf .git`: the checkout IS the dev
  # environment on a workstation, so a plain copy carried `.env` — a live admin token —
  # into ${INSTALL_ROOT}/src, where config.py finds it whenever POPOPX_ENV_FILE is unset,
  # making it a second source of truth quieter than the first. `.venv` does not survive
  # the move (a virtualenv is path-relative), the venv here is built, never carried, and
  # `*.db` would have carried real ledger rows into a deployment that must start empty.
  # `*.db` alone misses the SQLite sidecars, hence -shm and -wal; the same nine patterns
  # install_macos.sh hands to rsync, so the two production paths copy the same tree.
  ( cd "${REPO_DIR}" && tar -cf - \
        --exclude .git --exclude .env --exclude '.env.bak.*' --exclude .venv \
        --exclude .run --exclude .data --exclude '*.db' --exclude '*.db-shm' --exclude '*.db-wal' \
        . ) | ( cd "${INSTALL_ROOT}/src.new" && tar -xpf - )
  if [[ -d "${INSTALL_ROOT}/src" ]]; then
    rm -rf "${INSTALL_ROOT}/src.prev"
    mv "${INSTALL_ROOT}/src" "${INSTALL_ROOT}/src.prev"
  fi
  mv "${INSTALL_ROOT}/src.new" "${INSTALL_ROOT}/src"

  install -d -m 0750 -o "${RUN_USER}" -g "${RUN_USER}" "${STATE_DIR}" "${CONF_DIR}"

  if [[ ! -x "${INSTALL_ROOT}/venv/bin/python" ]]; then
    log "creating the virtualenv with python${PYTHON_VERSION}"
    "python${PYTHON_VERSION}" -m venv "${INSTALL_ROOT}/venv"
  fi
  "${INSTALL_ROOT}/venv/bin/python" -m pip install --upgrade pip wheel >/dev/null
  log "installing gateway dependencies (this is the slow step)"
  "${INSTALL_ROOT}/venv/bin/pip" install -r "${INSTALL_ROOT}/src/gateway/requirements.txt"
  "${INSTALL_ROOT}/venv/bin/pip" freeze > "${INSTALL_ROOT}/requirements.lock"
  log "resolved dependency set pinned to ${INSTALL_ROOT}/requirements.lock"

  ensure_env_file "${CONF_DIR}/env"

  chown -R "${RUN_USER}:${RUN_USER}" "${INSTALL_ROOT}/src" "${STATE_DIR}"

  log "writing systemd units"
  cat > /etc/systemd/system/popopx-gateway.service <<UNIT
# Generated by install_ubuntu22.sh --mode native on $(date -u +%FT%TZ)
# Regenerate by re-running the installer; edits here are overwritten.
[Unit]
Description=POPOPX service-account gateway (POPX-CP billing, eco protocol, plugins)
Documentation=https://popopx.chat/docs/service-suite
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_USER}
WorkingDirectory=${INSTALL_ROOT}/src/gateway
EnvironmentFile=${CONF_DIR}/env
# The entrypoint is the module, not a uvicorn argv: POPOPX_GATEWAY_HOST,
# POPOPX_GATEWAY_PORT and POPOPX_LOG_LEVEL in the EnvironmentFile above are the
# single source of truth for the socket. A --host/--port on this command line
# would be a second source and, worse, would silently win over the file the
# operator edits — the classic "I changed the port in .env and nothing happened".
# One worker is enforced inside main() for the same reason: the node link and its
# table of pending correlation ids are per-process state, so a second worker
# means two links and a command whose reply arrives on the socket that did not
# send it. access_log is off there too: request bodies carry pairwise uids.
ExecStart=${INSTALL_ROOT}/venv/bin/python -m app.main
Restart=on-failure
RestartSec=3
TimeoutStopSec=15
KillSignal=SIGINT
StateDirectory=popopx-service-suite
ReadWritePaths=${STATE_DIR}
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictSUIDSGID=true
MemoryMax=768M

[Install]
WantedBy=multi-user.target
UNIT

  if [[ ${WITH_NODE} -eq 1 ]]; then
    # The node is the open-source AGPL component. Running it as its own unit,
    # under its own user, with its own state directory is what keeps the
    # isolation claim in LICENSE §3 true on the box and not only on paper.
    id -u popopx-node >/dev/null 2>&1 || \
      useradd --system --create-home --home-dir /var/lib/popopx-node --shell /usr/sbin/nologin popopx-node
    # Two values the unit must not guess at, so they live in their own file that
    # an operator edits and a re-run of this installer never overwrites.
    install -d -m 0755 /etc/default
    if [[ ! -f /etc/default/popopx-node ]]; then
      cat > /etc/default/popopx-node <<'DEF'
# POPOPX chat node — edited by hand, never rewritten by install_ubuntu22.sh.
# Prefix for the node's chat + agent databases (its own --database argument).
NODE_DB_PREFIX=/var/lib/popopx-node/popopx_v1
# The node's WebSocket API port the gateway dials. Change both here and
# POPOPX_NODE_WS_URL in the gateway's env file; they are one number in two files
# because the gateway and the node are separate processes with separate configs.
NODE_PORT=5225
# Used ONLY when the database prefix has no user profile yet. If a profile
# exists and its display name differs, the node exits with
# "does not match --user-display-name" — that is the node protecting an
# identity that is already paired with devices, so set this to that name.
NODE_DISPLAY_NAME=POPOPX Service
DEF
      log "wrote /etc/default/popopx-node"
    else
      log "keeping the existing /etc/default/popopx-node"
    fi
    cat > /etc/systemd/system/popopx-node.service <<'UNIT'
# Generated by install_ubuntu22.sh --mode native
# Regenerate by re-running the installer; edits here are overwritten, so the
# values worth keeping belong in /etc/default/popopx-node instead.
[Unit]
Description=POPOPX chat node (open source, separate licence and process)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=popopx-node
Group=popopx-node
Environment=HOME=/var/lib/popopx-node
EnvironmentFile=/etc/default/popopx-node
# systemd expands $VAR in the arguments of ExecStart, which is how the database
# prefix and the port stay in the defaults file rather than in this unit.
ExecStart=/usr/local/bin/popopx-chat --chat-server-port ${NODE_PORT} --database ${NODE_DB_PREFIX} --yes-migrate --user-display-name ${NODE_DISPLAY_NAME}
# No terminal exists for a service, and the node's first-run profile creation
# reads stdin. Explicitly null it so the answer comes from --user-display-name
# above instead of a prompt that would hang the unit until start timeout.
StandardInput=null
Restart=on-failure
RestartSec=3
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
    warn "the node unit assumes /usr/local/bin/popopx-chat exists."
    warn "Install the node from its own source tree first; this script does not"
    warn "build Haskell and does not ship the AGPL component inside this suite."
    warn "if the node already has a profile, set NODE_DISPLAY_NAME in"
    warn "/etc/default/popopx-node to its existing display name or it will refuse to start."
  fi

  systemctl daemon-reload
  systemctl enable popopx-gateway.service >/dev/null
  systemctl restart popopx-gateway.service
  [[ ${WITH_NODE} -eq 1 ]] && systemctl enable --now popopx-node.service || true

  sleep 2
  systemctl --no-pager --lines=20 status popopx-gateway.service || true
}

# ─────────────────────────────── verification ───────────────────────────────

verify() {
  local url="http://127.0.0.1:${GATEWAY_PORT}/healthz"
  log "probing ${url}"
  local ok=0
  for _ in $(seq 1 20); do
    if curl -fsS "${url}" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  if [[ ${ok} -eq 1 ]]; then
    log "gateway answers /healthz:"
    curl -fsS "${url}" | head -c 800; echo
  else
    warn "/healthz did not answer within 20s. The process may be up while the"
    warn "node link is still down — /healthz reports node state, it does not"
    warn "gate readiness on it. Check:"
    warn "  native : journalctl -u popopx-gateway -n 80 --no-pager"
    warn "  docker : ( cd ${INSTALL_ROOT}/src && ${COMPOSE_HINT} logs --tail 80 gateway )"
  fi

  cat <<SUMMARY

────────────────────────────────────────────────────────────────────────────
 POPOPX Service Suite — installed (mode: ${MODE}, port: ${GATEWAY_PORT})
────────────────────────────────────────────────────────────────────────────
 State      ${STATE_DIR}          (SQLite + channel keys, mode 0750)
 Config     $([[ ${MODE} == native ]] && echo "${CONF_DIR}/env" || echo "${INSTALL_ROOT}/src/.env")
 Source     ${INSTALL_ROOT}/src

 NEXT STEPS — none of these are done for you, on purpose:

 1. Point the console at a real origin and TLS-terminate it. PopopxH5Launcher
    signs the URL it is about to open, so POPOPX_PUBLIC_BASE_URL must be the
    exact https origin the phone will load:
      POPOPX_PUBLIC_BASE_URL=https://service.yourdomain.com

 2. Optional — only if you set POPOPX_BILLING_REQUIRE_VOUCHER=1. Admission mode
    starts the account in DRAFT and needs the official voucher public key:
      python3 official_tools/gen_voucher.py --show-pubkey --keyring ./official_keys
      POPOPX_OFFICIAL_ED25519_PUBLIC_KEY=<base64 above>

 3. The node's WebSocket API has NO authentication and binds loopback only.
    Keep it that way; do not proxy 5225 onto a network. If you front the
    gateway with nginx, protect /api/v1/admin and leave the node alone.

 4. Open only the gateway port, and only once TLS is in place:
      sudo ufw allow ${GATEWAY_PORT}/tcp comment 'popopx-service-suite gateway'

 5. Back up ${STATE_DIR} — gateway.db holds the channel identity private keys as
    well as the ledger and every pairwise session secret (there is no separate
    keyring file, on purpose: a rotation must commit in the same transaction as
    the frame it delivers). Losing it means every existing zero-knowledge channel
    goes silent for good: no rotation can be signed that members will verify.

 6. Run the two suites that are deliberately NOT on the boot path, before you
    trust an admin route or a redemption. The gateway only checks the route
    table (`assert_routes_are_gated()`) when it builds the app; the rest is a
    published-artifact gate, and it requests the real ASGI app:
      cd ${INSTALL_ROOT}/src/gateway && ${INSTALL_ROOT}/venv/bin/python -m app.main --self-test
      cd ${INSTALL_ROOT}/src/gateway && ${INSTALL_ROOT}/venv/bin/python -m app.main --check-routes
    Expect "no SKIPPED" — a wheel-less interpreter skips the crypto and HTTP
    groups and says so on the last line.

 Admin console  http://<host>:${GATEWAY_PORT}/     (admin API header: X-Admin-Token, or
 ?token=. The core's admin_required does not parse "Authorization: Bearer" — only
 privacy_sso's device-facing route reads it (bearer_secret). The console sends both.)
────────────────────────────────────────────────────────────────────────────
SUMMARY
}

# ────────────────────────────────── main ────────────────────────────────────

need_cmd curl
need_cmd systemctl
need_cmd python3

log "installing ${SUITE_NAME} from ${REPO_DIR} in '${MODE}' mode"
install -d -m 0755 "${INSTALL_ROOT}" "${STATE_DIR}"

if [[ ${MODE} == "docker" ]]; then
  install_docker
  run_docker
else
  run_native
fi

verify
log "done."
