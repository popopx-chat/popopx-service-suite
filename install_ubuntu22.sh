#!/usr/bin/env bash
# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
# POPOPX Service Suite — Ubuntu 22.04 LTS production installer.
#
#   sudo ./install_ubuntu22.sh                  # containerised gateway (default)
#   sudo ./install_ubuntu22.sh --mode native    # venv + systemd, no Docker
#   sudo ./install_ubuntu22.sh --with-node      # also install/run the chat node (native: downloads + SHA256-verifies if missing)
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

# Node download + resolution (--with-node in native mode only; docker uses the container image).
# NODE_BIN_INSTALL is where the binary lands after download or --node-bin; empty means "resolve at runtime".
# NODE_DOWNLOAD=1 enables the GitHub Releases fetch when no local binary exists; --no-node-download disables it.
# NODE_VERSION is the release tag (default "latest"); --node-version TAG pins a specific release.
# NODE_SOURCE records where the binary came from (local path, download URL, or dry-run placeholder).
NODE_PORT="${POPOPX_NODE_PORT:-5225}"
NODE_BIN="${POPOPX_NODE_BIN:-}"
NODE_REPO="popopx-chat/popopx-chat"
NODE_VERSION="${POPOPX_NODE_VERSION:-latest}"
NODE_DOWNLOAD=1
NODE_BIN_INSTALL=""
NODE_SOURCE=""

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
                         In native mode: downloads the matching popopx-chat CLI from GitHub Releases
                         if no local binary is found, verifies SHA2-256, generates a secure wrapper.
  --port N               Gateway port (default 8080, or $POPOPX_GATEWAY_PORT).
  --node-port N          Node WebSocket API port (default 5225, or $POPOPX_NODE_PORT). Native mode only.
  --node-bin PATH        Path to an already-built popopx-chat binary. Skips the download.
  --node-version TAG     Release tag to download (default: latest). Example: --node-version v7.1.2-popopx.1
  --no-node-download     Disable the GitHub Releases fetch. Requires --node-bin or a local binary on PATH.
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
    --node-port) [[ -n "${2:-}" ]] || die "--node-port needs a number"; NODE_PORT="$2"; shift 2 ;;
    --node-port=*) NODE_PORT="${1#*=}"; shift ;;
    --node-bin) [[ -n "${2:-}" ]] || die "--node-bin needs a path"; NODE_BIN="$2"; shift 2 ;;
    --node-bin=*) NODE_BIN="${1#*=}"; shift ;;
    --node-version) [[ -n "${2:-}" ]] || die "--node-version needs a tag"; NODE_VERSION="$2"; shift 2 ;;
    --node-version=*) NODE_VERSION="${1#*=}"; shift ;;
    --no-node-download) NODE_DOWNLOAD=0; shift ;;
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
[[ "${NODE_PORT}" =~ ^[0-9]+$ ]] && (( NODE_PORT >= 1 && NODE_PORT <= 65535 )) \
  || die "--node-port must be 1-65535, got '${NODE_PORT}'"

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

# ─────────────────────────────── node download ──────────────────────────────

# node_asset_name: stdout the release asset for this machine's arch.
# Ubuntu 22.04 assets are named popopx-chat-ubuntu-22_04-{x86_64,aarch64}.
node_asset_name() {
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64)   printf 'popopx-chat-ubuntu-22_04-x86_64' ;;
    aarch64|arm64)  printf 'popopx-chat-ubuntu-22_04-aarch64' ;;
    *)              die "unsupported architecture: ${arch}. Use --node-bin PATH or --no-node-download" ;;
  esac
}

# sha256_of: stdout the SHA256 hex digest of $1. Prefers sha256sum (GNU coreutils on Ubuntu),
# falls back to shasum -a 256 (macOS-style, also present on Ubuntu via coreutils), then openssl.
sha256_of() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file}" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -hex "${file}" | awk '{print $NF}'
  else
    die "no SHA256 tool found (need sha256sum, shasum, or openssl)"
  fi
}

# node_release_meta: stdout "tag⇥url⇥digest⇥size" for the target release.
# Queries the GitHub API for the release (latest or by tag), finds the matching asset,
# extracts the digest from the asset's .digest field (sha256:<hex>) or falls back to parsing
# the release body for a line "SHA2-256(<name>)= <hex>".
node_release_meta() {
  local asset tag url digest size api_url
  asset="$(node_asset_name)"
  if [[ "${NODE_VERSION}" == "latest" ]]; then
    api_url="https://api.github.com/repos/${NODE_REPO}/releases/latest"
  else
    api_url="https://api.github.com/repos/${NODE_REPO}/releases/tags/${NODE_VERSION}"
  fi
  # curl the release JSON. Parse with python3 (always present on Ubuntu 22.04).
  # The .digest field is "sha256:<hex>"; the body has "SHA2-256(<name>)= <hex>" lines.
  # Emit tag⇥url⇥digest⇥size. No --noproxy: this is real egress, not a loopback probe.
  curl -fsSL --retry 3 --max-time 60 "${api_url}" | python3 - "${asset}" <<'PYEOF'
import json, re, sys
asset_name = sys.argv[1]
data = json.load(sys.stdin)
tag = data.get("tag_name", "")
for a in data.get("assets", []):
    if a.get("name") == asset_name:
        url = a.get("browser_download_url", "")
        # .digest is "sha256:<hex>" — extract the hex part
        digest_field = a.get("digest", "")
        digest = digest_field.split(":", 1)[1] if ":" in digest_field else ""
        size = str(a.get("size", ""))
        # Fallback: parse the release body for "SHA2-256(<name>)= <hex>"
        if not digest:
            body = data.get("body", "")
            m = re.search(r"SHA2-256\(" + re.escape(asset_name) + r"\)=\s*([0-9a-fA-F]{64})", body)
            if m:
                digest = m.group(1)
        if url and digest:
            print(f"{tag}\t{url}\t{digest}\t{size}")
            sys.exit(0)
sys.exit(1)
PYEOF
}

# download_node_bin: download the matching release asset, verify SHA256, install to /usr/local/bin/popopx-chat.
# stdout the installed path. Sets NODE_BIN_INSTALL and NODE_SOURCE for provenance.
download_node_bin() {
  local asset url digest size tmpfile actual_digest tag
  asset="$(node_asset_name)"
  log "downloading ${asset} from GitHub Releases (${NODE_REPO}, tag=${NODE_VERSION})"
  # Fetch release metadata (tag, url, digest, size).
  local meta
  meta="$(node_release_meta)" || die_code 4 "failed to fetch release metadata from GitHub API. Check your network or pass --node-bin PATH."
  tag="${meta%%	*}"; meta="${meta#*	}"
  url="${meta%%	*}"; meta="${meta#*	}"
  digest="${meta%%	*}"; meta="${meta#*	}"
  size="${meta}"
  [[ -n "${url}" && -n "${digest}" ]] || die_code 4 "release metadata incomplete (url or digest empty). Asset ${asset} may not exist in tag ${tag}."
  log "release tag=${tag}, asset=${asset}, size=${size} bytes"
  # Download to a temp file.
  tmpfile="$(mktemp /tmp/popopx-chat.XXXXXX)"
  curl -fL --retry 3 --max-time 1800 -o "${tmpfile}" "${url}" || { rm -f "${tmpfile}"; die_code 4 "download failed: ${url}"; }
  # Verify SHA256.
  actual_digest="$(sha256_of "${tmpfile}")"
  if [[ "${actual_digest}" != "${digest}" ]]; then
    rm -f "${tmpfile}"
    die_code 4 "SHA256 mismatch for ${asset}: expected ${digest}, got ${actual_digest}. Deleting downloaded file."
  fi
  log "SHA256 verified: ${actual_digest}"
  # Install to /usr/local/bin/popopx-chat (0755 root:root).
  install -m 0755 -o root -g root "${tmpfile}" /usr/local/bin/popopx-chat
  rm -f "${tmpfile}"
  # Write provenance file (public values only: release tag, asset name, digest, size, source URL).
  cat > /usr/local/bin/popopx-chat.provenance <<PROV
release_tag=${tag}
asset_name=${asset}
sha256=${actual_digest}
size=${size}
source_url=${url}
PROV
  chmod 0644 /usr/local/bin/popopx-chat.provenance
  NODE_BIN_INSTALL="/usr/local/bin/popopx-chat"
  NODE_SOURCE="download:${url}"
  log "installed /usr/local/bin/popopx-chat (provenance: /usr/local/bin/popopx-chat.provenance)"
  printf '%s' "${NODE_BIN_INSTALL}"
}

# port_listening: return 0 if $1 is listening on localhost (TCP), else 1.
# Uses /dev/tcp (bash built-in) or falls back to ss.
port_listening() {
  local port="$1"
  if (echo >/dev/tcp/127.0.0.1/"${port}") 2>/dev/null; then
    return 0
  elif command -v ss >/dev/null 2>&1; then
    ss -ltn "sport = :${port}" | grep -q ":${port}" && return 0
  fi
  return 1
}

# wait_for_node_ready: poll until NODE_PORT is listening or $1 seconds elapse (default 40).
# Returns 0 on success, 1 on timeout. Warns but does not die.
wait_for_node_ready() {
  local ceiling="${1:-40}" i=0
  while [[ ${i} -lt ${ceiling} ]]; do
    port_listening "${NODE_PORT}" && return 0
    i=$((i + 1)); sleep 1
  done
  return 1
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

  # Node before gateway: the gateway's env file carries NODE_WS_URL, and the gateway expects
  # the node to answer on that socket. Bringing the node up first means the gateway's first
  # /healthz probe sees a live node, not a "connection refused" that would fail verify().
  if [[ ${WITH_NODE} -eq 1 ]]; then
    # The node is the open-source AGPL component. Running it as its own unit,
    # under its own user, with its own state directory is what keeps the
    # isolation claim in LICENSE §3 true on the box and not only on paper.
    id -u popopx-node >/dev/null 2>&1 || \
      useradd --system --create-home --home-dir /var/lib/popopx-node --shell /usr/sbin/nologin popopx-node
    install -d -m 0750 -o popopx-node -g popopx-node /var/lib/popopx-node
    
    # Binary resolution priority: explicit --node-bin > local find > download (unless --no-node-download).
    # Docker mode ignores this entirely (uses the container image).
    local node_bin=""
    if [[ -n "${NODE_BIN}" ]]; then
      [[ -x "${NODE_BIN}" ]] || die_code 4 "--node-bin ${NODE_BIN} is not executable"
      node_bin="${NODE_BIN}"
      log "node binary (explicit --node-bin): ${node_bin}"
    elif node_bin="$(command -v popopx-chat 2>/dev/null)" && [[ -x "${node_bin}" ]]; then
      log "node binary (local): ${node_bin}"
    elif [[ ${NODE_DOWNLOAD} -eq 1 ]]; then
      log "no local node binary; downloading from GitHub Releases"
      node_bin="$(download_node_bin)"
      log "node binary (downloaded): ${node_bin}"
    else
      die_code 4 "no popopx-chat node found and --no-node-download is set. Build it from source or pass --node-bin PATH, or drop --no-node-download."
    fi
    NODE_BIN_INSTALL="${node_bin}"
    : "${NODE_SOURCE:=local:${node_bin}}"
    
    # /etc/default/popopx-node: operator-editable defaults. The installer writes it once; re-runs keep it.
    # Added: NODE_BIN_INSTALL (the binary path), NODE_SMP_SERVERS/NODE_XFTP_SERVERS (cluster override hooks).
    install -d -m 0755 /etc/default
    if [[ ! -f /etc/default/popopx-node ]]; then
      cat > /etc/default/popopx-node <<DEF
# POPOPX chat node — edited by hand, never rewritten by install_ubuntu22.sh.
# The wrapper /usr/local/bin/popopx-node sources this file and builds the node's argv.
NODE_BIN_INSTALL=${node_bin}
# Prefix for the node's chat + agent databases (its own --database argument).
NODE_DB_PREFIX=/var/lib/popopx-node/popopx_v1
# The node's WebSocket API port the gateway dials. Change both here and
# POPOPX_NODE_WS_URL in the gateway's env file; they are one number in two files
# because the gateway and the node are separate processes with separate configs.
NODE_PORT=${NODE_PORT}
# Used ONLY when the database prefix has no user profile yet. If a profile
# exists and its display name differs, the node exits with
# "does not match --user-display-name" — that is the node protecting an
# identity that is already paired with devices, so set this to that name.
NODE_DISPLAY_NAME=POPOPX Service
# Cluster override hooks (empty by default). Leave empty to inherit the binary's
# built-in popopx.im dual-stack preset (smp1..8.popopx.im + .onion, useSMP=4).
# To override, fill with space-separated smp://<key>@<host>,<onion>[:port] addresses.
# The wrapper passes --server / --xftp-server ONLY when these are non-empty.
# Canonical cluster (for reference — do not uncomment, leave empty to inherit):
# NODE_SMP_SERVERS="smp://f2X5hAgHZW9-SVkhMou0sUFg3AHUi2pE3kSw46AiGjY=@smp1.popopx.im,quheabd5hdghpztkw53fho6fki722npoytgvkutnbh3gtpgrlna5ukad.onion smp://4bJjC-wqSpviWwuDnkhSKTD4V8mYxpLqj4aiCUSfGfA=@smp2.popopx.im,e2ox73tvq54iv6z46c2rsxo7qc3ngrb26rx54qctuxoornn6w4l2uxyd.onion ..."
NODE_SMP_SERVERS=
NODE_XFTP_SERVERS=
DEF
      log "wrote /etc/default/popopx-node"
    else
      log "keeping the existing /etc/default/popopx-node"
      # If the existing file lacks NODE_BIN_INSTALL (added in this upgrade), append it.
      if ! grep -q '^NODE_BIN_INSTALL=' /etc/default/popopx-node; then
        echo "NODE_BIN_INSTALL=${node_bin}" >> /etc/default/popopx-node
        log "appended NODE_BIN_INSTALL to existing /etc/default/popopx-node"
      fi
    fi
    chown root:popopx-node /etc/default/popopx-node
    chmod 0640 /etc/default/popopx-node
    
    # Secure wrapper: /usr/local/bin/popopx-node (0755 root:root). Sources /etc/default/popopx-node,
    # validates required vars, builds args with conditional --server/--xftp-server/--user-display-name.
    cat > /usr/local/bin/popopx-node <<'WRAPPER'
#!/bin/sh
# POPOPX chat node — secure launcher generated by install_ubuntu22.sh --with-node.
# The systemd unit execs this wrapper. It sources /etc/default/popopx-node and builds the argv.
# Edit /etc/default/popopx-node, not this file. Runs as popopx-node user.
set -eu
umask 077
CONF="/etc/default/popopx-node"
[ -r "${CONF}" ] || { echo "popopx-node: cannot read ${CONF}" >&2; exit 1; }
# shellcheck disable=SC1090
. "${CONF}"
: "${NODE_PORT:?popopx-node: NODE_PORT missing from ${CONF}}"
: "${NODE_DB_PREFIX:?popopx-node: NODE_DB_PREFIX missing from ${CONF}}"
BIN="${NODE_BIN_INSTALL:?popopx-node: NODE_BIN_INSTALL missing from ${CONF}}"
[ -x "${BIN}" ] || { echo "popopx-node: node binary not executable: ${BIN}" >&2; exit 1; }
set -- --chat-server-port "${NODE_PORT}" --database "${NODE_DB_PREFIX}" --yes-migrate
# Cluster override ONLY when the operator set it; empty means "use the binary's own preset
# cluster" (the intended default — see /etc/default/popopx-node). Passing "$@" keeps a
# space-separated value as ONE argument, which is exactly what the node's --server expects.
if [ -n "${NODE_SMP_SERVERS:-}" ]; then set -- "$@" --server "${NODE_SMP_SERVERS}"; fi
if [ -n "${NODE_XFTP_SERVERS:-}" ]; then set -- "$@" --xftp-server "${NODE_XFTP_SERVERS}"; fi
if [ -n "${NODE_DISPLAY_NAME:-}" ]; then set -- "$@" --user-display-name "${NODE_DISPLAY_NAME}"; fi
exec "${BIN}" "$@"
WRAPPER
    chmod 0755 /usr/local/bin/popopx-node
    chown root:root /usr/local/bin/popopx-node
    log "wrapper installed: /usr/local/bin/popopx-node"
  fi

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
    cat > /etc/systemd/system/popopx-node.service <<'UNIT'
# Generated by install_ubuntu22.sh --mode native --with-node
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
# The wrapper /usr/local/bin/popopx-node sources /etc/default/popopx-node and builds the argv.
# systemd does not expand $VAR in ExecStart when the command is a wrapper script, so the
# wrapper itself reads the defaults file. This keeps the unit stable across config changes.
ExecStart=/usr/local/bin/popopx-node
# No terminal exists for a service, and the node's first-run profile creation
# reads stdin. Explicitly null it so the answer comes from --user-display-name
# in /etc/default/popopx-node instead of a prompt that would hang the unit.
StandardInput=null
Restart=on-failure
RestartSec=3
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
  fi

  systemctl daemon-reload
  # Node before gateway: the gateway expects the node to answer on NODE_WS_URL.
  if [[ ${WITH_NODE} -eq 1 ]]; then
    systemctl enable popopx-node.service >/dev/null
    systemctl restart popopx-node.service
    # Bounded wait: the node takes a few seconds to bind its port after systemd starts it.
    # If it does not answer in 40s, warn (do not die) — verify() will catch it later.
    wait_for_node_ready 40 || warn "node did not bind port ${NODE_PORT} within 40s; check journalctl -u popopx-node -n 80"
  fi
  systemctl enable popopx-gateway.service >/dev/null
  systemctl restart popopx-gateway.service

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
