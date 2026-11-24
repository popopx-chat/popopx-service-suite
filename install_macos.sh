#!/usr/bin/env bash
# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
# POPOPX Service Suite — macOS production installer (launchd, no Docker).
#
#   sudo ./install_macos.sh                # gateway as a LaunchDaemon, on 127.0.0.1
#   sudo ./install_macos.sh --lan          # same service bound to 0.0.0.0 — read the note
#   sudo ./install_macos.sh --with-node    # + a node LaunchDaemon; downloads + SHA256-verifies the popopx-chat CLI if none is found
#   ./install_macos.sh --check             # preflight only: report, write nothing, no root
#   ./install_macos.sh --dry-run           # render plist + env into a temp dir, lint, no root
#   sudo ./install_macos.sh --uninstall    # services, account and code go; state stays
#
# Until this file existed, macOS was the development platform and Ubuntu 22.04 the
# production one (README). This is the production path for a Mac: a dedicated role
# account, code / config / state / logs all outside your checkout, boot-autoload,
# crash-restart, and an installer that says what it cannot do.
#
# Why there is no --mode docker here: this suite dials the node's WebSocket API, which
# binds 127.0.0.1 and nothing else, and `network_mode: host` is a Linux kernel feature —
# in Docker Desktop a container's "host" is the linuxvm's loopback, not this Mac's. A
# containerised gateway and a node on the Mac cannot see each other and no `ports:`
# mapping changes that; start_macos.sh:10-15 and docker-compose.yml:19-20 say the same
# thing about the other two paths. Shipping a mode known not to work would be an
# installer that lies, which is worse than no installer.
#
# What systemd gives that launchd does not, listed here because a unit file cannot say
# it out loud and a silent gap is worse than a documented one:
#   * no KillSignal. launchd only ever sends SIGTERM. uvicorn installs handlers for
#     SIGINT *and* SIGTERM, so the graceful drain still happens; if you ever need the
#     exact SIGINT, it is one command:  sudo launchctl kill SIGINT system/<label>
#   * no ProtectSystem / PrivateTmp / NoNewPrivileges / RestrictSUIDSGID / ProtectHome.
#     There is no sandbox. The mitigations are the ones launchd does have: a role
#     account whose shell is /usr/bin/false, code owned root:wheel and NOT writable by
#     the service user, and Umask 077 on everything it creates.
#   * no MemoryMax. SoftResourceLimits exists, but RLIMIT_RSS is not enforced on
#     Darwin, so there is nothing honest to put there.
#   * no StartLimitBurst. launchd never stops trying. That is why this installer runs
#     the config gate BEFORE bootstrap: a bad env file is one failed start under
#     systemd and an infinite ThrottleInterval crash loop under launchd.
#
# Requires root for anything that writes. Portable shell on purpose: /bin/bash on macOS
# is 3.2 (GPLv2, frozen) and this script must run there without a brew-installed bash 5.

set -Eeuo pipefail

readonly SUITE_NAME="popopx-service-suite"
readonly INSTALL_ROOT="/usr/local/${SUITE_NAME}"
readonly CONF_DIR="/usr/local/etc/${SUITE_NAME}"
readonly STATE_DIR="/usr/local/var/${SUITE_NAME}"
readonly LOG_DIR="/usr/local/var/log/${SUITE_NAME}"
readonly PLIST_DIR="/Library/LaunchDaemons"
readonly GATEWAY_LABEL="com.popopx.gateway"
readonly NODE_LABEL="com.popopx.node"
readonly RUN_USER="_popopx"
readonly RUN_UID=450
readonly NODE_USER="_popopx-node"
readonly NODE_UID=451
readonly PYTHON_VERSION="3.11"

WITH_NODE=0
CHECK_ONLY=0
DRY_RUN=0
DO_UNINSTALL=0
KEEP_STATE=1
GATEWAY_PORT="${POPOPX_GATEWAY_PORT:-8080}"
BIND_HOST="${POPOPX_BIND_HOST:-127.0.0.1}"
LAN_EXPLICIT=0
NODE_PORT="${POPOPX_NODE_PORT:-5225}"
NODE_BIN="${POPOPX_NODE_BIN:-}"
# --with-node provisioning: when no local binary is found the installer downloads the
# matching popopx-chat CLI from the upstream Releases and verifies its SHA2-256 before it
# is ever run. NODE_VERSION is 'latest' or a tag like v7.1.2-popopx.1. NODE_DOWNLOAD=0
# (--no-node-download) keeps the path fully offline. NODE_BIN_INSTALL is where the binary
# lands, and it is baked into the node wrapper so launchd runs one stable path.
NODE_REPO="popopx-chat/popopx-chat"
NODE_VERSION="${POPOPX_NODE_VERSION:-latest}"
NODE_DOWNLOAD=1
NODE_BIN_INSTALL=""
NODE_SOURCE=""
NODE_DB_PREFIX=""
PUBLIC_BASE_URL="${POPOPX_PUBLIC_BASE_URL:-}"
PY_OVERRIDE="${POPOPX_PYTHON:-}"

log()  { printf '\033[1;35m[popopx]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fatal]\033[0m %s\n' "$*" >&2; exit 1; }
# The codes are part of the contract with the dev launcher and the Ubuntu installer:
# 1 fatal preflight, 3 no Python 3.11 (start_macos.sh:373), 4 --with-node with no node
# binary (start_macos.sh:325), 5 installed but /healthz silent. A caller that scripts
# around this installer branches on those numbers, so 3 and 4 must not collapse into 1.
die_code() { local code="$1"; shift; printf '\033[1;31m[fatal]\033[0m %s\n' "$*" >&2; exit "${code}"; }
plan_line() { # label path note — no trailing blank when there is no note
  if [[ -n "$3" ]]; then printf ' %-10s %-40s %s\n' "$1" "$2" "$3"; else printf ' %-10s %s\n' "$1" "$2"; fi
}

on_error() {
  local line="$1"
  warn "install_macos.sh aborted at line ${line}."
  warn "Nothing here is destructive: the previous deployment (if any) is still in place,"
  warn "the state directory is never deleted by this script, and your checkout was only read."
  warn "Resume with the same command, or undo it with:  sudo ./install_macos.sh --uninstall"
  exit 1
}
trap 'on_error ${LINENO}' ERR

usage() {
  # The ERR trap is dropped on purpose: `install_macos.sh --help | head` closes the pipe
  # early, awk dies of SIGPIPE, and the trap would otherwise print a red "aborted"
  # warning for a help screen that worked. Same trick as start_macos.sh:48 and
  # install_ubuntu22.sh:49.
  trap - ERR
  set +e
  awk 'NR > 1 { if (!/^#/) exit; sub(/^# ?/, ""); print }' "$0"
  cat <<'USAGE'

Options:
  --port N                Gateway port (default 8080, or $POPOPX_GATEWAY_PORT).
  --lan                   Bind 0.0.0.0 instead of 127.0.0.1 (or $POPOPX_BIND_HOST).
                          Off by default because a
                          Mac has no reverse proxy installed and, with the Application
                          Firewall off, 0.0.0.0 means every host on the LAN can reach
                          the admin API the moment the service starts.
  --public-base-url URL   Rewrite POPOPX_PUBLIC_BASE_URL to this origin (http(s)://…).
  --with-node             Also install a LaunchDaemon for the open-source chat node. When
                          no node binary is found locally, download the matching
                          popopx-chat CLI from the popopx-chat/popopx-chat Releases and
                          verify its SHA2-256 before it is run. Requires outbound HTTPS at
                          install time; --check and --dry-run stay offline.
  --node-bin PATH         Node binary (default: $POPOPX_NODE_BIN, then PATH, then the
                          Homebrew and /usr/local prefixes, then the sibling cabal build
                          tree). When set, this is used as-is and nothing is downloaded.
  --node-port N           Node's WebSocket API port (default 5225, or $POPOPX_NODE_PORT).
  --node-version TAG      Release to download (default: latest, or $POPOPX_NODE_VERSION).
                          A tag like v7.1.2-popopx.1 pins the node binary.
  --no-node-download      Never download: use a local/--node-bin binary only, and fail if
                          there is none. For an airgapped or review-first install.
  --python PATH           Interpreter to build the venv with (must be 3.11).
  --check                 Preflight only: run every read-only probe and write nothing.
  --dry-run               Generate the plist and the env file into a temporary directory,
                          lint the plist, report, change nothing on the system.
  --uninstall             Boot out the services, remove the plists, the code, the config
                          and the role accounts. State is kept unless --purge-state.
  --purge-state           With --uninstall only: also delete the state directory, which
                          deletes the channel identity keys. There is no undo.
  -h, --help              This text.

Nothing in this script calls apt, brew or any package manager. If the target Python is
missing it exits 3 and prints the command the login user has to run: the Homebrew prefix
here is owned by a human, so a sudo-run brew would litter it with root-owned files.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)            [[ -n "${2:-}" ]] || die "--port needs a number"; GATEWAY_PORT="$2"; shift 2 ;;
    --port=*)          GATEWAY_PORT="${1#*=}"; shift ;;
    --lan)             BIND_HOST="0.0.0.0"; LAN_EXPLICIT=1; shift ;;
    --public-base-url) [[ -n "${2:-}" ]] || die "--public-base-url needs a URL"; PUBLIC_BASE_URL="$2"; shift 2 ;;
    --public-base-url=*) PUBLIC_BASE_URL="${1#*=}"; shift ;;
    --with-node)       WITH_NODE=1; shift ;;
    --node-bin)        [[ -n "${2:-}" ]] || die "--node-bin needs a path"; NODE_BIN="$2"; shift 2 ;;
    --node-bin=*)      NODE_BIN="${1#*=}"; shift ;;
    --node-port)       [[ -n "${2:-}" ]] || die "--node-port needs a number"; NODE_PORT="$2"; shift 2 ;;
    --node-port=*)     NODE_PORT="${1#*=}"; shift ;;
    --node-version)    [[ -n "${2:-}" ]] || die "--node-version needs a release tag"; NODE_VERSION="$2"; shift 2 ;;
    --node-version=*)  NODE_VERSION="${1#*=}"; shift ;;
    --no-node-download) NODE_DOWNLOAD=0; shift ;;
    --python)          [[ -n "${2:-}" ]] || die "--python needs a path"; PY_OVERRIDE="$2"; shift 2 ;;
    --python=*)        PY_OVERRIDE="${1#*=}"; shift ;;
    --check)           CHECK_ONLY=1; shift ;;
    --dry-run)         DRY_RUN=1; shift ;;
    --uninstall)       DO_UNINSTALL=1; shift ;;
    --purge-state)     KEEP_STATE=0; shift ;;
    -h|--help)         usage; exit 0 ;;
    *)                 die "unknown argument: $1 (try --help)" ;;
  esac
done

# ───────────────────────────── preflight ────────────────────────────────────

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

require_port() { # $1 = what to name, $2 = the value
  # A port outside 1..65535 is not cosmetic: uvicorn masks it, truncates modulo 65536,
  # binds something else entirely, and this script would print URLs for the number you
  # typed. Checked here because the cost of catching it is one line.
  case "$2" in
    '' | *[!0-9]*) die "$1 must be a decimal port number, got '${2}' (try --help)" ;;
  esac
  [ "$2" -ge 1 ] && [ "$2" -le 65535 ] \
    || die "$1 must be between 1 and 65535, got ${2}"
}
require_port "--port / POPOPX_GATEWAY_PORT" "${GATEWAY_PORT}"
require_port "--node-port / POPOPX_NODE_PORT" "${NODE_PORT}"

if [[ ${CHECK_ONLY} -eq 0 && ${DRY_RUN} -eq 0 && ${DO_UNINSTALL} -eq 0 ]]; then
  [[ ${EUID} -eq 0 ]] || die "run as root:  sudo ./install_macos.sh"
elif [[ ${DO_UNINSTALL} -eq 1 ]]; then
  [[ ${EUID} -eq 0 ]] || die "run as root:  sudo ./install_macos.sh --uninstall"
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "${REPO_DIR}/gateway/app/main.py" && -f "${REPO_DIR}/.env.example" ]] \
  || die "${REPO_DIR} does not look like the ${SUITE_NAME} checkout (no gateway/app/main.py or .env.example)"

[[ "$(uname -s)" == "Darwin" ]] || die "this installer is the macOS path; on Linux use ./install_ubuntu22.sh"

OS_MAJOR="$(sw_vers -productVersion 2>/dev/null | cut -d. -f1)"
case "${OS_MAJOR}" in
  '' | *[!0-9]*) warn "could not read the macOS version from sw_vers; continuing" ;;
  *) [ "${OS_MAJOR}" -ge 13 ] || warn "this suite targets macOS 13+; detected ${OS_MAJOR}. Continuing." ;;
esac

if [[ ${LAN_EXPLICIT} -eq 1 ]]; then
  warn "--lan: binding 0.0.0.0. The admin API is token-gated, but this gateway also trusts"
  warn "       X-Forwarded-* from any peer (uvicorn runs with forwarded_allow_ips='*'), so"
  warn "       anything that can reach port ${GATEWAY_PORT} can make itself look like any"
  warn "       client. Front it with a proxy that sets those headers itself, or don't use"
  warn "       --lan. The firewall is not opened for you either way."
fi

# ──────────────────────────── read-only helpers ─────────────────────────────

port_listening() { # $1 = port
  lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

lan_ip() {
  # en0/en1 cover Wi-Fi and Thunderbolt Ethernet on Apple Silicon; the order is not a
  # guess about which is "primary", it is the first interface with an IPv4 lease.
  for iface in en0 en1 en2 en3 en4 en5 en6 bridge0; do
    ip="$(ipconfig getifaddr "${iface}" 2>/dev/null || true)"
    [ -n "${ip}" ] && { printf '%s' "${ip}"; return 0; }
  done
  printf '127.0.0.1'
}

find_python() {
  # Explicit --python / $POPOPX_PYTHON, then PATH, then the two Homebrew prefixes and
  # the python.org framework. Apple's /usr/bin/python3 is deliberately NOT a candidate:
  # it is whatever the CLT ships (3.9 here) and cannot satisfy ${PYTHON_VERSION}. Same
  # order as start_macos.sh:117-134.
  if [ -n "${PY_OVERRIDE}" ] && [ -x "${PY_OVERRIDE}" ]; then
    printf '%s' "${PY_OVERRIDE}"; return 0
  fi
  for cand in \
    "$(command -v python3.11 2>/dev/null || true)" \
    /opt/homebrew/bin/python3.11 \
    /usr/local/bin/python3.11 \
    /Library/Frameworks/Python.framework/Versions/3.11/bin/python3.11
  do
    [ -n "${cand}" ] && [ -x "${cand}" ] && { printf '%s' "${cand}"; return 0; }
  done
  return 1
}

python_version_of() { # $1 = interpreter path
  [ -n "${1}" ] && [ -x "${1}" ] || return 1
  "${1}" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null
}

python_is_target() { # $1 = interpreter path
  [ -n "${1}" ] && [ -x "${1}" ] || return 1
  # The version arrives through the environment, not through an interpolated -c string:
  # the comparison has to be exact (== not >=), because the venv is built from this
  # interpreter and a 3.12 that slipped past a >= test would silently become the
  # production runtime. start_macos.sh:136-139 compares the same exact (3, 11) tuple;
  # install_ubuntu22.sh needs no check because it installs and calls python3.11 by that
  # exact package name (:272, :299), which is a guarantee macOS has no equivalent of.
  POPOPX_TARGET_PYTHON="${PYTHON_VERSION}" "${1}" -c 'import os, sys
want = tuple(int(p) for p in os.environ["POPOPX_TARGET_PYTHON"].split("."))
sys.exit(0 if sys.version_info[:2] == want else 1)' 2>/dev/null
}

bootstrap_python() {
  # Only for the stdlib work this script does before a venv exists: generating secrets
  # and rewriting the env file (see ensure_env_file). It needs nothing but `secrets`
  # and `re`, so it is deliberately NOT version-gated — the gateway interpreter is
  # gated separately, and conflating the two would make a missing 3.11 look like a
  # missing crypto module.
  if PY="$(find_python 2>/dev/null)" && [ -n "${PY}" ]; then printf '%s' "${PY}"; return 0; fi
  [ -x /usr/bin/python3 ] && { printf '%s' /usr/bin/python3; return 0; }
  return 1
}

find_node_bin() {
  [ -n "${NODE_BIN}" ] && { [ -x "${NODE_BIN}" ] && { printf '%s' "${NODE_BIN}"; return 0; }; return 1; }
  for cand in \
    "$(command -v popopx-chat 2>/dev/null || true)" \
    /usr/local/bin/popopx-chat \
    /opt/homebrew/bin/popopx-chat
  do
    [ -n "${cand}" ] && [ -x "${cand}" ] && { printf '%s' "${cand}"; return 0; }
  done
  # The cabal build tree of the sibling checkout, newest match first — the same
  # discovery start_macos.sh:265-270 does, because on a Mac that is where the node
  # actually lives until someone installs it. Only the path relative to THIS checkout is
  # searched, not the launcher's two $HOME candidates: this step runs under sudo, and a
  # candidate that resolves or not depending on whose home directory survives the
  # privilege change is a branch whose result nobody can reproduce from the command line.
  for repo in "${REPO_DIR}/../popopx-chat"; do
    [ -d "${repo}" ] || continue
    newest="$(find "${repo}/dist-newstyle/build" -type f -name popopx-chat -perm +111 2>/dev/null | sort | tail -1)"
    [ -n "${newest}" ] && { printf '%s' "${newest}"; return 0; }
  done
  return 1
}

# ─────────────────────── node binary provisioning (download) ─────────────────
#
# These run ONLY on the real --with-node install path. --check and --dry-read must never
# require them, and --check must never die because the network is absent, so the actual
# download is called from install_node() alone. The values that cross the wire — asset
# name and SHA-256 — are derived from the live release (the generator), not hardcoded:
# a guessed asset name downloads nothing and a hardcoded digest is stale the moment a
# release is cut. macOS CLI assets are popopx-chat-macos-aarch64 / popopx-chat-macos-x86-64
# (note: x86-64 with a hyphen on the Intel one — measured against the published assets).

node_asset_name() { # stdout: the release asset for this machine
  local m; m="$(uname -m)"
  case "${m}" in
    arm64|aarch64) printf 'popopx-chat-macos-aarch64' ;;
    x86_64)        printf 'popopx-chat-macos-x86-64' ;;
    *) die "unsupported macOS architecture '${m}'; pass --node-bin PATH, or use --no-node-download and install the node yourself" ;;
  esac
}

sha256_of() { # $1 = file; stdout: lowercase hex digest
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'; return 0; fi
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; return 0; fi
  if command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 "$1" | awk '{print $NF}'; return 0; fi
  die "no SHA-256 tool found (shasum, sha256sum, or openssl); refusing to run an unverified binary"
}

node_release_meta() { # stdout: "tag<TAB>url<TAB>digest<TAB>size"; return 1 if unresolvable/offline
  # A read of the GitHub Releases API, not of any secret. The API is unauthenticated here,
  # so it can be rate-limited, but a failure is reported by the caller as "could not
  # resolve, pass --node-bin" rather than a silent fallback to an unverified download.
  local api asset py json
  asset="$(node_asset_name)"
  if [ "${NODE_VERSION}" = "latest" ]; then
    api="https://api.github.com/repos/${NODE_REPO}/releases/latest"
  else
    api="https://api.github.com/repos/${NODE_REPO}/releases/tags/${NODE_VERSION}"
  fi
  py="$(bootstrap_python || true)"; [ -n "${py}" ] || return 1
  # --noproxy is deliberately NOT used here: this is a real internet fetch, and a host
  # behind a corporate proxy reaches api.github.com only through that proxy.
  json="$(curl -fsSL --connect-timeout 10 --max-time 30 \
            -H 'Accept: application/vnd.github+json' "${api}" 2>/dev/null)" || return 1
  printf '%s' "${json}" | PY_ASSET="${asset}" "${py}" - <<'PYEOF'
import json, os, re, sys
want = os.environ["PY_ASSET"]
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
tag = d.get("tag_name", "") or ""
digest_from_body = ""
body = d.get("body") or ""
m = re.search(r"(?m)^SHA2-256\(%s\)=\s*([0-9a-fA-F]{64})\s*$" % re.escape(want), body)
if m:
    digest_from_body = m.group(1).lower()
for a in d.get("assets", []):
    if a.get("name") == want:
        dg = (a.get("digest") or "")
        if dg.startswith("sha256:"):
            dg = dg[len("sha256:"):].lower()
        dg = dg or digest_from_body
        print("%s\t%s\t%s\t%s" % (tag, a.get("browser_download_url", ""), dg, a.get("size", "")))
        sys.exit(0)
sys.exit(1)
PYEOF
}

download_node_bin() { # stdout: installed binary path; only on the real --with-node install
  local meta tag url want got size asset tmp dest
  asset="$(node_asset_name)"
  if ! meta="$(node_release_meta)"; then
    die_code 4 "could not resolve '${asset}' in the ${NODE_REPO} release '${NODE_VERSION}'. Check the tag and outbound HTTPS to api.github.com, or pass --node-bin PATH / --no-node-download."
  fi
  tag="$(printf '%s' "${meta}" | cut -f1)"
  url="$(printf '%s' "${meta}" | cut -f2)"
  want="$(printf '%s' "${meta}" | cut -f3)"
  size="$(printf '%s' "${meta}" | cut -f4)"
  [ -n "${url}" ] || die_code 4 "release '${tag}' published no '${asset}' download URL; use --node-bin PATH or --no-node-download"
  # An unverifiable download is not installed. GitHub exposes a per-asset digest, but if a
  # future API shape ever returns none, stopping is the honest answer — not trusting bytes.
  [ -n "${want}" ] || die_code 4 "no SHA-256 digest published for '${asset}' in release ${tag}; refusing to install an unverifiable binary"
  dest="${INSTALL_ROOT}/bin/popopx-chat"
  tmp="$(mktemp "${TMPDIR:-/tmp}/popopx-node.XXXXXX")"
  log "downloading ${asset} from ${NODE_REPO} ${tag}${size:+ (${size} bytes)}"
  if ! curl -fL --retry 3 --connect-timeout 15 --max-time 1800 -o "${tmp}" "${url}"; then
    rm -f "${tmp}"
    die_code 4 "download failed: ${url} (network or the release moved; nothing was installed)"
  fi
  got="$(sha256_of "${tmp}")"
  if [ "${got}" != "${want}" ]; then
    rm -f "${tmp}"
    die_code 4 "SHA-256 mismatch for ${asset}: expected ${want}, got ${got}; the download was deleted and nothing was installed"
  fi
  install -d -m 0755 -o root -g wheel "${INSTALL_ROOT}/bin"
  install -m 0755 -o root -g wheel "${tmp}" "${dest}"
  rm -f "${tmp}"
  # Provenance holds only public values (tag, asset, digest, size, source) — never a token —
  # so an operator can audit exactly which bytes are running without re-fetching the release.
  printf 'release=%s\nasset=%s\nsha256=%s\nsize=%s\nsource=https://github.com/%s\n' \
    "${tag}" "${asset}" "${want}" "${size}" "${NODE_REPO}" > "${dest}.provenance"
  chmod 0644 "${dest}.provenance"
  log "verified ${asset} against its published SHA-256; installed ${dest}"
  printf '%s' "${dest}"
}

wait_for_node_ready() { # $1 = ceiling in seconds (default 40); 0 = port is listening
  # Bounded, never fatal: a production node dials the popopx.im cluster over the internet,
  # and on a host that cannot reach it the port never opens. The gateway is documented to
  # start degraded without a node, so a timeout here is a warning the caller prints, not an
  # abort — an unbounded wait would hang a reinstall the same way an unbounded bootout would.
  local limit="${1:-40}" waited=0
  while [ "${waited}" -lt "${limit}" ]; do
    port_listening "${NODE_PORT}" && return 0
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

user_exists() { id -u "$1" >/dev/null 2>&1; }
group_exists() { dscl . -read "/Groups/$1" PrimaryGroupID >/dev/null 2>&1; }
uid_taken()    { dscl . -list /Users UniqueID 2>/dev/null | awk -v u="$1" '$2==u{f=1} END{exit !f}'; }
gid_taken()    { dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk -v g="$1" '$2==g{f=1} END{exit !f}'; }

job_loaded() { launchctl print "system/$1" >/dev/null 2>&1; }

# `bootout` is asynchronous: launchd has already torn the job's registration down by the
# time the command returns, but not necessarily its bookkeeping. A `bootstrap` issued
# inside that window answers "Bootstrap failed: 5: Input/output error" — the label is
# still taken — which on a reinstall looks like a broken plist while the file on disk is
# fine. Waiting for `print` to stop finding the job is the only signal launchd gives.
# Returns 0 once the job is gone, 1 when the ceiling (default 5s) elapsed with it still
# listed, so the caller decides whether to carry on; sleeping a fixed guess would be
# either slower than needed on a clean box or still racy on a loaded one.
wait_for_bootout() { # $1 = label, $2 = ceiling in 0.1s ticks
  # `${2:-50}`, never `"$2"`: this runs under `set -u` and bash 3.2 aborts on an unbound
  # second positional, so the common one-argument call would have killed the install
  # *after* the bootout, leaving the gateway down.
  local label="$1" limit="${2:-50}" ticks=0
  while job_loaded "${label}"; do
    [[ ${ticks} -lt ${limit} ]] || return 1
    sleep 0.1
    ticks=$((ticks + 1))
  done
  return 0
}

# ─────────────────────────────── reporting ──────────────────────────────────

print_plan() {
  cat <<PLAN

────────────────────────────────────────────────────────────────────────────
 ${SUITE_NAME} — macOS production install (launchd)
────────────────────────────────────────────────────────────────────────────
PLAN
  # printf with a fixed column instead of aligned heredoc text: every path here is
  # built from ${INSTALL_ROOT}/${CONF_DIR}/${STATE_DIR}, whose lengths differ by up to
  # nine characters, so hand-padding the notes would drift the moment a constant moves.
  plan_line "Source"     "${INSTALL_ROOT}/src"                "root:wheel 0755, NOT writable by the service user"
  plan_line "Virtualenv" "${INSTALL_ROOT}/venv"               "Python ${PYTHON_VERSION}, entrypoint is python -m app.main"
  plan_line "Locked at"  "${INSTALL_ROOT}/requirements.lock"  ""
  plan_line "Config"     "${CONF_DIR}/env"                    "${RUN_USER}:0600 — the gateway reads its socket from here only"
  plan_line "State"      "${STATE_DIR}"                       "SQLite + channel identity keys, 0750"
  plan_line "Logs"       "${LOG_DIR}/"                        "written by launchd, 0600, NO rotation (see NEXT STEPS)"
  plan_line "Service"    "${PLIST_DIR}/${GATEWAY_LABEL}.plist" ""
  plan_line "Account"    "${RUN_USER}"                        "UID ${RUN_UID}, shell /usr/bin/false, home ${STATE_DIR}"
  plan_line "Bind"       "${BIND_HOST}:${GATEWAY_PORT}"       ""
  if [[ ${WITH_NODE} -eq 1 ]]; then
    plan_line "Node"     "${PLIST_DIR}/${NODE_LABEL}.plist"   "${NODE_USER} (UID ${NODE_UID})"
    plan_line "Node ws"  "ws://127.0.0.1:${NODE_PORT}"        "the gateway env is rewritten to match"
  fi
}

check_only() {
  # Everything a careful operator wants to know before sudo, and nothing else. This
  # path must not write: no user, no directory, no plist, no env file, no launchctl.
  local py pv problems=0
  need_cmd curl; need_cmd plutil; need_cmd launchctl; need_cmd dscl
  need_cmd sysadminctl; need_cmd lsof; need_cmd rsync; need_cmd sw_vers

  log "macOS $(sw_vers -productVersion 2>/dev/null) ($(uname -m)), /bin/bash $(/bin/bash --version 2>/dev/null | head -1 | awk '{print $4}')"
  log "repo    ${REPO_DIR}"
  log "root    $([[ ${EUID} -eq 0 ]] && echo 'yes' || echo 'no (fine for --check; the install needs sudo)')"

  py="$(find_python || true)"
  if [[ -n "${py}" ]] && python_is_target "${py}"; then
    pv="$(python_version_of "${py}")"
    log "python  ${py} (${pv})"
  elif [[ -n "${py}" ]]; then
    # A separate branch from "not found", because the advice differs: here an
    # interpreter exists and is simply the wrong one, so telling the operator to run
    # brew install python@3.11 sends them past the flag they already passed.
    warn "python  found ${py} but it reports $(python_version_of "${py}"); the suite targets ${PYTHON_VERSION}"
    if [[ -n "${PY_OVERRIDE}" ]]; then
      warn "        that one came from --python / \$POPOPX_PYTHON — point it at a ${PYTHON_VERSION}"
    else
      warn "        run this as your login user, not under sudo:  brew install python@${PYTHON_VERSION}"
    fi
    problems=$((problems + 1))
  else
    warn "python  no Python ${PYTHON_VERSION} found (looked: \$POPOPX_PYTHON, PATH, /opt/homebrew/bin, /usr/local/bin, python.org framework)"
    warn "        run this as your login user, not under sudo:  brew install python@${PYTHON_VERSION}"
    problems=$((problems + 1))
  fi

  if user_exists "${RUN_USER}"; then
    log "account ${RUN_USER} exists (UID $(id -u "${RUN_USER}")) — it will be reused, not recreated"
    [[ "$(dscl . -read "/Users/${RUN_USER}" UserShell 2>/dev/null | awk '{print $2}')" == "/usr/bin/false" ]] \
      || warn "account ${RUN_USER} has a login shell; a service account should not"
  elif uid_taken "${RUN_UID}"; then
    warn "account UID ${RUN_UID} is already taken by someone else; the installer will refuse to guess"
    problems=$((problems + 1))
  else
    log "account ${RUN_USER} does not exist yet (UID ${RUN_UID} free)"
  fi

  if [[ -e "${STATE_DIR}" ]]; then
    log "state   ${STATE_DIR} exists — the installer never deletes or rewrites it"
  else
    log "state   ${STATE_DIR} will be created (0750, owned ${RUN_USER})"
  fi

  if port_listening "${GATEWAY_PORT}"; then
    warn "port    ${GATEWAY_PORT} is already in use by $(lsof -nP -iTCP:"${GATEWAY_PORT}" -sTCP:LISTEN 2>/dev/null | awk 'NR==2{print $1" (pid "$2")"}')"
    warn "        the gateway will fail to bind and launchd will retry forever. Free the port or use --port."
    problems=$((problems + 1))
  else
    log "port    ${GATEWAY_PORT} is free"
  fi

  if [[ -f "${CONF_DIR}/env" ]]; then
    log "config  ${CONF_DIR}/env exists and will be kept (a pre-run copy goes to ${CONF_DIR}/env.bak.<utc>)"
  else
    log "config  ${CONF_DIR}/env will be generated from .env.example with two fresh secrets"
  fi

  if [[ ${WITH_NODE} -eq 1 ]]; then
    local nb arch asset
    arch="$(uname -m)"
    asset="$(node_asset_name || echo '<unsupported arch>')"
    log "node    arch=${arch}, target asset=${asset}"
    nb="$(find_node_bin || true)"
    if [[ -n "${nb}" ]]; then
      log "node    local binary: ${nb}"
      port_listening "${NODE_PORT}" && warn "node    port ${NODE_PORT} is already listening — a second node will not bind it"
    elif [[ ${NODE_DOWNLOAD} -eq 1 ]]; then
      log "node    no local binary; will download ${asset} from GitHub Releases (popopx-chat/popopx-chat)"
      # Non-fatal egress probe: short timeout, no retry. Offline must still exit 0, so a probe
      # failure is informational only. The real download happens in the install path.
      if curl -fsS --noproxy '*' --max-time 5 --head "https://github.com" >/dev/null 2>&1; then
        log "node    egress to github.com: OK (the download will proceed when you run the installer)"
      else
        warn "node    egress to github.com: failed (offline or blocked); the installer will die_code 4 unless you pass --node-bin or --no-node-download"
      fi
    else
      warn "node    no popopx-chat binary found and --no-node-download is set"
      warn "        build it: cd <popopx-chat checkout> && cabal build popopx-chat && cabal list-bin popopx-chat"
      warn "        or pass --node-bin PATH, or drop --no-node-download"
      problems=$((problems + 1))
    fi
  fi

  log "firewall Application Firewall state: $(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | tr -d '\n' || echo 'unreadable')"
  log "         this installer opens nothing. Ever."

  if command -v docker >/dev/null 2>&1; then
    log "docker  present, and deliberately unused by this path (see the header note)"
  else
    log "docker  not installed — irrelevant here, this path never touches it"
  fi

  print_plan

  if [[ ${problems} -gt 0 ]]; then
    warn "--check found ${problems} thing(s) that would stop or degrade an install (above)."
    exit 1
  fi
  log "--check found nothing blocking an install. Nothing was written."
}

# ───────────────────────────────── env ──────────────────────────────────────

ensure_env_file() { # $1 = target path
  local target="$1"
  local example="${REPO_DIR}/.env.example"
  if [[ -f "${target}" ]]; then
    local backup="${target}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    log "existing env found; keeping it and saving the pre-run copy to ${backup}"
    cp -p "${target}" "${backup}"
    # Said out loud because the gateway reads its socket from this file and nothing
    # else: re-running the installer with --port 9000 over a deployment that says 8080
    # gets 8080, and the healthy-looking service on the old port is the last thing an
    # operator suspects. Same trap as install_ubuntu22.sh:119-123.
    warn "the existing file wins: a value already set here (POPOPX_GATEWAY_PORT included) is NOT replaced by --port. Edit ${target} to move the service."
    return 0
  fi
  [[ -f "${example}" ]] || die "no env file and no ${example} to seed one from"

  # No `install -d` of the parent here: make_dirs already creates ${CONF_DIR} as
  # 0755, and re-running it against the dry run's mktemp scratch would widen a 0700
  # directory that holds a freshly generated admin token.
  cp "${example}" "${target}"

  # Fill in only the values that must be unique per host or wrong for this platform.
  # Everything else stays at the shipped default so a diff of the env file against
  # .env.example shows the operator exactly what the installer decided for them.
  #
  # The secrets are generated INSIDE the python process, not in bash argv: a value
  # passed as an argument is readable by every local user through `ps -eww -o args`
  # for the lifetime of the call (install_ubuntu22.sh:135-138).
  #
  # POPOPX_DB_PATH and POPOPX_GATEWAY_HOST are rewritten because .env.example ships
  # Linux values: line 69 is /var/lib/…, which does not exist on macOS and cannot be
  # created by a role account, and line 28 is 0.0.0.0. A deployment that inherits
  # either gets a database error that looks like corruption, or an exposure it did not
  # ask for.
  local bootstrap_py
  bootstrap_py="$(bootstrap_python || true)"
  [[ -n "${bootstrap_py}" ]] || die "no Python interpreter to run the env rewrite with: nothing was written"
  GATEWAY_PORT="${GATEWAY_PORT}" GATEWAY_HOST="${BIND_HOST}" \
  STATE_DB="${STATE_DIR}/gateway.db" TARGET_ENV="${target}" \
  PUBLIC_BASE_URL_VAL="${PUBLIC_BASE_URL}" NODE_WS_URL_VAL="${NODE_WS_URL:-}" \
    "${bootstrap_py}" - <<'PYEOF'
import os, re, secrets

path = os.environ["TARGET_ENV"]
secrets_map = {
    "POPOPX_ADMIN_TOKEN": secrets.token_hex(32),
    "POPOPX_ALERT_WEBHOOK_TOKEN": secrets.token_hex(20),
}
rewrites = {
    "POPOPX_GATEWAY_PORT": os.environ["GATEWAY_PORT"],
    "POPOPX_GATEWAY_HOST": os.environ["GATEWAY_HOST"],
    "POPOPX_DB_PATH": os.environ["STATE_DB"],
}
# Only rewrite what the operator actually decided: an unset --public-base-url must not
# silently mint an origin the phone will be asked to trust. The shipped template value
# stays, and the installer warns about it in NEXT STEPS instead.
if os.environ.get("PUBLIC_BASE_URL_VAL"):
    rewrites["POPOPX_PUBLIC_BASE_URL"] = os.environ["PUBLIC_BASE_URL_VAL"]
# One number, two files, one decision: with --with-node the node's port and the URL
# the gateway dials are written by the same run, so the drift that
# install_ubuntu22.sh:368-370 tells the operator to change in two places by hand cannot
# happen here — launchd does not expand $NODE_PORT, so the installer is the only writer.
if os.environ.get("NODE_WS_URL_VAL"):
    rewrites["POPOPX_NODE_WS_URL"] = os.environ["NODE_WS_URL_VAL"]

values = dict(secrets_map)
values.update(rewrites)

text = open(path, encoding="utf-8").read()
for key, value in values.items():
    pattern = "(?m)^%s=.*$" % re.escape(key)
    # A callable replacement, not the %s form: a value containing a backslash would
    # otherwise be reinterpreted as a group reference by re.sub.
    if re.search(pattern, text):
        text = re.sub(pattern, lambda _m, v=value, k=key: "%s=%s" % (k, v), text)
    else:
        text = text.rstrip("\n") + ("\n%s=%s\n" % (key, value))

open(path, "w", encoding="utf-8").write(text)
os.chmod(path, 0o600)
print("[popopx] generated %d per-host secrets and set %d host/platform values in %s (values not displayed)"
      % (len(secrets_map), len(rewrites), path))
PYEOF

  if [[ ${DRY_RUN} -eq 0 ]]; then
    # 0600 and owner-only, not 0640: config.py refuses to be quiet about any bit
    # outside the owner — group-readable warns exactly like world-readable, because a
    # group that can read this file can read the bearer token.
    chown "${RUN_USER}:${RUN_USER}" "${target}" 2>/dev/null || \
      warn "could not chown ${target} to ${RUN_USER}; the service would not be able to read it"
  fi

  echo
  log "─────────────────────── ONE-TIME SECRET NOTICE ───────────────────────"
  log "POPOPX_ADMIN_TOKEN was generated and written to ${target} (mode 0600)."
  log "It was NOT printed to this terminal. Read it with:"
  log "    sudo grep POPOPX_ADMIN_TOKEN ${target}"
  log "If you ever paste that file into a chat, ticket or CI log, treat the token as"
  log "compromised and rotate it — it authorises sending cards and rotating keys here."
  log "──────────────────────────────────────────────────────────────────────"
  echo
}

ensure_node_conf() { # $1 = target path; written once, never rewritten; the WRAPPER sources it
  local conf="$1"
  if [[ -f "${conf}" ]]; then
    log "keeping the existing ${conf} (edited by hand, never rewritten here)"
    return 0
  fi
  cat > "${conf}" <<NODECONF
# POPOPX chat node — created by install_macos.sh on $(date -u +%FT%TZ), edited by hand after that.
# Read at runtime by ${INSTALL_ROOT}/bin/popopx-node, the node wrapper the LaunchDaemon execs.
# Unlike the gateway's env file, launchd gives the node no variable expansion in
# ProgramArguments, so these values are expanded by that wrapper, not by launchd.

# Absolute path to the node binary the wrapper runs. --with-node downloads and SHA256-
# verifies popopx-chat into here when nothing is found locally; edit to point at your own.
NODE_BIN_INSTALL=${NODE_BIN_INSTALL}
# Prefix for the node's chat + agent databases. It lives under the state directory on
# purpose: one directory to back up is one failure mode, and this suite's backup story
# is "the state directory", not "the state directory plus wherever the node went".
NODE_DB_PREFIX=${NODE_DB_PREFIX}
# The node's WebSocket API port the gateway dials. install_macos.sh --with-node writes the
# same number into the gateway env file (POPOPX_NODE_WS_URL) from the same run, so the two
# cannot drift the way install_ubuntu22.sh:380-383 warns an operator to avoid by hand.
NODE_PORT=${NODE_PORT}
# SMP / XFTP cluster override — OPTIONAL; empty inherits the binary's own preset, and empty
# is the intended default. The popopx-chat binary POPOPX ships already presets its dual-stack
# production cluster smp1..8.popopx.im (public host + .onion), so leaving these blank reaches
# that cluster. Fill them ONLY to point the node somewhere else, and then copy the FULL
# "smp://<key>@<host>,<onion>.onion" address: a bare hostname loses the server key and the
# .onion, so it is not dual-stack and will not verify against a preset cluster. Space-separated;
# the wrapper passes the whole value as ONE quoted argument, e.g.
#   NODE_SMP_SERVERS="smp://KEY=@smp1.example.com,aaa.onion smp://KEY=@smp2.example.com,bbb.onion"
NODE_SMP_SERVERS=
NODE_XFTP_SERVERS=
# Used ONLY when reusing an existing node profile whose display name must match: the node
# compares it against the active user and exits on a mismatch (src/Popopx/Chat/Core.hs:79-82),
# so an empty value is correct for a fresh identity — the node then creates its own profile.
NODE_DISPLAY_NAME=
NODECONF
  chmod 0600 "${conf}"
}

# ─────────────────────────── service account ────────────────────────────────

create_role_account() { # $1 = name, $2 = uid, $3 = home
  local name="$1" uid="$2" home="$3"
  if user_exists "${name}"; then
    log "account ${name} already exists (UID $(id -u "${name}")) — reusing it"
    return 0
  fi
  if uid_taken "${uid}"; then
    die "UID ${uid} is already taken by $(dscl . -list /Users UniqueID | awk -v u="${uid}" '$2==u{print $1}'). Refusing to pick a different one silently: a service account that moves UID leaves every file it owns behind."
  fi
  if ! group_exists "${name}"; then
    if gid_taken "${uid}"; then
      die "GID ${uid} is already taken by a group. Refusing to guess another one."
    fi
    log "creating group ${name} (GID ${uid})"
    dscl . -create "/Groups/${name}" PrimaryGroupID "${uid}"
    dscl . -create "/Groups/${name}" RecordName "${name}"
    dscl . -create "/Groups/${name}" RecordType "dsRecTypeStandard:Groups"
  fi
  log "creating role account ${name} (UID ${uid})"
  # sysadminctl's documented interface, and the role-account rule it enforces (a name
  # beginning with _ and a UID in 450-499) is exactly what we want: it keeps the
  # account out of the login window list. -home is asked for and NOT granted: a role
  # account comes back with NFSHomeDirectory=/var/empty whichever value is passed
  # (measured on this machine after a real install — `dscl . -read /Users/_popopx
  # NFSHomeDirectory`). So the two lines below, not the account record, are what put
  # the state directory under this uid, and the delete path must never be the
  # home-deleting kind: --uninstall passes -keepHome and nothing else, because with the
  # record pointing at /var/empty a `-secure` delete would aim a recursive delete at a
  # system directory.
  sysadminctl -addUser "${name}" -UID "${uid}" -GID "${uid}" \
    -shell /usr/bin/false -home "${home}" -roleAccount
  dscl . -create "/Users/${name}" Password '*' 2>/dev/null || true
  chmod 0750 "${home}" 2>/dev/null || true
  chown "${name}:${name}" "${home}" 2>/dev/null || true
}

delete_role_account() { # $1 = name
  if user_exists "$1"; then
    log "removing role account $1 (home kept: -keepHome, and this script never passes -secure)"
    sysadminctl -deleteUser "$1" -keepHome </dev/null >/dev/null 2>&1 || \
      warn "could not delete $1 with sysadminctl; remove it in System Settings or with: sudo sysadminctl -deleteUser $1 -keepHome"
    group_exists "$1" && dscl . -delete "/Groups/$1" 2>/dev/null || true
  fi
}

# ─────────────────────────────── install ────────────────────────────────────

sync_source() {
  install -d -m 0755 "${INSTALL_ROOT}"
  log "syncing source to ${INSTALL_ROOT}/src"
  rm -rf "${INSTALL_ROOT}/src.new"   # scratch path this script created, nothing else
  # .git is excluded because the install is a deployment, not a working copy (same list as
  # the `tar` excludes in install_ubuntu22.sh, run_native()). .env is excluded for two reasons: it would be a SECOND
  # env file in the place config.py looks when POPOPX_ENV_FILE is unset, and it carries
  # this host's dev token, which has no business being copied into /usr/local.
  # .venv is excluded because a virtualenv is path-relative and does not survive a
  # move: a copied one is a broken one, and the venv here is built, never carried.
  rsync -a --exclude .git --exclude .env --exclude '.env.bak.*' --exclude .venv \
        --exclude .run --exclude .data --exclude '*.db' --exclude '*.db-shm' --exclude '*.db-wal' \
        "${REPO_DIR}/" "${INSTALL_ROOT}/src.new/"
  if [[ -d "${INSTALL_ROOT}/src" ]]; then
    rm -rf "${INSTALL_ROOT}/src.prev"
    mv "${INSTALL_ROOT}/src" "${INSTALL_ROOT}/src.prev"
  fi
  mv "${INSTALL_ROOT}/src.new" "${INSTALL_ROOT}/src"
  # root:wheel 0755 and deliberately NOT chowned to the service user, which is where
  # this path diverges from install_ubuntu22.sh:309 on purpose: launchd has no
  # ProtectSystem, so the only thing standing between the gateway process and its own
  # source tree is ownership it cannot write through.
  chown -R root:wheel "${INSTALL_ROOT}/src"
}

make_dirs() {
  install -d -m 0750 -o "${RUN_USER}" -g "${RUN_USER}" "${STATE_DIR}" "${STATE_DIR}/tmp"
  install -d -m 0750 -o "${RUN_USER}" -g "${RUN_USER}" "${LOG_DIR}"
  install -d -m 0755 "${CONF_DIR}"
}

build_venv() {
  local py
  py="$(find_python || true)"
  [[ -n "${py}" ]] || die_code 3 "no Python ${PYTHON_VERSION} found. As your login user (not sudo):  brew install python@${PYTHON_VERSION}"
  python_is_target "${py}" || die_code 3 "${py} reports $(python_version_of "${py}"); this deployment targets Python ${PYTHON_VERSION}. Override the search with --python PATH or \$POPOPX_PYTHON."
  if [[ ! -x "${INSTALL_ROOT}/venv/bin/python" ]]; then
    log "creating the virtualenv with ${py}"
    "${py}" -m venv "${INSTALL_ROOT}/venv"
  fi
  local venv_py="${INSTALL_ROOT}/venv/bin/python"
  # The gate is re-run against the venv, not just the interpreter we started from:
  # start_macos.sh:377-380 only checks the discovered python, so a venv built earlier by
  # a different interpreter passes it silently. This repository's own .venv is exactly
  # that case (it reports 3.9), and a production deployment must not inherit it.
  python_is_target "${venv_py}" || die "${venv_py} reports $(python_version_of "${venv_py}"), not ${PYTHON_VERSION}. Remove ${INSTALL_ROOT}/venv and re-run with --python PATH."
  "${venv_py}" -m pip install --upgrade pip wheel >/dev/null
  log "installing gateway dependencies (this is the slow step)"
  "${venv_py}" -m pip install -r "${INSTALL_ROOT}/src/gateway/requirements.txt"
  "${venv_py}" -m pip freeze > "${INSTALL_ROOT}/requirements.lock"
  log "resolved dependency set pinned to ${INSTALL_ROOT}/requirements.lock"
  chown -R root:wheel "${INSTALL_ROOT}/venv" "${INSTALL_ROOT}/requirements.lock"
}

config_gate() {
  # Boot-time refusals are exit 3 (config.py raises ConfigError; main.py:6124-6130
  # turns it into a one-line stderr and a non-zero exit). Under launchd that becomes a
  # restart loop with no console, because there is no StartLimitBurst to stop trying.
  # So the refusals are evaluated here, before the job is ever bootstrapped, and the
  # warnings the gateway would carry are printed, because nothing else ever shows them:
  # config.warnings are only returned by GET /api/v1/diagnostics (main.py:3998).
  log "running the gateway's own config gate against ${CONF_DIR}/env"
  (
    cd "${INSTALL_ROOT}/src/gateway" || exit 1
    POPOPX_ENV_FILE="${CONF_DIR}/env" "${INSTALL_ROOT}/venv/bin/python" - <<'PYEOF'
import sys
from app.config import load_config, ConfigError
try:
    cfg = load_config()
except ConfigError as exc:
    sys.stderr.write("[popopx] the gateway would refuse to start: %s\n" % exc)
    sys.exit(1)
print("[popopx] config gate passed: binding %s:%d, service %s"
      % (cfg.gateway_host, cfg.gateway_port, cfg.service_id))
for w in cfg.warnings:
    sys.stderr.write("[warn] config warning the gateway would carry: %s\n" % w)
PYEOF
  )
}

render_gateway_plist() { # stdout
  # XML comments are legal in a plist and Apple itself uses them in 11 of the 425
  # /System/Library/LaunchDaemons files; plutil -lint gates what we write.
  cat <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Generated by install_macos.sh on $(date -u +%FT%TZ).
     Regenerate by re-running the installer; edits here are overwritten. -->
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${GATEWAY_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_ROOT}/venv/bin/python</string>
        <string>-m</string>
        <string>app.main</string>
    </array>
    <!-- The entrypoint is the module, not a uvicorn argv, exactly as in the systemd
         unit (install_ubuntu22.sh:327-336): POPOPX_GATEWAY_HOST, POPOPX_GATEWAY_PORT
         and POPOPX_LOG_LEVEL live in the env file and nowhere else. A --port here
         would be a second source of truth that silently wins over the file the
         operator edits. One worker is enforced inside main() for the same reason:
         the node link and its pending correlation ids are per-process state. -->
    <key>WorkingDirectory</key>
    <string>${INSTALL_ROOT}/src/gateway</string>
    <!-- launchd has no EnvironmentFile=. The one variable exported here is the PATH to
         the file, because config.py:369 honours POPOPX_ENV_FILE and because anything
         exported in this dict outranks the file (config.py:386-388) — so the socket
         must never appear here. WorkingDirectory, not PYTHONPATH, is what makes the
         'app' package importable: two mechanisms for one job is one that drifts. -->
    <key>EnvironmentVariables</key>
    <dict>
        <key>POPOPX_ENV_FILE</key>
        <string>${CONF_DIR}/env</string>
        <key>HOME</key>
        <string>${STATE_DIR}</string>
        <key>TMPDIR</key>
        <string>${STATE_DIR}/tmp</string>
        <key>PATH</key>
        <string>/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>LANG</key>
        <string>en_US.UTF-8</string>
        <key>PYTHONUNBUFFERED</key>
        <string>1</string>
    </dict>
    <key>UserName</key>
    <string>${RUN_USER}</string>
    <key>GroupName</key>
    <string>${RUN_USER}</string>
    <!-- Umask 077 because launchd creates the log files itself, with the mode this key
         gives it (launchd.plist(5), StandardErrorPath). Everything else the service
         writes is inside a 0750 directory it owns. -->
    <key>Umask</key>
    <string>077</string>
    <!-- KeepAlive{SuccessfulExit=false} is systemd's Restart=on-failure: restart on a
         non-zero exit, stay down after a clean one. Crashed covers the signal deaths.
         There is no StartLimitBurst here, so launchd retries forever, throttled; that
         is the reason config_gate() runs before this file is ever loaded. -->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>3</integer>
    <key>ExitTimeOut</key>
    <integer>15</integer>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/gateway.out.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/gateway.err.log</string>
    <!-- Separate out/err paths: one path for both keys is not documented behaviour.
         The interesting half is err — main.py logs through logging.basicConfig with no
         stream configured, so everything the gateway says goes to gateway.err.log and
         only the banner lines go to stdout. -->
</dict>
</plist>
PLIST
}

render_node_wrapper() { # stdout; the LaunchDaemon execs this, and it sources node.conf
  # A single stable ProgramArguments entry is how launchd gets the variable expansion it
  # lacks: every runtime value comes from node.conf, so the plist never bakes a port or a
  # path that would go silently stale when the operator edits the config. Quoted heredoc on
  # purpose — nothing here expands at generation time; the config path arrives as an env var.
  cat <<'WRAPPER'
#!/bin/sh
# POPOPX chat node — secure launcher generated by install_macos.sh --with-node.
# The installer regenerates this file; edit node.conf, not this. It runs as the node
# service account and reads nothing but node.conf — never the gateway's env file or token.
set -eu
umask 077
CONF="${POPOPX_NODE_CONF:?popopx-node: POPOPX_NODE_CONF not set by the LaunchDaemon}"
[ -r "${CONF}" ] || { echo "popopx-node: cannot read ${CONF}" >&2; exit 1; }
# shellcheck disable=SC1090
. "${CONF}"
: "${NODE_PORT:?popopx-node: NODE_PORT missing from ${CONF}}"
: "${NODE_DB_PREFIX:?popopx-node: NODE_DB_PREFIX missing from ${CONF}}"
BIN="${NODE_BIN_INSTALL:?popopx-node: NODE_BIN_INSTALL missing from ${CONF}}"
[ -x "${BIN}" ] || { echo "popopx-node: node binary not executable: ${BIN}" >&2; exit 1; }
set -- --chat-server-port "${NODE_PORT}" --database "${NODE_DB_PREFIX}" --yes-migrate
# Cluster override ONLY when the operator set it; empty means "use the binary's own preset
# cluster" (the intended default — see node.conf). Passing "$@" keeps a space-separated
# value as ONE argument, which is exactly what the node's --server/--xftp-server expect.
if [ -n "${NODE_SMP_SERVERS:-}" ]; then set -- "$@" --server "${NODE_SMP_SERVERS}"; fi
if [ -n "${NODE_XFTP_SERVERS:-}" ]; then set -- "$@" --xftp-server "${NODE_XFTP_SERVERS}"; fi
if [ -n "${NODE_DISPLAY_NAME:-}" ]; then set -- "$@" --user-display-name "${NODE_DISPLAY_NAME}"; fi
exec "${BIN}" "$@"
WRAPPER
}

render_node_plist() { # stdout; launchd execs the wrapper, which sources node.conf
  cat <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Generated by install_macos.sh --with-node on $(date -u +%FT%TZ).
     Regenerate by re-running the installer; edits here are overwritten.
     ProgramArguments is the node wrapper, not the binary with literal flags: launchd does
     not expand variables in ProgramArguments, so the wrapper reads ${CONF_DIR}/node.conf and
     builds the arguments there. POPOPX_NODE_CONF is the only value the wrapper needs at exec
     time; the port, database prefix and any cluster override all live in node.conf.
     The wrapper (not this plist) carries the --user-display-name decision: the flag exits the
     node when it disagrees with an existing profile (src/Popopx/Chat/Core.hs:79-82), so it is
     passed only when node.conf sets NODE_DISPLAY_NAME, never unconditionally. -->
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${NODE_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_ROOT}/bin/popopx-node</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>POPOPX_NODE_CONF</key>
        <string>${CONF_DIR}/node.conf</string>
        <key>HOME</key>
        <string>${STATE_DIR}/node-home</string>
        <key>PATH</key>
        <string>/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>LANG</key>
        <string>en_US.UTF-8</string>
    </dict>
    <key>UserName</key>
    <string>${NODE_USER}</string>
    <key>GroupName</key>
    <string>${NODE_USER}</string>
    <key>Umask</key>
    <string>077</string>
    <key>WorkingDirectory</key>
    <string>${STATE_DIR}/node-home</string>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>ExitTimeOut</key>
    <integer>20</integer>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/node.out.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/node.err.log</string>
</dict>
</plist>
PLIST
}

install_plist() { # $1 = label, $2 = rendered plist body
  local label="$1" body="$2" staged tmp
  tmp="$(mktemp -d)"
  staged="${tmp}/${label}.plist"
  printf '%s\n' "${body}" > "${staged}"
  # Lint before it lands: launchd's failure to parse a plist is a log line nobody reads
  # and a service that simply never exists.
  plutil -lint "${staged}" >/dev/null || { rm -rf "${tmp}"; die "${staged} is not a valid plist; refusing to install it"; }
  install -m 0644 -o root -g wheel "${staged}" "${PLIST_DIR}/${label}.plist"
  rm -rf "${tmp}"
}

bootstrap_job() { # $1 = label
  local label="$1"
  if job_loaded "${label}"; then
    log "booting out the previously loaded ${label}"
    launchctl bootout "system/${label}" || warn "bootout of ${label} failed; bootstrap may reject the new file"
    wait_for_bootout "${label}" || warn "${label} is still listed 5s after bootout; bootstrapping anyway, so a failure below is launchd still holding the label"
  fi
  launchctl bootstrap system "${PLIST_DIR}/${label}.plist"
  launchctl enable "system/${label}"
  launchctl kickstart -k "system/${label}" || warn "kickstart of ${label} returned non-zero; verify() will show whether it came up"
}

install_node_unit() {
  local bin
  bin="${NODE_BIN_RESOLVED}"
  [[ -x "${bin}" ]] || die_code 4 "no node binary at ${bin}"
  NODE_BIN_INSTALL="${bin}"
  NODE_DB_PREFIX="${STATE_DIR}/node/popopx_v1"
  # NODE_SOURCE is set by download_node_bin; if the binary was local (--node-bin or find_node_bin),
  # record that so the provenance file (written by ensure_node_conf) is honest about origin.
  : "${NODE_SOURCE:=local:${bin}}"
  create_role_account "${NODE_USER}" "${NODE_UID}" "${STATE_DIR}/node-home"
  install -d -m 0750 -o "${NODE_USER}" -g "${NODE_USER}" "${STATE_DIR}/node" "${STATE_DIR}/node-home"
  chown "${NODE_USER}:${NODE_USER}" "${NODE_DB_PREFIX%/*}" 2>/dev/null || true
  # node.conf must be readable by NODE_USER (the wrapper sources it at runtime), so chown after write.
  ensure_node_conf "${CONF_DIR}/node.conf"
  chown "${NODE_USER}:${NODE_USER}" "${CONF_DIR}/node.conf"
  chmod 0600 "${CONF_DIR}/node.conf"
  # The wrapper is the single ProgramArguments entry in the plist; it sources node.conf and builds
  # the node's argv. Installing it as root:wheel 0750 means NODE_USER can read+exec but not modify.
  render_node_wrapper > "${INSTALL_ROOT}/bin/popopx-node"
  chmod 0750 "${INSTALL_ROOT}/bin/popopx-node"
  chown root:wheel "${INSTALL_ROOT}/bin/popopx-node"
  install_plist "${NODE_LABEL}" "$(render_node_plist)"
  bootstrap_job "${NODE_LABEL}"
  # Bounded wait: the node takes a few seconds to bind its port after launchd kicks it. If it
  # does not answer in 40s, warn (do not die) — verify() will catch it later, and the operator
  # may have a slow machine or a firewall rule to add.
  wait_for_node_ready 40 || warn "node did not bind port ${NODE_PORT} within 40s; check ${LOG_DIR}/node.err.log"
  log "node installed as ${NODE_LABEL} (${bin}), databases under ${NODE_DB_PREFIX}"
  log "a production node under ${NODE_USER} is a NEW identity. It does not read or copy"
  log "the developer's ~/.popopx profile — the port and the account are different on purpose."
}

# ─────────────────────────────── verification ───────────────────────────────

verify() {
  local url="http://127.0.0.1:${GATEWAY_PORT}/healthz"
  local ok=0 rc=0
  log "probing ${url}"
  local i=0
  # --noproxy '*' is load-bearing, not decoration: an operator shell with ALL_PROXY set
  # (the normal state on a machine behind a corporate proxy) makes curl send loopback
  # requests to the proxy, which answers nothing. Without this the installer reports a
  # dead gateway that is actually up — measured here, where ALL_PROXY is exported.
  while [ ${i} -lt 20 ]; do
    if curl -fsS --noproxy '*' "${url}" >/dev/null 2>&1; then ok=1; break; fi
    i=$((i + 1)); sleep 1
  done

  if [[ ${ok} -eq 1 ]]; then
    log "gateway answers /healthz:"
    curl -fsS --noproxy '*' "${url}" | head -c 800; echo
  else
    rc=5
    warn "/healthz did not answer within 20s. Three distinct causes, in the order they are"
    warn "usually the answer:"
    warn "  1. the job is not running at all  ->  sudo launchctl print system.${GATEWAY_LABEL}"
    warn "     (look for 'state', 'pid', 'last exit code'; a service that never appears was"
    warn "     not bootstrapped, which is a launchd problem, not a gateway one)"
    warn "  2. it ran and exited             ->  tail -n 80 ${LOG_DIR}/gateway.err.log"
    warn "     (the config gate passed, so a refusal here means the env file changed since)"
    warn "  3. it is up but the node link is down"
    warn "     /healthz reports node state, it does not gate readiness on it."
  fi

  local uid_note="not running"
  local pid
  # [[:space:]] and not \s: this is BSD awk, which silently treats "\s" as "s" and would
  # report "not running" for a service that is demonstrably up. The same output is
  # proof of the run user, which is the claim the summary line makes.
  pid="$(launchctl print "system/${GATEWAY_LABEL}" 2>/dev/null | awk '/^[[:space:]]*pid = /{print $3; exit}')"
  if [[ -n "${pid}" ]]; then
    local run_as
    run_as="$(ps -o user= -p "${pid}" 2>/dev/null | tr -d ' ' || true)"
    uid_note="${run_as:-user unknown} (pid ${pid})"
  fi

  cat <<SUMMARY

────────────────────────────────────────────────────────────────────────────
 POPOPX Service Suite — installed on macOS (${BIND_HOST}:${GATEWAY_PORT})
────────────────────────────────────────────────────────────────────────────
 Service    ${GATEWAY_LABEL} — running as ${uid_note}
 State      ${STATE_DIR}          (SQLite + channel keys, mode 0750)
 Config     ${CONF_DIR}/env       (0600, owner ${RUN_USER}; POPOPX_ENV_FILE points here)
 Source     ${INSTALL_ROOT}/src   (root:wheel — the service user cannot edit its own code)
 Logs       ${LOG_DIR}/gateway.err.log   (everything the gateway says)
            ${LOG_DIR}/gateway.out.log   (banner lines only)

 Day-to-day:
   status     sudo launchctl print system/${GATEWAY_LABEL}
   logs       sudo tail -f ${LOG_DIR}/gateway.err.log
   restart    sudo launchctl kickstart -k system/${GATEWAY_LABEL}
   stop       sudo launchctl bootout system/${GATEWAY_LABEL}     (re-enable: sudo ./install_macos.sh)

 NEXT STEPS — none of these are done for you, on purpose:

 1. Point the console at a real origin and TLS-terminate it. PopopxH5Launcher signs
    the URL it is about to open, so POPOPX_PUBLIC_BASE_URL must be the exact https
    origin the phone will load. $([[ -n "${PUBLIC_BASE_URL}" ]] && echo "This run set it." || echo "This run left the template value (https://service.example.com) alone, so H5 links currently point at an origin that does not exist.")
      sudo \${EDITOR:-vi} ${CONF_DIR}/env      # POPOPX_PUBLIC_BASE_URL=…
      sudo launchctl kickstart -k system/${GATEWAY_LABEL}

 2. Logs do not rotate. launchd holds the log file's fd, so a newsyslog entry that
    deletes or renames the file leaves the running daemon writing to an inode nobody
    opens again — a rotation that silently stops logging is worse than no rotation.
    The safe procedure is the one that reopens the fd:
      sudo mv ${LOG_DIR}/gateway.err.log ${LOG_DIR}/gateway.err.\$(date -u +%Y%m%d).log
      sudo launchctl kickstart -k system/${GATEWAY_LABEL}

 3. Optional — only if you set POPOPX_BILLING_REQUIRE_VOUCHER=1. Admission mode starts
    the account in DRAFT and needs the official voucher public key:
      python3 official_tools/gen_voucher.py --show-pubkey --keyring ./official_keys
      POPOPX_OFFICIAL_ED25519_PUBLIC_KEY=<base64 above>

 4. The node's WebSocket API has NO authentication and binds loopback only. Keep it
    that way; do not proxy ${NODE_PORT} onto a network. If you front the gateway with a
    proxy, protect the admin routes there and leave the node alone. Note that this
    gateway trusts X-Forwarded-* from any peer, so a proxy that can be reached directly
    is a proxy that can forge clients.

 5. Open only the gateway port, only once TLS is in place, and only if you used --lan:
      sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/local/${SUITE_NAME}/venv/bin/python
      sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /usr/local/${SUITE_NAME}/venv/bin/python
    This installer changed no firewall setting. Check what you have with
    socketfilterfw --getglobalstate.

 6. Back up ${STATE_DIR} — gateway.db holds the channel identity private keys as well
    as the ledger and every pairwise session secret (there is no separate keyring file,
    on purpose: a rotation must commit in the same transaction as the frame it
    delivers). Losing it means every existing zero-knowledge channel goes silent for
    good: no rotation can be signed that members will verify.

 7. Run the two suites that are deliberately NOT on the boot path, before you trust an
    admin route or a redemption. The gateway only checks the route table
    (assert_routes_are_gated()) when it builds the app; the rest is a
    published-artifact gate, and it requests the real ASGI app:
      cd ${INSTALL_ROOT}/src/gateway && ${INSTALL_ROOT}/venv/bin/python -m app.main --self-test
      cd ${INSTALL_ROOT}/src/gateway && ${INSTALL_ROOT}/venv/bin/python -m app.main --check-routes
    Expect "no SKIPPED" — a wheel-less interpreter skips the crypto and HTTP groups and
    says so on the last line.

 Admin console  http://${BIND_HOST}:${GATEWAY_PORT}/   (admin API header: X-Admin-Token, or
 ?token=. The core's admin_required does not parse "Authorization: Bearer" — only
 privacy_sso's device-facing route reads it (bearer_secret). The console sends both.)
────────────────────────────────────────────────────────────────────────────
SUMMARY
  return ${rc}
}

# ──────────────────────────────── uninstall ─────────────────────────────────

uninstall() {
  local label
  for label in "${GATEWAY_LABEL}" "${NODE_LABEL}"; do
    if job_loaded "${label}"; then
      log "booting out system/${label}"
      launchctl bootout "system/${label}" || warn "bootout of ${label} failed"
    fi
    if [[ -f "${PLIST_DIR}/${label}.plist" ]]; then
      rm -f "${PLIST_DIR}/${label}.plist"
      log "removed ${PLIST_DIR}/${label}.plist"
    fi
  done

  rm -rf "${INSTALL_ROOT}" "${CONF_DIR}" "${LOG_DIR}"
  log "removed ${INSTALL_ROOT}, ${CONF_DIR} and ${LOG_DIR}"

  delete_role_account "${NODE_USER}"
  delete_role_account "${RUN_USER}"

  if [[ ${KEEP_STATE} -eq 1 ]]; then
    log "STATE KEPT: ${STATE_DIR}"
    log "  It holds gateway.db — the ledger, every pairwise session secret and the"
    log "  channel identity private keys. Nothing in this script deletes it, and a"
    log "  re-install reuses it. To finish:"
    log "    sudo rm -rf ${STATE_DIR}     # or move it somewhere you will not lose it"
  else
    warn "--purge-state: deleting ${STATE_DIR}. Every zero-knowledge channel created by"
    warn "this deployment goes silent for good — no rotation can be signed that members"
    warn "will verify."
    rm -rf "${STATE_DIR}"
    log "state directory removed"
  fi
  log "uninstalled. The checkout at ${REPO_DIR} was never touched."
}

# ──────────────────────────────── dry run ───────────────────────────────────

dry_run() {
  local scratch py plist
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/popopx-dryrun.XXXXXX")"
  py="$(bootstrap_python || true)"
  [[ -n "${py}" ]] || die "no python3 at all; the env generator cannot run"

  print_plan
  log "DRY RUN — writing under ${scratch} only. No user, no directory, no launchctl."
  warn "the values below are for the REAL install root (${INSTALL_ROOT}), which is why"
  warn "the linted plist is the one that would be installed."

  # Deliberately NOT a pre-copy of .env.example: ensure_env_file seeds it itself, and a
  # file already sitting at the target makes it take the "existing file wins" branch —
  # which would have made this whole dry run prove nothing about the rewrite.
  ensure_env_file "${scratch}/env"
  # No chmod here on purpose: os.chmod(0o600) inside the generator is the thing the
  # assertion below proves, so setting the mode from bash first would make it vacuous.

  # The re-install path, measured rather than promised. On a real redeploy the target
  # file holds the live admin token and whatever port the operator moved the service to,
  # so "the existing file wins" has to mean byte-for-byte unchanged, with only a
  # timestamped copy added. Proved here because it is the branch a sudo re-run takes and
  # the one branch a fresh dry run cannot reach.
  local keep="${scratch}/keep" before after backups
  install -d -m 0700 "${keep}"
  cp "${REPO_DIR}/.env.example" "${keep}/env"
  cp -p "${keep}/env" "${keep}/env.reference"
  before="$(cksum < "${keep}/env")"
  ensure_env_file "${keep}/env"
  after="$(cksum < "${keep}/env")"
  [[ "${before}" == "${after}" ]] || die "a pre-existing env file was modified; 'the existing file wins' is false"
  backups="$(find "${keep}" -maxdepth 1 -name 'env.bak.*' -type f | wc -l | tr -d ' ')"
  [[ "${backups}" == "1" ]] || die "expected exactly one env.bak.<utc> copy, found ${backups}"
  log "re-install probe: pre-existing env unchanged (${before%% *}), one backup copy written"
  # This probe's inputs come from .env.example, which contains no generated secrets, so
  # deleting the directory is safe; the linted plist is kept for the operator to read.
  rm -rf "${keep}"

  plist="${scratch}/${GATEWAY_LABEL}.plist"
  render_gateway_plist > "${plist}"
  plutil -lint "${plist}"
  log "gateway plist linted: ${plist}"

  if [[ ${WITH_NODE} -eq 1 ]]; then
    local bin arch asset
    arch="$(uname -m)"
    asset="$(node_asset_name || echo '<unsupported arch>')"
    log "node    arch=${arch}, target asset=${asset}"
    # Binary resolution priority: explicit --node-bin > local find_node_bin > download plan.
    # In dry-run we do NOT actually download; we only show what would happen.
    bin=""
    if [[ -n "${NODE_BIN}" ]]; then
      [[ -x "${NODE_BIN}" ]] || die_code 4 "--node-bin ${NODE_BIN} is not executable"
      bin="${NODE_BIN}"
      log "node    binary (explicit --node-bin): ${bin}"
    else
      # Avoid command substitution in the elif condition: under set -e the ERR trap fires
      # on the failed exit status even though elif should suppress it. Use a temp var instead.
      local found_bin
      found_bin="$(find_node_bin 2>/dev/null || true)"
      if [[ -n "${found_bin}" ]]; then
        bin="${found_bin}"
        log "node    binary (local): ${bin}"
      elif [[ ${NODE_DOWNLOAD} -eq 1 ]]; then
        log "node    no local binary; would download ${asset} from GitHub Releases (popopx-chat/popopx-chat)"
        log "node    (dry run does not fetch; the real install will verify SHA2-256 and write .provenance)"
        # Set a placeholder so the wrapper/node.conf render below has something to lint against.
        bin="/tmp/popopx-chat-dryrun"
        NODE_BIN_INSTALL="${bin}"
        NODE_SOURCE="dryrun:would-download-${asset}"
      else
        die_code 4 "--with-node + --no-node-download: no local binary found; cannot proceed"
      fi
    fi
    NODE_DB_PREFIX="${STATE_DIR}/node/popopx_v1"
    NODE_BIN_RESOLVED="${bin}"
    # Render node.conf + wrapper + plist to scratch; lint each. The wrapper is POSIX sh, so
    # sh -n is the syntax check. The plist is now wrapper-based (no literal flags).
    ensure_node_conf "${scratch}/node.conf"
    log "node.conf rendered: ${scratch}/node.conf"
    render_node_wrapper > "${scratch}/popopx-node"
    chmod 0750 "${scratch}/popopx-node"
    sh -n "${scratch}/popopx-node" || die "wrapper failed sh -n syntax check"
    log "wrapper linted: ${scratch}/popopx-node"
    render_node_plist > "${scratch}/${NODE_LABEL}.plist"
    plutil -lint "${scratch}/${NODE_LABEL}.plist"
    log "node plist linted: ${scratch}/${NODE_LABEL}.plist"
    warn "the node unit is GENERATED and linted here, not installed and not started. What"
    warn "this repository has started on a Mac is the development node — start_macos.sh:275-289"
    warn "runs it in the background as the login user against ~/.popopx. A node owned by"
    warn "${NODE_USER} with its own database prefix has not been started by anything, and"
    warn "that claim is reserved for the real install."
  fi

  # Prove the two platform rewrites without printing a secret: lengths and presence,
  # never values. This is the whole point of the rewrite step, so it is checked here
  # rather than assumed.
  "${py}" - "${scratch}/env" <<'PYEOF'
import os, re, sys
text = open(sys.argv[1], encoding="utf-8").read()
values = dict(re.findall(r"(?m)^([A-Z0-9_]+)=(.*)$", text))
checks = [
    ("POPOPX_DB_PATH is a macOS path", values.get("POPOPX_DB_PATH", "").startswith("/usr/local/var/")),
    ("POPOPX_GATEWAY_HOST is what was asked for", values.get("POPOPX_GATEWAY_HOST", "") in ("127.0.0.1", "0.0.0.0")),
    ("POPOPX_ADMIN_TOKEN is non-empty and long enough to boot", len(values.get("POPOPX_ADMIN_TOKEN", "")) >= 24),
    ("POPOPX_ALERT_WEBHOOK_TOKEN is non-empty", len(values.get("POPOPX_ALERT_WEBHOOK_TOKEN", "")) > 0),
    ("no Linux /var/lib path survived", "/var/lib/" not in text),
]
for name, ok in checks:
    print("%-52s %s" % (name, "ok" if ok else "FAIL"))
    if not ok:
        sys.exit(1)
print("POPOPX_ADMIN_TOKEN length: %d chars (value not displayed)" % len(values["POPOPX_ADMIN_TOKEN"]))
print("env file mode: %04o" % (os.stat(sys.argv[1]).st_mode & 0o777))
PYEOF
  [[ $(stat -f '%Lp' "${scratch}/env") == "600" ]] || die "env file is not mode 0600"
  # The env file is deleted on purpose. It holds freshly generated secrets, and a dry
  # run that leaves them sitting in $TMPDIR (world-readable parent on a shared machine,
  # never cleaned by anything) is a worse posture than not proving the mode at all. The
  # plist has no secrets and is kept, because it is the artifact worth reading.
  rm -f "${scratch}/env"
  log "the dry-run env file was deleted after the checks above; it held real generated secrets"

  echo
  log "Dry run complete. Nothing on the system changed. Inspect:"
  log "    ${scratch}/${GATEWAY_LABEL}.plist"
  log "Then install for real:  sudo ./install_macos.sh"
}

# ────────────────────────────────── main ────────────────────────────────────

need_cmd curl
need_cmd plutil
need_cmd launchctl
need_cmd dscl
need_cmd sysadminctl
need_cmd lsof
need_cmd rsync
need_cmd sw_vers

if [[ ${CHECK_ONLY} -eq 1 ]]; then
  check_only
  exit 0
fi

if [[ ${DO_UNINSTALL} -eq 1 ]]; then
  uninstall
  exit 0
fi

if [[ ${DRY_RUN} -eq 1 ]]; then
  dry_run
  exit 0
fi

if [[ ${WITH_NODE} -eq 1 ]]; then
  # Binary resolution priority: explicit --node-bin > local find_node_bin > download (unless --no-node-download).
  # The download path is the new default when nothing local exists; --no-node-download keeps the old behavior.
  NODE_BIN_RESOLVED=""
  if [[ -n "${NODE_BIN}" ]]; then
    [[ -x "${NODE_BIN}" ]] || die_code 4 "--node-bin ${NODE_BIN} is not executable"
    NODE_BIN_RESOLVED="${NODE_BIN}"
    log "node binary (explicit --node-bin): ${NODE_BIN_RESOLVED}"
  elif NODE_BIN_RESOLVED="$(find_node_bin 2>/dev/null)"; then
    log "node binary (local): ${NODE_BIN_RESOLVED}"
  elif [[ ${NODE_DOWNLOAD} -eq 1 ]]; then
    log "no local node binary; downloading from GitHub Releases"
    NODE_BIN_RESOLVED="$(download_node_bin)"
    log "node binary (downloaded): ${NODE_BIN_RESOLVED}"
  else
    die_code 4 "no popopx-chat node found and --no-node-download is set. Build it: cd <popopx-chat checkout> && cabal build popopx-chat && cabal list-bin popopx-chat — or pass --node-bin PATH, or drop --no-node-download. (If a node is already running that you maintain yourself, install without --with-node.)"
  fi
  NODE_WS_URL="ws://127.0.0.1:${NODE_PORT}"
fi

log "installing ${SUITE_NAME} from ${REPO_DIR} (launchd, ${BIND_HOST}:${GATEWAY_PORT})"
print_plan

# Order matters for a run that gets interrupted: the account first (harmless without a
# job), then code, then directories, then the venv, then the env file, then the gate,
# and the job last. A plist that failed to bootstrap leaves src.prev and the old env
# file in place; a user with no plist is inert; a venv with no plist is a directory.
create_role_account "${RUN_USER}" "${RUN_UID}" "${STATE_DIR}"
sync_source
make_dirs
build_venv
ensure_env_file "${CONF_DIR}/env"
config_gate

# Node before gateway: the gateway's env file carries NODE_WS_URL, and the gateway expects
# the node to answer on that socket. Bringing the node up first means the gateway's first
# /healthz probe sees a live node, not a "connection refused" that would fail verify().
if [[ ${WITH_NODE} -eq 1 ]]; then
  install_node_unit
fi

install_plist "${GATEWAY_LABEL}" "$(render_gateway_plist)"
bootstrap_job "${GATEWAY_LABEL}"

# verify() returns 5 when the service is installed but /healthz stayed silent. It must
# not be a bare statement: under set -e the ERR trap would fire first and the run would
# leave with 1, which is the code for "fatal preflight" — the one thing an operator
# needs to be able to tell apart from "installed, look at the log".
rc=0
verify || rc=$?
log "done."
exit ${rc}
