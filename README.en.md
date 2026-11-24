# popopx-service-suite
<!--
  Copyright (c) 2026 POPOPX (popopx.chat)
  SPDX-License-Identifier: AGPL-3.0-only
-->

English · 中文：[`README.md`](README.md)

The backend suite for POPOPX service accounts: a gateway (FastAPI), the POPX-CP credit
meter, channel envelope encryption with zero-knowledge key rotation, five business plugins
and a browser admin console. The wire protocol is aligned byte-for-byte with the shipped
POPOPX iOS client. The open-source node is reached only over
`ws://127.0.0.1:5225`; this suite links against, patches and redistributes none of its code.

## License and trademarks

The code is under **AGPL-3.0-only**; the full text is [`LICENSE`](LICENSE), the same licence as
the `popopx-chat` repository this suite interoperates with. The `Copyright` plus
`SPDX-License-Identifier: AGPL-3.0-only` pair at the top of every source file is the entry point
to that licence. You may use, modify and redistribute it freely; section 13 of AGPL-3.0 asks one
thing: if you run a modified version for other people over a network, ship them the modified
source too.

**The trademarks are not part of that grant.** The POPOPX name, the logo and the popopx.chat
domain belong to POPOPX — rename a modified distribution, and do not offer deployments, services
or endorsements under the POPOPX name. Sample keys in `official_tools/` and the sample token in
`.env.example` are placeholders; replace them before self-hosting.

## Layout

```text
popopx-service-suite/
├── LICENSE
├── README.md                Chinese documentation (this file's source of truth)
├── README.en.md             this document
├── install_ubuntu22.sh      production install (Ubuntu 22.04, docker by default; --mode native)
├── install_macos.sh         production install (macOS, launchd native, no docker mode)
├── start_macos.sh           one-command dev start (macOS, venv + local node)
├── docker-compose.yml       gateway + node, two services
├── .env.example             every configuration key, commented; copy to .env
├── official_tools/
│   ├── gen_voucher.py       offline POPX-CP voucher minting and verification
│   └── swift_crypto_oracle.swift   cross-checks the bytes against iOS via CryptoKit
└── gateway/
    ├── Dockerfile
    ├── requirements.txt     fastapi / uvicorn / pydantic / cryptography / httpx / qrcode / websockets
    └── app/                 config database billing_service crypto_service agent_bridge main
        ├── plugins/         ai_agent alert_ops privacy_sso polls web3_bridge
        └── static/          index.html admin console
```

## Requirements

- macOS 13+ (Apple Silicon or Intel) for development. Production runs on Ubuntu 22.04 LTS, or on
  macOS 13+ through the launchd-native path (`install_macos.sh`).
- Python 3.11 and the wheels in `gateway/requirements.txt` to serve traffic. There is no
  reduced server for a machine without them: `create_app()` raises `RuntimeError: FastAPI is
  not installed; run ./start_macos.sh, ./install_macos.sh or ./install_ubuntu22.sh first`, with
  the `ImportError`
  text appended (`gateway/app/main.py:3092`). What a standard-library-only machine *can* do is
  run 12 of the 14 self-test groups, because the runner names the two that import those wheels
  as `SKIPPED` — that is what the **2290 checks across 12 groups** figure below is, and it is
  not a gateway answering requests.
- A running `popopx-agent` / `popopx-chat` node exposing its WebSocket control API on
  `127.0.0.1:5225`.

## Quick start — macOS (development, iPhone debugging)

```bash
cp .env.example .env         # change at least POPOPX_ADMIN_TOKEN
./start_macos.sh             # gateway on http://127.0.0.1:8080/ , node on 127.0.0.1:5225
./start_macos.sh --check     # preflight only: report, start nothing
```

`start_macos.sh` uses the venv path by default and the compose path only when you pass
`--docker`. That path insists the interpreter be Python 3.11: if it cannot find one it prints
`brew install python@3.11` and exits 3 (point it somewhere else with
`POPOPX_PYTHON=/path/to/python3.11 ./start_macos.sh`). It creates `.venv` at the repository
root and installs `gateway/requirements.txt` only when the venv is new or that file is newer
than `.venv/.deps-ok`, so a warm start skips about 20 seconds of network. It generates a
64-character `POPOPX_ADMIN_TOKEN` (`openssl rand -hex 32`) when `.env` lacks one, then prints
the console URL, the H5 origin the phone must be able to reach, and the path of the file
holding the token. The value itself is never printed; read it on purpose
with `./start_macos.sh --show-token`. `--docker` needs docker on PATH and the daemon running,
and the script warns that a containerised gateway cannot reach a node running on macOS.

venv is the default rather than Docker for one concrete reason: the node binds its
WebSocket API to `127.0.0.1`, and inside Docker Desktop a container's "host" is the linuxvm
loopback, not this Mac's loopback — `network_mode: host` is a Linux kernel capability.
`docker-compose.yml` is a starting point for Linux production boxes. It is reviewed by the
same assertion as the three shell launchers (`every_launcher_probes_a_route_that_exists` turns
red when a route it names does not exist; the sibling
`every_shell_launcher_runs_the_module_entrypoint` counts `python -m app.main` in the three
scripts, and composes a container whose CMD is not that file's text, so it asserts 3 rather
than 4), but there is no Docker on this development
machine, so **compose has never been executed here** — `--check-routes` proves the URL in
the file exists, not that the two containers come up.

## Quick start — macOS (production)

```bash
sudo ./install_macos.sh                 # launchd native; binds 127.0.0.1 only by default
sudo ./install_macos.sh --lan           # explicit opt-in to 0.0.0.0 — see divergence 2 below
sudo ./install_macos.sh --with-node     # adds a second LaunchDaemon for the node (_popopx-node)
./install_macos.sh --check              # read-only preflight: zero writes, needs no root
./install_macos.sh --dry-run            # renders both plists and the env file to a temp dir
sudo ./install_macos.sh --uninstall     # service, account, code and config go; the state dir stays
```

`--with-node` on macOS now: detects the architecture (arm64/x86_64), downloads the matching
`popopx-chat-macos-{aarch64,x86-64}` binary from the official `popopx-chat/popopx-chat` GitHub Releases,
verifies its SHA2-256 (digest from the release's `.digest` field or the body's `SHA2-256(<name>)= <hex>`
line — both agree), installs it 0755 to `/usr/local/bin/popopx-chat`, and writes a `.provenance` file
recording release tag, asset name, digest, size, and source URL. It then generates a secure wrapper
`/usr/local/bin/popopx-node` (0750 root:wheel, `#!/bin/sh` + `set -eu` + `umask 077`, sources
`${CONF_DIR}/node.conf`, conditionally passes `--server`/`--xftp-server`/`--user-display-name` — only
when the corresponding env var is non-empty, otherwise inherits the binary's built-in `smp1..8.popopx.im`
dual-stack cluster preset). `node.conf` leaves `NODE_SMP_SERVERS`/`NODE_XFTP_SERVERS` empty by default,
with the canonical cluster addresses recorded in a comment as an optional override hook. Startup order
is now node-before-gateway: `install_node_unit` → `wait_for_node_ready` (40s ceiling, timeout warns but
does not die) → `install_plist gateway` → `bootstrap_job gateway`, so the gateway's first `/healthz` probe
sees a live node.

New flags: `--node-version TAG` (pin a release tag, default `latest`), `--no-node-download` (disable the
download; requires a local binary or `--node-bin`). `--check` now reports the target architecture and
asset name, and when no local binary exists performs a non-fatal egress probe (5s timeout, failure warns,
offline still exits 0). `--dry-run` renders node.conf, the wrapper, and the node plist to a temp dir and
lints them (`sh -n` + `plutil -lint`), without actually downloading.

This path is the peer of Ubuntu's `--mode native`: a dedicated service account, code,
configuration, state and logs all outside the working copy, start at boot, restart on crash,
reinstallable and uninstallable. The layout follows macOS conventions of its own — code in
`/usr/local/popopx-service-suite/{src,venv,requirements.lock}`, configuration in
`/usr/local/etc/popopx-service-suite/env`, state in `/usr/local/var/popopx-service-suite`,
logs in `/usr/local/var/log/popopx-service-suite/`. The service account is `_popopx` (UID/GID 450,
shell `/usr/bin/false`) created with `sysadminctl -roleAccount`. `-home` is asked for and **not
granted**: a role account's `NFSHomeDirectory` is pinned to `/var/empty` whatever is passed —
`dscl . -read /Users/_popopx NFSHomeDirectory` returns exactly that on the installed machine — so
the state directory's `_popopx` ownership and 0750 mode come from the installer's own `chown`, and
the uninstall therefore only ever uses `-keepHome`: with the record pointing at a system
directory, no flag that deletes a home is acceptable. `--with-node` adds `_popopx-node` (451).
The install order is the
one that is safest to interrupt: account → code → directories → venv → env → config gate →
plist → `launchctl bootstrap`, so a plist that never bootstrapped cannot disturb a running
deployment, and no path ever deletes the state directory.

Three choices **deliberately diverge from Ubuntu**, and the script prints all three:

1. There is no `--mode docker`. Same reason as `start_macos.sh:10-15` and
   `docker-compose.yml:19-20`: a container cannot reach this Mac's 127.0.0.1. Shipping a mode
   known not to start would make the installer a liar.
2. It binds `127.0.0.1` by default, not Ubuntu's `0.0.0.0`. The application firewall here is
   off by default, there is no reverse proxy, and the gateway trusts `X-Forwarded-*`
   unconditionally (uvicorn runs with `forwarded_allow_ips='*'`), so a default `0.0.0.0` means
   "reachable from the whole LAN the moment it installs". LAN exposure requires an explicit
   `--lan`, and the script then prints that you either put a reverse proxy in front and let
   only it set those headers, or you do not use `--lan`. The script never touches a firewall
   rule.
3. `src` is installed as `root:wheel 0755` and **deliberately not chowned to the service
   account** (diverging from `install_ubuntu22.sh:309`): a daemon should not be able to edit
   its own code. The price is that the logs are private too — launchd creates
   `gateway.err.log`/`gateway.out.log` under `Umask 077`, owner `_popopx`, mode 0600, so
   reading them takes sudo, which is the same posture as reading the journal on Ubuntu.

systemd to launchd is a key-by-key translation, not a copy: `User=` → `UserName`/`GroupName`
(effective only in the system domain, hence a LaunchDaemon and not an agent),
`WorkingDirectory=` → the same key (it is the only mechanism that makes `-m app.main`
importable, so no second `PYTHONPATH` is set), `EnvironmentFile=` → **one** entry in
`EnvironmentVariables`, `POPOPX_ENV_FILE` (process env outranks file values, so putting a port
or host in the plist would create the second source of truth), `Restart=on-failure` →
`KeepAlive{SuccessfulExit=false, Crashed=true}`, `RestartSec=3` → `ThrottleInterval=3` (a floor
on the interval, not a delay), `TimeoutStopSec=15` → `ExitTimeOut=15`. launchd has **no**
`StartLimitBurst` peer and retries forever, so this suite runs the gateway's own config gate
(`load_config()`) before `bootstrap`: a config that would refuse to start is caught there
instead of becoming a crash loop, and `cfg.warnings` get printed — otherwise only
`GET /api/v1/diagnostics` ever returns them.

Measured offline on this machine: `--help`, `--check` and `--dry-run` (including `--with-node`)
all exit 0, both plists pass `plutil -lint`, and the dry-run proves with `cksum` that a
pre-existing env file survives byte-identical with one `.bak.<utc>` added. `brew`'s Python 3.11.18
passes the interpreter gate, and a venv built from it with `gateway/requirements.txt` actually
installed measures **2324 checks across 14 groups, exit 0** on `--self-test` (that run also caught
an HTTP instrument that goes blind only on the newer starlette — see **Self-test** below).

The sudo install that really starts the service **was run on this Mac on 2026-11-22**:
`/Library/LaunchDaemons/com.popopx.gateway.plist` is on disk (root:wheel 0644), `_popopx` exists
(UID 450, shell `/usr/bin/false`), `/usr/local/etc/popopx-service-suite/env` is mode 0600 owned by
`_popopx`, the state and log directories are 0750, and
`curl http://127.0.0.1:8080/healthz` answers
`{"ok":true,"node_connected":false,"service_id":"popopx.official"}` — a degraded start with no
node, which is the path the documentation promises. That install also caught a crash no offline
run produces: when something on 5225 answers but is not HTTP, `websockets` raises `InvalidMessage`,
which is a `WebSocketException` and **not** an `OSError`, so it passed straight through the handler
in `AgentBridge.start()` and took the gateway down with it. After the fix the same situation logs
one warning, leaves `node_connected` false and retries in the background with capped backoff;
`strict=True` still raises, and that was verified too.

A reinstall can also hit launchd's own timing: `bootout` is asynchronous, so the label may still be
held when the command returns, and the `bootstrap` issued right after answers
`Bootstrap failed: 5: Input/output error` — which reads like a broken plist while the file on disk is
fine. `bootstrap_job` now polls `launchctl print` between those two commands until the job stops
being found, with a 5-second ceiling; when the ceiling expires it bootstraps anyway and says so, so
the wait is neither silent nor unbounded. The self-test pins that ordering as
`the_macos_installer_waits_for_bootout_before_bootstrapping`, and the instrument was shown to
discriminate: deleting the wait line, moving it after the bootstrap, and removing the ceiling each
make it fail.

Not measured yet: whether KeepAlive really pulls a `kill -9`ed process back, and whether `_popopx`
and `/usr/local/*` are genuinely gone after an uninstall. The bootout wait above carries the same
caveat — its evidence is a synthetic `launchctl` (teardown modelled as three further polls, plus the
ceiling path), and the window on real launchd cannot be summoned on demand, so "no more rc=5 on
reinstall" is only proven the next time you actually reinstall. The node unit likewise stops at
"generated and linted": what this repository has started on a Mac is the development node in
`start_macos.sh`; a node running as `_popopx-node` against its own database prefix has never been
started. The real download path of `--with-node` (fetching the binary from GitHub Releases, SHA2-256
verification, writing `.provenance`) and the node starting against the `smp1..8.popopx.im` cluster
are also not verifiable on this sandbox (no SMP egress) — `--check`/`--dry-run` perform a non-fatal
egress probe, and offline still exits 0.

## Quick start — Ubuntu 22.04 (production)

```bash
git clone https://github.com/popopx-chat/popopx-service-suite
cd popopx-service-suite
sudo ./install_ubuntu22.sh                # default --mode docker: gateway (+ node) as containers
sudo ./install_ubuntu22.sh --mode native  # venv + systemd unit, no containers
./install_ubuntu22.sh --help              # --with-node / --port / --skip-apt
```

`--with-node` in native mode now: detects the architecture (x86_64/aarch64), downloads the matching
`popopx-chat-ubuntu-22_04-{x86_64,aarch64}` binary from the official `popopx-chat/popopx-chat` GitHub
Releases, verifies its SHA2-256 (preferring `sha256sum`, falling back to `shasum -a 256` or `openssl`),
installs it 0755 to `/usr/local/bin/popopx-chat`, and writes a `.provenance` file. It then generates a
secure wrapper `/usr/local/bin/popopx-node` (0755 root:root, `#!/bin/sh` + `set -eu` + `umask 077`,
sources `/etc/default/popopx-node`, conditionally passes `--server`/`--xftp-server`/`--user-display-name`).
`/etc/default/popopx-node` leaves `NODE_SMP_SERVERS`/`NODE_XFTP_SERVERS` empty by default, with the
canonical `smp1..8.popopx.im` dual-stack cluster addresses recorded in a comment as an optional override
hook. The systemd unit's `ExecStart` is now `/usr/local/bin/popopx-node` (the wrapper), no longer inlining
`$NODE_PORT`/`$NODE_DB_PREFIX`. Startup order is node-before-gateway: `systemctl restart popopx-node` →
`wait_for_node_ready` (40s ceiling, timeout warns) → `systemctl restart popopx-gateway`.

New flags: `--node-port N` (node WebSocket port, default 5225), `--node-bin PATH` (skip the download),
`--node-version TAG` (pin a release tag), `--no-node-download` (disable the download). Docker mode's
`--with-node` still uses the container image and does not trigger a download.

Clone it wherever you like — `/opt/popopx-service-suite/src` is the installer's own copy, not
your checkout: docker mode copies the compose file, `gateway/`, `official_tools/` and
`LICENSE` into it, native mode copies the whole repo minus `.git` and keeps the previous copy
as `src.prev`. It needs root, `curl`, `systemctl`, `python3` and (unless `--skip-apt`) apt.
Both modes then write a per-host env file with three values
— `POPOPX_ADMIN_TOKEN`, `POPOPX_ALERT_WEBHOOK_TOKEN`, `POPOPX_GATEWAY_PORT` — at mode 0600,
values never displayed. If that file already exists the installer keeps it (the pre-run copy
goes to `.env.bak.<utc>`) and refuses to let `--port` overwrite what is in it, because the
gateway reads its socket from that file and nothing else. Where the file lives is the one
thing the modes differ on operationally: `src/.env` for compose to read in docker mode,
`/etc/popopx-service-suite/env` in native mode, where it is the unit's `EnvironmentFile=`.

`--mode native` is the layout most people expect from a self-hosted service. It creates the
nologin system user `popopx` homed in `/var/lib/popopx-service-suite` (0750, owned by
`popopx`, alongside `/etc/popopx-service-suite`), installs `python3.11` + venv, builds the
venv at `/opt/popopx-service-suite/venv`, installs `src/gateway/requirements.txt` and pins
the resolved set to `/opt/popopx-service-suite/requirements.lock` from `pip freeze`, then
installs `/etc/systemd/system/popopx-gateway.service`. `--with-node` adds a second nologin
user `popopx-node` and `popopx-node.service`, which reads its own
`EnvironmentFile=/etc/default/popopx-node`. Docker mode does not create `popopx` — it chowns
`/var/lib/popopx-service-suite` to the image's uid 1001 instead, because a bind mount owned
by whoever ran `install` fails on the first ledger write with a `SQLITE_CANTOPEN` that looks
like a corrupt database.

Either way the last step prints the two verification commands (`--self-test` and
`--check-routes`) and a numbered NEXT STEPS block that is deliberately not done for you: set
`POPOPX_PUBLIC_BASE_URL` to the exact https origin the phone loads (`PopopxH5Launcher` signs
that URL); give the gateway the official voucher public key only if you turned admission mode
on; keep the node's unauthenticated WebSocket port on loopback and never proxy 5225 onto a
network; open only the gateway port and only after TLS is terminated; and back up
`/var/lib/popopx-service-suite` — `gateway.db` holds the channel identity private keys
alongside the ledger and every pairwise session secret, on purpose, because a rotation must
commit in the same transaction as the frame it delivers. Lose it and every existing
zero-knowledge channel goes silent for good.

## Startup behaviour and plugin switches

A node that is not up at launch is not fatal: the gateway serves anyway, `/healthz` reports
`node_connected: false`, and the bridge retries on a capped backoff, attaching by itself
once the node answers (`strict=True` is reserved for callers that want fail-fast).

Of the five plugins only `web3_bridge` is off by default and needs
`POPOPX_PLUGIN_WEB3_BRIDGE=1`; the other four follow their own `POPOPX_PLUGIN_*` flag. Each
plugin answers `GET <its own prefix>/status`, which is what the five console panels read.

## Typical operations

Every `/api/v1/` call takes the admin token in a header (a `?token=` query parameter is also
accepted). The header name is literal, and the suite does not use one name everywhere: the
core's `admin_required` reads only `x-admin-token` or `?token=`
(`gateway/app/main.py:3170`, `:3254`) and never parses `Authorization: Bearer`; the one
place that does is `privacy_sso`'s device-facing route (`privacy_sso_plugin.py:1521`
`bearer_secret`); `alert_ops`' console routes read `X-Popopx-Admin-Token`
(`alert_ops_plugin.py:1105`). The console sends all three at once
(`gateway/app/static/index.html:585`–`:587`) so one token works whichever route it lands on.
Field names below are the ones the handlers read.

```bash
TOKEN=$(grep '^POPOPX_ADMIN_TOKEN=' .env | cut -d= -f2-)
API=http://127.0.0.1:8080
CHANNEL_ID=ch_1a2b3c4d                                # replace with a real id from `GET /api/v1/channels`

curl -s $API/healthz | python3 -m json.tool     # public: ok, node_connected, service_id

# 1. Redeem a POPX-CP voucher code into the account balance
curl -s -X POST $API/api/v1/vouchers/redeem -H "X-Admin-Token: $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"code":"POPX-CP-...","redeemed_by":"operator-a"}'

# 2. Push the configured bottom menu to every follower, or to a subset
curl -s -X POST $API/api/v1/menu/push -H "X-Admin-Token: $TOKEN" \
     -H 'content-type: application/json' -d '{}'
curl -s -X POST $API/api/v1/menu/push -H "X-Admin-Token: $TOKEN" \
     -H 'content-type: application/json' -d '{"contact_ids":[3,7]}'

# 3. Send a plain, uncharged text to one follower (the escape hatch when a plugin is fused)
curl -s -X POST $API/api/v1/send/text -H "X-Admin-Token: $TOKEN" \
     -H 'content-type: application/json' -d '{"contact_id":3,"text":"maintenance at 02:00 UTC"}'

# 4. Rotate a paid channel's key material (epoch increments; Ed25519-signed envelope)
curl -s -X POST "$API/api/v1/channels/$CHANNEL_ID/rotate" -H "X-Admin-Token: $TOKEN"

# 5. Plugin state
curl -s $API/api/v1/plugins -H "X-Admin-Token: $TOKEN"
curl -s $API/api/v1/plugins/alert_ops/status -H "X-Admin-Token: $TOKEN"
```

`POST /api/v1/channels/{channel_id}/rotate` takes `expires_at_ms`, `revoke_previous` (default
true) and `notify_members` (default true), and it is charged `key_rotation` **per member** —
rehearse on a small channel, not on 4 000 members. A send reports `queued` only when the node
accepted the command. A refusal is a 502 `node_refused` carrying the node's own reason under
`node_error`; a missing follower is a 400 `unknown_contact`, checked locally before the node is
asked at all.

## API overview

91 routes. The 52 declared in this file's tree are printed by
`python3 -m app.main --print-routes`, which also asserts that every admin route is covered by
the token. The five plugins add the other 39 (`alert_ops` 10, `web3_bridge` 9, `polls` 8,
`ai_agent` 6, `privacy_sso` 6); they arrive through `include_router`, invisible to
`--print-routes`, so `every_plugin_*` plus a per-plugin
`plugin_<id>_answers_status_at_its_own_prefix` cover the second half in the self-test.

Authorisation is one rule: `/api/v1/*` requires `X-Admin-Token`; a missing or wrong token is
always `401 {"ok":false,"error":"unauthorized"}`. Four classes of exception: `/`, `/healthz`
and `/h5/{article_id}` are public; `POST /api/v1/verifyH5Auth` proves its caller with a
device-side HMAC instead of a token; plugin paths ending in `/webhook`, `/verify` or
`/callback` skip the token (they carry a per-source token or a back-to-back caller); and
`GET /api/v1/plugins/sso/sessions/{id}` is exempt because the scan page has to poll it before
any login state exists.

Errors are always `{"ok": false, "error": "<code>", "detail": "…"}`, and the HTTP code is
chosen by the operational action it implies:

| Situation | Code | Examples |
| --- | --- | --- |
| Bad argument / object does not exist | 400 / 404 | `unknown_contact`, `contact_ids_required` / `card_not_found` |
| Token missing or wrong | 401 | `unauthorized` |
| Wrong state — retrying cannot help | 409 | `voucher_used`, `account_draft`, `no_session` |
| Balance exhausted or account fused | 402 | `insufficient_credits`, `account_suspended` |
| Node is alive but refused this command | 502 | `node_refused`, plus `node_error` = the node's own reason name |
| The node link itself is down | 503 | `node_unreachable` |

The last two rows are the operator's split: `node_refused` means the link is fine and this
command was rejected (a typo, `userExists`, a broker timeout — `node_error` says which), while
only `node_unreachable` should send you to the process and the network.
`POST /api/v1/node/accept` is the single exception — the inbound handler also calls it as an
internal function, so a failure still answers 200 and the body's `error` is the difference.

## Configuration

Every key lives in the root [`.env.example`](.env.example) (48 keys, each commented — count
them with `grep -cE '^[A-Z0-9_]+=' .env.example`);
`cp .env.example .env` and edit that. Lookup order is `--env <path>` → `$POPOPX_ENV_FILE` →
`.env` at the repository root, and process environment overrides keys from the file (the
orchestrator wins).

Both production paths keep that file outside the working copy and **readable only by its
owner**: Ubuntu's native mode at `/etc/popopx-service-suite/env` (the unit's `EnvironmentFile=`
line, `install_ubuntu22.sh:326`), macOS at `/usr/local/etc/popopx-service-suite/env`. launchd
has no `EnvironmentFile=` key, so the plist exports exactly one variable, `POPOPX_ENV_FILE`,
pointing at it (`config.py:369` honours it), and never a port or an address — process env
outranks the file's values (`config.py:386-388`), so a second copy in the plist would be a
source of truth that quietly wins. Both are 0600 owned by the service account, and that is a
code-level rule rather than documentation style: `_warn_if_world_readable()`
(`gateway/app/config.py:117-136`) counts **any** bit outside the owner, so a group-readable
`0640` earns the same warning as a world-readable `0644`, because any group that can read the
file can read the bearer token inside it — `config.py:858`
(`a_group_readable_env_file_warns_too`) is the assertion that pins that.

`load_config()` refuses to start with a sentence rather than a traceback when
`POPOPX_ADMIN_TOKEN` is missing, shorter than 24 characters or still the example value
(generate with `openssl rand -hex 32`); when `POPOPX_PUBLIC_BASE_URL` is missing — the client
`PopopxH5Launcher` signs exactly that URL, so leaving it empty signs something the phone will
reject; when `POPOPX_OFFICIAL_ED25519_PUBLIC_KEY` does not parse to 32 bytes (44 base64
characters or 64 hex); and for any malformed `KEY=value` line, out-of-range number or
non-boolean switch. Unrecognised `POPOPX_*` keys are ignored, not an error.

## Self-test

Every module ships a `self_test()`; 14 groups in total, run in one command:

```bash
# from the repository root
cd gateway && python3 -m app.main --self-test
```

The startup path does not run the suite — `create_app()` only runs the route gate
`assert_routes_are_gated()` (a route the token does not cover should never start listening).
The full suite is the pre-release entry point, and the three commands it needs are printed for
copying as the last step by `start_macos.sh`, `install_macos.sh` and `install_ubuntu22.sh`.

The authoritative count is the last line that command prints. On this machine on 2026-11-22
`/usr/bin/python3` has only the standard library (no `cryptography`, no `fastapi`), and the
measured result was **2290 checks across 12 groups**: `app.crypto_service.crypto_self_test` (needs
`cryptography`) and `app.main.http_self_test` (needs `fastapi`) were named as `SKIPPED` by the
runner, which prints "those paths are NOT verified here" — those two groups ran zero checks
here, which is not the same as having run and not been counted. Re-running on the same machine
inside a venv that has `gateway/requirements.txt` installed measured **2324 checks across 14
groups**, and the difference is exactly those two groups: the runner prints
`crypto_self_test 6 checks` and `http_self_test 28 checks` per group, and the 14 group figures
sum to the total line (2290 + 6 + 28 = 2324), so you can audit your own run the same way. Every
figure above was re-measured on 2026-11-22: the repository `.venv`'s 3.9.6 (fastapi 0.128.8) and a
fresh venv built from `brew`'s Python 3.11.18 both measure **2324 checks across 14 groups, exit 0**.
The second one was not a formality: `requirements.txt` pins ranges, so the new venv resolved
fastapi 0.165.0 with starlette 1.10.0, and starlette 1.x no longer flattens an
`include_router()` into `app.routes` — it keeps one nested `_IncludedRouter` in their place.
Reading the flat list through `isinstance(r, APIRoute)` therefore lost 30 plugin routes and
reported 39 verb+path pairs as "declared but never mounted", while
`GET /api/v1/plugins/ai/status` still answered 200 and still appeared in the OpenAPI document.
The gateway was fine; the instrument was blind, and the routes it could not see were silently
dropping out of the GET sweep rather than failing it. That check now walks nested routers before
comparing, and both fastapi versions give the same answer. The falsification control is still
there: replace `include_router` with a no-op and both versions immediately report
`every_declared_route_is_actually_mounted`.

The node group (`app.agent_bridge`, now 143 checks) gained 3 in the same version, because the live
install hit a class the degraded boot did not cover: when something on 5225 answers with bytes that
are not HTTP, `websockets` raises `InvalidMessage` — a `WebSocketException`, **not** an `OSError` —
which passed straight through the handler in `AgentBridge.start()` and took the gateway down. Every
fake in that group raised `ConnectionRefusedError`, which *is* an `OSError`, so the hole survived a
fully green suite. Those 3 now open a real listener that replies with non-HTTP bytes and let the
library pick the exception class; the last one asserts that the classes `start()` catches match
whether or not `websockets` is installed — on a wheel-less machine it asserts the three-class
fallback rather than skipping, so it cannot quietly read true on the configuration it cannot test.

Assertions cover the protocol layer, database, configuration, billing, cryptography, the node
bridge, the five plugins, cross-implementation cryptography, and the HTTP group
`app.main.http_self_test` — that last one issues real requests against the ASGI app, so it can
tell a mounted route from a route that merely exists in source.

```bash
# Still from the repository root (cd .. if the block above left you in gateway/)
python3.11 -m venv .venv                      # 3.11 is the suite's target interpreter
.venv/bin/pip install -r gateway/requirements.txt
cd gateway && ../.venv/bin/python -m app.main --self-test   # 14 groups green, no SKIPPED (2324 here)
```

## Cross-implementation crypto check

`crypto_self_test()` is a same-language round trip: it proves the module is self-consistent,
not that a phone can read these bytes. The other half is
`official_tools/swift_crypto_oracle.swift`, which uses CryptoKit — the same system framework
the client's `ChannelKeyRotationManager.swift` uses — to open and seal the counterpart
fixtures. No SPM, no network:

```bash
swiftc -O -o /tmp/oracle official_tools/swift_crypto_oracle.swift
/tmp/oracle selfcheck
cd gateway && python3 -m app.crypto_service emit /tmp/py.json && cd ..
/tmp/oracle verify /tmp/py.json                        # Python seals, CryptoKit opens
/tmp/oracle seal --out /tmp/sw.json
(cd gateway && python3 -m app.crypto_service open /tmp/sw.json)   # and the other direction
/tmp/oracle verify /tmp/py.json --tamper aad                      # all three forgeries must be refused
```

`--tamper aad` is the only forgery whose signature is still valid, so it is the only one that
tests whether the AAD is actually doing work. Fixture keys are generated per run; no envelope
private key touches disk.

## Compute vouchers (POPX-CP)

```bash
cd gateway && python3 ../official_tools/gen_voucher.py --help
```

Lifecycle is `DRAFT → ONLINE → SUSPENDED`, and the default is `ONLINE`:
`POPOPX_BILLING_REQUIRE_VOUCHER=0` creates the account already usable, meters every action and
records every ledger row without anybody redeeming a code. Set it to `1` for admission mode —
the account then starts `DRAFT`, metered calls answer 409 `account_draft` until a signed voucher
is redeemed, and `POPOPX_OFFICIAL_ED25519_PUBLIC_KEY` becomes a boot requirement.
The Ed25519 private key only ever lives on the
minting box; the gateway verifies offline with the public key, which is why it cannot create
codes. When a balance runs out, plugins are fused (`GateDecision`), and that decision is the
same code path the console reads back.

## Boundaries

- The spelling of the silent intercept prefixes `::CB::`, `::popopx_sys::`, `::REF::`,
  `::SSO_SCAN::` and of the ECO envelope `::POPOPX_ECO::<compact JSON>` is dictated by the
  client source. Changing those bytes changes the protocol.
- `POST /api/v1/verifyH5Auth` is HMAC-SHA256 with a ±300 second window.
- Actually executed here: `uvicorn` starting the process, a real `websockets` handshake and
  reconnect, offline mint → HTTP redeem → `DRAFT→ONLINE`, the 402 fuse when the balance is
  gone, `node_unreachable` 503 when the node is absent, and the token-free SSO polling while
  writes still require the token. The node side was not a stub: commands went to a real
  `popopx-chat` node (7.1.2.0) started on this machine, which accepted and executed `/users`,
  `/_create user`, `/_contacts`, `/_profile`, `/_accept`, `/_send` and `/_address`, and
  `/healthz` reported `node_connected: true`. `/_address` got as far as the SMP broker before
  failing, and `detail` carried the node's own words, `errorAgent / BROKER / NETWORK /
  timeoutError` — this sandbox has no SMP egress, so grammar and wiring are not the suspects.
- What the launchd side **cannot** do (`install_macos.sh` does not pretend otherwise, and its
  plists carry no key for any of it): there is no peer for `KillSignal=SIGINT` — launchd sends
  SIGTERM on stop. Uvicorn's `HANDLED_SIGNALS` covers SIGINT and SIGTERM alike
  (`.venv/.../uvicorn/server.py:32-35`), so the graceful drain still happens; if you really want
  SIGINT, `sudo launchctl kill SIGINT system/com.popopx.gateway`. There is no peer for
  `ProtectSystem=strict`, `ReadWritePaths=`, `ProtectHome`, `PrivateTmp`, `NoNewPrivileges` or
  `RestrictSUIDSGID`; the only substitutes are the dedicated account, `src` staying
  `root:wheel 0755` (so the service account cannot edit its own code), `Umask 077`, and `TMPDIR`
  pointed at a 0700 directory inside the state tree. There is no peer for `MemoryMax=768M`:
  `SoftResourceLimits.ResidentSetSize` exists as a key but Darwin does not enforce RLIMIT_RSS,
  and `NumberOfFiles` must **not** be set — `launchd.plist(5)` says it writes the global
  `kern.maxfiles`. There is no peer for `StartLimitBurst`/`StartLimitIntervalSec`: launchd never
  gives up retrying, and `ThrottleInterval` is only the floor on the gap between attempts, not a
  `RestartSec` delay — which is the entire reason the config gate runs before `bootstrap`. Do not
  use `KeepAlive.NetworkState` either; the man page states it is "no longer implemented". There is
  no journal, only the two `StandardOutPath`/`StandardErrorPath` files, and **this suite does not
  rotate them**: newsyslog would have to move a file descriptor launchd already holds, so the
  safe procedure is `mv` followed immediately by
  `sudo launchctl kickstart -k system/com.popopx.gateway` to make the service reopen its files —
  that is what the installer's NEXT STEPS prints, not a config that pretends to roll on its own.
- Not done here: an end-to-end send/receive with a real iOS client (needs a reachable broker),
  and the shape of the successful `userContactLinkCreated` frame — only failure frames were
  available, so `show_contact_address()` treats exactly one case, `userContactLinkNotFound`, as
  "no address yet" and re-raises every other refusal verbatim. Everything green above is
  reproducible on this machine and assumes nothing about an operations server.
