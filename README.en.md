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

- macOS 13+ (Apple Silicon or Intel) for development, or Ubuntu 22.04 LTS for production.
- Python 3.11 and the wheels in `gateway/requirements.txt` to serve traffic. There is no
  reduced server for a machine without them: `create_app()` raises `RuntimeError: FastAPI is
  not installed; run ./start_macos.sh or ./install_ubuntu22.sh first`, with the `ImportError`
  text appended (`gateway/app/main.py:3092`). What a standard-library-only machine *can* do is
  run 12 of the 14 self-test groups, because the runner names the two that import those wheels
  as `SKIPPED` — that is what the **2286 checks across 12 groups** figure below is, and it is
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
same assertion as the two shell launchers (`every_launcher_probes_a_route_that_exists` turns
red when a route it names does not exist), but there is no Docker on this development
machine, so **compose has never been executed here** — `--check-routes` proves the URL in
the file exists, not that the two containers come up.

## Quick start — Ubuntu 22.04 (production)

```bash
git clone https://github.com/popopx-chat/popopx-service-suite
cd popopx-service-suite
sudo ./install_ubuntu22.sh                # default --mode docker: gateway (+ node) as containers
sudo ./install_ubuntu22.sh --mode native  # venv + systemd unit, no containers
./install_ubuntu22.sh --help              # --with-node / --port / --skip-apt
```

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

curl -s $API/healthz | python3 -m json.tool     # public: node_connected, uptime, version

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
curl -s -X POST $API/api/v1/channels/<channel_id>/rotate -H "X-Admin-Token: $TOKEN"

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
The full suite is the pre-release entry point, and both launchers print the command as their
last step.

The authoritative count is the last line that command prints. On this machine on 2026-11-21
only the standard library was available (no `cryptography`, no `fastapi`), and the measured
result was **2286 checks across 12 groups**: `app.crypto_service.crypto_self_test` (needs
`cryptography`) and `app.main.http_self_test` (needs `fastapi`) were named as `SKIPPED` by the
runner, which prints "those paths are NOT verified here" — those two groups ran zero checks
here, which is not the same as having run and not been counted. Re-running on the same machine
inside a venv that has `gateway/requirements.txt` installed measured **2320 checks across 14
groups**, and the difference is exactly those two groups: the runner prints
`crypto_self_test 6 checks` and `http_self_test 28 checks` per group, and the 14 group figures
sum to the total line (2286 + 6 + 28 = 2320), so you can audit your own run the same way. One
caveat: this machine has no 3.11, so both measurements ran on 3.9.6, not on the
`requirements.txt` target interpreter.

Assertions cover the protocol layer, database, configuration, billing, cryptography, the node
bridge, the five plugins, cross-implementation cryptography, and the HTTP group
`app.main.http_self_test` — that last one issues real requests against the ASGI app, so it can
tell a mounted route from a route that merely exists in source.

```bash
# Still from the repository root (cd .. if the block above left you in gateway/)
python3.11 -m venv .venv                      # 3.11 is the suite's target interpreter
.venv/bin/pip install -r gateway/requirements.txt
cd gateway && ../.venv/bin/python -m app.main --self-test   # 14 groups green, no SKIPPED (2320 here)
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
- Not done here: an end-to-end send/receive with a real iOS client (needs a reachable broker),
  and the shape of the successful `userContactLinkCreated` frame — only failure frames were
  available, so `show_contact_address()` treats exactly one case, `userContactLinkNotFound`, as
  "no address yet" and re-raises every other refusal verbatim. Everything green above is
  reproducible on this machine and assumes nothing about an operations server.
