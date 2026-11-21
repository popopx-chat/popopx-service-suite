# popopx-service-suite
<!--
  Copyright (c) 2026 POPOPX (popopx.chat)
  SPDX-License-Identifier: AGPL-3.0-only
-->

中文 · English：[`README.en.md`](README.en.md)

POPOPX 服务号的后端套件：网关（FastAPI）、计费（POPX-CP）、频道信封加密、五个业务插件，
以及一个浏览器管理后台。协议与随包的 POPOPX iOS 客户端逐字节对齐；开源节点只通过
`ws://127.0.0.1:5225` 连接，本套件不链接、不修改、也不重新分发它的任何代码。

## 协议与商标

代码以 **AGPL-3.0-only** 授权，全文见 [`LICENSE`](LICENSE)，与 `popopx-chat` 主仓库同源同协议；
每个源文件顶部的 `Copyright` + `SPDX-License-Identifier: AGPL-3.0-only` 两行就是这份许可的入口。
你可以自由使用、修改、再分发；AGPL-3.0 第 13 条的条件是：改了这个套件又通过网络给别人用，
修改版源码要一并提供。

**商标不在这份授权里。** `POPOPX` 名称、标识与 `popopx.chat` 域名归 POPOPX 所有——分发修改版请
改名，不要以 POPOPX 的名义提供部署、服务或背书。`official_tools/` 里的示例密钥、`.env.example`
里的示例 token 都是占位值，自托管前换成自己的。

## 目录

```text
popopx-service-suite/
├── LICENSE
├── README.md                本文档（中文）
├── README.en.md             英文版，内容与本文档逐节对应
├── install_ubuntu22.sh      生产安装（Ubuntu 22.04，默认 docker；--mode native 走 systemd）
├── start_macos.sh           开发一键启动（macOS，venv + 本机节点）
├── docker-compose.yml       网关 + 节点两服务
├── .env.example             全部配置项与注释；复制为 .env
├── official_tools/
│   ├── gen_voucher.py       POPX-CP 算力码离线铸造与校验
│   └── swift_crypto_oracle.swift  用 CryptoKit 对照 iOS 端字节（见下）
└── gateway/
    ├── Dockerfile
    ├── requirements.txt     fastapi / uvicorn / pydantic / cryptography / httpx / qrcode / websockets
    └── app/                 config database billing_service crypto_service agent_bridge main
        ├── plugins/         ai_agent alert_ops privacy_sso polls web3_bridge
        └── static/          index.html 管理后台
```

## 环境要求

- 开发：macOS 13+（Apple Silicon 或 Intel）；生产：Ubuntu 22.04 LTS。
- 起服务要 Python 3.11 加 `gateway/requirements.txt` 里的 wheel。没装这些 wheel 的机器上并
  没有「降级 HTTP 路径」这回事：`create_app()` 直接抛 `RuntimeError: FastAPI is not installed;
  run ./start_macos.sh or ./install_ubuntu22.sh first`（后面拼 `ImportError` 原文，见
  `gateway/app/main.py:3092`）。这种机器能做的是跑 14 组自检里的 12 组——运行器会把依赖那两个
  wheel 的组点名 `SKIPPED`。下面「自检」里的 **2286 条 / 12 组** 就是这么来的，它不是一台正在
  应答的网关。
- 需要一个正在运行的 `popopx-agent` / `popopx-chat` 节点，它的 WebSocket 控制口在
  `127.0.0.1:5225`。没有节点也能起服务，见下面「启动行为与插件开关」。

## 快速开始 — macOS（开发、iPhone 调试）

```bash
cp .env.example .env         # 至少改掉 POPOPX_ADMIN_TOKEN
./start_macos.sh             # 网关 http://127.0.0.1:8080/ ，节点 127.0.0.1:5225
./start_macos.sh --check     # 只做预检并报告，不启动任何进程
```

`start_macos.sh` 默认走 venv，`--docker` 才走 compose。venv 路径要求解释器就是
Python 3.11：找不到会打印 `brew install python@3.11` 并退出 3（装在别处就
`POPOPX_PYTHON=/path/to/python3.11 ./start_macos.sh`）。虚拟环境建在仓库根的 `.venv`，
只有它不存在、或 `gateway/requirements.txt` 比 `.venv/.deps-ok` 新时才装依赖——venv 已就绪时
每次启动省掉约 20 秒的网络往返。`.env` 里缺 `POPOPX_ADMIN_TOKEN` 时现生成一个 64 字符的
（`openssl rand -hex 32`）写回文件、值不打印。`--docker` 需要 docker 在 PATH 且守护进程在跑，
脚本还会警告：容器问不到这台 Mac 上的节点。

启动后终端会打印控制台地址、手机侧 H5 来源，以及 token 所在的文件位置——值本身默认不打印，
要读出来用 `./start_macos.sh --show-token`。默认走 venv 而不是 Docker：节点的 WebSocket API
只绑 127.0.0.1，而 Docker Desktop 里容器的 "host" 是
linuxvm 的回环，不是这台 Mac 的回环——`network_mode: host` 是 Linux 才有的内核能力。
`docker-compose.yml` 是给 Linux 生产机的起点：它和两个 shell 启动脚本被同一条断言审着
（`every_launcher_probes_a_route_that_exists`，路由不存在就红），但这台开发机上没有 docker，
**它本身从未被执行过**——`--check-routes` 证的是文件里那条 URL 存在，不是两个容器起得来。

## 快速开始 — Ubuntu 22.04（生产）

```bash
git clone https://github.com/popopx-chat/popopx-service-suite
cd popopx-service-suite
sudo ./install_ubuntu22.sh                # 默认 --mode docker：网关（+节点）跑容器
sudo ./install_ubuntu22.sh --mode native  # venv + systemd 单元，不用容器
./install_ubuntu22.sh --help              # --with-node / --port / --skip-apt
```

仓库克隆在哪儿都行——`/opt/popopx-service-suite/src` 是安装脚本自己复制出来的，不是你的工作副本：
docker 模式只复制 compose 文件、`gateway/`、`official_tools/` 和 `LICENSE`，native 模式复制整个
仓库并去掉 `.git`，上一份留成 `src.prev`。它只要 root、`curl`、`systemctl`、`python3`，
以及（没加 `--skip-apt` 时）apt。两种模式都会写一份
每主机独立的 env 文件，里面三个值——`POPOPX_ADMIN_TOKEN`、`POPOPX_ALERT_WEBHOOK_TOKEN`、
`POPOPX_GATEWAY_PORT`——0600 权限、值不显示。文件已存在时脚本保留它（改前副本存成
`.env.bak.<utc>`），并且**不让 `--port` 覆盖文件里已有的值**，因为网关只从这份文件读它监听的
端口。两种模式真正需要在运维上分清的是文件位置：docker 模式在 `src/.env` 交给 compose 读，
native 模式在 `/etc/popopx-service-suite/env`，也就是 unit 的 `EnvironmentFile=`。

`--mode native` 才是大家熟悉的那套自托管布局：建 nologin 系统用户 `popopx`（家目录
`/var/lib/popopx-service-suite`，与 `/etc/popopx-service-suite` 一起 0750、属主 `popopx`），
装 `python3.11` 与 venv 模块，在 `/opt/popopx-service-suite/venv` 建虚拟环境，装
`src/gateway/requirements.txt` 并把解析出来的版本用 `pip freeze` 钉成
`/opt/popopx-service-suite/requirements.lock`，最后装 `/etc/systemd/system/popopx-gateway.service`。
`--with-node` 再加一个 nologin 用户 `popopx-node` 和 `popopx-node.service`（它自己的
`EnvironmentFile=/etc/default/popopx-node`）。docker 模式不建 `popopx` 用户，而是把
`/var/lib/popopx-service-suite` chown 给镜像里的 uid 1001——换成谁运行谁拥有的 bind mount，
容器第一次写账本就会 `SQLITE_CANTOPEN`，看起来像数据库坏了。

两种模式的最后一步都打印两条验证命令（`--self-test`、`--check-routes`）和一段刻意不代你做完的
NEXT STEPS：把 `POPOPX_PUBLIC_BASE_URL` 设成手机真正加载的那个 https origin（`PopopxH5Launcher`
签的就是它）；只有开了准入模式才需要给网关官方算力码公钥；节点的 WebSocket 口没有鉴权、只绑
回环，不要把 5225 代理到网络上；只放行网关端口，且要等 TLS 就位；最后备份
`/var/lib/popopx-service-suite`——`gateway.db` 里除了账本和每个 pairwise 会话密钥，还存着频道
身份私钥，这是有意的：轮换必须和它投递的那一帧在同一个事务里提交。这个目录丢了，现有全部
零知识频道就永久哑掉。

## 启动行为与插件开关

节点在启动那一刻没起来不是致命错误：网关照常开始服务，`/healthz` 报
`node_connected: false`，桥接层按封顶的退避一直重试，节点起来后自己接上（`strict=True`
留给需要 fail-fast 的调用方）。五个插件里只有 `web3_bridge` 默认关闭，需要
`POPOPX_PLUGIN_WEB3_BRIDGE=1`；其余四个跟着 `POPOPX_PLUGIN_*` 打开。每个插件在自己的
挂载前缀下答 `GET <prefix>/status`，控制台五个面板读的就是这一条。

## 使用示例

下面的字段名就是 handler 实际读的字段（`/api/v1/` 全部要带令牌）：

```bash
TOKEN=$(grep '^POPOPX_ADMIN_TOKEN=' .env | cut -d= -f2-)
API=http://127.0.0.1:8080

curl -s $API/healthz | python3 -m json.tool     # 公开：node_connected、uptime、version

# 1. 兑算力码：入账后 account 会随响应一起回来
curl -s -X POST $API/api/v1/vouchers/redeem -H "X-Admin-Token: $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"code":"POPX-CP-...","redeemed_by":"operator-a"}'

# 2. 下发底部菜单：空 body 推全部粉丝，带 contact_ids 推指定粉丝
curl -s -X POST $API/api/v1/menu/push -H "X-Admin-Token: $TOKEN" \
     -H 'content-type: application/json' -d '{}'
curl -s -X POST $API/api/v1/menu/push -H "X-Admin-Token: $TOKEN" \
     -H 'content-type: application/json' -d '{"contact_ids":[3,7]}'

# 3. 给单个粉丝发一条不计费的纯文本（插件熔断了、但仍要告知真人时的后门）
curl -s -X POST $API/api/v1/send/text -H "X-Admin-Token: $TOKEN" \
     -H 'content-type: application/json' -d '{"contact_id":3,"text":"02:00 UTC 维护"}'

# 4. 轮换付费频道密钥：epoch 自增，信封用频道 Ed25519 私钥签名
curl -s -X POST $API/api/v1/channels/<channel_id>/rotate -H "X-Admin-Token: $TOKEN"

# 5. 插件状态（控制台五个面板读的就是这一条）
curl -s $API/api/v1/plugins -H "X-Admin-Token: $TOKEN"
curl -s $API/api/v1/plugins/alert_ops/status -H "X-Admin-Token: $TOKEN"
```

空 body 一律按 `{}` 处理（`json_body`），所以轮换那条可以不发 body；它的开关是
`expires_at_ms`、`revoke_previous`（默认 true）、`notify_members`（默认 true），
按**每位成员**计 `key_rotation`——先在小组上排练，别拿 4000 人的频道试手。发送类调用只有在节点
接受命令之后才报 `queued`；节点拒了是 502 `node_refused` 并在 `node_error` 里带节点自己给的原因；
粉丝不存在是 400 `unknown_contact`，本地先查完，根本不会去问节点。

## 接口一览

91 条路由。本文件声明的 52 条由 `python3 -m app.main --print-routes` 打印，同一条命令顺手断言
"每条管理路由都被 token 盖住"；五个插件另贡献 39 条（`alert_ops` 10、`web3_bridge` 9、
`polls` 8、`ai_agent` 6、`privacy_sso` 6），它们走 `include_router` 进来，`--print-routes` 看不见，
所以自检里有 `every_plugin_*` 与逐插件的 `plugin_<id>_answers_status_at_its_own_prefix` 补上另一半。

鉴权只有一条规则：`/api/v1/*` 要 `X-Admin-Token`，也收 `?token=`；缺失或不对一律
`401 {"ok":false,"error":"unauthorized"}`。但请求头名并不统一：核心 `admin_required` 与插件
中间件 `plugin_auth` 都只读 `x-admin-token` 或 `?token=`（`gateway/app/main.py:3170`、`:3254`），
不解析 `Authorization: Bearer`——全套件只有 `privacy_sso` 的设备侧路由读它
（`privacy_sso_plugin.py:1521` `bearer_secret`），`alert_ops` 的控制台路由读
`X-Popopx-Admin-Token`（`alert_ops_plugin.py:1105`）。管理后台三个头一起发
（`gateway/app/static/index.html:585`–`:587`），一个令牌不用按路由切换。四类例外：
`/`、`/healthz`、`/h5/{article_id}` 公开；
`POST /api/v1/verifyH5Auth` 靠手机侧的 HMAC 签名证明调用者；插件路径以 `/webhook`、`/verify`、
`/callback` 结尾的不问 token（它们各自有 per-source token 或背靠背调用方）；
`GET /api/v1/plugins/sso/sessions/{id}` 也免 token——扫码页要能在拿到登录态之前轮询它。

出错一律 `{"ok": false, "error": "<code>", "detail": "…"}`，HTTP 码按运营动作分：

| 情况 | 码 | 例子 |
| --- | --- | --- |
| 参数不对、对象不存在 | 400 / 404 | `unknown_contact`、`contact_ids_required` / `card_not_found` |
| token 缺失或不对 | 401 | `unauthorized` |
| 状态不对，重试也没用 | 409 | `voucher_used`、`account_draft`、`no_session` |
| 余额不足或账户已熔断 | 402 | `insufficient_credits`、`account_suspended` |
| 节点还活着、但拒了这条命令 | 502 | `node_refused`，另带 `node_error`＝节点自己给的原因名 |
| 节点链路本身断了 | 503 | `node_unreachable` |

最后两行是给运维的分别是：`node_refused` 说明链路是通的、这条命令被拒（拼错、`userExists`、
broker 超时……`node_error` 里就是原因），只有 `node_unreachable` 才该去查进程和网络。
`POST /api/v1/node/accept` 是唯一的例外——它同时被入站处理器当内部函数调用，所以失败仍回 200，
靠 body 里的 `error` 区分。

## 配置

全部配置项在根目录的 [`.env.example`](.env.example)（48 个键，每个都有注释；用
`grep -cE '^[A-Z0-9_]+=' .env.example` 能数出同一个数），
`cp .env.example .env` 之后改它。查找顺序是 `--env <path>` → `$POPOPX_ENV_FILE` →
仓库根目录的 `.env`；进程环境覆盖文件里的同名键（编排器说的算）。

`load_config()` 拒绝启动的条件都会打成一句人话而不是 traceback：`POPOPX_ADMIN_TOKEN` 缺失、
短于 24 字符或还是示例值（`openssl rand -hex 32`）；`POPOPX_PUBLIC_BASE_URL` 缺失——客户端
`PopopxH5Launcher` 签的就是这个 URL，留空等于签一个手机验不过的签名；
`POPOPX_OFFICIAL_ED25519_PUBLIC_KEY` 解不出 32 字节（base64 44 字符或 hex 64 字符）；
以及任何 `KEY=value` 写坏的行、越界的数值、非布尔的开关。未识别的 `POPOPX_*` 键被忽略、不报错。

## 自检

每个模块都自带 `self_test()`，共 14 组，用下面这条命令一次性跑完：

```bash
# 两个代码块都从仓库根目录起跑
cd gateway && python3 -m app.main --self-test
```

启动路径上不跑这套件——`create_app()` 只跑路由门禁 `assert_routes_are_gated()`（一个没被
token 盖住的_admin 路由就不该开始监听），完整套件是开发/发布前的入口，两条命令都在
`start_macos.sh` 与 `install_ubuntu22.sh` 的最后一步打印出来供复制。

权威计数是这条命令自己打出来的最后一行。本机 2026-11-21 只有标准库（`cryptography` 和 `fastapi`
都没装），实测是 **2286 条 / 12 组**：`app.crypto_service.crypto_self_test`（缺 `cryptography`）和
`app.main.http_self_test`（缺 `fastapi`）两组被运行器点名 `SKIPPED`，并打印 "those paths are NOT
verified here"——这两组在本机一条都没跑过，不是"跑过了没记上"。同一台机器上换一个装了
`gateway/requirements.txt` 的 venv 再跑，实测 **2320 条 / 14 组**，多出来的正是那两组：运行器逐组打印
`crypto_self_test 6 checks` 与 `http_self_test 28 checks`，14 组之和恰好等于总行
（2286 + 6 + 28 = 2320），所以你机器上那一行也能这样拆开对账。一个限定：本机可用的解释器只有 3.9.6，
两次实测都跑在 3.9.6 上，不是 `requirements.txt` 指定的 3.11。

断言分布在：协议层、数据库、配置、计费、密码学、节点桥、五个插件、跨实现密码学、以及 HTTP 组
`app.main.http_self_test`——最后一组真的向 ASGI 应用发请求，所以它能证明一个路由是被装上了还是只是写在源码里。

```bash
# 同样从仓库根目录（跑过上一块就先 cd ..）
python3.11 -m venv .venv                      # 3.11 是这套件的目标解释器，见 requirements.txt 头几行
.venv/bin/pip install -r gateway/requirements.txt
cd gateway && ../.venv/bin/python -m app.main --self-test   # 14 组全绿、无 SKIPPED（本机实测 2320 条）
```

## 跨实现密码学校验

`crypto_self_test()` 是同语言往返，它能证明本模块自洽，证不了手机读得懂这些字节。
另一半在 `official_tools/swift_crypto_oracle.swift`：它用 CryptoKit——客户端
`ChannelKeyRotationManager.swift` 用的同一套系统框架——按对端的 fixture 收信并回信。
不需要 SPM、不需要联网：

```bash
swiftc -O -o /tmp/oracle official_tools/swift_crypto_oracle.swift
/tmp/oracle selfcheck
cd gateway && python3 -m app.crypto_service emit /tmp/py.json && cd ..
/tmp/oracle verify /tmp/py.json                        # Python 封装，CryptoKit 打开
/tmp/oracle seal --out /tmp/sw.json
(cd gateway && python3 -m app.crypto_service open /tmp/sw.json)   # 反方向
/tmp/oracle verify /tmp/py.json --tamper aad                      # 三种伪造都必须被拒
```

`--tamper aad` 是唯一签名有效的那条伪造，只有它会检验 AAD 是否真的在干活。fixture 里的
密钥每次现生成，信封私钥不落盘。

## 算力码

```bash
cd gateway && python3 ../official_tools/gen_voucher.py --help
```

默认 `POPOPX_BILLING_REQUIRE_VOUCHER=0`：账户一建行就是 `ONLINE`，五个插件开箱可用，
不需要向任何一方兑换激活码；计量照记、流水照平、控制台照看，所以配额数据是真的。
把它设成 `1` 才回到准入模式：账户起始 `DRAFT`，未兑换的计量动作一律 409 `account_draft`，
此时 `POPOPX_OFFICIAL_ED25519_PUBLIC_KEY` 变成启动必需项。私钥只在铸造机上，
网关只用公钥离线验签，因此它无法造码。余额耗尽时插件会被熔断（`GateDecision`），
这条判定与控制台里读到的结果是同一份代码。

## 边界

- 静默拦截前缀 `::CB::`、`::popopx_sys::`、`::REF::`、`::SSO_SCAN::` 与 ECO 信封
  `::POPOPX_ECO::<compact JSON>` 的拼写以客户端源码为准，改动这些字节等于改协议。
- `POST /api/v1/verifyH5Auth` 是 HMAC-SHA256、±300 秒时间窗。
- 已经真跑过的：`uvicorn` 起进程、真实 `websockets` 握手与断线重连、离线铸码 → HTTP 兑换 →
  `DRAFT→ONLINE`、余额耗尽时的 402 熔断、节点缺席时 `node_unreachable` 503、扫码登录的免 token
  轮询与写操作仍需 token。节点这一侧不是替身：命令是对本机起的一个真实 `popopx-chat` 节点
  （7.1.2.0）发的，`/users`、`/_create user`、`/_contacts`、`/_profile`、`/_accept`、`/_send`、
  `/_address` 全部被它接受并执行，`/healthz` 报 `node_connected: true`。其中 `/_address` 一路走到
  SMP broker 才失败，`detail` 里带的是节点原话 `errorAgent / BROKER / NETWORK / timeoutError`——
  这台沙箱机没有 SMP 出网，语法与接线不是嫌疑。
- 还没做的：拿真实 iOS 客户端跑端到端收发（要一个能连上的 broker），以及
  `userContactLinkCreated` 成功帧的形状——手上只有失败帧，所以 `show_contact_address()` 只按
  `userContactLinkNotFound` 这一条判"还没有地址"，其他拒绝照原样抛出。上面所有绿色都是本机可复现
  的断言，不包含对运营服务器的任何假设。
