# popopx-service-suite
<!--
  Copyright (c) 2026 POPOPX (popopx.chat)
  SPDX-License-Identifier: AGPL-3.0-only
-->

中文 · English：[`README.en.md`](README.en.md)

POPOPX 服务号的后端套件：网关（FastAPI）、计费（POPX-CP）、频道信封加密、九个业务插件，
以及一个浏览器管理后台。协议与随包的 POPOPX iOS 客户端逐字节对齐；开源节点只通过
`ws://127.0.0.1:5225` 连接，本套件不链接、不修改、也不重新分发它的任何代码。

其中四个连接器面向自建办公栈：`workflow_webhook` 把事件以 HMAC-SHA256 签名推给
Node-RED / Activepieces，并把入站动作强制转成人工确认卡片；`carddav_connector` 与
`caldav_connector` 只按关键词/时间窗现场查询，返回前剥离私密联系字段与会议标题；
`slack_discord` 把一个工作区的入站 webhook 作为独立的出站通道，逐工作区保存密钥并按次计费。

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
├── install_macos.sh         生产安装（macOS，launchd 原生，没有 docker 模式）
├── start_macos.sh           开发一键启动（macOS，venv + 本机节点）
├── docker-compose.yml       网关 + 节点两服务
├── .env.example             全部配置项与注释；复制为 .env
├── official_tools/
│   ├── gen_voucher.py       POPX-CP 算力码离线铸造与校验
│   └── swift_crypto_oracle.swift  用 CryptoKit 对照 iOS 端字节（见下）
└── gateway/
    ├── Dockerfile
    ├── requirements.txt     fastapi / uvicorn / pydantic / cryptography / httpx / qrcode / websockets
    ├── requirements-dev.txt 同一批运行时依赖 + pytest（测试适配器用，生产启动器不读）
    ├── tests/               pytest 适配器：调用各模块 self_test()，不复制断言
    └── app/                 config database admin_auth vault billing_service crypto_service agent_bridge main
        ├── plugins/         ai_agent alert_ops privacy_sso polls web3_bridge
        │                    workflow_webhook carddav_connector caldav_connector slack_discord
        └── static/          index.html 管理后台
```

## 环境要求

- 开发：macOS 13+（Apple Silicon 或 Intel）；生产：Ubuntu 22.04 LTS，或 macOS 13+ 的 launchd
  原生路径（`install_macos.sh`）。
- 起服务要 Python 3.11 加 `gateway/requirements.txt` 里的 wheel。没装这些 wheel 的机器上并
  没有「降级 HTTP 路径」这回事：`create_app()` 直接抛 `RuntimeError: FastAPI is not installed;
  run ./start_macos.sh, ./install_macos.sh or ./install_ubuntu22.sh first`（后面拼 `ImportError` 原文，见
  `gateway/app/main.py:3385`）。这种机器能做的是跑 22 组自检里的 19 组——运行器会把依赖那两个
  wheel 的组点名 `SKIPPED`。下面「自检」里的 **2637 条 / 19 组** 就是这么来的，它不是一台正在
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
`docker-compose.yml` 是给 Linux 生产机的起点：它和三个 shell 启动脚本被同一条断言审着
（`every_launcher_probes_a_route_that_exists`，路由不存在就红；另一条
`every_shell_launcher_runs_the_module_entrypoint` 数的是三个脚本里的 `python -m app.main`，
compose 起的是容器、它的 CMD 不归脚本文本管，所以那条断言数到 3 而不是 4），但这台开发机上没有 docker，
**它本身从未被执行过**——`--check-routes` 证的是文件里那条 URL 存在，不是两个容器起得来。

## 快速开始 — macOS（生产）

```bash
sudo ./install_macos.sh                 # launchd 原生；默认只绑 127.0.0.1
sudo ./install_macos.sh --lan           # 明确改绑 0.0.0.0，暴露面见下面第三条
sudo ./install_macos.sh --with-node     # 再加一个节点 LaunchDaemon（_popopx-node）
./install_macos.sh --check              # 只读预检：零写入，不需要 root
./install_macos.sh --dry-run            # 把 plist 与 env 生成到临时目录并 plutil -lint
sudo ./install_macos.sh --uninstall     # 服务、账号、代码、配置都删；状态目录默认保留
```

`--with-node` 在 macOS 上现在会：探测架构（arm64/x86_64），从 `popopx-chat/popopx-chat` 官方 GitHub Releases
动态下载对应的 `popopx-chat-macos-{aarch64,x86-64}` 二进制，SHA2-256 校验（digest 来自 release 的 `.digest` 字段
或 body 里的 `SHA2-256(<name>)= <hex>` 行，两者一致），0755 装到 `/usr/local/bin/popopx-chat`，写 `.provenance`
记录 release tag/asset/digest/size/source。然后生成安全包装脚本 `/usr/local/bin/popopx-node`（0750 root:wheel，
`#!/bin/sh` + `set -eu` + `umask 077`，从 `${CONF_DIR}/node.conf` 读配置，条件式传 `--server`/`--xftp-server`/
`--user-display-name`——仅当对应环境变量非空时才传，否则继承二进制内置的 `smp1..8.popopx.im` 双栈集群预设）。
`node.conf` 里 `NODE_SMP_SERVERS`/`NODE_XFTP_SERVERS` 默认留空，注释里记录官方集群地址作为可选覆写钩子。
启动顺序改成节点先于网关：`install_node_unit` → `wait_for_node_ready`（40 秒上限，超时只 warn 不 die）→
`install_plist gateway` → `bootstrap_job gateway`，这样网关的第一次 `/healthz` 探测能看到活节点。

新增的 flag：`--node-version TAG`（钉死 release tag，默认 `latest`）、`--no-node-download`（禁用下载，要求本地
有二进制或传 `--node-bin`）。`--check` 现在会报告目标架构和 asset 名，无本地二进制时做一次非致命的 egress
探测（5 秒超时，失败只 warn，离线仍 exit 0）。`--dry-run` 会把 node.conf、包装脚本、节点 plist 都渲染到临时
目录并 lint（`sh -n` + `plutil -lint`），不实际下载。

这条路径与 Ubuntu 的 `--mode native` 对等：专用服务账号、代码/配置/状态/日志全部离开工作副本、
开机自起、崩溃自拉、可重装可卸载。布局用 macOS 自己的惯例——代码在
`/usr/local/popopx-service-suite/{src,venv,requirements.lock}`，配置在
`/usr/local/etc/popopx-service-suite/env`，状态在 `/usr/local/var/popopx-service-suite`，日志在
`/usr/local/var/log/popopx-service-suite/`。服务账号是 `sysadminctl -roleAccount` 建的 `_popopx`
（UID/GID 450，shell `/usr/bin/false`）。`-home` 传了但**不生效**：role 账号的 `NFSHomeDirectory`
被系统固定成 `/var/empty`，实测 `dscl . -read /Users/_popopx NFSHomeDirectory` 就是这个值，所以
状态目录的 `_popopx:0750` 是脚本自己 chown 出来的，卸载也因此只走 `-keepHome`——记录既然指向系统
目录，任何会删家目录的 flag 都不能碰。`--with-node` 再加 `_popopx-node`
（451）。安装顺序按"中途被打断最安全"排：账号 → 代码 → 目录 → venv → env → 配置门 → plist →
`launchctl bootstrap`，所以一个没 bootstrap 成功的 plist 不会动到你的旧部署，状态目录任何路径都不删。

有三处**刻意不与 Ubuntu 一致**，脚本会把它们打印出来：

1. 没有 `--mode docker`。理由和 `start_macos.sh:10-15`、`docker-compose.yml:19-20` 是同一条：容器问不到
   这台 Mac 的 127.0.0.1。写一个已知起不来的模式就是做一个说谎的安装器。
2. 默认绑 `127.0.0.1`，不是 Ubuntu 那边的 `0.0.0.0`。这台机器上应用防火墙默认关、没有反代，而网关
   无条件信任 `X-Forwarded-*`（uvicorn 以 `forwarded_allow_ips='*'` 运行），默认 `0.0.0.0` 等于"装完即
   整局域网可打"。要局域网可达必须显式 `--lan`，脚本同时会打印"要么配反代并只让反代改这些头，要么别用
   `--lan`"。防火墙任何一条规则都不代你加。
3. `src` 装成 `root:wheel 0755`，**故意不 chown 给服务账号**（与 `install_ubuntu22.sh:309` 分歧）：
   守护进程不该能改自己的代码。代价是日志也得自己看——launchd 按 `Umask 077` 建
   `gateway.err.log`/`gateway.out.log`，属主 `_popopx`、0600，读它要 sudo，和 Ubuntu 上读 journal 同姿态。

systemd 到 launchd 是一一对应翻译，不是照抄：`User=`→`UserName`/`GroupName`（只在 system 域生效，所以
必须 LaunchDaemon）、`WorkingDirectory=`→ 同名键（它是 `-m app.main` 能 import 的唯一机制，不再另设
`PYTHONPATH`）、`EnvironmentFile=`→ `EnvironmentVariables` 里**只放一个** `POPOPX_ENV_FILE`（进程环境压过
文件值，端口/host 进 plist 就是第二个真相源）、`Restart=on-failure`→`KeepAlive{SuccessfulExit=false,
Crashed=true}`、`RestartSec=3`→`ThrottleInterval=3`（那是最短间隔的地板，不是延迟）、`TimeoutStopSec=15`→
`ExitTimeOut=15`。launchd **没有** `StartLimitBurst` 对等物、永不放弃重试，所以这套件在 `bootstrap` 之前先
跑一次网关自己的配置门（`load_config()`），把会拒启动的配置挡在崩溃循环之外，并打印 `cfg.warnings`——
那些 warning 平时只有 `GET /api/v1/diagnostics` 才返回。

本机离线实测到的：`--help`、`--check`、`--dry-run`（含 `--with-node`）全部退出 0，两个 plist
`plutil -lint` 通过，dry-run 里"已存在的 env 逐字节不变、只多一个 `.bak.<utc>`"这条由 cksum 现场
证明；`brew` 装的 Python 3.11.18 过了版本门，用它按 `gateway/requirements.txt` 实装依赖建一个 venv，
`--self-test` 实测 **2776 条 / 22 组、exit 0**（这一跑顺手揪出一个只在新版 starlette 上失明的 HTTP
量具，见「自检」）。

带 sudo 的真装真起 **2026-11-22 在这台 Mac 上跑过了**：`/Library/LaunchDaemons/com.popopx.gateway.plist`
落盘（root:wheel 0644）、`_popopx` 建出来（UID 450、shell `/usr/bin/false`）、
`/usr/local/etc/popopx-service-suite/env` 是 `_popopx` 的 0600、状态与日志目录 0750，
`curl http://127.0.0.1:8080/healthz` 回 `{"ok":true,"node_connected":false,"service_id":"popopx.official"}`
——没有节点就是降级启动，正是文档承诺的那条路径。这次真装还抓出一个离线跑不出来的崩溃：5225 上如果
有东西应答但不是 HTTP，`websockets` 抛 `InvalidMessage`，它是 `WebSocketException` 的子类、**不是**
`OSError`，于是穿过 `AgentBridge.start()` 的 except 把整个网关带下去。修完之后
同一场景下 `start()` 只记一条 warning、`node_connected` 保持 false、supervisor 后台退避重连；
`strict=True` 的 fail-fast 仍然抛，这条也现场验过。

重装时还会撞到 launchd 自己的时序：`bootout` 是异步的，命令返回那一刻标签未必已经释放，紧跟其后的
`bootstrap` 于是回 `Bootstrap failed: 5: Input/output error`——读起来像 plist 坏了，盘上那个文件其实没问题。
`bootstrap_job` 现在在两条命令之间轮询 `launchctl print`，直到任务查不到为止，上限 5 秒；到点还没消失就
照样 bootstrap 并明说"这是 launchd 还占着标签"，既不静默死等、也不假装成功。自检里
`the_macos_installer_waits_for_bootout_before_bootstrapping` 钉住这段顺序，量具用三种破坏做过对照（删掉等待行、
把等待挪到 bootstrap 之后、去掉上限），三种都判失败。

还没实测到的：`kill -9` 之后 KeepAlive 是否真把进程拉回来、卸载之后 `_popopx` 与 `/usr/local/*`
是否真没有了。上面那条 bootout 等待也一样——证据是合成 `launchctl`（异步拆解按 3 次轮询建模，加上
到上限那一路），真机 launchd 的这个窗口不能按需重现，所以"真装时不再报 5"要等你下一次重装才算验过。节点单元同样只到"生成并 lint"——本仓在 Mac 上起过的是 `start_macos.sh` 那个开发节点，
以 `_popopx-node` 身份、自己的数据库前缀跑起来的节点还没起过。`--with-node` 的真实下载路径（从 GitHub
Releases 拉二进制、SHA2-256 校验、写 `.provenance`）和本机沙箱没有 SMP 出站访问，所以"下载的二进制真能
起、起完真连上 `smp1..8.popopx.im` 集群"这条也还没验过——`--check`/`--dry-run` 的 egress 探测是非致命的，
离线仍 exit 0。

## 快速开始 — Ubuntu 22.04（生产）

```bash
git clone https://github.com/popopx-chat/popopx-service-suite
cd popopx-service-suite
sudo ./install_ubuntu22.sh                # 默认 --mode docker：网关（+节点）跑容器
sudo ./install_ubuntu22.sh --mode native  # venv + systemd 单元，不用容器
./install_ubuntu22.sh --help              # --with-node / --port / --skip-apt
```

`--with-node` 在 native 模式下现在会：探测架构（x86_64/aarch64），从 `popopx-chat/popopx-chat` 官方 GitHub
Releases 动态下载对应的 `popopx-chat-ubuntu-22_04-{x86_64,aarch64}` 二进制，SHA2-256 校验（优先用 `sha256sum`，
fallback 到 `shasum -a 256` 或 `openssl`），0755 装到 `/usr/local/bin/popopx-chat`，写 `.provenance`。然后生成安全
包装脚本 `/usr/local/bin/popopx-node`（0755 root:root，`#!/bin/sh` + `set -eu` + `umask 077`，从
`/etc/default/popopx-node` 读配置，条件式传 `--server`/`--xftp-server`/`--user-display-name`）。
`/etc/default/popopx-node` 里 `NODE_SMP_SERVERS`/`NODE_XFTP_SERVERS` 默认留空，注释里记录官方 `smp1..8.popopx.im`
双栈集群地址作为可选覆写钩子。systemd unit 的 `ExecStart` 改成 `/usr/local/bin/popopx-node`（包装脚本），不再内联
`$NODE_PORT`/`$NODE_DB_PREFIX`。启动顺序改成节点先于网关：`systemctl restart popopx-node` → `wait_for_node_ready`
（40 秒上限，超时只 warn）→ `systemctl restart popopx-gateway`。

新增的 flag：`--node-port N`（节点 WebSocket 端口，默认 5225）、`--node-bin PATH`（跳过下载）、`--node-version TAG`
（钉死 release tag）、`--no-node-download`（禁用下载）。docker 模式的 `--with-node` 仍然用容器镜像，不触发下载。

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
留给需要 fail-fast 的调用方）。`ai_agent`、`alert_ops`、`privacy_sso`、`polls` 默认开启；
`web3_bridge` 与四个连接器（`workflow_webhook`、`carddav_connector`、`caldav_connector`、
`slack_discord`）默认关闭，各自跟着自己的 `POPOPX_PLUGIN_*` 打开。四个连接器还要求先在
控制台配置好订阅/签名密钥、DAV 端点或 Slack/Discord webhook：未配置时 `/status` 报
`configured: false`、查询返回 `409 not_configured`，不会静默外联。每个插件在自己的挂载前缀下
答 `GET <prefix>/status`，控制台九个面板读的就是这一条。

## 开放工作流与 DAV 连接器

三个连接器都默认关闭，且都要求先配置再使用；控制台的「工作流与 DAV」面板是它们的管理入口。

**`workflow_webhook`（Node-RED / Activepieces）**
- 出站：控制台创建订阅时生成独立签名密钥（只显示一次）；每次投递带
  `X-PPX-Timestamp` 与 `X-PPX-Signature: sha256=<hex>`，签名串是
  `timestamp + "." + body`；只发送订阅勾选的事件 scope。公网目标必须 HTTPS，
  元数据地址（`169.254.169.254` 等）永远拒绝，私网/回环要显式 `allow_private`；
  连续失败按指数退避并在 8 次后熔断 15 分钟。
- 入站：`POST /api/v1/workflows/trigger`，请求头 `X-PPX-Workflow-Token`；令牌有有效期、
  可一键撤销、按 `message.send` / `approval.request` 分 scope。请求里只要带 `action`
  （或 `approval.action`），无论 `kind` 写什么都会强制变成人工确认卡片，审批通过后
  才把动作作为 `approval.decided` 事件发回订阅方。
- 独立网关语义：节点未连接（`node_connected:false`）时，入站触发不会 502。它仍会完成
  令牌鉴权、scope 校验、插件与计费策略评估，再把文本写入本地 `outbox`（审批则写
  `workflow_approvals` 与卡片帧），返回 HTTP 202、`status:"queued_local"`（文本）或
  `status:"pending_approval"`（审批）、`delivery_mode:"standalone_gateway"`、`queued:true`。
  节点在线且已投递时返回 HTTP 200、`delivery_mode:"popopx_node"` 与 `status:"delivered"` /
  `"pending_approval"`；只有既没发送也没排队时才回 502 并退款。独立部署与离线联调因此有
  明确状态，不会把“已排队”误报成“投递失败”。
- 脱敏审计：进出站、订阅/令牌操作都写 `connector_audit`，只有时间、方向、动作、
  来源、scope、状态码、结果与耗时，不存 URL、正文或密钥。

**`carddav_connector`（通讯录）**
- `POST /api/v1/plugins/carddav/query` 只接受关键词，单次最多 5 条；不做整本缓存。
  返回字段受白名单限制（默认 `FN,ORG,TITLE,TEL,EMAIL,CATEGORIES`），`NOTE`、`ADR`、
  `BDAY`、`PHOTO` 等私密字段在解析时剥离，家庭电话/邮箱不因白名单而泄漏。
- `PUT /api/v1/plugins/carddav/config` 保存端点与白名单；`POST .../probe` 做一次
  CardDAV `PROPFIND`。

**`caldav_connector`（日历）**
- `POST /api/v1/plugins/caldav/freebusy` 取时间窗内的忙闲；`SUMMARY`、`DESCRIPTION`、
  `LOCATION`、`ATTENDEE`、`ORGANIZER` 在解析时即丢弃，返回体只有 `busy`/`free` 区间
  与 `可预约` 标签；窗口最多 31 天、slot 15–240 分钟。

**`slack_discord`（Slack / Discord 出站）**
- 七个管理路由：`GET /status`、`GET|POST /workspaces`、
  `PATCH|DELETE /workspaces/{id}`、`POST /send`、`GET /audit`。网关不保存任何消息历史，
  也不学习 Slack/Discord 身份；正文只存在于请求体和那一次出站 POST 里，落盘的只有动作、
  结果和 HTTP 状态码。
- webhook URL 本身就是 bearer 凭据（路径即秘密），所以控制台只看得到主机名；
  设置了 `POPOPX_VAULT_KEY` 时 URL 与逐工作区签名密钥都以 `vault1:` 密文落库。每个
  工作区在创建/轮换时拿到一次独立的 HMAC-SHA256 密钥，投递带
  `X-Popopx-Timestamp` 与 `X-Popopx-Signature: v1=<hex>`，签名串与告警入口同形。
- 出站走 `connectors.request_pinned`：不跟随重定向、不走代理、DNS 解析结果先校验再连接。
  公网目标必须是 HTTPS 且主机属于 Slack/Discord 的 webhook 域；`allow_private` 只给运维
  自己起的回环接收器，局域网地址一律拒绝——否则 webhook bearer token 会明文出网。
- 按 `slack_discord_event` 计费，投递失败自动退款并写审计；离线测试用本地 HTTP 接收器
  验过签名、计费/退款、工作区更新和审计，但**没有连过真实的 Slack 或 Discord**。

## 静态加密、作用域令牌与签名告警

这一节的三项控制都默认不改变既有部署：vault 与告警签名只在设置对应环境变量时启用，
作用域令牌是在根令牌之外新增的第二条凭据路径；根令牌本身不落库、行为不变。

**静态加密（`POPOPX_VAULT_KEY`，`gateway/app/vault.py`）**
- 64 hex 字符或 44 base64 字符的 32 字节操作者密钥（`openssl rand -hex 32`）。设置后，
  `eco_sessions.secret_hex`、`channels.identity_sec_b64url`、`channel_epochs.key_b64url`、
  `workflow_subscriptions.secret`、`dav_endpoints.password` 与
  `slack_discord_workspaces.{webhook_url,secret}` 在写入 SQLite 前用 HKDF-SHA256 派生密钥 +
  ChaCha20-Poly1305 封装，AAD 绑定 `表|列|主体`，行被搬到另一行会解密失败。密文带
  `vault1:` 前缀；不带前缀的值按明文读，所以开启密钥可以不停机。
- `python3 -m app.main --migrate-secrets` 把已有明文逐行封装，幂等、可重复跑；报告按
  `sealed/skipped/errors` 三列打印，有错误就退出 1。**这把密钥是运维自己的**：丢了，
  所有已封装的频道、会话和连接器凭据都不可恢复；它不从 `POPOPX_ADMIN_TOKEN` 派生，
  也不要和数据目录放在同一份备份里。没装 `cryptography` 时启用密钥会在写入/读取处抛
  `VaultUnavailable`，而不是退回明文。

**作用域管理令牌（`gateway/app/admin_auth.py`，四条 `/api/v1/admin/tokens*` 路由）**
- 根令牌仍由 `POPOPX_ADMIN_TOKEN` 提供，不存数据库。新增的 `pxa_…` 令牌只存 SHA-256
  与 16 字符前缀，明文只在 `POST /api/v1/admin/tokens` 的响应里出现一次。
  scope 语法只有三种：`*`、`core:<resource>:ro|rw`、`plugin:<id>:ro|rw`；`core:admin`
  不是可授予的 scope，所以泄露的 scoped 令牌不能再造出更宽的令牌。`ro` 只允许
  `GET`/`HEAD`，其余方法要 `rw`；`expires_in_days` 可选，范围 1–3650。
- `GET /api/v1/admin/tokens` 列元数据（含前缀、scope、创建/最后使用/过期、是否撤销），
  `DELETE /api/v1/admin/tokens/{token_id}` 撤销，`GET /api/v1/admin/tokens/audit?limit=`
  读审计。四条都是 root-only：scoped 令牌访问它们得到 403。
- 插件路径由中间件按 `PLUGIN_SPEC.url_prefix` 映射为 `plugin:<id>`，未知插件前缀只认根
  令牌；核心路由按第一段路径映射为 `core:<resource>`，`/api/v1/admin/*` 只认根令牌。
  缺失/未知/已撤销/已过期一律 401，scope 不够 403；根令牌的请求不写审计，scoped 请求
  写 `used`/`scope_denied`/`revoked` 与状态码，最多保留 5000 行。控制台的「API 令牌」
  面板就是这四条路由的管理界面。

**告警入口签名（`POPOPX_ALERT_WEBHOOK_SECRET`，`alert_ops_plugin.py`）**
- 设置后，`POST /api/v1/plugins/alerts/webhook` 在共享 `POPOPX_ALERT_WEBHOOK_TOKEN`
  之后还要求 `X-Popopx-Timestamp: <unix 秒>` 与
  `X-Popopx-Signature: v1=<hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>`。
  时间戳偏离 ±300 秒拒绝；同一 (timestamp, signature) 在进程内重放缓存里出现过也拒绝。
  HMAC 先验、缓存后写，伪造请求不能靠刷缓存把真签名挤出去；签名比较是常数时间。
- 重放缓存是**进程内**的 2048 条 OrderedDict；多进程/多实例部署要各自接受一次窗口内的
  重放，或在外层反代上做去重。签名是强制项：配置了密钥而请求没签名就是 401，不会静默
  退回“只验共享令牌”。

## 使用示例

下面的字段名就是 handler 实际读的字段（`/api/v1/` 全部要带令牌）：

```bash
TOKEN=$(grep '^POPOPX_ADMIN_TOKEN=' .env | cut -d= -f2-)
API=http://127.0.0.1:8080
CHANNEL_ID=ch_1a2b3c4d                                # 换成 `GET /api/v1/channels` 里的真实 id

curl -s $API/healthz | python3 -m json.tool     # 公开：ok、node_connected、service_id

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
curl -s -X POST "$API/api/v1/channels/$CHANNEL_ID/rotate" -H "X-Admin-Token: $TOKEN"

# 5. 插件状态（控制台九个面板读的就是这一条）
curl -s $API/api/v1/plugins -H "X-Admin-Token: $TOKEN"
curl -s $API/api/v1/plugins/alert_ops/status -H "X-Admin-Token: $TOKEN"

# 6. opaque 邀请链接：服务号名片 / 零知识频道，默认连同 SVG 二维码一起返回
curl -s -X POST $API/api/v1/invite-links -H "X-Admin-Token: $TOKEN" \
     -H 'content-type: application/json' -d '{}'
curl -s -X POST $API/api/v1/invite-links -H "X-Admin-Token: $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"kind":"channel","channel_id":"'"$CHANNEL_ID"'"}'
curl -s "$API/api/v1/invite-links/audit?limit=20" -H "X-Admin-Token: $TOKEN"

# 7. 只读作用域令牌：明文只在响应里出现一次；之后 GET 可用、POST 403
curl -s -X POST $API/api/v1/admin/tokens -H "X-Admin-Token: $TOKEN" \
     -H 'content-type: application/json' \
     -d '{"label":"read-only-status","scopes":["core:status:ro"],"expires_in_days":30}'
curl -s $API/api/v1/status -H "X-Admin-Token: pxa_..."
curl -s $API/api/v1/admin/tokens/audit?limit=20 -H "X-Admin-Token: $TOKEN"
```

对外分享的字段是 `contact_link`（服务号）与 `invite_link`（频道），形如
`https://popopx.chat/i/v1/<Base64URL>`：原始连接 URI 被封进 ChaCha20-Poly1305 信封，链接与 `qr_svg`
都不含 `smpN.popopx.im` 中继域名。`contact_address` / `public_uri` 原样保留，只有控制台的
「高级诊断：查看原始协议地址」才展示。格式密钥是**公开常量**（HKDF-SHA256 从公布的 IKM 派生），
所以这层保护的是链接预览、截图和随手转发，不是对读到源码者的机密性。`POST /api/v1/invite-links`
只封装网关自己持有的 URI——它忽略 body 里的 `uri`，否则就成了一个用 `popopx.chat` 域名替别人签字的
钓鱼工具；响应带 `link`、`masked`、`created_at_ms`、`cached` 与 `qr_svg`。`GET /api/v1/invite-links/audit`
只列生成时间、类型、对象 id 和 10 字符前缀：审计表里没有能装下完整密文或原始 URI 的列。

空 body 一律按 `{}` 处理（`json_body`），所以轮换那条可以不发 body；它的开关是
`expires_at_ms`、`revoke_previous`（默认 true）、`notify_members`（默认 true），
按**每位成员**计 `key_rotation`——先在小组上排练，别拿 4000 人的频道试手。发送类调用只有在节点
接受命令之后才报 `queued`；节点拒了是 502 `node_refused` 并在 `node_error` 里带节点自己给的原因；
粉丝不存在是 400 `unknown_contact`，本地先查完，根本不会去问节点。

## 接口一览

129 条路由。本文件声明的 59 条由 `python3 -m app.main --print-routes` 打印，同一条命令顺手断言
"每条管理路由都被 token 盖住"；九个插件另贡献 70 条（`workflow_webhook` 12、`alert_ops` 10、
`web3_bridge` 9、`polls` 8、`ai_agent` 6、`privacy_sso` 6、`carddav_connector` 6、
`caldav_connector` 6、`slack_discord` 7），它们走 `include_router` 进来，`--print-routes` 看不见，
所以自检里有 `every_plugin_*` 与逐插件的 `plugin_<id>_answers_status_at_its_own_prefix` 补上另一半。

鉴权只有一条规则：`/api/v1/*` 要管理凭据，也收 `?token=`；缺失或不对一律
`401 {"ok":false,"error":"unauthorized"}`，凭据有效但 scope 不够是 403。凭据可以是根令牌
（`POPOPX_ADMIN_TOKEN`），也可以是 `POST /api/v1/admin/tokens` 铸出的 `pxa_…` scoped 令牌；
两者都接受 `x-admin-token`、`X-Popopx-Admin-Token`、`Authorization: Bearer` 与 `?token=`
这四种写法（`admin_auth.presented_credential`，`gateway/app/admin_auth.py:202`）。核心
`admin_required` 与插件中间件 `admin_gate` 都走同一个解析器
（`gateway/app/main.py:3461`、`:3583`），不再各自拼一套头名判断；`privacy_sso` 的设备侧
路由仍只认 `Authorization`（`privacy_sso_plugin.py:1522` `bearer_secret`），`alert_ops` 的
控制台路由也兼容 `X-Popopx-Admin-Token`（`alert_ops_plugin.py:1216`）。管理后台三个头
一起发（`gateway/app/static/index.html:642`–`:644`），一个令牌不用按路由切换。五类例外：
`/`、`/healthz`、`/h5/{article_id}` 公开；
`POST /api/v1/verifyH5Auth` 靠手机侧的 HMAC 签名证明调用者；`POST /api/v1/workflows/trigger`
只认 `X-PPX-Workflow-Token`（带过期、可撤销、按 scope 拒绝），管理令牌对它是无意义的；插件路径以 `/webhook`、`/verify`、
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

全部配置项在根目录的 [`.env.example`](.env.example)（58 个键，每个都有注释；用
`grep -cE '^[A-Z0-9_]+=' .env.example` 能数出同一个数），
`cp .env.example .env` 之后改它。查找顺序是 `--env <path>` → `$POPOPX_ENV_FILE` →
仓库根目录的 `.env`；进程环境覆盖文件里的同名键（编排器说的算）。

两条生产路径都把这份文件放到工作副本之外，并且**只让它的所有者读得到**：Ubuntu 的 native 模式在
`/etc/popopx-service-suite/env`（unit 里那一行 `EnvironmentFile=`，`install_ubuntu22.sh:326`），
macOS 在 `/usr/local/etc/popopx-service-suite/env`——launchd 没有 `EnvironmentFile=` 这个键，
所以 plist 的 `EnvironmentVariables` 里只导出一个 `POPOPX_ENV_FILE` 指过去（`config.py:369` 认它），
端口和地址绝不进 plist，因为进程环境压过文件里的值（`config.py:386-388`），进了就是第二份会悄悄赢的真相源。
两边都是 0600、属主为服务账号，这不是文档口径而是代码里的判定：`_warn_if_world_readable()`
（`gateway/app/config.py:117-136`）把 owner 之外**任何**一位都算一件事，`0640` 组可读和 `0644`
世界可读收到同一句警告，因为能读这个文件的组就能读里面的 bearer token——`config.py:858` 的
`a_group_readable_env_file_warns_too` 就是钉住这一条的断言。

`load_config()` 拒绝启动的条件都会打成一句人话而不是 traceback：`POPOPX_ADMIN_TOKEN` 缺失、
短于 24 字符或还是示例值（`openssl rand -hex 32`）；`POPOPX_PUBLIC_BASE_URL` 缺失——客户端
`PopopxH5Launcher` 签的就是这个 URL，留空等于签一个手机验不过的签名；
`POPOPX_OFFICIAL_ED25519_PUBLIC_KEY` 解不出 32 字节（base64 44 字符或 hex 64 字符）；
以及任何 `KEY=value` 写坏的行、越界的数值、非布尔的开关。未识别的 `POPOPX_*` 键被忽略、不报错。

## 自检

每个模块都自带 `self_test()`，共 22 组，用下面这条命令一次性跑完：

```bash
# 两个代码块都从仓库根目录起跑
cd gateway && python3 -m app.main --self-test
```

启动路径上不跑这套件——`create_app()` 只跑路由门禁 `assert_routes_are_gated()`（一个没被
token 盖住的_admin 路由就不该开始监听），完整套件是开发/发布前的入口，三条命令分别由
`start_macos.sh`、`install_macos.sh` 与 `install_ubuntu22.sh` 在最后一步打印出来供复制。

权威计数是这条命令自己打出来的最后一行。本机 2026-11-26 用 `/usr/bin/python3` 跑只有标准库那一档
（`cryptography` 和 `fastapi` 都没装），实测是 **2637 条 / 19 组**：`app.crypto_service.crypto_self_test`（缺 `cryptography`）、
`app.opaque_invite_codec.opaque_invite_self_test`（同样缺 `cryptography`）和 `app.main.http_self_test`（缺 `fastapi`）
三组被运行器点名 `SKIPPED`，并打印 "those paths are NOT verified here"——这三组在本机一条都没跑过，不是"跑过了没记上"。
同一台机器上换一个装了 `gateway/requirements.txt` 的 venv 再跑，实测 **2776 条 / 22 组**，多出来的
正是那三组加 vault 的真实密码学分支：运行器逐组打印 `crypto_self_test 6 checks`、
`http_self_test 67 checks` 与 `opaque_invite_codec.opaque_invite_self_test 50 checks`，而
`app.vault` 在有 `cryptography` 时是 29 条、没有时只有 13 条（16 条真实封装/解封检查被换成一个
具名的 `VaultUnavailable` 断言），所以 2637 + 6 + 50 + 67 + 16 = 2776。协议层在两种解释器下
都是同样的 308 条；缺少 `cryptography` 时新增的 invite 断言改为验证
`invite_crypto_unavailable` 这一具名降级答复，而不是悄悄跳过。上面每一档都在 2026-11-26 重测过：
仓库 `.venv` 的 3.9.6（fastapi 0.128.8）与 `brew` 装的 3.11.18（fastapi 0.165.0）各建一个 venv，
两边同为 **2776 条 / 22 组、exit 0**。连接器那五组是 `app.connectors`（34）、`workflow_webhook_plugin`
（57）、`carddav_connector`（43）、`caldav_connector`（48）与 `slack_discord_plugin`（27）；它们把
HMAC/SSRF、令牌过期与撤销、vCard 敏感字段剥离、CalDAV 标题零泄漏、逐工作区签名与失败退款
都放进了可执行断言。作用域令牌那组是 `app.admin_auth`（51），静态加密是 `app.vault`（29）。
后一次不是重复劳动：`requirements.txt` 钉的是区间，新 venv 因此拿到 fastapi 0.165.0 + starlette 1.10.0，
而 starlette 1.x 的 `include_router` 不再把插件路由摊平进 `app.routes`（改成挂一个嵌套的
`_IncludedRouter`），HTTP 组按 `isinstance(r, APIRoute)` 读一遍就少了 30 条插件路由、报出
39 个 verb+path「声明了却没装上」。实际 `GET /api/v1/plugins/ai/status` 仍然返回 200，
OpenAPI 里也在——是量具瞎了，不是网关坏了。所以那条检查现在递归下钻嵌套路由再比，
两个 fastapi 版本给同一个答案；把它证伪的控制实验也还在：把 `include_router` 换成空操作，
两个版本都立刻报 `every_declared_route_is_actually_mounted`。

节点桥那组（`app.agent_bridge`，现 143 条）在同一版加了 3 条，起因是实机安装撞到的类别盲区：5225 上
如果有东西应答但不是 HTTP，`websockets` 抛 `InvalidMessage`——`WebSocketException` 的子类、**不是**
`OSError`——穿过 `AgentBridge.start()` 的 except 把网关整个带下去。此前那组的 fake 一律抛
`ConnectionRefusedError`（那正是 `OSError`），所以这个洞在满绿的自检里活了下来。现在这 3 条开一个真
监听口、回非 HTTP 字节，让库自己决定异常类；最后一条直接断言 `start()` 兜底的类清单和装没装
`websockets` 一致——缺 wheel 那档断言的是三元回退表，不是"跳过"，所以它不会在测不到的配置里悄悄为真。

断言分布在：协议层、数据库、配置、作用域令牌、静态加密、计费、密码学、节点桥、九个插件、
跨实现密码学、以及 HTTP 组 `app.main.http_self_test`——最后一组真的向 ASGI 应用发请求，所以它能
证明一个路由是被装上了还是只是写在源码里。

`--self-test` 仍是唯一的真值门。`gateway/tests/` 只是 pytest 的薄适配器：参数化
`SELF_TEST_MODULES` 并调用同一个 `self_test()`，对 `crypto_self_test`、
`opaque_invite_self_test`、`http_self_test` 用 `importorskip` 保持与运行器相同的
SKIPPED 语义，再调一次 `assert_routes_are_gated()`；它没有复制任何一条断言。

```bash
# 同样从仓库根目录（跑过上一块就先 cd ..）
python3.11 -m venv .venv                      # 3.11 是这套件的目标解释器，见 requirements.txt 头几行
.venv/bin/pip install -r gateway/requirements-dev.txt
cd gateway && ../.venv/bin/python -m app.main --self-test   # 22 组全绿、无 SKIPPED（本机实测 2776 条）
../.venv/bin/python -m pytest                                # 22 passed：同一批 helper，不重复断言
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

opaque invite 也有一条同样的对端校验。`official_tools/swift_opaque_invite_oracle.swift` 读取
`gateway/app/opaque_invite_vectors.json` 公布的 HKDF 参数与两条向量（服务号、频道），用 CryptoKit
重算密钥与 ChaCha20-Poly1305 密文并逐字节比对，再验证解码、无明文残留和翻转 tag 被拒；Python 侧
`opaque_invite_self_test` 的 50 条断言与它共用同一份 JSON。向量文件放在 `gateway/app/` 里，
因为 Dockerfile 只复制这个目录：

```bash
swiftc -O -o /tmp/opaque_invite_oracle official_tools/swift_opaque_invite_oracle.swift
/tmp/opaque_invite_oracle gateway/app/opaque_invite_vectors.json
# PASS opaque invite v1: 2 vectors, 2 URI kinds, CryptoKit agrees
```

## 算力码

```bash
cd gateway && python3 ../official_tools/gen_voucher.py --help
```

默认 `POPOPX_BILLING_REQUIRE_VOUCHER=0`：账户一建行就是 `ONLINE`，四个默认开启的插件开箱可用
（`web3_bridge` 与三个连接器默认关闭，见上文），不需要向任何一方兑换激活码；计量照记、流水照平、控制台照看，所以配额数据是真的。
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
- launchd 这一侧**做不到**的（`install_macos.sh` 不假装它们存在，plist 里一个相关键都没有）：
  `KillSignal=SIGINT` 没有对等键，launchd 停机只发 SIGTERM——好在 uvicorn 的 `HANDLED_SIGNALS`
  同时含 SIGINT 与 SIGTERM（`.venv/.../uvicorn/server.py:32-35`），优雅排空仍在，真要 SIGINT 得自己
  `sudo launchctl kill SIGINT system/com.popopx.gateway`；`ProtectSystem=strict`、`ReadWritePaths=`、
  `ProtectHome`、`PrivateTmp`、`NoNewPrivileges`、`RestrictSUIDSGID` 全无对等物，可用的替代只有
  专用账号 + `src` 保持 `root:wheel 0755`（服务账号写不动自己的代码）+ `Umask 077` + 把 `TMPDIR`
  指进状态树里那个 0700 目录；`MemoryMax=768M` 没有对等物，`SoftResourceLimits.ResidentSetSize` 这个
  键虽然存在但 Darwin 不执行 RLIMIT_RSS，而 `NumberOfFiles` **不要设**——`launchd.plist(5)` 明写它写的是
  全局 `kern.maxfiles`；`StartLimitBurst`/`StartLimitIntervalSec` 没有对等物，launchd 永不放弃重试，
  `ThrottleInterval` 只是"两次尝试之间的最短间隔"这块地板，不是 systemd 的 `RestartSec` 那种延迟，
  这就是配置门必须排在 `bootstrap` 之前的全部理由；`KeepAlive.NetworkState` 也别用，man 明写
  "no longer implemented"。日志没有 journal 对等物，只有 `StandardOutPath`/`StandardErrorPath` 两个
  文件，而且**这套件不做轮转**：newsyslog 要移动 launchd 已经握着的 fd，安全做法是 `mv` 之后立刻
  `sudo launchctl kickstart -k system/com.popopx.gateway` 让服务重新开文件，安装器的 NEXT STEPS 里
  写的就是这条，不是一个假装能自动滚动的配置。
- 还没做的：拿真实 iOS 客户端跑端到端收发（要一个能连上的 broker），以及
  `userContactLinkCreated` 成功帧的形状——手上只有失败帧，所以 `show_contact_address()` 只按
  `userContactLinkNotFound` 这一条判"还没有地址"，其他拒绝照原样抛出。上面所有绿色都是本机可复现
  的断言，不包含对运营服务器的任何假设。
