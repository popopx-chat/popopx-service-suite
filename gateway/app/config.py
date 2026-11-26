# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Deployment configuration for the POPOPX service suite gateway.

One rule shapes this whole module: a value that decides whether a merchant's
channel keys, compute credits or session secrets are safe has no safe default.
Such settings raise :class:`ConfigError` at import time rather than falling back
to something that runs — a gateway that boots with a guessable admin token in
order to answer "/healthz" is not a gateway that failed to start, it is a
gateway that succeeded at being break-in-able. Everything genuinely optional
does take a documented default, so a minimal ``.env`` is three lines.

The environment is the only input. ``load_dotenv`` exists here rather than in
python-dotenv because the file format we read is a deliberate subset —
``KEY=value``, ``#`` comments, optional single-layer quoting — and a
configuration parser that can execute a value is a parser a mounted volume can
attack. Values are never interpolated into a shell, never logged, and never
echoed back in an error message: :class:`ConfigError` names the *key*.
"""

import base64
import binascii
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

__all__ = [
    "Config",
    "ConfigError",
    "load_config",
    "parse_dotenv",
]

_ENV_PREFIX = "POPOPX_"

#: Shortest :envvar:`POPOPX_H5_SERVER_SECRET` that is worth booting with.
#: The SSO plugin refuses to mint a credential from its pairwise-session fallback
#: below this length (``privacy_sso_plugin._MIN_FALLBACK_KEY_BYTES``), so a value
#: under it is not a weaker key — it is a setting that does nothing, discovered on
#: the first follower who cannot sign in. The number is duplicated rather than
#: imported because this module is the layer everything imports, not the plugin
#: layer; :func:`self_test` gates the two copies against each other.
_MIN_FALLBACK_KEY_BYTES = 16

#: Anything equal to one of these, compared case-insensitively, is a template
#: value that survived into production. The gateway will not serve on one.
_WEAK_TOKENS = frozenset(
    {
        "",
        "change-me",
        "changeme",
        "replace-me",
        "secret",
        "popopx",
        "admin",
        "password",
        "test",
        "dev",
        "local",
        "example",
    }
)


class ConfigError(RuntimeError):
    """A deployment setting is missing, malformed, or unsafe to start with."""


# ────────────────────────────────── .env reading ────────────────────────────


def parse_dotenv(path: Path) -> Dict[str, str]:
    """Read a ``KEY=value`` file into a dict, ignoring anything unrecognised.

    Quoting is single-layer on purpose: ``shlex`` would let a value carry a
    command substitution, and this file is read before anything validates who
    wrote it. Backslash-escapes are left alone except ``\\n``/``\\t``, which are
    the only two a system prompt or a URL ever needs.
    """
    values: Dict[str, str] = {}
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return values
    except OSError as exc:  # unreadable is a deployment error, not an empty env
        raise ConfigError("cannot read %s: %s" % (path.name, exc.strerror or exc)) from exc

    for line_no, line in enumerate(raw.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # `export KEY=value` is what every install guide tells an operator to
        # paste into a shell; accepting the prefix costs one test and prevents
        # a silent "my setting is not applying".
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].lstrip()
        key, sep, value = stripped.partition("=")
        if not sep:
            raise ConfigError("%s:%d: expected KEY=value" % (path.name, line_no))
        key = key.strip()
        if not key or not key.replace("_", "").isalnum():
            raise ConfigError("%s:%d: invalid key %r" % (path.name, line_no, key[:40]))
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        else:
            # An unquoted trailing comment is the other thing operators write.
            hash_at = value.find(" #")
            if hash_at >= 0:
                value = value[:hash_at].rstrip()
        values[key] = value.replace("\\n", "\n").replace("\\t", "\t")
    return values


def _warn_if_world_readable(path: Path) -> Optional[str]:
    """Return a warning string when ``.env`` is readable by anyone but its owner.

    A warning, not an error: this is a judgement about a host the gateway cannot
    see, and refusing to start over a permission bit would take a working
    deployment offline for a question the operator can answer in one ``chmod``.
    The rule is every bit outside the owner (``0600`` is the only quiet mode),
    because on this suite's two supported installs there is no legitimate second
    reader — ``start_macos.sh`` and ``install_ubuntu22.sh`` both write 0600, and
    compose passes the values to the container as an environment, not as a
    shared file. A group that can read this file can read the admin bearer
    token, so group-readable gets the same one line as world-readable.
    """
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None
    if mode & 0o077:
        return "%s is mode %04o; it holds %s and should be 0600" % (path, mode, "POPOPX_ADMIN_TOKEN")
    return None


# ─────────────────────────────────── helpers ────────────────────────────────


def _as_bool(source: Dict[str, str], key: str, default: bool) -> bool:
    raw = source.get(key)
    if raw is None or raw == "":
        return default
    lowered = raw.strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    raise ConfigError("%s must be a boolean (1/0, on/off, true/false), got %r" % (key, lowered[:20]))


def _as_int(source: Dict[str, str], key: str, default: int, minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
    raw = source.get(key)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw.strip(), 10)
    except ValueError:
        raise ConfigError("%s must be an integer, got %r" % (key, raw[:40])) from None
    if minimum is not None and value < minimum:
        raise ConfigError("%s must be >= %d, got %d" % (key, minimum, value))
    if maximum is not None and value > maximum:
        raise ConfigError("%s must be <= %d, got %d" % (key, maximum, value))
    return value


def _as_float(source: Dict[str, str], key: str, default: float, minimum: Optional[float] = None) -> float:
    raw = source.get(key)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw.strip())
    except ValueError:
        raise ConfigError("%s must be a number, got %r" % (key, raw[:40])) from None
    if minimum is not None and value < minimum:
        raise ConfigError("%s must be >= %s, got %s" % (key, minimum, value))
    return value


def _as_str(source: Dict[str, str], key: str, default: str = "") -> str:
    raw = source.get(key)
    return default if raw is None else raw.strip()


def _as_url(source: Dict[str, str], key: str, default: str, schemes: List[str]) -> str:
    url = _as_str(source, key, default)
    if not url:
        return url
    for scheme in schemes:
        if url.lower().startswith(scheme + "://"):
            rest = url[len(scheme) + 3 :]
            if rest and " " not in rest:
                return url
            break
    raise ConfigError("%s is not a valid %s URL" % (key, "/".join(schemes)))


def _as_ed25519_public_key(source: Dict[str, str], key: str) -> Optional[bytes]:
    """Decode the official voucher verification key: 32 raw bytes, base64 or hex.

    Both spellings are accepted because the tooling that hands this value to a
    merchant is not one tool: ``gen_voucher.py --show-pubkey`` emits base64,
    while an operator copying from a hex dump has neither.

    The length decides the alphabet, not the attempt order. A 64-character
    string of ``[0-9a-f]`` is also a legal base64 document, one that decodes to
    48 bytes, so trying base64 first and falling back only on a decode *error*
    rejects a perfectly good hex key. Both readings are computed and the one
    that yields 32 bytes wins; no input can yield 32 bytes both ways, because
    32 bytes is 44 base64 characters and 64 hex characters.
    """
    raw = _as_str(source, key)
    if not raw:
        return None
    candidate = raw.replace(" ", "")

    readings: List[bytes] = []
    try:
        readings.append(base64.b64decode(candidate, validate=True))
    except (binascii.Error, ValueError):
        pass
    if len(candidate) % 2 == 0:
        try:
            readings.append(bytes.fromhex(candidate))
        except ValueError:
            pass

    for decoded in readings:
        if len(decoded) == 32:
            return decoded

    if not readings:
        raise ConfigError("%s is neither valid base64 nor valid hex" % key)
    raise ConfigError(
        "%s must decode to exactly 32 bytes, got %s — expected 44 base64 characters or 64 hex characters"
        % (key, "/".join(str(len(r)) for r in readings))
    )


def _as_port(source: Dict[str, str], key: str, default: int) -> int:
    return _as_int(source, key, default, minimum=1, maximum=65535)


# ─────────────────────────────────── the config ─────────────────────────────


@dataclass
class PluginToggles:
    ai_agent: bool = True
    alert_ops: bool = True
    privacy_sso: bool = True
    polls: bool = True
    web3_bridge: bool = False
    workflow_webhook: bool = False
    carddav_connector: bool = False
    caldav_connector: bool = False

    @property
    def enabled(self) -> List[str]:
        return [
            name
            for name, on in (
                ("ai_agent", self.ai_agent),
                ("alert_ops", self.alert_ops),
                ("privacy_sso", self.privacy_sso),
                ("polls", self.polls),
                ("web3_bridge", self.web3_bridge),
                ("workflow_webhook", self.workflow_webhook),
                ("carddav_connector", self.carddav_connector),
                ("caldav_connector", self.caldav_connector),
            )
            if on
        ]


@dataclass
class NodeConfig:
    """The IPC seam to the open-source chat node.

    ``ws_url`` is loopback because the node's ``runLocalTCPServer`` binds
    127.0.0.1 and offers no way to serve elsewhere; the field is not validated
    to *require* loopback so that a merchant fronting it with an authenticated
    TLS proxy (the documented cross-machine option) can point at ``wss://``.
    """

    ws_url: str = "ws://127.0.0.1:5225"
    reconnect_seconds: float = 3.0
    command_timeout_seconds: float = 30.0
    service_requests: bool = True
    send_files: bool = False


@dataclass
class BillingConfig:
    require_voucher: bool = False
    suspend_threshold: int = 0
    official_ed25519_public_key: Optional[bytes] = None
    per_card: int = 1
    per_menu_push: int = 1
    per_key_rotation: int = 2
    per_ai_message: int = 5
    per_alert: int = 2
    per_sso_login: int = 1
    per_poll: int = 1
    per_web3_event: int = 1
    per_workflow_event: int = 1
    per_carddav_query: int = 1
    per_caldav_query: int = 1


@dataclass
class Config:
    node: NodeConfig
    gateway_host: str
    gateway_port: int
    public_base_url: str
    admin_token: str
    h5_server_secret: str
    db_path: Path
    service_name: str
    service_full_name: str
    service_id: str
    billing: BillingConfig
    plugins: PluginToggles
    ai_base_url: str
    ai_api_key: str
    ai_model: str
    ai_max_tokens: int
    ai_timeout_seconds: float
    ai_system_prompt: str
    ai_rate_limit_messages: int
    ai_rate_limit_window_seconds: int
    alert_webhook_token: str
    alert_min_severity: str
    alert_resolve_keywords: List[str]
    sso_ttl_seconds: int
    sso_poll_interval_ms: int
    web3_evm_rpc_url: str
    web3_solana_rpc_url: str
    web3_poll_interval_seconds: int
    log_level: str
    warnings: List[str] = field(default_factory=list)

    @property
    def h5_origin(self) -> str:
        """The origin the client signs against — no trailing slash."""
        return self.public_base_url.rstrip("/")

    def redacted_summary(self) -> str:
        """One line for the boot banner. No secret appears in it, ever."""
        return (
            "node=%s listen=%s:%d public=%s db=%s plugins=%s billing=%s"
            % (
                self.node.ws_url,
                self.gateway_host,
                self.gateway_port,
                self.h5_origin,
                self.db_path,
                ",".join(self.plugins.enabled) or "(none)",
                "voucher-required" if self.billing.require_voucher else "open",
            )
        )


def load_config(env_path: Optional[Path] = None) -> Config:
    """Build a :class:`Config` from ``os.environ``, overlaid on ``.env``.

    The process environment wins over the file. A deployment that sets a value
    in both places means the file for humans and the environment for the
    orchestrator, and the orchestrator is the one that has to be right.
    """
    source: Dict[str, str] = {}
    warnings: List[str] = []

    root = Path(__file__).resolve().parents[2]
    candidates = [env_path] if env_path else [Path(os.environ.get(_ENV_PREFIX + "ENV_FILE", "")), root / ".env"]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if not path.is_absolute():
            path = (root / path).resolve()
        if path.is_file():
            file_values = parse_dotenv(path)
            # File first, env on top: the loop below only fills what is absent.
            for key, value in file_values.items():
                source.setdefault(key, value)
            warning = _warn_if_world_readable(path)
            if warning:
                warnings.append(warning)
            break

    for key, value in os.environ.items():
        if key.startswith(_ENV_PREFIX):
            source[key] = value

    # ── required: authentication ────────────────────────────────────────────
    admin_token = _as_str(source, _ENV_PREFIX + "ADMIN_TOKEN")
    if admin_token.lower() in _WEAK_TOKENS or len(admin_token) < 24:
        raise ConfigError(
            "POPOPX_ADMIN_TOKEN is missing, too short (<24 chars), or still an example value. "
            "Generate one with: openssl rand -hex 32"
        )

    public_base_url = _as_url(source, _ENV_PREFIX + "PUBLIC_BASE_URL", "", ["http", "https"])
    if not public_base_url:
        raise ConfigError(
            "POPOPX_PUBLIC_BASE_URL is required: PopopxH5Launcher signs the URL it is about to open, "
            "so an unset origin means every signed H5 link points at a host that does not exist."
        )

    # There is deliberately no keyring *file* setting. Channel identity keys and
    # epoch keys are rows in the same SQLite database as the ledger and the
    # sessions, because a rotation must commit the new epoch and retire the old one
    # atomically: a DB commit plus a separate file write can desync into a state
    # where members hold a key the server can no longer sign rotations for, which
    # is unrecoverable for those members. One file, one backup, one failure mode.
    # A relative value is resolved against the repo root rather than the current
    # working directory, for the same reason the env file is: `start_macos.sh`
    # runs uvicorn from `gateway/`, a systemd unit or compose service can run it
    # from anywhere, and a ledger that silently reappears under a different
    # directory every time the cwd changes is a ledger with two histories.
    db_path = Path(_as_str(source, _ENV_PREFIX + "DB_PATH", str(root / "data" / "gateway.db")))
    if not db_path.is_absolute():
        db_path = (root / db_path).resolve()

    billing = BillingConfig(
        require_voucher=_as_bool(source, _ENV_PREFIX + "BILLING_REQUIRE_VOUCHER", False),
        suspend_threshold=_as_int(source, _ENV_PREFIX + "BILLING_SUSPEND_THRESHOLD", 0, minimum=0),
        official_ed25519_public_key=_as_ed25519_public_key(source, _ENV_PREFIX + "OFFICIAL_ED25519_PUBLIC_KEY"),
        per_card=_as_int(source, _ENV_PREFIX + "CP_PER_CARD", 1, minimum=0),
        per_menu_push=_as_int(source, _ENV_PREFIX + "CP_PER_MENU_PUSH", 1, minimum=0),
        per_key_rotation=_as_int(source, _ENV_PREFIX + "CP_PER_KEY_ROTATION", 2, minimum=0),
        per_ai_message=_as_int(source, _CP_KEYS["ai"], 5, minimum=0),
        per_alert=_as_int(source, _CP_KEYS["alert"], 2, minimum=0),
        per_sso_login=_as_int(source, _CP_KEYS["sso"], 1, minimum=0),
        per_poll=_as_int(source, _CP_KEYS["poll"], 1, minimum=0),
        per_web3_event=_as_int(source, _CP_KEYS["web3"], 1, minimum=0),
        per_workflow_event=_as_int(source, _CP_KEYS["workflow"], 1, minimum=0),
        per_carddav_query=_as_int(source, _CP_KEYS["carddav"], 1, minimum=0),
        per_caldav_query=_as_int(source, _CP_KEYS["caldav"], 1, minimum=0),
    )
    if billing.require_voucher and billing.official_ed25519_public_key is None:
        raise ConfigError(
            "POPOPX_OFFICIAL_ED25519_PUBLIC_KEY is required while POPOPX_BILLING_REQUIRE_VOUCHER=1: "
            "without it no POPX-CP activation code can be verified, so the account can never leave DRAFT. "
            "Print the public half with: python3 official_tools/gen_voucher.py --show-pubkey"
        )

    plugins = PluginToggles(
        ai_agent=_as_bool(source, _ENV_PREFIX + "PLUGIN_AI_AGENT", True),
        alert_ops=_as_bool(source, _ENV_PREFIX + "PLUGIN_ALERT_OPS", True),
        privacy_sso=_as_bool(source, _ENV_PREFIX + "PLUGIN_PRIVACY_SSO", True),
        polls=_as_bool(source, _ENV_PREFIX + "PLUGIN_POLLS", True),
        web3_bridge=_as_bool(source, _ENV_PREFIX + "PLUGIN_WEB3_BRIDGE", False),
        workflow_webhook=_as_bool(source, _ENV_PREFIX + "PLUGIN_WORKFLOW_WEBHOOK", False),
        carddav_connector=_as_bool(source, _ENV_PREFIX + "PLUGIN_CARDDAV_CONNECTOR", False),
        caldav_connector=_as_bool(source, _ENV_PREFIX + "PLUGIN_CALDAV_CONNECTOR", False),
    )

    alert_min_severity = _as_str(source, _ENV_PREFIX + "ALERT_MIN_SEVERITY", "warning").lower()
    if alert_min_severity not in ("debug", "info", "warning", "critical"):
        raise ConfigError("POPOPX_ALERT_MIN_SEVERITY must be one of debug|info|warning|critical")

    keywords = _as_str(source, _ENV_PREFIX + "ALERT_RESOLVE_KEYWORDS", "确认,已处理,ack,resolve")
    resolve_keywords = [k.strip().lower() for k in keywords.split(",") if k.strip()]

    config = Config(
        node=NodeConfig(
            ws_url=_as_url(source, _ENV_PREFIX + "NODE_WS_URL", "ws://127.0.0.1:5225", ["ws", "wss"]),
            reconnect_seconds=_as_float(source, _ENV_PREFIX + "NODE_RECONNECT_SECONDS", 3.0, minimum=0.2),
            command_timeout_seconds=_as_float(source, _ENV_PREFIX + "NODE_COMMAND_TIMEOUT_SECONDS", 30.0, minimum=1.0),
            service_requests=_as_bool(source, _ENV_PREFIX + "NODE_SERVICE_REQUESTS", True),
            send_files=_as_bool(source, _ENV_PREFIX + "NODE_SEND_FILES", False),
        ),
        gateway_host=_as_str(source, _ENV_PREFIX + "GATEWAY_HOST", "0.0.0.0"),
        gateway_port=_as_port(source, _ENV_PREFIX + "GATEWAY_PORT", 8080),
        public_base_url=public_base_url,
        admin_token=admin_token,
        h5_server_secret=_as_str(source, _ENV_PREFIX + "H5_SERVER_SECRET"),
        db_path=db_path,
        service_name=_as_str(source, _ENV_PREFIX + "SERVICE_NAME", "POPOPX 服务号"),
        service_full_name=_as_str(source, _ENV_PREFIX + "SERVICE_FULL_NAME", "POPOPX Service Account"),
        service_id=_as_str(source, _ENV_PREFIX + "SERVICE_ID", "popopx.official"),
        billing=billing,
        plugins=plugins,
        ai_base_url=_as_url(source, _ENV_PREFIX + "AI_BASE_URL", "https://api.openai.com/v1", ["http", "https"]),
        ai_api_key=_as_str(source, _ENV_PREFIX + "AI_API_KEY"),
        ai_model=_as_str(source, _ENV_PREFIX + "AI_MODEL", "gpt-4o-mini"),
        ai_max_tokens=_as_int(source, _ENV_PREFIX + "AI_MAX_TOKENS", 512, minimum=1, maximum=8192),
        ai_timeout_seconds=_as_float(source, _ENV_PREFIX + "AI_TIMEOUT_SECONDS", 30.0, minimum=1.0),
        ai_system_prompt=_as_str(
            source,
            _ENV_PREFIX + "AI_SYSTEM_PROMPT",
            "你是 POPOPX 服务号的智能客服。回答简洁、礼貌，不索要任何个人身份信息。",
        ),
        ai_rate_limit_messages=_as_int(source, _ENV_PREFIX + "AI_RATE_LIMIT_MESSAGES", 20, minimum=1),
        ai_rate_limit_window_seconds=_as_int(source, _ENV_PREFIX + "AI_RATE_LIMIT_WINDOW_SECONDS", 300, minimum=1),
        alert_webhook_token=_as_str(source, _ENV_PREFIX + "ALERT_WEBHOOK_TOKEN"),
        alert_min_severity=alert_min_severity,
        alert_resolve_keywords=resolve_keywords,
        sso_ttl_seconds=_as_int(source, _ENV_PREFIX + "SSO_TTL_SECONDS", 180, minimum=15, maximum=3600),
        sso_poll_interval_ms=_as_int(source, _ENV_PREFIX + "SSO_POLL_INTERVAL_MS", 2000, minimum=250, maximum=20000),
        web3_evm_rpc_url=_as_url(source, _ENV_PREFIX + "WEB3_EVM_RPC_URL", "https://eth.llamarpc.com", ["http", "https"]),
        web3_solana_rpc_url=_as_url(source, _ENV_PREFIX + "WEB3_SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com", ["http", "https"]),
        web3_poll_interval_seconds=_as_int(source, _ENV_PREFIX + "WEB3_POLL_INTERVAL_SECONDS", 30, minimum=5),
        log_level=_as_str(source, _ENV_PREFIX + "LOG_LEVEL", "INFO").upper(),
        warnings=warnings,
    )

    if plugins.alert_ops and not config.alert_webhook_token:
        config.warnings.append(
            "alert_ops is enabled but POPOPX_ALERT_WEBHOOK_TOKEN is empty — every POST to "
            "/api/v1/plugins/alerts/webhook will be refused with 401"
        )
    if plugins.ai_agent and not config.ai_api_key and "127.0.0.1" not in config.ai_base_url and "localhost" not in config.ai_base_url:
        config.warnings.append("ai_agent is enabled but POPOPX_AI_API_KEY is empty — hosted models will answer 401")
    if config.log_level == "DEBUG":
        config.warnings.append("POPOPX_LOG_LEVEL=DEBUG logs message bodies, which include pairwise uids and signatures")
    if 0 < len(config.h5_server_secret.encode("utf-8")) < _MIN_FALLBACK_KEY_BYTES:
        config.warnings.append(
            "POPOPX_H5_SERVER_SECRET is %d bytes: privacy_sso will refuse to mint an SSO credential from it "
            "for any follower without a pairwise session secret, so set it to at least %d bytes or leave it empty "
            % (len(config.h5_server_secret.encode("utf-8")), _MIN_FALLBACK_KEY_BYTES)
        )

    if config.log_level not in ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"):
        raise ConfigError("POPOPX_LOG_LEVEL must be one of CRITICAL|ERROR|WARNING|INFO|DEBUG")

    return config


#: The per-action meter keys, spelled once. A dict rather than literals at the
#: call sites because these names have to agree with `.env.example`, and a typo
#: in one of them is a plugin that silently bills nothing.
_CP_KEYS = {
    "ai": _ENV_PREFIX + "CP_PER_AI_MESSAGE",
    "alert": _ENV_PREFIX + "CP_PER_ALERT",
    "sso": _ENV_PREFIX + "CP_PER_SSO_LOGIN",
    "poll": _ENV_PREFIX + "CP_PER_POLL",
    "web3": _ENV_PREFIX + "CP_PER_WEB3_EVENT",
    "workflow": _ENV_PREFIX + "CP_PER_WORKFLOW_EVENT",
    "carddav": _ENV_PREFIX + "CP_PER_CARDDAV_QUERY",
    "caldav": _ENV_PREFIX + "CP_PER_CALDAV_QUERY",
}


# ───────────────────────────────── self-test ────────────────────────────────


def self_test() -> List[str]:
    """Every loading rule in this module, verified against real throwaway ``.env`` files.

    Nothing here opens a database or starts a gateway. That is deliberate: the
    most expensive defect this module can have is a deployment that refuses to
    load in the field, or one that *loads* while believing a setting the
    operator never actually gave it. So the suite loads files — and around every
    load it clears the ``POPOPX_*`` process environment and puts it back, so a
    developer's live ``.env``, an orchestrator's export, or this very suite's own
    fixture cannot quietly satisfy an assertion it is not making.

    Returns the list of passed check names and raises :class:`AssertionError` on
    the first failure, so a caller cannot mistake a half-run suite for a green one.
    """
    import dataclasses
    import os
    import re
    import shutil
    import tempfile

    from app.billing_service import METER_ACTIONS

    checks: List[str] = []
    root = Path(__file__).resolve().parents[2]
    tmp = Path(tempfile.mkdtemp(prefix="popopx-config-selftest-")).resolve()
    seq = [0]

    def credit(name: str) -> None:
        if name in checks:
            raise AssertionError("config self_test: %r is credited twice — a name must carry exactly one assertion, or the roster lies about what was checked" % name)
        checks.append(name)

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("config self_test failed: %s" % name)
        credit(name)

    def refusal(needle: str, call) -> str:
        """The message of the :class:`ConfigError` ``call`` must raise, naming ``needle``.

        The needle is part of the contract, not decoration: an operator reads
        this text in a journal and has to act on it without opening the source,
        so a refusal that does not name the setting it refused is a failure of
        this module, not a success.
        """
        try:
            call()
        except ConfigError as exc:
            if needle not in str(exc):
                raise AssertionError("config self_test: refused with %r, expected a mention of %r" % (str(exc), needle)) from exc
            return str(exc)
        except Exception as exc:  # noqa: BLE001
            raise AssertionError("config self_test: raised %s (%s), expected ConfigError" % (type(exc).__name__, exc)) from exc
        raise AssertionError("config self_test: the deployment loaded; it must not have")

    def refuses(name: str, needle: str, call) -> str:
        """:func:`refusal`, credited — for the cases whose whole assertion is the refusal."""
        message = refusal(needle, call)
        credit(name)
        return message

    def fails(name: str, expected, call):
        """``call()`` must raise exactly ``expected`` — not a subclass of convenience."""
        try:
            call()
        except expected as exc:
            credit(name)
            return exc
        except Exception as exc:  # noqa: BLE001
            raise AssertionError("config self_test: %s raised %s (%s), expected %s" % (name, type(exc).__name__, exc, expected.__name__)) from exc
        raise AssertionError("config self_test: %s did not raise %s" % (name, expected.__name__))

    def write(mapping, mode: int = 0o600, tag: str = "env") -> Path:
        seq[0] += 1
        path = tmp / ("%s-%d" % (tag, seq[0]))
        path.write_text("".join("%s=%s\n" % (key, value) for key, value in mapping.items()), encoding="utf-8")
        path.chmod(mode)
        return path

    def isolate(path: Optional[Path], process: Optional[Dict[str, str]], explicit: bool):
        """Run :func:`load_config` with only the variables this case names.

        The save/restore in the ``finally`` is what makes the suite re-runnable
        and re-entrant from a gateway that is itself configured from the real
        environment.
        """
        saved = {key: value for key, value in os.environ.items() if key.startswith(_ENV_PREFIX)}
        for key in saved:
            del os.environ[key]
        for key, value in (process or {}).items():
            os.environ[key] = value
        try:
            return load_config(path if explicit else None)
        finally:
            for key in [k for k in os.environ if k.startswith(_ENV_PREFIX)]:
                del os.environ[key]
            os.environ.update(saved)

    key_bytes = bytes(range(32))
    pub_b64 = base64.b64encode(key_bytes).decode("ascii")
    pub_hex = key_bytes.hex()

    #: A file that satisfies every rule, so each case below changes exactly one
    #: setting and a failure names the setting rather than the fixture.
    base_env = {
        "POPOPX_ADMIN_TOKEN": "t" * 32,
        "POPOPX_PUBLIC_BASE_URL": "https://eco.example.test",
        "POPOPX_OFFICIAL_ED25519_PUBLIC_KEY": pub_b64,
        "POPOPX_H5_SERVER_SECRET": "s" * 48,
        "POPOPX_ALERT_WEBHOOK_TOKEN": "w" * 24,
        "POPOPX_AI_API_KEY": "k" * 24,
        "POPOPX_LOG_LEVEL": "WARNING",
    }

    def load(overrides: Optional[Dict[str, Optional[str]]] = None, process: Optional[Dict[str, str]] = None, mode: int = 0o600, explicit: bool = True) -> Config:
        merged = dict(base_env)
        for key, value in (overrides or {}).items():
            if value is None:
                merged.pop(key, None)
            else:
                merged[key] = value
        return isolate(write(merged, mode), process, explicit)

    def load_exact(mapping: Dict[str, str], mode: int = 0o600, explicit: bool = True) -> Config:
        """Load a file with *only* these lines — the "minimal ``.env``" case."""
        return isolate(write(mapping, mode, tag="exact"), None, explicit)

    # ── 1. the ``.env`` reader is a subset parser, on purpose ───────────────
    def read_blob(text: str) -> Path:
        seq[0] += 1
        path = tmp / ("blob-%d" % seq[0])
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
        return path

    def parse(text: str) -> Dict[str, str]:
        return parse_dotenv(read_blob(text))

    check("parse_dotenv_reads_key_value_pairs", parse("A=1\nB=two\n") == {"A": "1", "B": "two"})
    check("parse_dotenv_skips_blank_lines_and_comments", parse("# lead\n\n   \nA=1\n  # tail\n") == {"A": "1"})
    check("parse_dotenv_accepts_the_export_prefix", parse("export A=1\nexport  B=2\n") == {"A": "1", "B": "2"})
    check("parse_dotenv_strips_one_layer_of_matching_quotes", parse('A="q"\nB=\'s\'\n') == {"A": "q", "B": "s"})
    check("parse_dotenv_keeps_a_mismatched_quote_as_data", parse('A="q\'\n') == {"A": "\"q'"})
    check("parse_dotenv_drops_an_unquoted_trailing_comment", parse("A=a # note\nB=b #note\n") == {"A": "a", "B": "b"})
    check("parse_dotenv_never_interprets_a_value", parse('A=$(touch /tmp/pwned)\nB=`id`\nC=a;b`\n') == {"A": "$(touch /tmp/pwned)", "B": "`id`", "C": "a;b`"})
    check("parse_dotenv_unescapes_only_newline_and_tab", parse("A=x\\ny\nB=x\\ty\n") == {"A": "x\ny", "B": "x\ty"})
    # Greedy on purpose: the escape is textual, so `\newfolder` loses its `\n`.
    # Documented here rather than silently fixed, because a Windows path in a
    # POPOPX `.env` is not a supported deployment — macOS and Ubuntu both use
    # forward slashes — and a half-escape rule would be worse than this one.
    check("parse_dotenv_unescapes_backslash_n_inside_a_word", parse("A=C:\\newfolder\n") == {"A": "C:" + chr(10) + "ewfolder"})
    check("parse_dotenv_refuses_a_line_without_equals", "expected KEY=value" in refusal("expected KEY=value", lambda: parse("A\n")))
    check("parse_dotenv_names_the_line_that_broke", ":3:" in refusal(":3:", lambda: parse("A=1\nB=2\nbogus\n")))
    check("parse_dotenv_refuses_a_key_that_is_not_one_word", "invalid key" in refusal("invalid key", lambda: parse("bad key!=1\n")))
    check("parse_dotenv_refuses_an_empty_key", "invalid key" in refusal("invalid key", lambda: parse("=1\n")))
    check("a_missing_env_file_reads_as_an_empty_env", parse_dotenv(tmp / "definitely-absent") == {})
    unreadable = fails("a_directory_in_place_of_an_env_file_is_a_deployment_error", ConfigError, lambda: parse_dotenv(tmp))
    check("the_unreadable_file_error_names_the_file_and_the_reason", "cannot read" in str(unreadable) and tmp.name in str(unreadable))

    # ── 2. authentication and the public origin: no safe default ────────────
    clean = load()
    check("a_clean_deployment_loads", clean.service_id == "popopx.official")
    check("a_clean_deployment_produces_no_warnings", clean.warnings == [])
    check("the_admin_token_is_taken_verbatim", load({"POPOPX_ADMIN_TOKEN": " " + "u" * 30 + " "}).admin_token == "u" * 30)
    check("a_missing_admin_token_refuses_to_load", "POPOPX_ADMIN_TOKEN" in refusal("POPOPX_ADMIN_TOKEN", lambda: load({"POPOPX_ADMIN_TOKEN": None})))
    check("a_short_admin_token_names_the_length_rule", "<24 chars" in refusal("<24 chars", lambda: load({"POPOPX_ADMIN_TOKEN": "x" * 23})))
    check("the_token_refusal_hands_over_the_generator", "openssl rand -hex 32" in refusal("openssl rand -hex 32", lambda: load({"POPOPX_ADMIN_TOKEN": ""})))
    check("a_random_twenty_four_character_token_is_enough", load({"POPOPX_ADMIN_TOKEN": "a" * 24}).admin_token == "a" * 24)
    for placeholder in ("change-me", "ChangeMe", "SECRET", "popopx", "Admin", "password", "example"):
        name = "the_template_token_%s_is_refused" % placeholder.lower()
        check(name, "example value" in refusal("example value", lambda placeholder=placeholder: load({"POPOPX_ADMIN_TOKEN": placeholder})))
    check("a_blank_public_base_url_names_the_launcher_that_needs_it", "PopopxH5Launcher" in refusal("PopopxH5Launcher", lambda: load({"POPOPX_PUBLIC_BASE_URL": None})))
    check("a_schemeless_origin_is_refused_as_a_url_not_as_a_missing_one", "not a valid http/https URL" in refusal("not a valid http/https URL", lambda: load({"POPOPX_PUBLIC_BASE_URL": "eco.example.test"})))
    check("an_ftp_origin_is_refused", "not a valid http/https URL" in refusal("not a valid http/https URL", lambda: load({"POPOPX_PUBLIC_BASE_URL": "ftp://eco.example.test"})))
    check("an_origin_with_a_space_inside_is_refused", "not a valid http/https URL" in refusal("not a valid http/https URL", lambda: load({"POPOPX_PUBLIC_BASE_URL": "https://eco.example.test /x"})))
    check("an_http_origin_is_allowed_for_loopback_pairing", load({"POPOPX_PUBLIC_BASE_URL": "http://127.0.0.1:8080"}).public_base_url == "http://127.0.0.1:8080")
    check("the_h5_origin_never_keeps_a_trailing_slash", load({"POPOPX_PUBLIC_BASE_URL": "https://eco.example.test/"}).h5_origin == "https://eco.example.test")
    check("the_h5_server_secret_is_stripped_not_resized", load({"POPOPX_H5_SERVER_SECRET": "  s3cret  "}).h5_server_secret == "s3cret")

    banner = clean.redacted_summary()
    check("the_boot_banner_carries_no_admin_token", clean.admin_token not in banner)
    check("the_boot_banner_carries_no_server_secret", clean.h5_server_secret not in banner)
    check("the_boot_banner_carries_no_verification_key", pub_b64 not in banner and key_bytes.hex() not in banner)
    check("the_boot_banner_shows_what_an_operator_can_act_on", "listen=0.0.0.0:8080" in banner and "billing=open" in banner and "ws://127.0.0.1:5225" in banner)
    check("the_boot_banner_says_so_when_admission_is_opted_into",
          "billing=voucher-required" in load({"POPOPX_BILLING_REQUIRE_VOUCHER": "1"}).redacted_summary())
    check("the_boot_banner_lists_only_enabled_plugins", ",".join(clean.plugins.enabled) in banner)

    # ── 3. precedence: the orchestrator is the one that has to be right ──────
    check("the_process_environment_beats_the_file", load({"POPOPX_PLUGIN_POLLS": "1"}, {"POPOPX_PLUGIN_POLLS": "0"}).plugins.polls is False)
    check("a_setting_only_in_the_file_is_still_read", load({"POPOPX_SERVICE_ID": "popopx.from.file"}).service_id == "popopx.from.file")
    check("a_setting_only_in_the_environment_is_read", load(None, {"POPOPX_SERVICE_ID": "popopx.from.env"}).service_id == "popopx.from.env")
    # The sharp edge of the rule: an exported *empty* string outranks a real
    # file value and lands as the default, so an orchestrator that exports
    # `POPOPX_CP_PER_CARD=` (a common Helm/compose slip) gets a free meter.
    check("an_empty_environment_value_outranks_a_real_file_value", load({"POPOPX_CP_PER_CARD": "7"}, {"POPOPX_CP_PER_CARD": ""}).billing.per_card == 1)
    def popopx_env() -> Dict[str, str]:
        return {key: value for key, value in os.environ.items() if key.startswith(_ENV_PREFIX)}

    before = popopx_env()
    load({"POPOPX_SERVICE_ID": "popopx.scrutiny"})
    check("load_config_never_edits_the_process_environment", popopx_env() == before)
    after_refusal = None
    try:
        load({"POPOPX_ADMIN_TOKEN": "nope"})
    except ConfigError:
        after_refusal = popopx_env()
    check("the_environment_is_restored_after_a_refusal_too", after_refusal == before)
    load(None, {"POPOPX_SERVICE_ID": "popopx.injected"})
    check("an_injected_variable_does_not_outlive_the_load", popopx_env().get("POPOPX_SERVICE_ID") != "popopx.injected")

    # ── 4. which file gets read, and what a relative path means ─────────────
    env_file = write(dict(base_env, POPOPX_SERVICE_ID="popopx.by.env.file"))
    check("popopx_env_file_selects_the_file_when_no_path_is_given", isolate(None, {"POPOPX_ENV_FILE": str(env_file)}, False).service_id == "popopx.by.env.file")
    relative = Path(os.path.relpath(env_file, root))
    check("a_relative_env_file_path_resolves_against_the_repo_root", not relative.is_absolute() and isolate(relative, None, True).service_id == "popopx.by.env.file")
    check("an_explicit_path_skips_the_search", isolate(env_file, {"POPOPX_ENV_FILE": str(write(dict(base_env, POPOPX_SERVICE_ID="popopx.ignored")))}, True).service_id == "popopx.by.env.file")
    check("a_relative_database_path_resolves_against_the_repo_root", load({"POPOPX_DB_PATH": "data/relative.db"}).db_path == root / "data" / "relative.db")
    check("an_absolute_database_path_is_kept_verbatim", load({"POPOPX_DB_PATH": "/var/lib/popopx-service-suite/gateway.db"}).db_path == Path("/var/lib/popopx-service-suite/gateway.db"))
    check("the_default_database_is_under_the_repo_data_directory", load({"POPOPX_DB_PATH": None}).db_path == root / "data" / "gateway.db")

    # ── 5. the scalar helpers, through the settings that use them ───────────
    for spelling in ("1", "true", "TRUE", "Yes", "on"):
        name = "the_boolean_%s_means_on" % spelling.strip()
        check(name, load({"POPOPX_PLUGIN_POLLS": spelling}).plugins.polls is True)
    for spelling in ("0", "false", "No", "OFF"):
        name = "the_boolean_%s_means_off" % spelling.strip()
        check(name, load({"POPOPX_PLUGIN_POLLS": spelling}).plugins.polls is False)
    check("surrounding_space_does_not_change_a_boolean", load({"POPOPX_PLUGIN_POLLS": " 1 "}).plugins.polls is True and load({"POPOPX_PLUGIN_POLLS": " Off "}).plugins.polls is False)
    check("an_empty_boolean_falls_back_to_its_default", load({"POPOPX_PLUGIN_WEB3_BRIDGE": ""}).plugins.web3_bridge is False)
    check("a_boolean_refuses_a_word_that_is_neither", "must be a boolean" in refusal("must be a boolean", lambda: load({"POPOPX_PLUGIN_POLLS": "maybe"})))
    check("an_integer_setting_refuses_a_word", "must be an integer" in refusal("must be an integer", lambda: load({"POPOPX_CP_PER_CARD": "many"})))
    check("an_integer_setting_refuses_a_fraction", "must be an integer" in refusal("must be an integer", lambda: load({"POPOPX_CP_PER_CARD": "1.5"})))
    check("an_integer_setting_strips_surrounding_space", load({"POPOPX_CP_PER_CARD": " 9 "}).billing.per_card == 9)
    check("a_meter_of_zero_is_a_free_action", load({"POPOPX_CP_PER_ALERT": "0"}).billing.per_alert == 0)
    check("a_negative_meter_is_refused", "must be >= 0" in refusal("must be >= 0", lambda: load({"POPOPX_CP_PER_ALERT": "-1"})))
    check("a_negative_suspend_threshold_is_refused", "must be >= 0" in refusal("must be >= 0", lambda: load({"POPOPX_BILLING_SUSPEND_THRESHOLD": "-5"})))
    check("a_float_setting_refuses_a_word", "must be a number" in refusal("must be a number", lambda: load({"POPOPX_NODE_RECONNECT_SECONDS": "soon"})))
    check("the_node_reconnect_interval_has_a_floor", "must be >= 0.2" in refusal("must be >= 0.2", lambda: load({"POPOPX_NODE_RECONNECT_SECONDS": "0.1"})))
    check("the_node_command_timeout_has_a_floor", "must be >= 1.0" in refusal("must be >= 1.0", lambda: load({"POPOPX_NODE_COMMAND_TIMEOUT_SECONDS": "0.5"})))
    check("a_port_of_zero_is_not_a_port", "must be >= 1" in refusal("must be >= 1", lambda: load({"POPOPX_GATEWAY_PORT": "0"})))
    check("a_port_above_the_tcp_maximum_is_refused", "must be <= 65535" in refusal("must be <= 65535", lambda: load({"POPOPX_GATEWAY_PORT": "65536"})))
    check("a_non_numeric_port_is_refused", "must be an integer" in refusal("must be an integer", lambda: load({"POPOPX_GATEWAY_PORT": "http"})))
    check("the_node_may_be_a_tls_endpoint_when_fronted", load({"POPOPX_NODE_WS_URL": "wss://node.example.test:9000"}).node.ws_url == "wss://node.example.test:9000")
    check("the_node_cannot_be_an_http_origin", "not a valid ws/wss URL" in refusal("not a valid ws/wss URL", lambda: load({"POPOPX_NODE_WS_URL": "http://127.0.0.1:5225"})))
    check("the_ai_endpoint_cannot_be_a_script_url", "not a valid http/https URL" in refusal("not a valid http/https URL", lambda: load({"POPOPX_AI_BASE_URL": "javascript:alert(1)"})))
    check("an_empty_setting_blanks_a_url_default", load({"POPOPX_AI_BASE_URL": ""}).ai_base_url == "")

    # ── 6. the POPX-CP key rule: the one that decides if money can move ─────
    three_lines = load_exact({"POPOPX_ADMIN_TOKEN": "t" * 32, "POPOPX_PUBLIC_BASE_URL": "https://eco.example.test", "POPOPX_OFFICIAL_ED25519_PUBLIC_KEY": pub_b64})
    check("a_minimal_env_is_three_lines", three_lines.billing.require_voucher is False and three_lines.gateway_port == 8080 and three_lines.gateway_host == "0.0.0.0")
    check("a_minimal_env_warns_about_the_two_settings_it_omits", len(three_lines.warnings) == 2 and any("ALERT_WEBHOOK_TOKEN" in w for w in three_lines.warnings) and any("AI_API_KEY" in w for w in three_lines.warnings))
    check("requiring_vouchers_without_a_key_refuses_to_load", "gen_voucher.py --show-pubkey" in refusal("gen_voucher.py --show-pubkey", lambda: load({"POPOPX_BILLING_REQUIRE_VOUCHER": "1", "POPOPX_OFFICIAL_ED25519_PUBLIC_KEY": None})))
    check("the_voucher_refusal_names_both_settings_it_needs", "POPOPX_BILLING_REQUIRE_VOUCHER" in refusal("POPOPX_BILLING_REQUIRE_VOUCHER", lambda: load({"POPOPX_BILLING_REQUIRE_VOUCHER": "1", "POPOPX_OFFICIAL_ED25519_PUBLIC_KEY": ""})))
    check("an_omitted_key_is_only_optional_when_admission_is_off",
          load({"POPOPX_OFFICIAL_ED25519_PUBLIC_KEY": None}).billing.official_ed25519_public_key is None
          and load({"POPOPX_BILLING_REQUIRE_VOUCHER": "0", "POPOPX_OFFICIAL_ED25519_PUBLIC_KEY": None}).billing.require_voucher is False)
    check("the_official_key_is_read_from_base64", load({"POPOPX_OFFICIAL_ED25519_PUBLIC_KEY": pub_b64}).billing.official_ed25519_public_key == key_bytes)
    check("the_official_key_is_read_from_hex", load({"POPOPX_OFFICIAL_ED25519_PUBLIC_KEY": pub_hex}).billing.official_ed25519_public_key == key_bytes)
    check("a_hex_key_survives_being_legal_base64_too", load({"POPOPX_OFFICIAL_ED25519_PUBLIC_KEY": pub_hex}).billing.official_ed25519_public_key == key_bytes and len(base64.b64decode(pub_hex, validate=True)) == 48)
    check("spaces_inside_the_key_are_ignored", load({"POPOPX_OFFICIAL_ED25519_PUBLIC_KEY": pub_hex[:32] + " " + pub_hex[32:]}).billing.official_ed25519_public_key == key_bytes)
    wrong_length = base64.b64encode(bytes(range(33))).decode("ascii")
    check("a_key_of_the_wrong_length_says_how_long_it_should_be", "44 base64 characters or 64 hex characters" in refusal("44 base64 characters or 64 hex characters", lambda: load({"POPOPX_OFFICIAL_ED25519_PUBLIC_KEY": wrong_length})))
    check("a_key_that_is_neither_base64_nor_hex_says_so", "neither valid base64 nor valid hex" in refusal("neither valid base64 nor valid hex", lambda: load({"POPOPX_OFFICIAL_ED25519_PUBLIC_KEY": "not-base64!!!"})))

    # ── 7. meters, plugins and the fields they land in ──────────────────────
    priced = load({("POPOPX_CP_" + attr.upper()): "13" for _action, attr in METER_ACTIONS})
    check("every_meter_env_key_round_trips_to_its_billing_field", all(getattr(priced.billing, attr) == 13 for _action, attr in METER_ACTIONS))
    meter_fields = {f.name for f in dataclasses.fields(BillingConfig)} - {"require_voucher", "suspend_threshold", "official_ed25519_public_key"}
    check("no_meter_field_exists_that_no_action_prices", meter_fields == {attr for _action, attr in METER_ACTIONS})
    cp_keys_from_actions = {"POPOPX_CP_" + attr.upper() for _action, attr in METER_ACTIONS}
    check("the_cp_table_agrees_with_the_engines_own_action_list", set(_CP_KEYS.values()) <= cp_keys_from_actions)
    check("no_two_metered_actions_share_one_env_key", len(set(_CP_KEYS.values())) == len(_CP_KEYS) and len(cp_keys_from_actions) == len(METER_ACTIONS))
    toggles = load({"POPOPX_PLUGIN_WEB3_BRIDGE": "1"})
    check("web3_bridge_is_off_until_an_operator_turns_it_on", three_lines.plugins.web3_bridge is False and toggles.plugins.web3_bridge is True)
    check("the_enabled_list_is_the_on_ones_in_declaration_order", three_lines.plugins.enabled == ["ai_agent", "alert_ops", "privacy_sso", "polls"])
    check("the_three_connectors_start_off", not (three_lines.plugins.workflow_webhook or three_lines.plugins.carddav_connector or three_lines.plugins.caldav_connector))
    for plugin in ("ai_agent", "alert_ops", "privacy_sso", "polls", "web3_bridge", "workflow_webhook", "carddav_connector", "caldav_connector"):
        name = "switching_off_%s_removes_it_from_the_enabled_list" % plugin
        check(name, plugin not in load({"POPOPX_PLUGIN_" + plugin.upper(): "0"}).plugins.enabled)
    check("every_plugin_toggle_is_a_named_field", {f.name for f in dataclasses.fields(PluginToggles)} == {"ai_agent", "alert_ops", "privacy_sso", "polls", "web3_bridge", "workflow_webhook", "carddav_connector", "caldav_connector"})

    # ── 8. vocabularies, keywords and the bounds a typo would breach ────────
    check("alert_min_severity_is_case_insensitive", load({"POPOPX_ALERT_MIN_SEVERITY": "CRITICAL"}).alert_min_severity == "critical")
    check("the_default_alert_floor_is_warning", three_lines.alert_min_severity == "warning")
    check("an_unknown_alert_severity_is_refused", "debug|info|warning|critical" in refusal("debug|info|warning|critical", lambda: load({"POPOPX_ALERT_MIN_SEVERITY": "notice"})))
    check("the_resolve_keywords_are_split_stripped_and_lowercased", load({"POPOPX_ALERT_RESOLVE_KEYWORDS": "Ack , 已处理 , ,RESOLVED"}).alert_resolve_keywords == ["ack", "已处理", "resolved"])
    check("the_default_resolve_keywords_survive_their_own_parse", three_lines.alert_resolve_keywords == ["确认", "已处理", "ack", "resolve"])
    check("a_blank_keyword_list_is_empty_not_a_list_of_one_empty_string", load({"POPOPX_ALERT_RESOLVE_KEYWORDS": " , , "}).alert_resolve_keywords == [])
    check("log_level_is_upper_cased", load({"POPOPX_LOG_LEVEL": "debug"}).log_level == "DEBUG")
    check("an_unknown_log_level_is_refused", "CRITICAL|ERROR|WARNING|INFO|DEBUG" in refusal("CRITICAL|ERROR|WARNING|INFO|DEBUG", lambda: load({"POPOPX_LOG_LEVEL": "verbose"})))
    check("debug_logging_warns_that_message_bodies_are_logged", any("message bodies" in w for w in load({"POPOPX_LOG_LEVEL": "DEBUG"}).warnings))

    def bounded(name: str, key: str, attr: str, low: str, high: str, inside: str) -> None:
        refuses("%s_refuses_its_floor" % name, "must be >=", lambda key=key, low=low: load({key: low}))
        refuses("%s_refuses_its_ceiling" % name, "must be <=", lambda key=key, high=high: load({key: high}))
        check("%s_accepts_a_value_inside_its_bounds" % name, str(getattr(load({key: inside}), attr)) == inside)

    bounded("sso_ttl", "POPOPX_SSO_TTL_SECONDS", "sso_ttl_seconds", "14", "3601", "120")
    bounded("sso_poll", "POPOPX_SSO_POLL_INTERVAL_MS", "sso_poll_interval_ms", "249", "20001", "1500")
    bounded("ai_max_tokens", "POPOPX_AI_MAX_TOKENS", "ai_max_tokens", "0", "8193", "256")

    def floored(name: str, key: str, attr: str, low: str, inside: str) -> None:
        refuses("%s_refuses_below_its_floor" % name, "must be >=", lambda key=key, low=low: load({key: low}))
        check("%s_accepts_a_value_above_its_floor" % name, str(getattr(load({key: inside}), attr)) == inside)

    floored("web3_poll", "POPOPX_WEB3_POLL_INTERVAL_SECONDS", "web3_poll_interval_seconds", "4", "15")
    floored("ai_rate_limit", "POPOPX_AI_RATE_LIMIT_MESSAGES", "ai_rate_limit_messages", "0", "5")

    # ── 9. defaults that a one-click run depends on ─────────────────────────
    check("the_node_defaults_are_loopback_with_files_off", three_lines.node.ws_url == "ws://127.0.0.1:5225" and three_lines.node.send_files is False and three_lines.node.service_requests is True and three_lines.node.reconnect_seconds == 3.0 and three_lines.node.command_timeout_seconds == 30.0)
    check("the_service_identity_defaults_are_the_paired_account", three_lines.service_name == "POPOPX 服务号" and three_lines.service_full_name == "POPOPX Service Account" and three_lines.service_id == "popopx.official")
    check("the_ai_defaults_are_a_hosted_model_and_a_restraint", three_lines.ai_model == "gpt-4o-mini" and three_lines.ai_max_tokens == 512 and "不索要任何个人身份信息" in three_lines.ai_system_prompt)
    check("the_public_rpc_defaults_are_two_chain_endpoints", three_lines.web3_evm_rpc_url == "https://eth.llamarpc.com" and three_lines.web3_solana_rpc_url == "https://api.mainnet-beta.solana.com")
    check("the_meter_defaults_match_the_published_price_list", [three_lines.billing.per_card, three_lines.billing.per_menu_push, three_lines.billing.per_key_rotation, three_lines.billing.per_ai_message, three_lines.billing.per_alert, three_lines.billing.per_sso_login, three_lines.billing.per_poll, three_lines.billing.per_web3_event, three_lines.billing.per_workflow_event, three_lines.billing.per_carddav_query, three_lines.billing.per_caldav_query] == [1, 1, 2, 5, 2, 1, 1, 1, 1, 1, 1])
    check("sso_defaults_are_a_three_minute_login", three_lines.sso_ttl_seconds == 180 and three_lines.sso_poll_interval_ms == 2000)

    # ── 10. warnings: the settings that run, but not as the operator means ──
    check("alert_ops_without_a_webhook_token_warns_and_says_401", any("ALERT_WEBHOOK_TOKEN" in w and "401" in w for w in load({"POPOPX_ALERT_WEBHOOK_TOKEN": None}).warnings))
    check("a_disabled_alert_ops_does_not_warn_about_its_token", not any("ALERT_WEBHOOK_TOKEN" in w for w in load({"POPOPX_ALERT_WEBHOOK_TOKEN": None, "POPOPX_PLUGIN_ALERT_OPS": "0"}).warnings))
    check("ai_agent_without_a_key_warns_for_a_hosted_endpoint", any("AI_API_KEY" in w for w in load({"POPOPX_AI_API_KEY": None}).warnings))
    check("a_loopback_ai_endpoint_does_not_warn_about_a_key", not any("AI_API_KEY" in w for w in load({"POPOPX_AI_API_KEY": None, "POPOPX_AI_BASE_URL": "http://127.0.0.1:11434/v1"}).warnings))
    check("a_key_for_a_loopback_endpoint_needs_no_warning", not any("AI_API_KEY" in w for w in load({"POPOPX_AI_BASE_URL": "http://localhost:11434/v1"}).warnings))
    check("a_world_readable_env_file_warns_about_its_mode", any("is mode 0644" in w and "POPOPX_ADMIN_TOKEN" in w for w in load(mode=0o644).warnings))
    check("a_group_readable_env_file_warns_too", any("is mode 0640" in w for w in load(mode=0o640).warnings))
    check("the_mode_warning_is_spelled_in_octal", any("should be 0600" in w for w in load(mode=0o604).warnings))
    check("owner_only_mode_is_quiet", load(mode=0o600).warnings == [])
    # A secret this short is not a weak key, it is an unused one: privacy_sso
    # refuses to mint from it, and the operator only finds out from a follower.
    short_h5 = load({"POPOPX_H5_SERVER_SECRET": "abc"})
    check("a_short_h5_server_secret_warns_that_it_will_not_be_used", any("POPOPX_H5_SERVER_SECRET" in w and "3 bytes" in w for w in short_h5.warnings))
    check("the_short_secret_warning_gives_the_fix", any("at least %d bytes or leave it empty" % _MIN_FALLBACK_KEY_BYTES in w for w in short_h5.warnings))
    check("a_long_enough_h5_server_secret_is_quiet", not any("H5_SERVER_SECRET" in w for w in load({"POPOPX_H5_SERVER_SECRET": "x" * _MIN_FALLBACK_KEY_BYTES}).warnings))
    check("an_empty_h5_server_secret_is_a_choice_not_a_mistake", not any("H5_SERVER_SECRET" in w for w in load({"POPOPX_H5_SERVER_SECRET": None}).warnings))
    check("a_multibyte_secret_is_measured_in_bytes_not_characters", any("15 bytes" in w for w in load({"POPOPX_H5_SERVER_SECRET": "字" * 5}).warnings))

    # ── 11. the shipped template, and the contract between the two files ────
    example = root / ".env.example"
    if not example.is_file():
        raise AssertionError("config self_test: %s is missing — the drift checks are meaningless without it" % example)
    example_keys = set(re.findall(r"^(POPOPX_[A-Z0-9_]+)=", example.read_text(encoding="utf-8"), re.M))
    from app.plugins.privacy_sso_plugin import _MIN_FALLBACK_KEY_BYTES as plugin_minimum

    check("the_fallback_key_minimum_agrees_with_the_plugin_that_enforces_it", plugin_minimum == _MIN_FALLBACK_KEY_BYTES)
    read_keys = {"POPOPX_" + name for name in re.findall(r'_ENV_PREFIX \+ "([A-Z0-9_]+)"', Path(__file__).read_text(encoding="utf-8"))} | {"POPOPX_ENV_FILE"}
    check("every_meter_env_key_is_documented", all("POPOPX_CP_" + attr.upper() in example_keys for _action, attr in METER_ACTIONS))
    check("every_setting_this_module_reads_is_documented", read_keys - example_keys == {"POPOPX_ENV_FILE"})
    check("env_example_documents_no_setting_this_module_ignores", example_keys - read_keys == {"POPOPX_NODE_IMAGE"})
    check("the_example_file_cannot_be_loaded_as_a_config", "POPOPX_ADMIN_TOKEN" in refusal("POPOPX_ADMIN_TOKEN", lambda: isolate(example, None, True)))
    # The example file promises "values shown are the defaults". That is a
    # machine-checkable claim for every numeric setting: a config loaded with
    # the key *absent* must be indistinguishable from one loaded with the key
    # present at the documented value. A drift here means an operator reads one
    # number in the template and runs on another.
    documented = dict(re.findall(r"^(POPOPX_[A-Z0-9_]+)=([0-9]+(?:\.[0-9]+)?)$", example.read_text(encoding="utf-8"), re.M))
    check("the_example_file_documents_numeric_settings", len(documented) >= 20)
    for key, value in sorted(documented.items()):
        name = "the_documented_default_for_%s_is_the_real_default" % key[len(_ENV_PREFIX) :].lower()
        with_key = isolate(write(dict(base_env, **{key: value})), None, True)
        without_key = isolate(write({k: v for k, v in dict(base_env).items() if k != key}), None, True)
        if dataclasses.asdict(with_key) != dataclasses.asdict(without_key):
            raise AssertionError("config self_test: %s is documented as %r in .env.example but omitting it changes the config" % (key, value))
        credit(name)

    # ── 12. re-load determinism: the same file, the same decisions ──────────
    twice_a = load({"POPOPX_BILLING_SUSPEND_THRESHOLD": "3"})
    twice_b = load({"POPOPX_BILLING_SUSPEND_THRESHOLD": "3"})
    check("two_loads_of_one_file_agree", dataclasses.asdict(twice_a) == dataclasses.asdict(twice_b))
    check("the_suspend_threshold_reaches_the_engine_field", twice_b.billing.suspend_threshold == 3)
    check("warnings_are_a_fresh_list_per_load", twice_a.warnings is not twice_b.warnings)
    check("the_node_and_billing_sub_structures_are_not_shared_between_loads", twice_a.node is not twice_b.node and twice_a.billing is not twice_b.billing)

    shutil.rmtree(tmp, ignore_errors=True)
    return checks
