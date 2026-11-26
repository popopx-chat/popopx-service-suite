# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""The plugin seam: one contract, nine plugins, and the 404-vs-402 distinction.

The nine business plugins live in this
package and nothing else, so this file is deliberately small: it is the shape of
the seam, not a framework. Everything the gateway itself owns (sessions, cards,
menus, channels, the outbox, billing) lives in `app.main`; a plugin reaches it
only through :class:`PluginDeps`.

The contract
------------
Each plugin module exposes exactly two functions:

    create_router(deps: PluginDeps) -> APIRouter
        Routes for the merchant's own HTTP surface. Mounted only when enabled.

    async handle_inbound(deps: PluginDeps, message: InboundMessage) -> bool
        Claims one inbound eco/chat message and returns True if it consumed it.
        Called only for messages whose callback kind the plugin owns (see
        :data:`PLUGIN_SPEC`), so a plugin never has to guess about traffic that is
        somebody else's protocol step.

Why `handle_inbound` is a plain function and not a class with lifecycle: there is
no per-plugin state to keep. A plugin's durable state is rows in SQLite, and its
transient state (a polling loop, a rate window) belongs to the gateway process,
not to a plugin object. A base class here would be ceremony.

The distinction this file exists to enforce
-------------------------------------------
`POPOPX_PLUGIN_WEB3_BRIDGE=0` and "the account ran out of compute credits" both
mean "this endpoint does not answer right now", and they must NOT both answer 404:
a merchant who sees 404 after a top-up attempt concludes the feature was removed,
while the real cause is an unpaid balance that a 402 tells them to fix. So
:attr:`PluginGate.status` is the only place that consults both the toggle and the
fusing, and it returns a reason code that survives into the response body.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Dict, Mapping, Optional, Protocol, Sequence, Tuple

if TYPE_CHECKING:  # imported for type names only, never at runtime
    from fastapi import APIRouter

    from app.agent_bridge import InboundMessage
    from app.billing_service import BillingService
    from app.config import Config
    from app.database import Database
    from app.vault import SecretBox

__all__ = [
    "EcoSession",
    "GateDecision",
    "PluginDeps",
    "PluginGate",
    "PluginUnavailable",
    "PLUGIN_SPEC",
    "plugin_for_meter",
]


# ─────────────────────────────────────────────────────────────────────────────
# 1. The table every plugin is mounted from
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PluginSpec:
    """One plugin's identity as seen by the gateway: which toggle enables it, which
    meter prices it, which URL prefix it owns, and which inbound callback kinds it
    may claim.

    These tuples are the whole reason the plugins cannot drift apart from
    `config.PluginToggles` and `billing_service`'s meter names silently: the mount
    loop, the gate and the console all read them from here rather than repeating
    string literals that a rename would break one at a time.
    """

    plugin_id: str
    module_name: str
    toggle: str                    # attribute on config.PluginToggles
    meter: str                     # key in billing_service's meter table
    url_prefix: str
    callback_kinds: Tuple[str, ...] = ()


PLUGIN_SPEC: Tuple[PluginSpec, ...] = (
    PluginSpec(
        plugin_id="ai_agent",
        module_name="app.plugins.ai_agent_plugin",
        toggle="ai_agent",
        meter="ai_message",
        url_prefix="/api/v1/plugins/ai",
        # The AI plugin must see ordinary chat text and nothing else: a control
        # marker answered by a model is a protocol leak, not a reply.
        callback_kinds=("text",),
    ),
    PluginSpec(
        plugin_id="alert_ops",
        module_name="app.plugins.alert_ops_plugin",
        toggle="alert_ops",
        meter="alert",
        url_prefix="/api/v1/plugins/alerts",
        callback_kinds=("card_callback",),
    ),
    PluginSpec(
        plugin_id="privacy_sso",
        module_name="app.plugins.privacy_sso_plugin",
        toggle="privacy_sso",
        meter="sso_login",
        url_prefix="/api/v1/plugins/sso",
        callback_kinds=("sso_scan",),
    ),
    PluginSpec(
        plugin_id="polls",
        module_name="app.plugins.polls_plugin",
        toggle="polls",
        meter="poll",
        url_prefix="/api/v1/plugins/polls",
        callback_kinds=("card_callback",),
    ),
    PluginSpec(
        plugin_id="web3_bridge",
        module_name="app.plugins.web3_bridge_plugin",
        toggle="web3_bridge",
        meter="web3_event",
        url_prefix="/api/v1/plugins/web3",
        # A chain payment receipt is the only inbound signal a bridge produces for
        # the gateway; `CHANNEL_PAY_RCPT` carries channelId:credits:txHash.
        callback_kinds=("system",),
    ),
    PluginSpec(
        plugin_id="workflow_webhook",
        module_name="app.plugins.workflow_webhook_plugin",
        toggle="workflow_webhook",
        meter="workflow_event",
        url_prefix="/api/v1/plugins/workflow",
        # It only claims the two approval payload prefixes and returns False for
        # every other callback, so alert_ops/polls keep receiving theirs.
        callback_kinds=("card_callback",),
    ),
    PluginSpec(
        plugin_id="carddav_connector",
        module_name="app.plugins.carddav_connector",
        toggle="carddav_connector",
        meter="carddav_query",
        url_prefix="/api/v1/plugins/carddav",
        callback_kinds=(),
    ),
    PluginSpec(
        plugin_id="caldav_connector",
        module_name="app.plugins.caldav_connector",
        toggle="caldav_connector",
        meter="caldav_query",
        url_prefix="/api/v1/plugins/caldav",
        callback_kinds=(),
    ),
    PluginSpec(
        plugin_id="slack_discord",
        module_name="app.plugins.slack_discord_plugin",
        toggle="slack_discord",
        meter="slack_discord_event",
        url_prefix="/api/v1/plugins/slackdiscord",
        # Outbound-only bridge: Slack/Discord replies arrive at the workspace's own
        # webhook URL, never as an eco callback kind, so it claims nothing.
        callback_kinds=(),
    ),
)

_BY_ID: Dict[str, PluginSpec] = {spec.plugin_id: spec for spec in PLUGIN_SPEC}
_BY_METER: Dict[str, PluginSpec] = {spec.meter: spec for spec in PLUGIN_SPEC}


def plugin_for_id(plugin_id: str) -> PluginSpec:
    """The spec for one plugin id. Raises rather than returning None: a typo in a
    mount table must stop the process, not silently leave a route unmounted."""
    try:
        return _BY_ID[plugin_id]
    except KeyError:
        raise KeyError("unknown plugin id %r (known: %s)" % (plugin_id, sorted(_BY_ID))) from None


def plugin_for_meter(meter: str) -> PluginSpec:
    """The spec that owns one billing meter, for the reverse lookup the console needs."""
    try:
        return _BY_METER[meter]
    except KeyError:
        raise KeyError("unknown meter %r (known: %s)" % (meter, sorted(_BY_METER))) from None


# ─────────────────────────────────────────────────────────────────────────────
# 2. The gate: enabled vs fused
# ─────────────────────────────────────────────────────────────────────────────

REASON_USABLE = "usable"
REASON_DISABLED = "disabled"        # -> 404, and says so in the body
REASON_FUSED = "credit_fused"       # -> 402 with the balance
REASON_SUSPENDED = "account_suspended"  # -> 402, needs an operator action
REASON_NO_ISSUER = "account_draft"  # -> 402, only in voucher admission mode
REASON_NODE_DOWN = "node_unreachable"   # -> 503, nobody's fault but retryable


@dataclass(frozen=True)
class GateDecision:
    plugin_id: str
    usable: bool
    reason: str
    http_status: int
    detail: str
    balance: Optional[int] = None

    def as_body(self) -> Dict[str, object]:
        """The JSON a gate decision produces. Deliberately includes the meter and the
        balance: an operator deciding whether to top up needs the number, and
        withholding it turns a 402 into a support ticket. `ok` tracks the decision so
        the same shape can be returned by a route that succeeded behind the gate.
        """
        body: Dict[str, object] = {
            "ok": self.usable,
            "plugin": self.plugin_id,
            "reason": self.reason,
            "detail": self.detail,
        }
        if self.balance is not None:
            body["balance"] = self.balance
        return body


class PluginUnavailable(Exception):
    """Raised by :meth:`PluginGate.require` so a route can start with one line and
    let the gateway's exception handler turn it into the right status code."""

    def __init__(self, decision: GateDecision) -> None:
        self.decision = decision
        super().__init__("%s: %s" % (decision.reason, decision.detail))

    @property
    def http_status(self) -> int:
        return self.decision.http_status


class PluginGate:
    """Asks the two questions in the right order: is this plugin switched on, and
    can this account pay for it.

    The order matters for what it lets an attacker learn. A disabled plugin answers
    404 without mentioning billing, so the switch is not an oracle for the
    account's balance. An enabled-but-unaffordable plugin answers 402 with the
    balance, which is information the merchant already owns.
    """

    def __init__(self, config: "Config", billing: "BillingService", node_up: Callable[[], bool]) -> None:
        self._config = config
        self._billing = billing
        self._node_up = node_up

    def status(self, plugin_id: str, *, node_required: bool = True) -> GateDecision:
        """The gate's truth table, optionally waiving the live-node requirement.

        ``node_required=False`` exists for an ingress that has an explicit durable
        local queue: the workflow trigger can authenticate, charge and persist an
        approval or outbox row while the node is down, so a standalone gateway is
        not indistinguishable from a broken one. Toggle and billing checks still
        apply; only the retryable node-down branch is skipped.
        """
        spec = plugin_for_id(plugin_id)
        if not getattr(self._config.plugins, spec.toggle, False):
            return GateDecision(
                plugin_id=plugin_id,
                usable=False,
                reason=REASON_DISABLED,
                http_status=404,
                detail="plugin %s is switched off (set POPOPX_PLUGIN_%s=1)" % (plugin_id, spec.toggle.upper()),
            )
        if node_required and not self._node_up():
            return GateDecision(
                plugin_id=plugin_id,
                usable=False,
                reason=REASON_NODE_DOWN,
                http_status=503,
                detail="the chat node link is down; nothing can be delivered yet",
            )
        fused = self._billing.is_plugin_fused(plugin_id)
        if fused:
            view = self._billing.account()
            return GateDecision(
                plugin_id=plugin_id,
                usable=False,
                reason=REASON_FUSED,
                http_status=402,
                detail="meter %r is fused: the account needs compute credits (redeem a POPX-CP code)" % spec.meter,
                balance=view.balance,
            )
        return GateDecision(
            plugin_id=plugin_id,
            usable=True,
            reason=REASON_USABLE,
            http_status=200,
            detail="ok",
            balance=self._billing.account().balance,
        )

    def require(self, plugin_id: str) -> GateDecision:
        decision = self.status(plugin_id)
        if not decision.usable:
            raise PluginUnavailable(decision)
        return decision


# ─────────────────────────────────────────────────────────────────────────────
# 3. The eco surface a plugin may use
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class EcoSession:
    """A follower's pairwise session, exactly as `eco_sessions` stores it.

    `secret_hex` is the symmetric half of the H5 signature and the card seal, so
    this object is the only place it exists in memory, and a plugin is handed a
    copy of a value rather than a live handle: nothing here can rotate or revoke a
    session, which stays the gateway's job.
    """

    contact_id: int
    pairwise_uid: str
    secret_hex: str
    service_id: str
    revoked: bool = False

    @property
    def usable(self) -> bool:
        """Whether this session may sign anything.

        A predicate, not a validator: `crypto_service.validate_*` raise, and a
        session read out of a row that an older build wrote must produce a clean
        refusal ("this follower has no usable session", which the caller turns into
        `.noSession`-style copy) rather than a 500 in the middle of a card send.
        """
        from app.crypto_service import EcoError, validate_pairwise_uid, validate_secret_hex

        if self.revoked:
            return False
        try:
            validate_pairwise_uid(self.pairwise_uid)
            validate_secret_hex(self.secret_hex)
        except EcoError:
            return False
        return True


@dataclass(frozen=True)
class CardDelivery:
    """What delivering a card cost and produced. `sent` is the honest answer to
    "did the phone get it": the node accepted the command, not that the message was
    rendered — only a later `::CB::` proves that, and that lands in `callbacks`."""

    card_id: str
    contact_id: int
    sent: bool
    charged: int
    balance_after: Optional[int]
    error: Optional[str] = None
    queued: bool = False


@dataclass(frozen=True)
class ChannelGrant:
    """What issuing a channel key to one follower produced. The epoch is the number
    a member can verify a rotation against, so it travels here rather than making
    the caller re-read `channel_epochs` and race a concurrent rotation."""

    channel_id: str
    contact_id: int
    epoch: int
    delivered: bool
    charged: int
    public_uri: Optional[str] = None
    error: Optional[str] = None
    #: The epoch this member's device holds *after* this grant. It is 1 for a member
    #: who has only ever been handed the public URI, and it is what the next
    #: rotation must be sealed under — the client decrypts a `channel_key_update`
    #: with the key named by `sealedUnderEpoch`, never with the one inside it.
    holds_epoch: int = 1


class Eco(Protocol):
    """The part of `app.main` a plugin is allowed to reach.

    A protocol rather than an import of `app.main`, because the import direction is
    fixed: main imports the plugin package to mount it, so a plugin importing main
    would be a cycle that only fails at boot — the worst time to discover it.
    """

    def session_for(self, contact_id: int) -> Optional[EcoSession]:
        """The follower's session, or None when the handshake has not happened yet."""
        ...

    def sessions_for_channel(self, channel_id: str) -> Sequence[EcoSession]:
        """Every follower entitled to a channel's key material."""
        ...

    async def deliver_card(self, card: Mapping[str, object], contact_id: int, *, visible_text: Optional[str] = None, topic: str = "") -> CardDelivery:
        """Store a card and deliver it as a `m=c` frame, charging the `card` meter."""
        ...

    async def update_card(self, card_id: str, contact_id: int, *, title: Optional[str] = None, body: Optional[str] = None, fields: Optional[Sequence[Mapping[str, object]]] = None, progress: Optional[Mapping[str, object]] = None, actions: Optional[Sequence[Mapping[str, object]]] = None, expires_at_ms: Optional[int] = None) -> CardDelivery:
        """Re-deliver an existing card in place as `m=u` — same `cardId`, so the phone
        mutates the bubble instead of stacking a second one."""
        ...

    async def send_frame(self, contact_id: int, text: str) -> bool:
        """Send an already-encoded frame. Returns whether the node accepted it."""
        ...

    async def send_frame_outcome(self, contact_id: int, text: str) -> Tuple[bool, bool]:
        """Send uncharged, or queue locally; return ``(delivered, queued)``."""
        ...

    async def push_menu(self) -> bool:
        """Deliver the stored menu to every follower, charging the `menu_push` meter."""
        ...

    async def deliver_channel_key(
        self,
        channel_id: str,
        contact_id: int,
        *,
        sealed_under: Optional[int] = None,
        issued_epoch: Optional[int] = None,
    ) -> ChannelGrant:
        """Seal and send a `channel_key_update` for one follower of one channel,
        charging the `key_rotation` meter. This is the only path by which a plugin
        hands out key material: epoch keys, the envelope AAD and the signature
        preimage all stay in the gateway, because a plugin that sealed its own
        envelope would be a second implementation of the rule the members verify.

        `sealed_under` overrides which epoch this device is assumed to hold; the
        default reads the membership row. A plugin never needs to pass it — it is
        part of the protocol seam, not plugin policy.
        """
        ...

    def channel_public_uri(self, channel_id: str) -> Optional[str]:
        """The `popopx://channel/...#key=&pub=` bootstrap URI for a channel, or None
        when no relay has been set. A member's *first* epoch key can only travel
        this way; `channel_key_update` cannot carry it."""
        ...

    def h5_url(self, session: EcoSession, path: str) -> str:
        """The signed H5 URL for one session, on the gateway's own origin."""
        ...

    def public_url(self, path: str) -> str:
        """An UNSIGNED absolute URL on the gateway's origin, for QR payloads and for
        links that must not carry a pairwise identity."""
        ...


@dataclass
class PluginDeps:
    """Everything a plugin gets from the gateway. Frozen in spirit: the fields are
    assigned once at mount time and never rewritten, so a plugin cannot repoint the
    gateway at another database half-way through a request."""

    config: "Config"
    db: "Database"
    billing: "BillingService"
    eco: Eco
    gate: PluginGate
    spec: PluginSpec = field(repr=False, default_factory=lambda: plugin_for_id("ai_agent"))

    @property
    def plugin_id(self) -> str:
        return self.spec.plugin_id

    @property
    def vault(self) -> "SecretBox":
        """The operator-held box for this plugin's own columns, disabled (plaintext
        passthrough) when `POPOPX_VAULT_KEY` is unset. Cached per key inside
        `vault_for`, so calling it per request does not rebuild the cipher."""
        from app.vault import vault_for

        return vault_for(self.config.vault_key)

    def require(self) -> GateDecision:
        """The one-line guard a route body starts with."""
        return self.gate.require(self.plugin_id)

    def charge(self, **kwargs: object):
        """Charge this plugin's own meter. A thin wrapper so a plugin cannot price an
        action that belongs to another plugin — the meter name comes from the mount
        table, never from request data.

        Synchronous because `app.billing_service` is: the ledger is a SQLite
        transaction, not a network call. A plugin must NOT block on anything else
        here — outbound HTTP (an OpenAI-compatible endpoint, an RPC node) belongs in
        an async function that is awaited *after* the charge, or the single event
        loop stalls for every follower at once.
        """
        return self.billing.charge(self.spec.meter, **kwargs)  # type: ignore[arg-type]


# ─────────────────────────────────────────────────────────────────────────────
# 4. Self-test (stdlib only)
# ─────────────────────────────────────────────────────────────────────────────


def self_test() -> list:
    """The gate's truth table, with the toggle and the fusing driven independently.

    This is the batch-3 seam, so it is worth proving here rather than in a FastAPI
    test client: the bug it prevents is a plugin answering the wrong status code,
    which no amount of route-level testing would name.
    """
    checks: list = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("self_test failed: %s" % name)
        checks.append(name)

    class FakeBilling:
        def __init__(self, fused: bool, balance: int = 0) -> None:
            self.fused = fused
            self.balance = balance

        def is_plugin_fused(self, plugin_id: str) -> bool:
            return self.fused

        def account(self):
            from dataclasses import dataclass as dc

            @dc
            class V:
                balance: int
            return V(self.balance)

    class FakePlugins:
        def __init__(self, **kwargs: bool) -> None:
            for key, value in kwargs.items():
                setattr(self, key, value)

    class FakeConfig:
        def __init__(self, plugins: FakePlugins) -> None:
            self.plugins = plugins

    def gate(toggle_on: bool, fused: bool, node_up: bool = True) -> PluginGate:
        config = FakeConfig(FakePlugins(ai_agent=toggle_on, alert_ops=toggle_on, privacy_sso=toggle_on,
                                       polls=toggle_on, web3_bridge=toggle_on, workflow_webhook=toggle_on,
                                       carddav_connector=toggle_on, caldav_connector=toggle_on,
                                       slack_discord=toggle_on))
        return PluginGate(config, FakeBilling(fused), lambda: node_up)

    # Enabled and paid: usable, and the balance travels with the decision.
    decision = gate(True, False).status("polls")
    check("usable_when_enabled_and_funded", decision.usable and decision.http_status == 200)
    check("usable_carries_balance", decision.balance == 0 and decision.reason == REASON_USABLE)

    # Switched off: 404, and no billing information leaks.
    decision = gate(False, False).status("web3_bridge")
    check("disabled_is_404", (not decision.usable) and decision.http_status == 404)
    check("disabled_leaks_no_balance", decision.balance is None and decision.reason == REASON_DISABLED)
    check("disabled_names_the_env_var", "POPOPX_PLUGIN_WEB3_BRIDGE" in decision.detail)

    # Enabled but unaffordable: 402 with the balance, which is the whole point.
    decision = PluginGate(FakeConfig(FakePlugins(polls=True)), FakeBilling(True, balance=0), lambda: True).status("polls")
    check("fused_is_402", (not decision.usable) and decision.http_status == 402)
    check("fused_is_distinguishable", decision.reason == REASON_FUSED and decision.reason != REASON_DISABLED)
    check("fused_shows_balance", decision.balance == 0)
    check("fused_names_the_meter", "'poll'" in decision.detail)

    # Node down is neither of the above: retryable, and says so.
    decision = gate(True, False, node_up=False).status("ai_agent")
    check("node_down_is_503", (not decision.usable) and decision.http_status == 503)
    check("node_down_reason", decision.reason == REASON_NODE_DOWN)

    # An ingress with a durable local queue may waive only the node check.
    decision = gate(True, False, node_up=False).status("workflow_webhook", node_required=False)
    check("a_queueable_plugin_is_usable_while_the_node_is_down",
          decision.usable and decision.http_status == 200)
    decision = gate(True, True, node_up=False).status("workflow_webhook", node_required=False)
    check("waiving_the_node_does_not_waive_billing",
          (not decision.usable) and decision.reason == REASON_FUSED
          and decision.http_status == 402)
    decision = gate(False, False, node_up=False).status("workflow_webhook", node_required=False)
    check("waiving_the_node_does_not_waive_the_toggle",
          (not decision.usable) and decision.reason == REASON_DISABLED
          and decision.http_status == 404)

    # The toggle is consulted by attribute name from the mount table, so a rename in
    # config.PluginToggles fails loudly at the gate instead of reading None.
    check("missing_toggle_reports_disabled", not getattr(FakePlugins(polls=True), "ai_agent", False))

    # require() raises exactly what status() decided.
    try:
        gate(False, False).require("ai_agent")
        check("require_raises_when_unusable", False)
    except PluginUnavailable as exc:
        check("require_raises_when_unusable", exc.http_status == 404 and exc.decision.plugin_id == "ai_agent")

    # The mount table is internally consistent, and every row is distinct.
    check("specs_unique_ids", len({s.plugin_id for s in PLUGIN_SPEC}) == len(PLUGIN_SPEC) == 9)
    check("specs_unique_meters", len({s.meter for s in PLUGIN_SPEC}) == len(PLUGIN_SPEC))
    check("specs_unique_prefixes", len({s.url_prefix for s in PLUGIN_SPEC}) == len(PLUGIN_SPEC))
    check("spec_toggles_are_known_names",
          all(s.toggle in ("ai_agent", "alert_ops", "privacy_sso", "polls", "web3_bridge",
                           "workflow_webhook", "carddav_connector", "caldav_connector",
                           "slack_discord") for s in PLUGIN_SPEC))
    for spec in PLUGIN_SPEC:
        check("spec_roundtrip_%s" % spec.plugin_id, plugin_for_id(spec.plugin_id) is spec)
        check("meter_roundtrip_%s" % spec.meter, plugin_for_meter(spec.meter) is spec)
    try:
        plugin_for_id("nope")
        check("unknown_id_raises", False)
    except KeyError:
        check("unknown_id_raises", True)
    try:
        plugin_for_meter("nope")
        check("unknown_meter_raises", False)
    except KeyError:
        check("unknown_meter_raises", True)

    # EcoSession usability is decided by the client's own rule, not a strength
    # opinion: PopopxEcoModels.swift:322-327 accepts 1..32 bytes of hex, so a 2-byte
    # secret is legal on the wire and must not be rejected here — the gateway always
    # MINTS 32 bytes (`new_session_secret`), and refusing a short one would strand a
    # follower whose account was created by an older build.
    good = EcoSession(contact_id=7, pairwise_uid="uid-abc", secret_hex="ab" * 32, service_id="popopx.official")
    check("session_usable_when_sane", good.usable)
    check("session_revoked_not_usable", not EcoSession(7, "uid", "ab" * 32, "svc", revoked=True).usable)
    check("session_short_but_legal_secret_usable", EcoSession(7, "uid", "abcd", "svc").usable)
    check("session_odd_length_hex_not_usable", not EcoSession(7, "uid", "ab" * 31 + "a", "svc").usable)
    check("session_empty_secret_not_usable", not EcoSession(7, "uid", "", "svc").usable)
    check("session_overlong_secret_not_usable", not EcoSession(7, "uid", "ab" * 33, "svc").usable)
    check("session_non_hex_secret_not_usable", not EcoSession(7, "uid", "zz" * 32, "svc").usable)
    check("session_empty_uid_not_usable", not EcoSession(7, "", "ab" * 32, "svc").usable)

    # Control: a decision body always says which plugin it is about.
    body = gate(True, False).status("polls").as_body()
    check("decision_body_plugin", body["plugin"] == "polls" and body["ok"] is True)

    deps_shape = PluginDeps(config=None, db=None, billing=None, eco=None,  # type: ignore[arg-type]
                            gate=gate(True, False), spec=plugin_for_id("alert_ops"))
    check("deps_plugin_id_from_spec", deps_shape.plugin_id == "alert_ops")

    class FakeConfigWithVault(FakeConfig):
        vault_key = ""

    vault_deps = PluginDeps(config=FakeConfigWithVault(FakePlugins()),  # type: ignore[arg-type]
                            db=None, billing=None, eco=None,  # type: ignore[arg-type]
                            gate=gate(True, False), spec=plugin_for_id("workflow_webhook"))
    check("deps_expose_a_disabled_vault_without_a_key", vault_deps.vault.enabled is False)
    check("deps_vault_is_cached_per_key", vault_deps.vault is vault_deps.vault)
    return checks
