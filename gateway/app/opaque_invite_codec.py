# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Opaque invite links: the public share form of a connection URI.

The gateway's connection URIs contain the relay host (`smpN.popopx.im`). That is
an operational detail, not part of what a follower is being invited to, and a
link pasted into a chat app should not advertise it to every link preview,
screenshot and forward. This module wraps the raw URI in an authenticated
envelope and exposes it as one path-shaped URL:

    https://popopx.chat/i/v1/<unpadded-base64url(nonce || ciphertext || tag)>

Format v1 is fixed on purpose, not versioned away from:

* HKDF-SHA256 derives a 32-byte key from a **published** 32-byte IKM, a fixed
  salt and a fixed info string. The key is a format key, not a secret: any
  client may derive it, which is what makes a link decodable by an app that has
  never talked to this gateway. It hides the relay from casual view and from
  link previews; it is not confidentiality against someone who reads this file.
* A 12-byte nonce is generated per link with `secrets.token_bytes`. The same URI
  therefore produces a different link every time, and a link cannot be compared
  to another without decoding it.
* ChaCha20-Poly1305 authenticates the payload with a fixed AAD. A single flipped
  bit anywhere in the ciphertext, tag, nonce or version is rejected; a link is
  either intact or it is not an invite link.
* Base64URL is unpadded so the code can live in a path segment, URL fragment or
  QR payload without percent-encoding.

The literal form `https://popopx.chat.<ciphertext>` from an early brief is not
usable: DNS labels cap at 63 characters, the ciphertext is longer than that, and
the last label would be read as a TLD. The path form keeps the link on the
associated domain `popopx.chat`, which is the only host the shipped iOS client
accepts for an HTTPS invite.

Wrong-version and wrong-shape links fail closed. The one operation that must
never raise is :func:`mask_invite_link`, because it is used on the logging path;
it answers a fixed ellipsis instead.
"""

from __future__ import annotations

import base64
import re
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional

__all__ = [
    "LINK_PREFIX",
    "InviteCodecError",
    "encode_invite",
    "decode_invite",
    "seal_invite_code",
    "open_invite_code",
    "mask_invite_link",
    "mask_invite_code",
    "invite_code_prefix",
    "is_opaque_invite_link",
    "opaque_invite_self_test",
]

# ─────────────────────────────────────────────────────────────────────────────
# 1. Format v1 — fixed, published, cross-language constants
# ─────────────────────────────────────────────────────────────────────────────

VERSION = "v1"
LINK_PREFIX = "https://popopx.chat/i/%s/" % VERSION

#: Published format key material. Changing any of these constants is a new link
#: format, not a configuration change: every link ever exported becomes
#: undecodable unless the old derivation inputs are kept beside the new ones.
IKM = bytes.fromhex("d1abbcb09b5bf244d9d8b6b1dcc38835b5a419d8a1d62b014c1bb49e765dbdeb")
SALT = b"popopx.chat/invite-link/v1/salt"
INFO = b"popopx.chat/invite-link/v1/key"
AAD = b"popopx.chat/invite-link/v1/aad"

NONCE_BYTES = 12
TAG_BYTES = 16
KEY_BYTES = 32
MAX_URI_BYTES = 2048
MAX_SEALED_BYTES = NONCE_BYTES + MAX_URI_BYTES + TAG_BYTES
MAX_LINK_CHARS = len(LINK_PREFIX) + 4 * ((MAX_SEALED_BYTES + 2) // 3)

#: A connection URI is what the codec accepts. This is deliberately narrower
#: than "any string": a wrapper that will happily seal `javascript:` or a
#: follower-visible banner is a phishing primitive with a trusted domain.
URI_SCHEMES = ("popopx:/", "popopx://", "https://")

_CODE_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_PREFIX_LEN = len(LINK_PREFIX)

#: RFC 5869 test case 1, used to prove the HKDF wrapper itself before the
#: invite vectors prove the composition. (IKM, salt, info, L, OKM)
_HKDF_RFC5869_CASE1 = (
    bytes.fromhex("0b" * 22),
    bytes.fromhex("000102030405060708090a0b0c"),
    bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
    42,
    bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    ),
)


class InviteCodecError(ValueError):
    """A link or URI the codec refuses. `.code` is the stable reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail or code
        super().__init__("%s: %s" % (code, self.detail))


def _crypto() -> Any:
    """Import the wheel lazily, like `crypto_service`, and name its absence."""
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError as exc:  # pragma: no cover — deployment state, not a code path
        raise InviteCodecError(
            "invite_crypto_unavailable",
            "opaque invite links need the `cryptography` package "
            "(pip install -r gateway/requirements.txt)",
        ) from exc
    return hashes, HKDF, ChaCha20Poly1305, InvalidTag


def derive_key(ikm: bytes, salt: bytes, info: bytes, length: int = KEY_BYTES) -> bytes:
    """HKDF-SHA256, exposed by name so a vector can test it separately."""
    hashes, HKDF, _aead, _invalid = _crypto()
    return HKDF(algorithm=hashes.SHA256(), length=int(length), salt=salt, info=info).derive(ikm)


def format_key() -> bytes:
    """The published 32-byte format key."""
    return derive_key(IKM, SALT, INFO)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(text: str) -> bytes:
    if not _CODE_RE.fullmatch(text):
        raise InviteCodecError("invite_code_invalid", "expected unpadded base64url")
    try:
        # `validate=True` still wants the padding character to be present; the
        # wire form is unpadded, so restore exactly what RFC 4648 elides.
        return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise InviteCodecError("invite_code_invalid", "base64url did not decode") from exc


def _validate_uri(uri: str) -> str:
    if not isinstance(uri, str) or not uri:
        raise InviteCodecError("invite_uri_required", "a non-empty connection URI is required")
    if uri != uri.strip():
        raise InviteCodecError("invite_uri_invalid", "leading or trailing whitespace")
    if not uri.startswith(URI_SCHEMES):
        raise InviteCodecError(
            "invite_uri_scheme_invalid",
            "expected a popopx:/ or https:// connection URI",
        )
    try:
        payload = uri.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise InviteCodecError("invite_uri_invalid", "not valid UTF-8") from exc
    if len(payload) > MAX_URI_BYTES:
        raise InviteCodecError(
            "invite_uri_too_long",
            "%d bytes exceeds %d" % (len(payload), MAX_URI_BYTES),
        )
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F or ch.isspace() for ch in uri):
        raise InviteCodecError("invite_uri_invalid", "control characters or whitespace")
    return uri


def seal_invite_code(uri: str, *, nonce: Optional[bytes] = None) -> str:
    """Seal one URI and return the bare Base64URL code (no link prefix)."""
    text = _validate_uri(uri)
    hashes, _hkdf, ChaCha20Poly1305, _invalid = _crypto()
    nonce_bytes = secrets.token_bytes(NONCE_BYTES) if nonce is None else bytes(nonce)
    if len(nonce_bytes) != NONCE_BYTES:
        raise InviteCodecError(
            "invite_nonce_invalid", "expected %d bytes, got %d" % (NONCE_BYTES, len(nonce_bytes))
        )
    aead = ChaCha20Poly1305(format_key())
    sealed = nonce_bytes + aead.encrypt(nonce_bytes, text.encode("utf-8"), AAD)
    return _b64url(sealed)


def encode_invite(uri: str, *, nonce: Optional[bytes] = None) -> str:
    """The public form: `https://popopx.chat/i/v1/<code>`."""
    return LINK_PREFIX + seal_invite_code(uri, nonce=nonce)


def invite_code_from_link(link: str) -> str:
    if not isinstance(link, str) or not link.startswith(LINK_PREFIX):
        raise InviteCodecError(
            "invite_link_version_unsupported",
            "expected %s<code>" % LINK_PREFIX,
        )
    code = link[_PREFIX_LEN:]
    if not code or len(code) > MAX_LINK_CHARS - _PREFIX_LEN:
        raise InviteCodecError("invite_link_invalid", "empty or oversized code")
    return code


def open_invite_code(code: str) -> str:
    """Open a bare code. Raises `invite_link_tampered` for any AEAD failure."""
    raw = _unb64url(code)
    if len(raw) < NONCE_BYTES + TAG_BYTES:
        raise InviteCodecError("invite_link_invalid", "shorter than a nonce and a tag")
    if len(raw) > MAX_SEALED_BYTES:
        raise InviteCodecError("invite_link_too_long", "sealed payload exceeds the v1 limit")
    hashes, _hkdf, ChaCha20Poly1305, InvalidTag = _crypto()
    nonce, body = raw[:NONCE_BYTES], raw[NONCE_BYTES:]
    try:
        plaintext = ChaCha20Poly1305(format_key()).decrypt(nonce, body, AAD)
    except InvalidTag as exc:
        raise InviteCodecError(
            "invite_link_tampered",
            "the authenticated envelope did not verify",
        ) from exc
    try:
        uri = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InviteCodecError("invite_link_invalid", "payload is not UTF-8") from exc
    return _validate_uri(uri)


def decode_invite(link: str) -> str:
    """Open an opaque link and return the raw connection URI it carries."""
    return open_invite_code(invite_code_from_link(link))


def is_opaque_invite_link(value: Any) -> bool:
    """Shape check only; it does not prove the envelope authenticates."""
    if not isinstance(value, str) or not value.startswith(LINK_PREFIX):
        return False
    try:
        invite_code_from_link(value)
    except InviteCodecError:
        return False
    return True


def invite_code_prefix(link: Any, length: int = 10) -> str:
    """The masked prefix an audit row may keep. Never the whole code."""
    try:
        code = invite_code_from_link(link) if isinstance(link, str) else ""
    except InviteCodecError:
        return ""
    return code[: max(0, int(length))]


def mask_invite_link(link: Any) -> str:
    """Safe for logs: `https://popopx.chat/i/v1/<10 chars>…`, or a lone ellipsis."""
    prefix = invite_code_prefix(link)
    return "%s%s…" % (LINK_PREFIX, prefix) if prefix else "…"


def mask_invite_code(code: Any) -> str:
    if not isinstance(code, str) or not _CODE_RE.fullmatch(code):
        return "…"
    return "%s…" % code[:10] if code else "…"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Self-test — fixed vectors, tamper rejection, leak checks
# ─────────────────────────────────────────────────────────────────────────────

VECTORS_PATH = Path(__file__).with_name("opaque_invite_vectors.json")


def load_vectors(path: Optional[Path] = None) -> Dict[str, Any]:
    import json

    target = path or VECTORS_PATH
    try:
        loaded = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AssertionError(
            "opaque invite vectors are missing at %s — the Dockerfile copies gateway/app, "
            "so this file must live beside the codec" % target
        ) from exc
    if not isinstance(loaded, dict) or not isinstance(loaded.get("vectors"), list) or not loaded["vectors"]:
        raise AssertionError("opaque invite vectors file has no vectors: %s" % target)
    return loaded


def _flip_last_sealed_byte(code: str) -> str:
    """Change one bit of the tag, not one base64 character.

    Flipping a character can leave the decoded bytes untouched: the final
    base64 digit carries padding bits that `b64decode` discards. A tamper test
    that can produce the same bytes would pass for the wrong reason.
    """
    raw = bytearray(_unb64url(code))
    raw[-1] ^= 0x01
    return _b64url(bytes(raw))


def opaque_invite_self_test(path: Optional[Path] = None) -> List[str]:
    """Cross-language vectors plus the failure modes the format exists for."""
    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("opaque_invite_self_test failed: %s" % name)
        checks.append(name)

    def raises(name: str, expected_code: str, call: Any) -> None:
        try:
            call()
        except InviteCodecError as exc:
            if exc.code != expected_code:
                raise AssertionError(
                    "opaque_invite_self_test failed: %s raised %s, expected %s"
                    % (name, exc.code, expected_code)
                ) from exc
            checks.append(name)
            return
        raise AssertionError("opaque_invite_self_test failed: %s did not raise %s" % (name, expected_code))

    hashes, HKDF, ChaCha20Poly1305, InvalidTag = _crypto()

    # 1. The KDF wrapper itself, against RFC 5869 case 1.
    ikm, salt, info, length, okm = _HKDF_RFC5869_CASE1
    check(
        "hkdf_sha256_matches_rfc5869_case_1",
        HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm) == okm,
    )

    vectors = load_vectors(path)
    check("vectors_name_the_v1_format", vectors.get("format") == "opaque-invite-%s" % VERSION)
    check("vectors_publish_the_link_prefix", vectors.get("link_prefix") == LINK_PREFIX)
    check("vectors_publish_the_same_ikm", str(vectors.get("ikm_hex")) == IKM.hex())
    check("vectors_publish_the_same_salt", str(vectors.get("salt_utf8")) == SALT.decode("ascii"))
    check("vectors_publish_the_same_info", str(vectors.get("info_utf8")) == INFO.decode("ascii"))
    check("vectors_publish_the_same_aad", str(vectors.get("aad_utf8")) == AAD.decode("ascii"))
    check("vectors_publish_the_derived_format_key", str(vectors.get("key_hex")) == format_key().hex())

    contact_seen = False
    channel_seen = False
    for vector in vectors["vectors"]:
        name = str(vector.get("name") or "unnamed")
        plaintext = str(vector.get("plaintext_utf8") or "")
        nonce = bytes.fromhex(str(vector.get("nonce_hex") or ""))
        expected_code = str(vector.get("sealed_b64url") or "")
        expected_link = str(vector.get("link") or "")

        check("vector_%s_has_a_12_byte_nonce" % name, len(nonce) == NONCE_BYTES)
        check(
            "vector_%s_seal_matches_the_published_bytes" % name,
            seal_invite_code(plaintext, nonce=nonce) == expected_code,
        )
        check(
            "vector_%s_link_matches_the_published_link" % name,
            encode_invite(plaintext, nonce=nonce) == expected_link,
        )
        check("vector_%s_decodes_to_the_original_uri" % name, decode_invite(expected_link) == plaintext)
        check(
            "vector_%s_plaintext_really_names_the_relay" % name,
            ".popopx.im" in plaintext.lower(),
        )
        check(
            "vector_%s_link_carries_no_plaintext" % name,
            plaintext not in expected_link and plaintext.lower() not in expected_link.lower(),
        )
        check(
            "vector_%s_link_carries_no_relay_domain" % name,
            ".popopx.im" not in expected_link.lower() and "popopx.im" not in expected_link.lower(),
        )
        check(
            "vector_%s_mask_keeps_only_a_prefix" % name,
            mask_invite_link(expected_link) == LINK_PREFIX + expected_code[:10] + "…"
            and expected_code not in mask_invite_link(expected_link),
        )
        check("vector_%s_is_recognised_as_an_opaque_link" % name, is_opaque_invite_link(expected_link))
        raises(
            "vector_%s_rejects_a_flipped_tag_byte" % name,
            "invite_link_tampered",
            lambda link=expected_link: decode_invite(LINK_PREFIX + _flip_last_sealed_byte(link[_PREFIX_LEN:])),
        )
        raises(
            "vector_%s_rejects_a_truncated_code" % name,
            "invite_link_invalid",
            lambda link=expected_link: decode_invite(link[: _PREFIX_LEN + 16]),
        )
        contact_seen = contact_seen or name == "contact"
        channel_seen = channel_seen or name == "channel"

    check("vectors_cover_a_service_account_uri", contact_seen)
    check("vectors_cover_a_channel_uri", channel_seen)

    sample = "https://smp1.popopx.im/a#example"
    fresh_a = encode_invite(sample)
    fresh_b = encode_invite(sample)
    check("fresh_links_use_a_random_nonce", fresh_a != fresh_b)
    check("fresh_links_round_trip", decode_invite(fresh_a) == sample and decode_invite(fresh_b) == sample)
    check("fresh_links_hide_the_relay_domain",
          "popopx.im" not in fresh_a.lower() and "popopx.im" in sample.lower())
    check("fresh_links_stay_within_the_v1_length", len(fresh_a) <= MAX_LINK_CHARS)
    check("opaque_shape_check_accepts_a_fresh_link", is_opaque_invite_link(fresh_a))
    check("opaque_shape_check_rejects_a_bare_code", not is_opaque_invite_link(fresh_a[_PREFIX_LEN:]))
    check("opaque_shape_check_rejects_the_old_literal_form", not is_opaque_invite_link("https://popopx.chat." + fresh_a[_PREFIX_LEN:]))
    raises(
        "a_wrong_version_is_unsupported",
        "invite_link_version_unsupported",
        lambda: decode_invite(fresh_a.replace("/i/v1/", "/i/v2/")),
    )
    raises(
        "a_plain_https_link_is_not_an_invite",
        "invite_link_version_unsupported",
        lambda: decode_invite(sample),
    )
    raises("a_non_uri_is_refused", "invite_uri_scheme_invalid", lambda: encode_invite("smp1.popopx.im/a"))
    raises("a_javascript_uri_is_refused", "invite_uri_scheme_invalid", lambda: encode_invite("javascript:alert(1)"))
    raises("a_uri_with_whitespace_is_refused", "invite_uri_invalid", lambda: encode_invite("https://smp1.popopx.im/a b"))
    raises("a_uri_with_a_newline_is_refused", "invite_uri_invalid", lambda: encode_invite("https://smp1.popopx.im/a\nb"))
    raises("an_empty_uri_is_refused", "invite_uri_required", lambda: encode_invite(""))
    raises("an_oversized_uri_is_refused", "invite_uri_too_long", lambda: encode_invite("https://smp1.popopx.im/" + "a" * MAX_URI_BYTES))
    raises("a_short_nonce_is_refused", "invite_nonce_invalid", lambda: encode_invite(sample, nonce=b"\x00" * 8))
    check("masking_a_non_link_is_a_bare_ellipsis", mask_invite_link("https://smp1.popopx.im/a") == "…")
    check("masking_a_code_is_a_bare_ellipsis_for_garbage", mask_invite_code("not base64!") == "…")

    return checks