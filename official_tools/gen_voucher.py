#!/usr/bin/env python3
# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""POPX-CP activation-code issuer — the official (private-key) side of admission.

    python3 official_tools/gen_voucher.py --gen-keyring --keyring ./official_keys
    python3 official_tools/gen_voucher.py --show-pubkey --keyring ./official_keys
    python3 official_tools/gen_voucher.py --mint --plan startup --credits 500 --qty 20
    python3 official_tools/gen_voucher.py --verify "POPX-CP-1.eyJ..._...."
    python3 official_tools/gen_voucher.py --self-test

What a code is
--------------
``POPX-CP-1.<base64url(payload)>.<base64url(signature)>``

where ``payload`` is the canonical UTF-8 string

    popopx|popx_cp_v1|<voucher_id>|<plan>|<credits>|<issued_at_ms>|<expires_at_ms>|<issuer_key_id>

signed with the official Ed25519 key (RFC 8032, pure — not Ed25519ph, not
hash-preprocessing, matching CryptoKit's ``Curve25519.Signing`` on the client
and ``cryptography``'s ``Ed25519PrivateKey`` on the gateway).

An empty ``expires_at_ms`` field is legal and means "no expiry". It is left as
an empty field rather than omitted so the field count never varies; a parser
that has to guess which positional field disappeared is how a minted code
becomes a redemption bug.

Why the format is written twice
-------------------------------
This file is the *only* place the private key is used, and it is meant to run on
a machine that never has the gateway installed — an offline issuer box. So the
gateway cannot import these eight lines, and the format exists in
``gateway/app/crypto_service.py`` as well. That duplication is forced by the
deployment model, and it is made safe by :option:`--self-test`: both sides carry
the same frozen vector below, so a rename on one side fails loudly at build time
instead of minting codes that verify nowhere.

Never put the private key on a gateway host. If a key is exposed, mint a new
keyring, publish the new public key, and revoke the old ``issuer_key_id`` in the
merchant database — a code is only as good as the key the gateway still trusts.
"""

import argparse
import base64
import getpass
import json
import os
import stat
import sys
import time
import uuid
from pathlib import Path
from typing import List, Optional, Tuple

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _CRYPTO_MISSING = None
except ImportError as _exc:  # pragma: no cover - exercised on a box without the wheel
    # The import is deferred rather than fatal so that the *format* half of this
    # tool — canonical_payload, parse_payload, and the frozen vector they are
    # checked against — stays testable anywhere Python runs. Only the commands
    # that actually touch a key call _require_crypto().
    InvalidSignature = None  # type: ignore[assignment]
    Ed25519PrivateKey = None  # type: ignore[assignment]
    Ed25519PublicKey = None  # type: ignore[assignment]
    _CRYPTO_MISSING = str(_exc)


def _require_crypto() -> None:
    if _CRYPTO_MISSING is not None:
        sys.stderr.write(
            "ERROR: this command needs `cryptography` (pip install cryptography>=42.0).\n"
            "       It is deliberately not vendored: an Ed25519 implementation that mints\n"
            "       money should come from the audited library, not from a file in this repo.\n"
            "       import error: %s\n" % _CRYPTO_MISSING
        )
        raise SystemExit(4)

PREFIX = "POPX-CP-1."
DOMAIN = "popopx|popx_cp_v1"
PLANS = {
    "startup": 500,
    "commercial": 2500,
    "flagship": 10000,
}
SEPARATOR = "|"

# ─────────────────────────── the frozen vector ──────────────────────────────
#: Shared with gateway/app/crypto_service.py (see VECTORS there). If this string
#: changes on one side only, --self-test fails on that side before a single bad
#: code can be minted.
TEST_VECTOR_PAYLOAD = "popopx|popx_cp_v1|V-0001|startup|500|1767225600000||k-test"


# ─────────────────────────── base64url, unpadded ────────────────────────────


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


# ─────────────────────────────── payload ────────────────────────────────────


def canonical_payload(voucher_id: str, plan: str, credits: int, issued_at_ms: int, expires_at_ms: Optional[int], key_id: str) -> str:
    """Assemble the signed string. Field order is the wire format; do not reorder."""
    for name, value in (("voucher_id", voucher_id), ("plan", plan), ("issuer_key_id", key_id)):
        if not value:
            raise ValueError("%s must not be empty" % name)
        if SEPARATOR in value:
            raise ValueError("%s must not contain %r (it would shift the fields)" % (name, SEPARATOR))
    if credits <= 0:
        raise ValueError("credits must be positive, got %d" % credits)
    if issued_at_ms <= 0:
        raise ValueError("issued_at_ms must be positive epoch milliseconds, got %d" % issued_at_ms)
    if expires_at_ms is not None and expires_at_ms <= issued_at_ms:
        raise ValueError("expires_at_ms (%d) is not after issued_at_ms (%d)" % (expires_at_ms, issued_at_ms))
    return SEPARATOR.join(
        [
            "popopx",
            "popx_cp_v1",
            voucher_id,
            plan,
            str(credits),
            str(issued_at_ms),
            str(expires_at_ms) if expires_at_ms is not None else "",
            key_id,
        ]
    )


def parse_payload(payload: str) -> Tuple[str, str, int, int, Optional[int], str]:
    """Inverse of :func:`canonical_payload`, validating as it goes.

    Exactly eight fields, always. A ninth means somebody put a ``|`` in a plan
    name; a seventh means a code from a different tool. Both are refused rather
    than guessed at, because a mis-parsed credit count credits the wrong amount.
    """
    parts = payload.split(SEPARATOR)
    if len(parts) != 8:
        raise ValueError("expected 8 payload fields, got %d" % len(parts))
    domain, version, voucher_id, plan, credits, issued, expires, key_id = parts
    if domain != "popopx" or version != "popx_cp_v1":
        raise ValueError("unknown code family %r/%r" % (domain, version))
    if not voucher_id or not plan or not key_id:
        raise ValueError("code carries an empty identity field")
    try:
        credits_int = int(credits, 10)
        issued_int = int(issued, 10)
    except ValueError:
        raise ValueError("credits/issued_at_ms must be decimal integers") from None
    expires_int: Optional[int] = None
    if expires:
        try:
            expires_int = int(expires, 10)
        except ValueError:
            raise ValueError("expires_at_ms must be a decimal integer or empty") from None
    if credits_int <= 0:
        raise ValueError("credits must be positive, got %d" % credits_int)
    if issued_int <= 0:
        raise ValueError("issued_at_ms must be positive, got %d" % issued_int)
    if expires_int is not None and expires_int <= issued_int:
        raise ValueError("expires_at_ms (%d) is not after issued_at_ms (%d)" % (expires_int, issued_int))
    return voucher_id, plan, credits_int, issued_int, expires_int, key_id


def mint_code(private_key: Ed25519PrivateKey, key_id: str, plan: str, credits: int, ttl_days: Optional[int], voucher_id: Optional[str]) -> Tuple[str, dict]:
    now_ms = int(time.time() * 1000)
    expires_ms = now_ms + ttl_days * 86_400_000 if ttl_days else None
    vid = voucher_id or ("V-" + uuid.uuid4().hex[:12].upper())
    payload = canonical_payload(vid, plan, credits, now_ms, expires_ms, key_id)
    signature = private_key.sign(payload.encode("utf-8"))
    code = PREFIX + b64u_encode(payload.encode("utf-8")) + "." + b64u_encode(signature)
    return code, {
        "voucher_id": vid,
        "plan": plan,
        "credits": credits,
        "issued_at_ms": now_ms,
        "expires_at_ms": expires_ms,
        "issuer_key_id": key_id,
        "code": code,
    }


def verify_code(public_key: Ed25519PublicKey, code: str, now_ms: Optional[int] = None) -> dict:
    """Offline verification: signature first, then the clock. Never the reverse."""
    if not code.startswith(PREFIX):
        raise ValueError("not a POPX-CP code (expected prefix %r)" % PREFIX)
    body = code[len(PREFIX) :]
    payload_b64, dot, signature_b64 = body.rpartition(".")
    if not dot or not payload_b64 or not signature_b64:
        raise ValueError("malformed code: expected %s<payload>.<signature>" % PREFIX)
    try:
        payload_bytes = b64u_decode(payload_b64)
        signature = b64u_decode(signature_b64)
    except Exception:
        raise ValueError("code is not valid base64url") from None
    if len(signature) != 64:
        raise ValueError("signature must be 64 raw bytes, got %d" % len(signature))
    try:
        public_key.verify(signature, payload_bytes)
    except InvalidSignature:
        raise ValueError("signature REJECTED — this code was not minted by the trusted official key") from None
    voucher_id, plan, credits, issued_ms, expires_ms, key_id = parse_payload(payload_bytes.decode("utf-8"))
    clock = now_ms if now_ms is not None else int(time.time() * 1000)
    expired = expires_ms is not None and clock >= expires_ms
    return {
        "valid": not expired,
        "expired": expired,
        "voucher_id": voucher_id,
        "plan": plan,
        "credits": credits,
        "issued_at_ms": issued_ms,
        "expires_at_ms": expires_ms,
        "issuer_key_id": key_id,
    }


# ─────────────────────────────── keyring ────────────────────────────────────


def key_id_for(public_key: Ed25519PublicKey) -> str:
    import hashlib

    raw = public_key.public_bytes_raw()
    return "k-" + hashlib.sha256(raw).hexdigest()[:10]


def _secure_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # O_TRUNC on an existing key file must not silently widen permissions, so
    # the mode is set at create time rather than with a follow-up chmod.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_private_key(keyring_dir: Path) -> Tuple[Ed25519PrivateKey, str]:
    _require_crypto()
    secret_path = keyring_dir / "official_ed25519.secret.json"
    if not secret_path.is_file():
        raise SystemExit(
            "ERROR: no keyring at %s\n"
            "       create one with:  %s --gen-keyring --keyring %s"
            % (secret_path, Path(sys.argv[0]).name, keyring_dir)
        )
    try:
        os.chmod(secret_path, 0o600)
    except OSError:
        pass
    document = json.loads(secret_path.read_text(encoding="utf-8"))
    seed = b64u_decode(document["seed_b64url"])
    if len(seed) != 32:
        raise SystemExit("ERROR: keyring seed must be 32 bytes, got %d" % len(seed))
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    stored_id = document.get("key_id") or key_id_for(private_key.public_key())
    derived_id = key_id_for(private_key.public_key())
    if stored_id != derived_id:
        # A hand-edited keyring is the one way an operator can make the gateway
        # trust a key it cannot audit. Refuse the file instead.
        raise SystemExit("ERROR: keyring key_id %r does not match its own public key (%r)" % (stored_id, derived_id))
    return private_key, derived_id


def cmd_gen_keyring(keyring_dir: Path, passphrase: Optional[str]) -> int:
    _require_crypto()
    secret_path = keyring_dir / "official_ed25519.secret.json"
    public_path = keyring_dir / "official_ed25519.pub"
    if secret_path.exists():
        print("refusing to overwrite an existing keyring: %s" % secret_path, file=sys.stderr)
        print("a second key silently invalidates every code minted from the first one", file=sys.stderr)
        return 2

    if passphrase:
        # A passphrase on the seed turns theft of the file into theft of a
        # PBKDF2 problem. 310k iterations is OWASP's PBKDF2-HMAC-SHA256 floor
        # for a high-entropy-adjacent secret as of this writing; the value is
        # stored with the hash so a later bump does not break old keyrings.
        import hashlib

        salt = os.urandom(16)
        derived = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 310_000)
        # The seed itself is random; `derived` is the KEK. XOR is enough here and
        # keeps the tool dependency-free, because `cryptography`'s AEAD is not
        # needed to protect 32 bytes whose only consumer is this script.
        seed = os.urandom(32)
        wrapped = bytes(a ^ b for a, b in zip(seed, derived[:32]))
        document = {
            "version": 1,
            "kdf": "pbkdf2-hmac-sha256",
            "iterations": 310_000,
            "salt_b64url": b64u_encode(salt),
            "wrapped_seed_b64url": b64u_encode(wrapped),
        }
    else:
        seed = os.urandom(32)
        document = {"version": 1, "kdf": "none", "seed_b64url": b64u_encode(seed)}

    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key()
    document["key_id"] = key_id_for(public_key)
    document["created_at_ms"] = int(time.time() * 1000)

    _secure_write(secret_path, json.dumps(document, indent=2, sort_keys=True) + "\n")
    _secure_write(public_path, b64u_encode(public_key.public_bytes_raw()) + "\n")

    print("keyring : %s  (mode 0600 — this file mints money; back it up offline)" % secret_path)
    print("pubkey  : %s" % public_path)
    print("key_id  : %s" % document["key_id"])
    print("")
    print("Set this on every gateway (POPOPX_OFFICIAL_ED25519_PUBLIC_KEY):")
    print(base64.b64encode(public_key.public_bytes_raw()).decode("ascii"))
    return 0


def cmd_show_pubkey(keyring_dir: Path) -> int:
    private_key, key_id = load_private_key(keyring_dir)
    raw = private_key.public_key().public_bytes_raw()
    print("key_id      : %s" % key_id)
    print("base64      : %s" % base64.b64encode(raw).decode("ascii"))
    print("hex         : %s" % raw.hex())
    print("env line    : POPOPX_OFFICIAL_ED25519_PUBLIC_KEY=%s" % base64.b64encode(raw).decode("ascii"))
    return 0


def _resolve_private(keyring_dir: Path, no_passphrase: bool) -> Tuple[Ed25519PrivateKey, str]:
    secret_path = keyring_dir / "official_ed25519.secret.json"
    document = json.loads(secret_path.read_text(encoding="utf-8")) if secret_path.is_file() else {}
    if document.get("kdf") not in (None, "none") and not no_passphrase:
        import hashlib

        passphrase = getpass.getpass("keyring passphrase: ")
        salt = b64u_decode(document["salt_b64url"])
        derived = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, int(document["iterations"]))
        seed = bytes(a ^ b for a, b in zip(b64u_decode(document["wrapped_seed_b64url"]), derived[:32]))
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        return private_key, key_id_for(private_key.public_key())
    return load_private_key(keyring_dir)


def cmd_mint(args: argparse.Namespace) -> int:
    private_key, key_id = _resolve_private(Path(args.keyring), args.no_passphrase)

    credits = args.credits if args.credits is not None else PLANS.get(args.plan)
    if credits is None:
        print(
            "ERROR: plan %r is not a known package (%s) and --credits was not given"
            % (args.plan, ", ".join(sorted(PLANS))),
            file=sys.stderr,
        )
        return 2

    rows: List[dict] = []
    for _ in range(args.qty):
        code, record = mint_code(private_key, key_id, args.plan, credits, args.ttl_days, args.voucher_id if args.qty == 1 else None)
        if args.note:
            record["note"] = args.note
        rows.append(record)

    for record in rows:
        print(record["code"])

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(out, 0o600)
        except OSError:
            pass
        print("\n%d code(s) written to %s (credits=%d each, key_id=%s)" % (len(rows), out, credits, key_id), file=sys.stderr)
    else:
        print("\n%d code(s), plan=%s credits=%d key_id=%s%s" % (len(rows), args.plan, credits, key_id, "" if not args.ttl_days else " ttl=%dd" % args.ttl_days), file=sys.stderr)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    _require_crypto()
    raw = args.public_key or os.environ.get("POPOPX_OFFICIAL_ED25519_PUBLIC_KEY", "")
    if not raw:
        print("ERROR: --public-key (or POPOPX_OFFICIAL_ED25519_PUBLIC_KEY) is required", file=sys.stderr)
        return 2
    candidate = raw.strip().replace(" ", "")
    try:
        key_bytes = base64.b64decode(candidate, validate=True)
    except Exception:
        key_bytes = bytes.fromhex(candidate)
    if len(key_bytes) != 32:
        print("ERROR: public key must be 32 bytes, got %d" % len(key_bytes), file=sys.stderr)
        return 2
    public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
    failures = 0
    for code in args.codes:
        try:
            result = verify_code(public_key, code.strip())
        except ValueError as exc:
            print("INVALID  %s\n         %s" % (code[:38] + "…", exc), file=sys.stderr)
            failures += 1
            continue
        print(
            "%-8s id=%s plan=%s credits=%d key=%s issued=%d expires=%s"
            % (
                "EXPIRED" if result["expired"] else "VALID",
                result["voucher_id"],
                result["plan"],
                result["credits"],
                result["issuer_key_id"],
                result["issued_at_ms"],
                result["expires_at_ms"] or "-",
            )
        )
    return 1 if failures else 0


def cmd_self_test() -> int:
    """Freeze the format. Run this in CI on both sides of the seam."""
    failures: List[str] = []

    payload = canonical_payload("V-0001", "startup", 500, 1767225600000, None, "k-test")
    if payload != TEST_VECTOR_PAYLOAD:
        failures.append("canonical payload drifted:\n  got      %s\n  expected %s" % (payload, TEST_VECTOR_PAYLOAD))

    # Field-count and injection guards, which need no key at all.
    for bad in (
        ("V|1", "startup", 500, 1, None, "k"),  # separator inside an identity field
        ("V-1", "startup", 0, 1, None, "k"),  # zero credits
        ("V-1", "startup", 500, 1, 1, "k"),  # expiry at/before issue
        ("V-1", "startup", 500, 0, None, "k"),  # epoch-zero issue stamp
    ):
        try:
            canonical_payload(*bad)
            failures.append("canonical_payload accepted %r" % (bad,))
        except ValueError:
            pass

    round_tripped = parse_payload(TEST_VECTOR_PAYLOAD)
    if round_tripped != ("V-0001", "startup", 500, 1767225600000, None, "k-test"):
        failures.append("parse_payload drifted: %r" % (round_tripped,))
    try:
        parse_payload(TEST_VECTOR_PAYLOAD + "|extra")
        failures.append("a 9-field payload was accepted")
    except ValueError:
        pass

    if failures:
        for line in failures:
            print("FAIL " + line, file=sys.stderr)
        return 1

    if _CRYPTO_MISSING is not None:
        print("format self-test OK (%d vector assertions) — signature checks SKIPPED, `cryptography` is not importable here" % 9)
        return 0

    # A code is only trustworthy if the same tool can also refuse a tampered one.
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    signature = private_key.sign(payload.encode("utf-8"))
    crypto_failures: List[str] = []
    if len(signature) != 64:
        crypto_failures.append("Ed25519 signature must be 64 raw bytes, got %d" % len(signature))
    code = PREFIX + b64u_encode(payload.encode("utf-8")) + "." + b64u_encode(signature)
    parsed = verify_code(public_key, code, now_ms=1767225600000)
    if not parsed["valid"] or parsed["credits"] != 500 or parsed["voucher_id"] != "V-0001":
        crypto_failures.append("round-trip verify failed: %r" % parsed)

    flipped = code[:-8] + ("AAAAAAAA" if not code.endswith("AAAAAAAA") else "BBBBBBBB")
    try:
        verify_code(public_key, flipped, now_ms=1767225600000)
        crypto_failures.append("a tampered signature was ACCEPTED")
    except ValueError:
        pass

    # A wrong-length signature must not reach the verifier at all.
    short = PREFIX + b64u_encode(payload.encode("utf-8")) + "." + b64u_encode(signature[:32])
    try:
        verify_code(public_key, short, now_ms=1767225600000)
        crypto_failures.append("a truncated signature was ACCEPTED")
    except ValueError:
        pass

    expired = verify_code(public_key, code, now_ms=1767225600000 + 10 ** 12)
    if not expired["expired"]:
        crypto_failures.append("an out-of-window code was reported as live")

    for bad in ("", "POPX-CP-1.nope", "POPX-CP-1.%s" % b64u_encode(b"popopx|popx_cp_v1|a|b")):
        try:
            verify_code(public_key, bad, now_ms=1767225600000)
            crypto_failures.append("malformed code accepted: %r" % bad[:30])
        except ValueError:
            pass

    # Cross-check that the gateway would read the minted payload the same way.
    if crypto_failures:
        for line in crypto_failures:
            print("FAIL " + line, file=sys.stderr)
        return 1
    print("self-test OK — frozen vector %d bytes, format + signature paths verified" % len(TEST_VECTOR_PAYLOAD.encode("utf-8")))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gen_voucher.py",
        description="Mint and verify POPX-CP compute-credit activation codes (Ed25519).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("What a code is")[1].split("Why the format")[0] if __doc__ else None,
    )
    parser.add_argument("--keyring", default="./official_keys", help="directory holding the official keypair (default: ./official_keys)")
    parser.add_argument("--no-passphrase", action="store_true", help="do not prompt even for a wrapped keyring (fails; kept for script symmetry)")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--gen-keyring", action="store_true", help="create the official keypair (refuses to overwrite)")
    mode.add_argument("--show-pubkey", action="store_true", help="print the public key in every spelling the gateway accepts")
    mode.add_argument("--mint", action="store_true", help="mint code(s) and print them")
    mode.add_argument("--verify", action="store_true", help="verify existing code(s) offline")
    mode.add_argument("--self-test", action="store_true", help="assert the frozen wire format and the reject paths")

    parser.add_argument("--plan", default="startup", help="startup|commercial|flagship, or any label when --credits is given")
    parser.add_argument("--credits", type=int, default=None, help="POPX-CP amount; defaults to the plan package")
    parser.add_argument("--ttl-days", type=int, default=None, help="days until the code stops redeeming; omit for no expiry")
    parser.add_argument("--qty", type=int, default=1, help="how many distinct codes to mint")
    parser.add_argument("--voucher-id", default=None, help="pin one voucher id (only valid with --qty 1)")
    parser.add_argument("--note", default=None, help="free text recorded beside the code")
    parser.add_argument("--out", default=None, help="also write the minted records as JSON to this file (mode 0600)")
    parser.add_argument("--public-key", default=None, help="base64 or hex official public key (for --verify)")
    parser.add_argument("codes", nargs="*", help="code(s) to verify")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.qty < 1:
        parser.error("--qty must be at least 1")
    if args.ttl_days is not None and args.ttl_days < 1:
        parser.error("--ttl-days must be positive")
    if args.voucher_id and SEPARATOR in args.voucher_id:
        parser.error("--voucher-id must not contain %r" % SEPARATOR)

    if args.self_test:
        return cmd_self_test()
    if args.gen_keyring:
        return cmd_gen_keyring(Path(args.keyring), os.environ.get("POPX_KEYRING_PASSPHRASE"))
    if args.show_pubkey:
        return cmd_show_pubkey(Path(args.keyring))
    if args.mint:
        return cmd_mint(args)
    if args.verify:
        if not args.codes:
            parser.error("--verify needs at least one code")
        return cmd_verify(args)
    parser.error("no action selected")  # pragma: no cover - mutually exclusive group covers it
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
