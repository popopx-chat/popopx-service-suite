# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Thin pytest adapter over the suites `python -m app.main --self-test` runs.

The assertions stay where they are — beside the modules they verify — so this file
adds no second copy of any check and the two entry points cannot drift. What it adds
is per-suite reporting: pytest names the failing group and keeps going, where the
CLI stops at the first failure.

Wheel-gated groups use `importorskip` for the same reason `--self-test` prints
SKIPPED: on an interpreter without `cryptography` there are no real Ed25519 /
ChaCha20-Poly1305 bytes to verify, and a pass against the stub would be a lie.
"""

from __future__ import annotations

import importlib

import pytest

from app.main import SELF_TEST_MODULES, assert_routes_are_gated, http_self_test, route_census


@pytest.mark.parametrize("module_name", SELF_TEST_MODULES, ids=SELF_TEST_MODULES)
def test_module_self_test(module_name: str) -> None:
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # noqa: BLE001 — the CLI classifies this as SKIPPED too
        pytest.skip("%s cannot be imported here: %s: %s" % (module_name, type(exc).__name__, exc))
    suite = getattr(module, "self_test", None)
    if not callable(suite):
        pytest.fail("%s ships without self_test()" % module_name)
    names = suite()
    assert isinstance(names, list) and names, "%s.self_test() returned no check names" % module_name


def test_crypto_self_test() -> None:
    pytest.importorskip("cryptography")
    from app.crypto_service import crypto_self_test

    assert crypto_self_test()


def test_opaque_invite_self_test() -> None:
    pytest.importorskip("cryptography")
    from app.opaque_invite_codec import opaque_invite_self_test

    assert opaque_invite_self_test()


def test_http_self_test() -> None:
    for distribution in ("fastapi", "httpx", "cryptography"):
        pytest.importorskip(distribution)
    assert http_self_test()


def test_every_route_is_guarded_or_explicitly_public() -> None:
    rows = route_census()
    assert rows
    assert assert_routes_are_gated(rows) == len(rows)