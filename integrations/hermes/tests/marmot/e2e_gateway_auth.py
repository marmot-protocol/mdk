#!/usr/bin/env python3
"""Fresh-process Hermes gateway authorization check against installed Marmot .env."""

from __future__ import annotations

import os
import sys


def main() -> int:
    hermes_home = os.environ.get("HERMES_HOME")
    if not hermes_home:
        print("error: HERMES_HOME is required", file=sys.stderr)
        return 2

    allowed_hex = os.environ.get("MARMOT_TEST_ALLOWED_USER_HEX")
    unknown_hex = os.environ.get("MARMOT_TEST_UNKNOWN_USER_HEX")
    if not allowed_hex or not unknown_hex:
        print(
            "error: MARMOT_TEST_ALLOWED_USER_HEX and MARMOT_TEST_UNKNOWN_USER_HEX are required",
            file=sys.stderr,
        )
        return 2

    from hermes_cli.env_loader import load_hermes_dotenv
    load_hermes_dotenv(hermes_home=hermes_home)

    from hermes_cli.plugins import discover_plugins

    discover_plugins()

    from gateway.config import Platform
    from gateway.run import GatewayRunner
    from gateway.session import SessionSource

    runner = object.__new__(GatewayRunner)
    try:
        runner.adapters = {}
        runner.pairing_store = None
        runner.pairing_stores = {}
    except AttributeError:
        print(
            "error: Hermes GatewayRunner internals changed; update e2e_gateway_auth.py",
            file=sys.stderr,
        )
        return 3

    allowed_source = SessionSource(
        platform=Platform("marmot"),
        chat_id=allowed_hex,
        chat_type="dm",
        user_id=allowed_hex,
    )
    unknown_source = SessionSource(
        platform=Platform("marmot"),
        chat_id=unknown_hex,
        chat_type="dm",
        user_id=unknown_hex,
    )

    try:
        allowed_ok = runner._is_user_authorized(allowed_source)
        unknown_ok = runner._is_user_authorized(unknown_source)
    except AttributeError:
        print(
            "error: Hermes GatewayRunner authorization hook changed; update e2e_gateway_auth.py",
            file=sys.stderr,
        )
        return 3

    print(f"allowed={str(allowed_ok).lower()} unknown={str(unknown_ok).lower()}")
    return 0 if allowed_ok and not unknown_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
