"""Reject the retired public gateway credential without disclosing it in logs."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from mcp_monitor.production.config import Config


# Construct a previously public demonstration value solely for the negative
# regression; do not add any working token, secret or account credential.
_RETIRED_DEMO = "lab-" + "api-key-not-for-production"


@pytest.mark.parametrize(
    "environment",
    [
        {"MCP_API_KEY": _RETIRED_DEMO},
        {"MCP_API_KEYS": "a" * 32 + "," + _RETIRED_DEMO},
    ],
)
def test_retired_gateway_key_rejected_in_all_modes(environment: dict[str, str]) -> None:
    with patch.dict(os.environ, {"MCP_ENV": "development", **environment}, clear=True):
        with pytest.raises(ValueError, match="publicly exposed") as err:
            Config()
    assert _RETIRED_DEMO not in str(err.value)


def test_fresh_operator_key_not_rejected() -> None:
    with patch.dict(
        os.environ,
        {"MCP_ENV": "development", "MCP_API_KEY": "synthetic-" + "x" * 64},
        clear=True,
    ):
        assert Config().api_keys == ("synthetic-" + "x" * 64,)


def test_no_anonymous_fallback_on_retired_value() -> None:
    with patch.dict(
        os.environ,
        {
            "MCP_ENV": "development",
            "MCP_API_KEY": _RETIRED_DEMO,
            "MCP_ALLOW_ANONYMOUS": "true",
        },
        clear=True,
    ):
        with pytest.raises(ValueError, match="publicly exposed"):
            Config()
