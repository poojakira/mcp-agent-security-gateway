"""Phase 13: narrow fail-closed static release gate for the local detection lab.

This is not a whole-repository secret scan or a production deployment audit.
"""

from pathlib import Path

import pytest
import yaml

COMPOSE = Path(__file__).resolve().parents[1] / "docker-compose.detection-lab.yml"


def _lab_services() -> dict:
    content = COMPOSE.read_text(encoding="utf-8")
    data = yaml.safe_load(content)
    assert isinstance(data, dict) and isinstance(data.get("services"), dict)
    return data["services"]


@pytest.mark.parametrize("service_name", ["mcp-gateway", "elasticsearch", "kibana"])
def test_published_lab_ports_bind_only_loopback(service_name: str) -> None:
    service = _lab_services()[service_name]
    ports = service.get("ports")
    assert isinstance(ports, list) and ports, "Expected explicit published port bindings"
    assert all(
        isinstance(port, str) and port.startswith("127.0.0.1:") for port in ports
    ), f"{service_name} has a non-loopback port binding"


def test_lab_requires_operator_supplied_api_key_without_fallback() -> None:
    service = _lab_services()["mcp-gateway"]
    environment = service.get("environment")
    assert isinstance(environment, list)
    key_entries = [
        item for item in environment if isinstance(item, str) and item.startswith("MCP_API_KEY=")
    ]
    assert len(key_entries) == 1, "Require exactly one explicit MCP_API_KEY variable"
    mandatory_prefix = "MCP_API_KEY=" + "$" + "{MCP_API_KEY:?"
    assert key_entries[0].startswith(
        mandatory_prefix
    ), "MCP_API_KEY must use a required operator-supplied Compose environment variable"


def test_public_demo_credential_is_not_active_compose_configuration() -> None:
    content = COMPOSE.read_text(encoding="utf-8")
    assert "lab-api-key-not-for-production" not in content
