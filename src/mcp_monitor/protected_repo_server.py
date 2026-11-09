"""First-party protected stdio MCP server for an explicitly approved dependency change.

No network, no model service, no generic read/write shell or arbitrary path tool.
The server enforces the resource boundary independently of the MCP gateway.
This is a constrained demonstrator, not an enterprise-grade multi-user server.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

MAX_FRAME_BYTES = 131072
MAX_MANIFEST_BYTES = 65536
PROTOCOL_VERSION = "2025-03-26"
TOOLS = (
    {
        "name": "read_manifest",
        "description": "Read the package.json dependency section for the authorized workspace.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "update_dependency",
        "description": "Apply only a preapproved package/version update to package.json.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string"},
                "version": {"type": "string"},
                "expected_previous": {"type": "string"},
            },
            "required": ["package", "version", "expected_previous"],
            "additionalProperties": False,
        },
    },
)


class ProtectedOperationError(Exception):
    """Non-sensitive denial to return to the MCP client."""


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ProtectedOperationError("Duplicate JSON key")
        obj[key] = value
    return obj


def _no_constants(_value: str) -> None:
    raise ProtectedOperationError("Non-finite JSON number")


def _load_json(raw: str) -> Any:
    return json.loads(raw, object_pairs_hook=_object_pairs, parse_constant=_no_constants)


class ProtectedRepo:
    """Single explicitly provisioned workspace, with no client-controlled paths."""

    def __init__(self, root: Path, updates: dict[str, str]):
        if not root.is_dir() or root.is_symlink() or not root.is_absolute():
            raise ValueError("Workspace must be an existing absolute non-symlink directory")
        if (
            not isinstance(updates, dict)
            or not updates
            or any(
                not isinstance(k, str) or not k or not isinstance(v, str) or not v
                for k, v in updates.items()
            )
        ):
            raise ValueError("At least one operator-approved package/version required")
        self.root = root.resolve(strict=True)
        self.approved = dict(updates)

    def _manifest(self) -> tuple[Path, dict[str, Any]]:
        path = self.root / "package.json"
        if path.is_symlink() or not path.is_file() or path.parent.resolve() != self.root:
            raise ProtectedOperationError("Manifest missing or not a regular workspace file")
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ProtectedOperationError("Manifest exceeds size limit")
        try:
            content = _load_json(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError, OSError) as exc:
            raise ProtectedOperationError("Manifest is not valid JSON") from exc
        if not isinstance(content, dict) or not isinstance(content.get("dependencies"), dict):
            raise ProtectedOperationError("Manifest dependencies missing")
        return path, content

    def read(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if arguments:
            raise ProtectedOperationError("Unexpected read arguments")
        _, data = self._manifest()
        return {"dependencies": data["dependencies"]}

    def update(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(arguments, dict) or set(arguments) != {
            "package",
            "version",
            "expected_previous",
        }:
            raise ProtectedOperationError("Invalid dependency update arguments")
        name, version, previous = (
            arguments["package"],
            arguments["version"],
            arguments["expected_previous"],
        )
        if not all(isinstance(v, str) and v for v in (name, version, previous)):
            raise ProtectedOperationError("Invalid package or version")
        if self.approved.get(name) != version:
            raise ProtectedOperationError("Dependency change not approved by workspace operator")
        path, data = self._manifest()
        if data["dependencies"].get(name) != previous:
            raise ProtectedOperationError("Dependency version changed or package not present")
        if previous == version:
            raise ProtectedOperationError("No change requested")
        data["dependencies"][name] = version
        output = (json.dumps(data, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
        if len(output) > MAX_MANIFEST_BYTES:
            raise ProtectedOperationError("Updated manifest exceeds size limit")
        # Avoid in-place truncation; temp file is under the same trusted directory.
        # This does not provide cross-process compare-and-swap or OS containment.
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.root, prefix=".manifest-", suffix=".tmp", delete=False
            ) as handle:
                temporary = handle.name
                os.chmod(temporary, 0o600)
                handle.write(output)
                handle.flush()
                os.fsync(handle.fileno())
            # Fail closed if the manifest was swapped for a symlink since validation.
            if path.is_symlink() or not path.is_file():
                raise ProtectedOperationError("Manifest changed while updating")
            os.replace(temporary, path)
            temporary = None
            # Synchronize directory metadata on Unix when supported.
            if hasattr(os, "O_DIRECTORY"):
                fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except OSError as exc:
            raise ProtectedOperationError("Could not persist approved update") from exc
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
        return {"package": name, "previous": previous, "version": version, "status": "updated"}


def _result(identity: Any, value: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": identity, "result": value}


def _error(identity: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": identity, "error": {"code": code, "message": message}}


def handle(request: Any, repo: ProtectedRepo) -> dict[str, Any] | None:
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        return _error(None, -32600, "Invalid MCP request")
    method = request.get("method")
    identity = request.get("id")
    if not isinstance(method, str) or not method:
        return _error(identity, -32600, "Invalid MCP method")
    if method == "notifications/initialized":
        return None
    if "id" not in request or isinstance(identity, bool) or not isinstance(identity, int | str):
        return _error(None, -32600, "Invalid request ID")
    if method == "initialize":
        return _result(
            identity,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "first-party-protected-repo", "version": "0.1.0"},
            },
        )
    if method == "ping":
        return _result(identity, {})
    if method == "tools/list":
        return _result(identity, {"tools": list(TOOLS)})
    if method != "tools/call":
        return _error(identity, -32601, "MCP method not supported")
    params = request.get("params")
    if not isinstance(params, dict) or set(params) != {"name", "arguments"}:
        return _error(identity, -32602, "Invalid tool parameters")
    name = params["name"]
    arguments = params["arguments"]
    if not isinstance(arguments, dict):
        return _error(identity, -32602, "Invalid tool arguments")
    try:
        if name == "read_manifest":
            result = repo.read(arguments)
        elif name == "update_dependency":
            result = repo.update(arguments)
        else:
            raise ProtectedOperationError("Tool not supported or not authorized")
        return _result(identity, {"content": [{"type": "text", "text": json.dumps(result)}]})
    except ProtectedOperationError as exc:
        return _error(identity, -32003, str(exc))


def main() -> None:
    # Trusted operator-controlled environment. Do not permit the agent to set
    # these values through tools/call arguments.
    root_value = os.environ.get("MCP_PROTECTED_REPO_ROOT")
    approval_value = os.environ.get("MCP_APPROVED_DEPENDENCY_UPDATES")
    if not root_value or not approval_value:
        raise SystemExit("Required protected workspace / approval environment missing")
    try:
        repo = ProtectedRepo(Path(root_value), _load_json(approval_value))
    except (ValueError, OSError) as exc:
        raise SystemExit("Invalid protected workspace configuration") from exc
    for raw in sys.stdin.buffer:
        if len(raw) > MAX_FRAME_BYTES:
            response = _error(None, -32600, "MCP request too large")
        else:
            try:
                request = _load_json(raw.decode("utf-8"))
                response = handle(request, repo)
            except (ValueError, UnicodeError, ProtectedOperationError):
                response = _error(None, -32700, "Invalid MCP JSON")
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
