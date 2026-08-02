"""Real-time MCP Security Gateway — FastAPI + WebSocket streaming server.

Run: uvicorn mcp_monitor.server.realtime:app --reload
Or:  python -m mcp_monitor.server.realtime
"""

from __future__ import annotations

import asyncio
import random
import time
from pathlib import Path
from typing import Any

try:
    import uvicorn
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse
except ImportError as _err:
    raise ImportError("pip install fastapi uvicorn[standard]") from _err

from mcp_monitor.layers import (
    FiveLayerDefense,
    InlineProxyGateway,
    KernelMonitor,
    NetworkEgressPolicy,
    SemanticIntentAnalyzer,
)
from mcp_monitor.layers.egress import EgressRule
from mcp_monitor.layers.kernel import ServerPolicy
from mcp_monitor.layers.proxy import ProxyAction
from mcp_monitor.redteam.payloads import ATTACK_CATALOG

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = FastAPI(title="MCP Security Gateway — Real-Time Monitor")

DASHBOARD_PATH = Path(__file__).parent / "dashboard.html"

# ---------------------------------------------------------------------------
# Defense system initialization
# ---------------------------------------------------------------------------


def _build_defense() -> FiveLayerDefense:
    """Construct the full 5-layer defense pipeline with comprehensive detection rules."""
    from mcp_monitor.layers.proxy import ProxyRule

    proxy = InlineProxyGateway(block_threshold=50, quarantine_threshold=30)
    kernel = KernelMonitor()
    semantic = SemanticIntentAnalyzer(sensitivity=0.7)
    egress = NetworkEgressPolicy(default_deny=True)

    # ---- Proxy rules for new attack patterns ----

    # SSRF detection: block internal IPs
    def _is_ssrf(call: dict) -> bool:
        import re as _re

        args = call.get("arguments", {})
        url = str(args.get("url", "")) + str(args.get("path", "")) + str(args.get("endpoint", ""))
        ssrf_patterns = [
            r"169\.254\.\d+\.\d+",
            r"127\.0\.0\.\d+",
            r"10\.\d+\.\d+\.\d+",
            r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
            r"192\.168\.\d+\.\d+",
            r"0\.0\.0\.0",
            r"localhost",
            r"\[::1\]",
            r"metadata\.google\.internal",
        ]
        for pat in ssrf_patterns:
            if _re.search(pat, url, _re.IGNORECASE):
                return True
        return False

    proxy.add_rule(
        ProxyRule(
            name="ssrf_block",
            description="Block SSRF to internal/cloud metadata IPs",
            tool_pattern=r".*",
            action=ProxyAction.BLOCK,
            condition=_is_ssrf,
            priority=90,
        )
    )

    # Path traversal detection
    def _is_path_traversal(call: dict) -> bool:
        import re as _re
        import urllib.parse

        args = call.get("arguments", {})
        for val in _all_string_values(args):
            decoded = urllib.parse.unquote(val)
            if _re.search(r"\.\.[/\\]", decoded):
                return True
            if _re.search(r"%2e%2e[/\\%]", val, _re.IGNORECASE):
                return True
        return False

    proxy.add_rule(
        ProxyRule(
            name="path_traversal_block",
            description="Block directory traversal attacks",
            tool_pattern=r".*",
            action=ProxyAction.BLOCK,
            condition=_is_path_traversal,
            priority=88,
        )
    )

    # Command injection detection
    def _is_command_injection(call: dict) -> bool:
        import re as _re

        args = call.get("arguments", {})
        for val in _all_string_values(args):
            # Shell metacharacters in non-shell tools
            if _re.search(
                r"[;|&`$]\s*(rm|curl|wget|nc|cat|chmod|sudo|bash|sh|python)",
                val,
                _re.IGNORECASE,
            ):
                return True
            # Backtick execution
            if _re.search(r"`[^`]+`", val):
                return True
            # Command chaining
            if _re.search(r";\s*(rm|curl|wget|nc|cat)\s", val, _re.IGNORECASE):
                return True
        return False

    proxy.add_rule(
        ProxyRule(
            name="command_injection_block",
            description="Block OS command injection patterns",
            tool_pattern=r".*",
            action=ProxyAction.BLOCK,
            condition=_is_command_injection,
            priority=89,
        )
    )

    # Credential pattern detection in payloads
    def _has_credential_patterns(call: dict) -> bool:
        import re as _re

        args = call.get("arguments", {})
        for val in _all_string_values(args):
            cred_patterns = [
                r"AWS_SECRET[_A-Z]*=\S+",
                r"GITHUB_TOKEN=\S+",
                r"ghp_[A-Za-z0-9]{36,}",
                r"sk-[A-Za-z0-9]{32,}",
                r"AKIA[0-9A-Z]{16}",
                r"password\s*[:=]\s*\S{8,}",
                r"api[_-]?key\s*[:=]\s*\S{10,}",
                r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
            ]
            for pat in cred_patterns:
                if _re.search(pat, val, _re.IGNORECASE):
                    return True
        return False

    proxy.add_rule(
        ProxyRule(
            name="credential_exfil_block",
            description="Block credential/secret exfiltration",
            tool_pattern=r"(email|webhook|http|api)\.",
            action=ProxyAction.BLOCK,
            condition=_has_credential_patterns,
            priority=92,
        )
    )

    # Deserialization attack detection
    def _is_deserialization_attack(call: dict) -> bool:
        import re as _re

        args = call.get("arguments", {})
        for val in _all_string_values(args):
            if _re.search(r"!!python/object", val):
                return True
            if _re.search(r"pickle|marshal|shelve", val, _re.IGNORECASE):
                url = args.get("url", "")
                if _re.search(r"\.(pkl|pickle|marshal)$", url, _re.IGNORECASE):
                    trust = args.get("trust_remote", False)
                    if trust:
                        return True
        fmt = args.get("format", "")
        if fmt == "pickle" and args.get("trust_remote"):
            return True
        return False

    proxy.add_rule(
        ProxyRule(
            name="deserialization_block",
            description="Block unsafe deserialization patterns",
            tool_pattern=r".*",
            action=ProxyAction.BLOCK,
            condition=_is_deserialization_attack,
            priority=87,
        )
    )

    # Env var credential harvesting
    def _is_env_harvest(call: dict) -> bool:
        import re as _re

        args = call.get("arguments", {})
        cmd = str(args.get("command", ""))
        if _re.search(
            r"(env|printenv|set)\s*\|.*grep.*(SECRET|TOKEN|KEY|PASSWORD|CRED)",
            cmd,
            _re.IGNORECASE,
        ):
            return True
        if _re.search(r"\$\{?[A-Z_]*(SECRET|TOKEN|KEY|PASSWORD)", cmd, _re.IGNORECASE):
            return True
        return False

    proxy.add_rule(
        ProxyRule(
            name="env_credential_harvest_block",
            description="Block credential harvesting via env commands",
            tool_pattern=r"(shell|exec|system|cmd)\.",
            action=ProxyAction.BLOCK,
            condition=_is_env_harvest,
            priority=91,
        )
    )

    # Large payload exfiltration
    def _is_large_payload(call: dict) -> bool:
        args = call.get("arguments", {})
        for val in _all_string_values(args):
            if len(val) > 50000:
                return True
        return False

    proxy.add_rule(
        ProxyRule(
            name="large_payload_block",
            description="Block oversized payloads (>50KB) indicating data exfil",
            tool_pattern=r"(webhook|http|api)\.",
            action=ProxyAction.BLOCK,
            condition=_is_large_payload,
            priority=70,
        )
    )

    # Prompt injection detection
    def _is_prompt_injection(call: dict) -> bool:
        import re as _re

        args = call.get("arguments", {})
        for val in _all_string_values(args):
            injection_patterns = [
                r"ignore\s+(all\s+)?previous\s+instructions",
                r"system\s+override",
                r"you\s+are\s+now\s+DAN",
                r"reveal\s+(your\s+)?(system\s+prompt|api\s*key)",
                r"<system>.*</system>",
                r"<\s*/?system\s*>",
                r"new\s+instructions?\s*:",
                r"jailbreak",
                r"bypass\s+(safety|filter|restriction)",
            ]
            for pat in injection_patterns:
                if _re.search(pat, val, _re.IGNORECASE):
                    return True
        return False

    proxy.add_rule(
        ProxyRule(
            name="prompt_injection_block",
            description="Block prompt injection attempts",
            tool_pattern=r".*",
            action=ProxyAction.BLOCK,
            condition=_is_prompt_injection,
            priority=93,
        )
    )

    # Rogue/unregistered server detection
    _known_servers = {
        "postmark",
        "email",
        "sendgrid",
        "smtp",
        "vault",
        "openai",
        "search",
        "database",
        "webhook",
        "calc",
        "system",
        "filesystem",
        "api",
        "proxy",
        "network",
        "auth",
        "ml-pipeline",
        "storage",
        "package-manager",
    }

    def _is_rogue_server(call: dict) -> bool:
        server_id = call.get("server_id", "")
        return server_id not in _known_servers and bool(server_id)

    proxy.add_rule(
        ProxyRule(
            name="rogue_server_block",
            description="Block calls from unregistered MCP servers",
            tool_pattern=r".*",
            action=ProxyAction.BLOCK,
            condition=_is_rogue_server,
            priority=95,
        )
    )

    # Email to known attacker domains
    def _is_email_to_attacker(call: dict) -> bool:
        import re as _re

        args = call.get("arguments", {})
        suspicious_domains = [
            r"@evil\.com",
            r"@attacker",
            r"@malicious",
            r"@bad\.com",
            r"@hack",
            r"\.(tk|ml|ga|cf|gq|club|xyz|top|buzz)\b",
        ]
        for val in _all_string_values(args):
            for pat in suspicious_domains:
                if _re.search(pat, val, _re.IGNORECASE):
                    return True
        return False

    proxy.add_rule(
        ProxyRule(
            name="email_attacker_domain_block",
            description="Block email to known malicious domains",
            tool_pattern=r"(email|smtp|sendgrid|postmark)\.",
            action=ProxyAction.BLOCK,
            condition=_is_email_to_attacker,
            priority=85,
        )
    )

    # PII query detection (SQL with sensitive columns)
    def _is_pii_query(call: dict) -> bool:
        import re as _re

        args = call.get("arguments", {})
        sql = str(args.get("sql", "")) + str(args.get("query", ""))
        pii_columns = r"(ssn|social_security|credit_card|card_number|cvv|password|secret)"
        if _re.search(pii_columns, sql, _re.IGNORECASE):
            return True
        return False

    proxy.add_rule(
        ProxyRule(
            name="pii_query_block",
            description="Block queries selecting PII/sensitive columns",
            tool_pattern=r"(db|database|sql)\.",
            action=ProxyAction.BLOCK,
            condition=_is_pii_query,
            priority=80,
        )
    )

    # Privilege escalation detection
    def _is_privilege_escalation(call: dict) -> bool:
        import re as _re

        args = call.get("arguments", {})
        for val in _all_string_values(args):
            priv_patterns = [
                r"sudo\s+",
                r"chmod\s+[0-7]*[4-7][0-7]*\s",
                r"chown\s+root",
                r"--privileged",
                r"setuid",
            ]
            for pat in priv_patterns:
                if _re.search(pat, val, _re.IGNORECASE):
                    return True
        if str(args.get("run_as", "")).lower() == "root":
            return True
        return False

    proxy.add_rule(
        ProxyRule(
            name="privilege_escalation_block",
            description="Block privilege escalation attempts",
            tool_pattern=r".*",
            action=ProxyAction.BLOCK,
            condition=_is_privilege_escalation,
            priority=94,
        )
    )

    # Supply chain typosquat detection
    def _is_supply_chain_attack(call: dict) -> bool:
        import re as _re

        args = call.get("arguments", {})
        source = str(args.get("source", "")) + str(args.get("index_url", ""))
        if source and not _re.search(r"pypi\.org|npmjs\.com|registry\.npmjs", source):
            if _re.search(r"https?://", source):
                return True
        return False

    proxy.add_rule(
        ProxyRule(
            name="supply_chain_block",
            description="Block package installs from untrusted sources",
            tool_pattern=r"(pip|npm|yarn|package)\.",
            action=ProxyAction.BLOCK,
            condition=_is_supply_chain_attack,
            priority=82,
        )
    )

    # DNS tunneling / suspicious DNS
    def _is_dns_tunneling(call: dict) -> bool:
        import re as _re

        args = call.get("arguments", {})
        domain = str(args.get("domain", ""))
        suspicious_tlds = [r"\.(xyz|tk|ml|ga|cf|gq|club|top|buzz)$"]
        for pat in suspicious_tlds:
            if _re.search(pat, domain, _re.IGNORECASE):
                return True
        # Long subdomain (common in DNS tunneling)
        if len(domain) > 50:
            return True
        return False

    proxy.add_rule(
        ProxyRule(
            name="dns_tunneling_block",
            description="Block suspicious DNS queries (tunneling)",
            tool_pattern=r"(dns|resolve)\.",
            action=ProxyAction.BLOCK,
            condition=_is_dns_tunneling,
            priority=78,
        )
    )

    # Register server policies for kernel
    for sid in (
        "postmark",
        "email",
        "sendgrid",
        "smtp",
        "vault",
        "openai",
        "search",
        "database",
        "webhook",
        "calc",
        "system",
        "filesystem",
        "api",
        "proxy",
        "network",
        "auth",
        "ml-pipeline",
        "storage",
        "package-manager",
    ):
        kernel.register_policy(
            ServerPolicy(
                server_id=sid,
                allowed_destinations={"api.postmarkapp.com", "smtp.postmarkapp.com"},
                allowed_ports={443, 80},
                allow_subprocess=False,
            )
        )

    # Add egress rules
    egress.add_rule(
        EgressRule(
            name="default_servers",
            description="Allow known API endpoints only",
            server_pattern=r".*",
            allowed_domains={
                "api.postmarkapp.com",
                "smtp.postmarkapp.com",
                "api.sendgrid.com",
                "api.openai.com",
            },
            allowed_ports={443, 80},
            blocked_domains={
                "giftshop.club",
                "evil.com",
                "attacker-domain.tk",
                "evil-collector.ngrok.io",
                "darkweb.onion",
                "attacker-dns.xyz",
                "evil-pypi.com",
            },
            blocked_ips={"185.234.72.15", "169.254.169.254", "127.0.0.1", "10.0.0.1"},
            max_payload_bytes=50000,
        )
    )

    return FiveLayerDefense(proxy=proxy, kernel=kernel, semantic=semantic, egress=egress)


def _all_string_values(obj: Any) -> list[str]:
    """Recursively extract all string values from nested dict/list."""
    strings: list[str] = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            strings.extend(_all_string_values(v))
    elif isinstance(obj, list | tuple):
        for item in obj:
            strings.extend(_all_string_values(item))
    return strings


defense = _build_defense()

# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------


class ConnectionManager:
    """Manages active WebSocket connections."""

    def __init__(self) -> None:
        self.active: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active:
            self.active.remove(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)


manager = ConnectionManager()

# ---------------------------------------------------------------------------
# Event statistics
# ---------------------------------------------------------------------------

stats: dict[str, Any] = {
    "total_events": 0,
    "blocked": 0,
    "allowed": 0,
    "by_layer": {2: 0, 3: 0, 4: 0, 5: 0},
    "by_category": {},
    "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    "start_time": time.time(),
    "events_per_second": 0.0,
    "recent_eps": [],
}

recent_threats: list[dict[str, Any]] = []

# ---------------------------------------------------------------------------
# Background event simulator
# ---------------------------------------------------------------------------

_simulator_running = False


async def event_simulator() -> None:
    """Continuously simulate attacks and broadcast results."""
    global _simulator_running
    _simulator_running = True
    event_count_window: list[float] = []

    while _simulator_running:
        attack = random.choice(ATTACK_CATALOG)
        tool_call = attack.get("tool_call")

        if tool_call is None:
            # Kernel-only attack — simulate it differently
            event_data = _simulate_kernel_attack(attack)
        else:
            verdict = defense.evaluate_call(tool_call)
            event_data = {
                "type": "security_event",
                "timestamp": time.time(),
                "attack_name": attack["name"],
                "category": attack["category"],
                "severity": attack.get("severity", "MEDIUM"),
                "tool_name": tool_call.get("name", "unknown"),
                "server_id": tool_call.get("server_id", "unknown"),
                "blocked": not verdict.allowed,
                "blocked_by_layer": verdict.blocked_by_layer,
                "risk_score": verdict.total_risk_score,
                "findings": [f for lr in verdict.layer_results for f in lr.findings][:3],
                "verdict": "BLOCKED" if not verdict.allowed else "ALLOWED",
            }

        # Update stats
        stats["total_events"] += 1
        if event_data.get("blocked"):
            stats["blocked"] += 1
        else:
            stats["allowed"] += 1

        layer = event_data.get("blocked_by_layer")
        if layer and layer in stats["by_layer"]:
            stats["by_layer"][layer] += 1

        cat = event_data.get("category", "unknown")
        stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

        sev = event_data.get("severity", "MEDIUM")
        if sev in stats["by_severity"]:
            stats["by_severity"][sev] += 1

        # EPS tracking
        now = time.time()
        event_count_window.append(now)
        event_count_window = [t for t in event_count_window if now - t <= 5.0]
        stats["events_per_second"] = len(event_count_window) / 5.0
        stats["recent_eps"].append(round(stats["events_per_second"], 2))
        stats["recent_eps"] = stats["recent_eps"][-60:]

        # Track recent threats
        recent_threats.insert(0, event_data)
        if len(recent_threats) > 200:
            recent_threats.pop()

        # Broadcast to all connected clients
        await manager.broadcast(event_data)

        # Random delay 300-700ms for realistic feel
        await asyncio.sleep(random.uniform(0.3, 0.7))


def _simulate_kernel_attack(attack: dict[str, Any]) -> dict[str, Any]:
    """Process kernel-only attacks."""
    from mcp_monitor.layers.kernel import SyscallEvent, SyscallType

    kernel_events = attack.get("kernel_events", [])
    blocked = False
    findings: list[str] = []

    for ke in kernel_events:
        syscall_type = SyscallType(ke["syscall_type"])
        event = SyscallEvent(
            server_id="unknown",
            syscall_type=syscall_type,
            details=ke["details"],
        )
        alerts = defense.evaluate_kernel_event(event)
        if alerts:
            blocked = True
            for a in alerts:
                findings.append(f"{a.alert_type}: {a.description}")

    return {
        "type": "security_event",
        "timestamp": time.time(),
        "attack_name": attack["name"],
        "category": attack["category"],
        "severity": attack.get("severity", "HIGH"),
        "tool_name": "kernel_syscall",
        "server_id": "system",
        "blocked": blocked,
        "blocked_by_layer": 3 if blocked else None,
        "risk_score": 90 if blocked else 0,
        "findings": findings[:3],
        "verdict": "BLOCKED" if blocked else "ALLOWED",
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.on_event("startup")
async def startup_event() -> None:
    """Start the background event simulator."""
    asyncio.create_task(event_simulator())


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    """Serve the SOC dashboard."""
    html_content = DASHBOARD_PATH.read_text(encoding="utf-8")
    return HTMLResponse(content=html_content)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time event streaming."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, accept any messages from client
            data = await websocket.receive_text()
            # Echo back stats on request
            if data == "stats":
                await websocket.send_json({"type": "stats", **stats})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


@app.get("/api/stats")
async def api_stats() -> dict[str, Any]:
    """Return current statistics."""
    total = stats["total_events"]
    blocked = stats["blocked"]
    return {
        "total_events": total,
        "blocked": blocked,
        "allowed": stats["allowed"],
        "detection_rate": round(blocked / max(total, 1) * 100, 1),
        "events_per_second": round(stats["events_per_second"], 2),
        "by_layer": stats["by_layer"],
        "by_category": stats["by_category"],
        "by_severity": stats["by_severity"],
        "uptime_seconds": round(time.time() - stats["start_time"], 1),
    }


@app.get("/api/threats")
async def api_threats() -> list[dict[str, Any]]:
    """Return recent threat events."""
    return recent_threats[:50]


@app.post("/api/scan")
async def api_scan(tool_call: dict[str, Any]) -> dict[str, Any]:
    """Scan a tool call through the 5-layer defense and return verdict."""
    verdict = defense.evaluate_call(tool_call)
    return {
        "call_id": verdict.call_id,
        "allowed": verdict.allowed,
        "blocked_by_layer": verdict.blocked_by_layer,
        "risk_score": verdict.total_risk_score,
        "enforcement_action": verdict.enforcement_action,
        "layer_results": [
            {
                "layer": lr.layer,
                "layer_name": lr.layer_name,
                "passed": lr.passed,
                "risk_score": lr.risk_score,
                "findings": lr.findings,
                "execution_time_ms": round(lr.execution_time_ms, 3),
            }
            for lr in verdict.layer_results
        ],
    }


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════╗")
    print("║  MCP Security Gateway — Real-Time Monitor           ║")
    print("╠══════════════════════════════════════════════════════╣")
    print("║  Dashboard: http://localhost:8000                    ║")
    print("║  WebSocket: ws://localhost:8000/ws                   ║")
    print("║  API Docs:  http://localhost:8000/docs               ║")
    print("╚══════════════════════════════════════════════════════╝")
    uvicorn.run(app, host="0.0.0.0", port=8000)
