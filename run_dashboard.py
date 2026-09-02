#!/usr/bin/env python3
"""Run the MCP Security Gateway Monitor dashboard.

Wires the detector-backed Layer-2 inspector into the 5-layer defense, replays
the bundled red-team attack catalog, prints a terminal report, generates an
HTML dashboard, and opens it in the default browser.

NOTE ON THE DETECTION NUMBER
----------------------------
The percentage printed here is a **regression self-test against the bundled
catalog** (``mcp_monitor/redteam/payloads.py``) shipped in this repo. It proves
the five layers are wired correctly and that every catalogued technique is
caught end-to-end. It is *not* a real-world detection rate against novel,
unseen attacks. Treat it as a build gate, not a benchmark.
"""

import os
import tempfile
import webbrowser

from mcp_monitor.audit.log import AuditLog
from mcp_monitor.dashboard import HTMLReportGenerator, TerminalDashboard
from mcp_monitor.layers import (
    FiveLayerDefense,
    InlineProxyGateway,
    KernelMonitor,
    NetworkEgressPolicy,
    SemanticIntentAnalyzer,
)
from mcp_monitor.layers.egress import EgressRule
from mcp_monitor.layers.kernel import ServerPolicy
from mcp_monitor.monitor import MCPSecurityMonitor
from mcp_monitor.redteam import AttackSimulator


def main() -> None:
    # --- Layer 1/2 inspector: the real detector suite (prompt-injection, PII,
    # shadow-server, exfiltration) backing the inline proxy. Without this the
    # proxy has no content intelligence, which is the configuration that made
    # earlier demo runs under-report. ---
    audit = AuditLog(os.path.join(tempfile.gettempdir(), "mcp_dashboard_selftest_audit.log"))
    inspector = MCPSecurityMonitor(allowed_servers={"mcp-server"}, audit_log=audit)

    # --- Layer 2: Inline Proxy Gateway (detector-backed) ---
    proxy = InlineProxyGateway(inspector=inspector, block_threshold=50, quarantine_threshold=30)

    # --- Layer 3: Kernel Monitor with a default server policy ---
    kernel = KernelMonitor()
    default_policy = ServerPolicy(
        server_id="mcp-server",
        allowed_destinations={"api.github.com", "smtp.postmarkapp.com"},
        allowed_ports={443, 993},
        allowed_paths={"/tmp", "/var/log"},
        blocked_destinations={"evil.com", "attacker.tk", "exfil.ngrok.io"},
        max_connections_per_minute=60,
        allow_subprocess=False,
        allow_dns=True,
    )
    kernel.register_policy(default_policy)

    # --- Layer 4: Semantic Intent Analyzer ---
    semantic = SemanticIntentAnalyzer(sensitivity=0.7)

    # --- Layer 5: Network Egress Policy with rules ---
    egress = NetworkEgressPolicy(default_deny=True)
    egress.add_rule(
        EgressRule(
            name="allow-known-apis",
            description="Allow traffic to trusted API endpoints",
            server_pattern=".*",
            allowed_domains={"api.github.com", "smtp.postmarkapp.com", "api.openai.com"},
            allowed_ports={443, 993},
            blocked_domains={"evil.com", "attacker.tk", "exfil.ngrok.io", "malware.xyz"},
            max_payload_bytes=102400,
        )
    )

    # --- Assemble the 5-Layer Defense ---
    defense = FiveLayerDefense(
        proxy=proxy,
        kernel=kernel,
        semantic=semantic,
        egress=egress,
    )

    # --- Run the full red-team attack catalog ---
    simulator = AttackSimulator(defense)
    report = simulator.run_full_catalog()

    # --- Terminal Dashboard output ---
    terminal = TerminalDashboard()
    terminal_output = terminal.render_simulation_report(report)
    print(terminal_output)

    # --- HTML Report ---
    html_gen = HTMLReportGenerator()
    html_content = html_gen.generate(report)

    output_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "security_dashboard.html"
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"  HTML dashboard saved to: {output_path}")
    print("  Opening in browser...")
    webbrowser.open(f"file://{output_path}")


if __name__ == "__main__":
    main()
