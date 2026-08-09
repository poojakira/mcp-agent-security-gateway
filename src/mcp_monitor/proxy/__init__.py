"""Real-time stdio MCP proxy for inspecting and blocking malicious tool calls."""

from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy, inspect_message

__all__ = ["StdioMCPProxy", "inspect_message"]
