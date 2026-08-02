"""Launch the real-time MCP security dashboard.

Usage: python run_realtime.py
Then open: http://localhost:8000
"""

import uvicorn

from mcp_monitor.server.realtime import app

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════╗")
    print("║  MCP Security Gateway — Real-Time Monitor           ║")
    print("╠══════════════════════════════════════════════════════╣")
    print("║  Dashboard: http://localhost:8000                    ║")
    print("║  WebSocket: ws://localhost:8000/ws                   ║")
    print("║  API Docs:  http://localhost:8000/docs               ║")
    print("╚══════════════════════════════════════════════════════╝")
    uvicorn.run(app, host="0.0.0.0", port=8000)
