"""Launch the MCP Security Gateway real-time dashboard.

Usage: python run_realtime.py
Open:  http://localhost:8000
"""

import uvicorn
from mcp_monitor.server.realtime import app

if __name__ == "__main__":
    print("MCP Security Gateway - Real-Time Monitor")
    print("Dashboard: http://localhost:8000")
    print("API Docs:  http://localhost:8000/docs")
    print("WebSocket: ws://localhost:8000/ws")
    uvicorn.run(app, host="127.0.0.1", port=8000)
