"""Run inside a disposable network-none, read-only gateway image, never on a host."""

import importlib.util
import json
import os
import subprocess
import time
import urllib.error
import urllib.request

assert os.getuid() != 0
for module in ("pip", "setuptools", "ensurepip"):
    assert importlib.util.find_spec(module) is None, module
assert not os.path.exists("/var/run/docker.sock")
assert os.listdir("/sys/class/net") == ["lo"]
try:
    open("/forbidden-root-write", "w").close()
    raise AssertionError("writable root")
except OSError:
    pass
process = subprocess.Popen(
    ["python", "-c", "from mcp_monitor.production.server import run_server; run_server()"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    for attempt in range(60):
        try:
            with opener.open("http://127.0.0.1:8080/v1/health", timeout=0.2) as reply:
                assert reply.status == 200
            break
        except OSError:
            time.sleep(0.05)
    else:
        raise AssertionError("gateway did not become healthy")
    try:
        opener.open(
            urllib.request.Request(
                "http://127.0.0.1:8080/v1/inspect_call",
                data=b"{}",
                headers={"Content-Type": "application/json"},
            ),
            timeout=2,
        )
        raise AssertionError("unauthenticated inspection accepted")
    except urllib.error.HTTPError as error:
        assert error.code == 503, error.code
    print(
        json.dumps(
            {
                "non_root": True,
                "readonly_root": True,
                "docker_socket_absent": True,
                "network_interfaces": ["lo"],
                "health": 200,
                "unconfigured_auth_inspection": 503,
            }
        )
    )
finally:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
