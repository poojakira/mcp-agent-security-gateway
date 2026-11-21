"""Real browser acceptance; run after installing the package and Playwright."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from playwright.sync_api import expect, sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--chromium", default="/usr/bin/chromium")
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(
        [sys.executable, "-m", "mcp_monitor.workbench", "--port", "0"],
        stdout=subprocess.PIPE,
        text=True,
    )
    line = process.stdout.readline()
    if not line.startswith("MCP Security Workbench: http://127.0.0.1:"):
        raise RuntimeError("This test's server did not start")
    base = line.strip().split()[-1]
    try:
        for _ in range(100):
            try:
                with urlopen(base + "/health", timeout=1) as response:
                    health = json.load(response)
                break
            except (URLError, TimeoutError):
                time.sleep(0.05)
        else:
            raise RuntimeError("Local startup failed")
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=args.chromium, headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 1100}, accept_downloads=True)
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(base)

            def execute(expected):
                page.get_by_role("button", name="Execute request", exact=True).click()
                expect(page.locator("#run")).to_be_enabled(timeout=10000)
                assert page.locator("#outcome").inner_text() == expected

            execute("CONFIRMED_SUCCEEDED")
            page.locator("#scenario").select_option("write")
            original = page.locator("#request").input_value()
            execute("NOT_INVOKED")
            assert '"receipts": []' in page.locator("#state").inner_text()
            page.locator("#guarded").uncheck()
            execute("CONFIRMED_SUCCEEDED")
            assert page.locator("#request").input_value() == original
            assert "A browser supplied update." in page.locator("#state").inner_text()
            with page.expect_download() as pending:
                page.get_by_role("button", name="Export redacted evidence").click()
            pending.value.save_as(output / "browser-export.json")
            report = json.loads((output / "browser-export.json").read_text())
            assert report["request"].startswith("[REDACTED")
            assert report["tool_state"]["note"].startswith("[REDACTED")
            assert "A browser supplied update." not in json.dumps(report)
            page.screenshot(path=str(output / "desktop.png"), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            page.screenshot(path=str(output / "mobile.png"), full_page=True)
            assert not errors, errors
            browser.close()
        (output / "browser-result.json").write_text(
            json.dumps(
                {
                    "result": "passed",
                    "health": health,
                    "checks": [
                        "real read",
                        "denied write has no receipt",
                        "same request permission comparator writes",
                        "redacted export",
                        "mobile bounds",
                        "no page errors",
                    ],
                },
                indent=2,
            )
        )
    finally:
        process.terminate()
        process.wait(timeout=10)


if __name__ == "__main__":
    main()
