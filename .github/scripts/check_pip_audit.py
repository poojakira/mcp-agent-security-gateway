import json
import sys
from pathlib import Path

report = Path("pip-audit.json")
if not report.exists():
    print("FAIL: pip-audit.json was not produced")
    sys.exit(1)

try:
    data = json.loads(report.read_text(encoding="utf-8"))
except json.JSONDecodeError as exc:
    print(f"FAIL: invalid pip-audit JSON: {exc}")
    sys.exit(1)

if isinstance(data, dict):
    packages = data.get("dependencies")
elif isinstance(data, list):
    packages = data
else:
    packages = None

if not isinstance(packages, list):
    print("FAIL: unrecognized pip-audit JSON schema")
    sys.exit(1)

vulnerable = [pkg for pkg in packages if pkg.get("vulns")]
if vulnerable:
    print(f"FAIL: {len(vulnerable)} packages with known vulnerabilities")
    for pkg in vulnerable:
        for vuln in pkg["vulns"]:
            print(f"  {pkg.get('name')}=={pkg.get('version')}: {vuln.get('id')}")
    sys.exit(1)

print("PASS: No known vulnerabilities reported by pip-audit")