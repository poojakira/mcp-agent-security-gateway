import json
import sys

with open('bandit-report.json') as f:
    data = json.load(f)

high_med = [r for r in data.get('results', []) if r['issue_severity'] in ('HIGH', 'MEDIUM')]
if high_med:
    print(f'FAIL: {len(high_med)} HIGH/MEDIUM findings')
    for r in high_med:
        print(f'  {r["filename"]}:{r["line_number"]} - {r["issue_text"]}')
    sys.exit(1)
print('PASS: No HIGH/MEDIUM Bandit findings')