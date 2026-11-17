"""Independent adversarial checks; never writes the source checkout."""
import asyncio
import datetime
import hashlib
import http.client
import json
import pathlib
import subprocess
import threading

from playwright.sync_api import expect, sync_playwright

from mcp_monitor.workbench.__main__ import create_server
from mcp_monitor.workbench.runtime import INITIAL_NOTE, execute

ROOT = pathlib.Path('/workspace/work/candidates/mcp-agent-security-gateway')
OUT = pathlib.Path('/workspace/work/reviews/mcp-agent-security-gateway/final-archive-recheck')
EVIDENCE = pathlib.Path('/workspace/work/evidence/mcp-agent-security-gateway/final')
sha = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
result = {'source_commit': sha, 'utc_start': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'checks': []}

def record(name, passed, **details):
    result['checks'].append({'name': name, 'passed': bool(passed), **details})

def raw(name, args=None, identifier=1):
    return json.dumps({'jsonrpc': '2.0', 'id': identifier, 'method': 'tools/call', 'params': {'name': name, 'arguments': args or {}}})

manifest = json.loads((EVIDENCE / 'manifest.json').read_text())
mismatches = [name for name, digest in manifest['artifacts'].items() if hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest() != digest]
record('manifest artifact checksums', not mismatches, artifacts=len(manifest['artifacts']), mismatches=mismatches)
record('manifest source is checked-out clean source', manifest['source_commit'] == sha and not subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain'], text=True).strip())

one = asyncio.run(execute(raw('append_note', {'text': 'independent-repeat\n'}), preset='read-write', repeats=1))
two = asyncio.run(execute(raw('append_note', {'text': 'independent-repeat\n'}), preset='read-write', repeats=2))
record('repeat count represented by configuration hash', one['configuration_sha256'] != two['configuration_sha256'], one_hash=one['configuration_sha256'], two_hash=two['configuration_sha256'], one_receipts=len(one['tool_state']['receipts']), two_receipts=len(two['tool_state']['receipts']), repeat_count_in_report='repeats' in one)

for name, message, options, expected in [
    ('duplicate JSON keys', '{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call","params":{"name":"read_note"}}', {}, 'NOT_INVOKED'),
    ('outbound metadata destination', raw('http_get', {'url': 'http://169.254.169.254/latest/meta-data/'}), {}, 'NOT_INVOKED'),
    ('literal cross-workspace path', raw('read_note', {'path': '/etc/passwd'}), {'guarded': False}, 'CONFIRMED_FAILED'),
    ('alternate method', json.dumps({'jsonrpc':'2.0','id':1,'method':'resources/read','params':{'uri':'file:///etc/passwd'}}), {'guarded':False}, 'NOT_INVOKED'),
    ('crash uncertainty', raw('crash'), {}, 'UNKNOWN / REQUIRES_RECONCILIATION'),
    ('timeout uncertainty', raw('timeout'), {}, 'UNKNOWN / REQUIRES_RECONCILIATION'),
]:
    actual = asyncio.run(execute(message, **options))
    record(name, actual['outcome'] == expected, expected=expected, actual=actual['outcome'], error=actual['error'], receipts=len(actual['tool_state']['receipts']), unchanged_note=actual['tool_state']['note'] == INITIAL_NOTE)

server = create_server(0)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
base = f'http://127.0.0.1:{server.server_port}'

def post(body, headers=None):
    conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=10)
    conn.request('POST', '/api/execute', body=body, headers={'Content-Type':'application/json', **(headers or {})})
    response = conn.getresponse()
    data = json.loads(response.read())
    status = response.status
    conn.close()
    return status, data

try:
    for name, body, headers, expected in [
        ('cross-origin HTTP rejection', json.dumps({'request': raw('read_note')}), {'Origin':'https://attacker.example'},403),
        ('DNS-rebinding Host rejection', json.dumps({'request': raw('read_note')}), {'Host':'attacker.example'},403),
        ('unknown fields rejected', json.dumps({'request':raw('read_note'),'target':'/etc/passwd'}), {},400),
        ('oversized body rejected', 'x'*16385, {},413),
        ('deep malformed JSON rejected', '['*1400+'0'+']'*1400, {},400),
        ('simple-form CSRF content type rejected', json.dumps({'request':raw('read_note')}), {'Content-Type':'text/plain'},415),
    ]:
        status, data = post(body,headers)
        record(name,status == expected,expected=expected,actual=status,detail=data)
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path='/usr/bin/chromium', headless=True)
        page = browser.new_page(accept_downloads=True)
        page.goto(base)
        text = 'Independent operator supplied note for the actual tool'
        page.locator('#request').fill(raw('update_note', {'text':text}, identifier='synthetic-sensitive-id'))
        page.locator('#preset').select_option('read-write')
        page.get_by_role('button', name='Execute request', exact=True).click()
        expect(page.locator('#run')).to_be_enabled(timeout=10000)
        record('browser custom user input reaches actual engine', page.locator('#outcome').inner_text() == 'CONFIRMED_SUCCEEDED' and json.loads(page.locator('#state').inner_text())['note'] == text)
        record('browser treats result markup as text', page.evaluate('window.reviewInjection === undefined') and page.locator('#state img').count() == 0)
        with page.expect_download() as download:
            page.get_by_role('button', name='Export redacted evidence').click()
        download.value.save_as(OUT/'independent-export.json')
        report = json.loads((OUT/'independent-export.json').read_text())
        record('browser export source provenance',report['source_commit'] == sha)
        record('browser export removes request result note and IDs',text not in json.dumps(report) and 'synthetic-sensitive-id' not in json.dumps(report))
        markup = '<img src=x onerror="window.reviewInjection=1">'
        page.locator('#request').fill(raw('update_note', {'text':markup}))
        page.get_by_role('button', name='Execute request', exact=True).click()
        expect(page.locator('#run')).to_be_enabled(timeout=10000)
        record('hostile markup is denied by actual injection engine',page.locator('#outcome').inner_text() == 'NOT_INVOKED' and json.loads(page.locator('#state').inner_text())['receipts'] == [])
        record('hostile request displayed safely as text',page.evaluate('window.reviewInjection === undefined') and page.locator('#result img').count() == 0)
        page.screenshot(path=str(OUT/'independent-browser.png'),full_page=True)
        browser.close()
    statuses = []
    for _ in range(45):
        status,_ = post(json.dumps({'request':raw('read_note')}))
        statuses.append(status)
        if status == 429:
            break
    record('actual requests exhaust HTTP rate limiter',429 in statuses,request_count=len(statuses),statuses=statuses)
finally:
    server.shutdown()
    server.server_close()
    thread.join()

result['utc_end']=datetime.datetime.now(datetime.timezone.utc).isoformat()
(OUT/'independent-checks.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'checks':len(result['checks']),'failed':[x for x in result['checks'] if not x['passed']]},indent=2))
