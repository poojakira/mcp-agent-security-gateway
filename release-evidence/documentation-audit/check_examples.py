from pathlib import Path
import json,re,subprocess,threading,urllib.request,datetime
from mcp_monitor.workbench.__main__ import create_server
repo=Path('/workspace/work/candidates/mcp-agent-security-gateway');checks=[]
for name in subprocess.check_output(['git','ls-files'],cwd=repo,text=True).splitlines():
 p=repo/name
 if p.suffix!='.md':continue
 for language,body in re.findall(r'^```([^\n]*)\n(.*?)^```',p.read_text(),re.M|re.S):
  if language.strip() in ['sh','bash']:
   result=subprocess.run(['bash','-n'],input=body,text=True,capture_output=True);checks.append({'document':name,'check':'bash syntax only; not executed','exit_code':result.returncode,'error':result.stderr});assert result.returncode==0,(name,result.stderr)
  if language.strip()=='json':json.loads(body);checks.append({'document':name,'check':'JSON example syntax','exit_code':0})
text=(repo/'docs/API_VERSIONING.md').read_text();body=re.search(r'^```json\n(.*?)^```',text,re.M|re.S).group(1);payload=json.loads(body);server=create_server(0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
try:
 request=urllib.request.Request('http://127.0.0.1:'+str(server.server_port)+'/api/execute',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(request,timeout=10) as response:report=json.load(response)
 assert report['outcome']=='CONFIRMED_SUCCEEDED' and len(report['tool_state']['receipts'])==1
 checks.append({'document':'docs/API_VERSIONING.md','check':'actual documented API envelope through fresh loopback server, real policy/proxy/stdio child','exit_code':0,'observed_outcome':report['outcome'],'source_commit_observed':report['source_commit'],'source_status_observed':report['source_status'],'receipt_count':len(report['tool_state']['receipts'])})
finally:server.shutdown();server.server_close();thread.join(2)
result={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Documentation example checks; exact source/status observed in runtime check; no full-suite or release claim','checks':checks};Path('/workspace/work/doc-reconciliation/mcp-agent-security-gateway/example-checks.json').write_text(json.dumps(result,indent=2)+'\n');print('Documentation example checks:',len(checks),'passed')
