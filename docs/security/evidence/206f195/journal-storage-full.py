import json,os
from pathlib import Path
from mcp_monitor.protocol.effect_journal import DurableEffectJournal,EffectJournalError
journal=DurableEffectJournal.bootstrap('/scratch/effects.db')
# Fill only the container's dedicated, size-limited disposable tmpfs.
with open('/scratch/filler','wb',buffering=0) as filler:
 try:
  while True:filler.write(b'x'*4096)
 except OSError as error:
  assert error.errno==28
acknowledged=0
for number in range(1000):
 try:
  journal.reserve(principal='test',server='test',tool='test',operation_key=f'op{number}',arguments={})
 except EffectJournalError:
  # A denied reservation must never enter the dispatch branch.
  result={'reservation_denied_on_full_storage':True,'denied_operation_dispatched':False,'prior_reservations':acknowledged}
  print(json.dumps(result));break
 else:
  acknowledged+=1
else:raise AssertionError('No full-store denial')
import asyncio
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy

class Target:
 def __init__(self):self.sent=0
 async def send(self,raw):
  self.sent+=1
  Path('/tmp/actual-effect.txt').write_text('changed')
 async def receive(self):return b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'

before=Path('/tmp/actual-effect.txt')
before.write_text('unchanged')
target=Target()
proxy=StdioMCPProxy(['test'],transport=target,authenticated_principal='test',effect_journal=journal,effect_tools={'write_file'})
request=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'write_file','_gateway_operation_key':'full-storage-proxy','arguments':{'path':'/tmp/actual-effect.txt','content':'changed'}}}).encode()
response=json.loads(asyncio.run(proxy.handle_message(request)))
assert 'error' in response
assert target.sent==0
assert before.read_text()=='unchanged'
print(json.dumps({'gateway_full_storage_denial':True,'actual_dispatches':target.sent,'downstream_file_unchanged':before.read_text()=='unchanged'}))
