"""Read-only comparisons of APTrace artifacts, not a firmware model/runner."""
import pathlib,json,hashlib,collections
P=pathlib.Path(__file__).resolve().parent
checks=[];out=[];data={}
def ck(n,b): checks.append(dict(check=n,passed=bool(b)))
rows=json.loads((P/'concrete-commands.json').read_text())
for r in rows:
 n=r['name'];f=P/(n+'.json');d=json.loads(f.read_text());data[n]=d
 ck(n+' error-free',d['error_free']);ck(n+' bounded termination',d['stop_reason'].startswith(('reached stop address','instruction limit reached')))
 ck(n+' watch cap',len(d['watch_hits'])<4000)
 writes=[x for x in d['mmio_log'] if x['direction']=='write']
 out.append(dict(name=n,scope=r['scope'],sha256=hashlib.sha256(f.read_bytes()).hexdigest(),instructions=d['instructions_executed'],stop=d['stop_reason'],memory=d['memory'],calls=dict(collections.Counter(h['address'] for h in d['watch_hits'])),mmio_writes=writes,events=[dict(pc=h['address'],instruction=h['instruction'],r0=h['registers']['r0'],lr=h['registers']['lr']) for h in d['watch_hits'] if h['address'] in ['0x00005f8c','0x00005810','0x00005fa4','0x00006fd8','0x00006e4c']]))
for n in ['B1-full-reset','G-to-enable','W1-to-enable','W1-nonzero-to-enable']:
 d=data[n];ck(n+' original enable/live boundary',d['registers']['pc']=='0x00005fa6' and int.from_bytes(bytes.fromhex(d['memory']['0x40003800'])[:4],'little')&2 and d['memory']['0x20001b14'].startswith('01'))
ck('B1 before MC4 with invalid marker',data['B1-full-reset']['memory']['0x20001b38']=='ff000000' and data['B1-full-reset']['memory']['0x20000060']=='01')
for n in ['B1-latch-blocked','B1-busy-blocked']:
 ck(n+' no rate/enable',not any(h['address']=='0x00005f8c' for h in data[n]['watch_hits']) and not(int.from_bytes(bytes.fromhex(data[n]['memory']['0x40003800'])[:4],'little')&2))
for n in ['G-to-enable','W1-to-enable','W1-nonzero-to-enable']:
 ck(n+' no external trigger acceptance',not any(h['address']=='0x00008f98' for h in data[n]['watch_hits']))
ck('G reaches request',any(h['address']=='0x00006fd8' for h in data['G-to-enable']['watch_hits']))
ck('W1 uses reload, no G request',any(h['address']=='0x00006e4c' for h in data['W1-to-enable']['watch_hits']) and not any(h['address']=='0x00006fd8' for h in data['W1-to-enable']['watch_hits']))
addrs={0:'0x40003800',1:'0x40003c00',2:'0x4101a000',3:'0x4101c000',7:'0x41018000'}
for ch in [0,1,2,3,7,4]:
 d=data['enable-ch'+str(ch)];enabled=[a for a in addrs.values() if int.from_bytes(bytes.fromhex(d['memory'][a])[:4],'little')&2];ck('enable dispatch ch'+str(ch),enabled==([addrs[ch]] if ch in addrs else []))
for n,pos in [('period-catchup','01000000'),('period-equal','00000000'),('period-below','00000000')]:
 ck(n+' position',data[n]['memory']['0x20002064']==pos)
 ck(n+' timer remains disabled',not(int.from_bytes(bytes.fromhex(data[n]['memory']['0x40003800'])[:4],'little')&2))
 ck(n+' pulse writes',sum(x['direction']=='write' and x['address'] in ['0x41008098','0x41008094'] for x in data[n]['mmio_log'])==(2 if n=='period-catchup' else 0))
for n,second in [('group-two-channels',True),('group-zero-ratio',False),('group-threshold-control',False)]:
 ck(n+' positions',data[n]['memory']['0x20002064']==('0100000001000000' if second else '0100000000000000'))
 ck(n+' pulse selection',[h['registers']['r0'] for h in data[n]['watch_hits']]==(['0x00000000','0x00000001'] if second else ['0x00000000']))
 ck(n+' slave TC1 disabled',data[n]['memory']['0x40003c00']=='00000000')
for ch in range(4):
 expect=b''.join((1 if i==ch else 0).to_bytes(4,'little') for i in range(4)).hex();ck('handler channel'+str(ch)+' position',data['handler-ch'+str(ch)]['memory']['0x20002064']==expect)
ck('auxiliary handler toggles PB22',any(x['direction']=='write' and x['address']=='0x4100809c' and x['value']=='0x400000' for x in data['handler-ch7']['mmio_log']))
(P/'checks.json').write_text(json.dumps(checks,indent=2)+'\n');(P/'outcomes.json').write_text(json.dumps(out,indent=2)+'\n')
print(len(checks),'checks;',sum(c['passed'] for c in checks),'pass')
for c in checks:
 if not c['passed']:print(c)
assert all(c['passed'] for c in checks)
