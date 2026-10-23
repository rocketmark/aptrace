"""Saved APTrace artifacts only: no execution, controller, or ISA semantics."""
import argparse,collections,gzip,hashlib,json,math,statistics,struct
from pathlib import Path
P=Path(__file__).resolve().parent
A=P.parent/'acquisition-reuse-2026-10-23'
M=json.loads((P/'modification-manifest.json').read_text())
CORE=['digital-500','digital-10','startup-active','pc-transient','before-commit','analog-500','analog-startup-fault','analog-fault-after-arm','held-w','running-w','repress-w']
EXTRA=['digital-49','digital-51','after-commit','analog-10','analog-x2-500','analog-x-change','invalid-state']
AUX=['analog-x2-fault','digital-to-analog-active','return-edge']
ADV=['cached-no-raw','cache-forged-filter','stale-observation','gap20','gap21','gate-age20','gate-age21','mode-flip-active','release-during-motion']
EXPECTED={'digital-500':1,'digital-10':0,'startup-active':0,'pc-transient':0,'before-commit':0,'analog-500':1,'analog-startup-fault':0,'analog-fault-after-arm':1,'held-w':1,'running-w':1,'repress-w':2,'digital-49':0,'digital-51':None,'after-commit':1,'analog-10':0,'analog-x2-500':1,'analog-x-change':0,'invalid-state':0,'gap20':None,'gap21':0,'gate-age20':None,'gate-age21':0,'mode-flip-active':0,'release-during-motion':2,'analog-x2-fault':0,'digital-to-analog-active':0,'return-edge':1}
checks=[]
def ck(n,v):checks.append({'check':n,'pass':bool(v)})
def load(f):return json.loads(gzip.decompress(f.read_bytes()))if f.suffix=='.gz'else json.loads(f.read_text())
def hits(d,pc):return [h for h in d['watch_hits']if int(h['address'],16)==pc]
def memory(h,a,n):
 for k,v in h['memory'].items():
  lo=int(k,16);b=bytes.fromhex(v)
  if lo<=a and a+n<=lo+len(b):return b[a-lo:a-lo+n]
 raise KeyError(hex(a))
def u(h,a):return int.from_bytes(memory(h,a,4),'little')
def db(h,a):return struct.unpack('<d',memory(h,a,8))[0]
def fp(h):return struct.unpack('<d',struct.pack('<II',int(h['registers']['r0'],16),int(h['registers']['r1'],16)))[0]
def stats(v):return {'n':len(v),'min':min(v),'median':statistics.median(v),'max':max(v),'sum':sum(v)}if v else None
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--partial',action='store_true');arg=ap.parse_args();data={};summary={};pending=[];motor={}
 for im in ['original','phase3','optimized']:
  for case in CORE+(EXTRA+ADV+AUX if im!='original'else []):
   n=im+'-'+case;f=(P if im=='optimized'else A)/(n+'.json.gz')
   if not f.exists():pending.append(n);continue
   d=load(f);data[n]=d;bound=20000000 if case=='return-edge'else 65000000 if case in ['held-w','repress-w','release-during-motion','return-edge']else 16000000
   ck(n+': full native bound',d['error_free']and d['stop_reason']=='instruction limit reached'and bound<=d['instructions_executed']<=bound+8)
   ck(n+': untruncated',d['mem_write_dropped']==0 and len(d['watch_hits'])<100000 and d['external_fixture']['dropped_poll_ticks']==0)
   ck(n+': fixture identity',d['external_fixture']['fixture_sha256']==hashlib.sha256(((P if im=='optimized'else A)/('return-edge.py'if case=='return-edge'else 'extra-controls.py'if case in AUX else 'run-experiments.py')).read_bytes()).hexdigest())
   starts=len(hits(d,0x5fa4));accept=len(hits(d,0x8f9c));want=EXPECTED.get(case)
   if im=='original':want=2 if case in ['held-w','running-w','repress-w']else 1
   if case in ['cached-no-raw','cache-forged-filter','stale-observation']:want=0 if im=='optimized'else 1
   if want is not None:
    ck(n+': expected acceptances',accept==want);ck(n+': expected starts',starts==want)
   else:ck(n+': boundary count characterized',starts in [0,1])
   if want==0:
    for pc in [0x5f8c,0x571c,0x5810,0x5fa4]:ck(n+': no initiation at '+hex(pc),not hits(d,pc))
   if case in ['held-w','running-w','repress-w','release-during-motion','return-edge']:
    ck(n+': exactly one W delivery',sum(e.get('rx_hex')=='577c'for e in d['external_fixture']['events'])==1)
    ck(n+': native return runs',bool(hits(d,0x6fd8)))
    if im!='original' and case=='release-during-motion':
     manifest=json.loads(((P if im=='optimized'else P.parent/'stateful-trigger-patch-2026-10-22')/'modification-manifest.json').read_text());armed=int(manifest['symbols']['armed'],16)
     ck(n+': inactive arms while live',any(h['memory']['0x20001b14'].startswith('01')for h in hits(d,armed)))
    if im!='original' and case in ['held-w','running-w']:ck(n+': idle9 restored',d['memory']['0x200000d8'].startswith('09'))
   summary[n]={'acceptances':accept,'starts':starts,'instructions':d['instructions_executed'],'input_events':d['external_fixture']['events'],'milestones':d['external_fixture']['milestones'],'final_idle':d['memory']['0x200000d8'][:2],'final_state':d['memory']['0x2000531c']if im!='original'else None,'acquisitions':d['external_fixture']['acquisitions'],'patch_instructions':d['external_fixture']['patch_instructions']}
 for case in CORE+EXTRA:
  a,b='phase3-'+case,'optimized-'+case
  if a in data and b in data and not hits(data[a],0x5fa4):ck(case+': no newly accepted Phase3-excluded history',not hits(data[b],0x5fa4))
 for case in ['digital-500','analog-500']:
  group={}
  for im in ['original','phase3','optimized']:
   n=im+'-'+case
   if n not in data:continue
   d=data[n];hs=d['watch_hits'];live=hits(d,0x5fa4)[0]['instruction'];latest={};samples=[];spans=[];acqspans=[]
   for i,h in enumerate(hs):
    pc=int(h['address'],16)
    if pc in [0x6368,0x6420,0x66ee]:latest[pc]=h
    if pc==0x8e18 and h['instruction']>live:
     end=next((x for x in hs[i+1:]if int(x['address'],16)==0x943e),None)
     if end:spans.append(end['instruction']-h['instruction'])
    if pc==0x8e76 and h['instruction']>live:
     end=next((x for x in hs[i+1:]if int(x['address'],16)==0x8e7a),None)
     if end:acqspans.append(end['instruction']-h['instruction'])
    if pc==0x5c44:
     e=latest[0x6368];pol=latest[0x6420];raw=latest[0x66ee];elapsed=(int(e['registers']['r0'],16)-int(e['registers']['r3'],16))/1000;t=elapsed+u(e,0x20002954);c=[db(e,a)for a in [0x20000850,0x20000e90,0x200014d0]];target=((c[0]*t+c[1])*t+c[2])*t+db(e,0x20002908)
     rawperiod=int(raw['registers']['r0'],16);cc=int(h['registers']['r1'],16)
     ck(n+': polynomial '+str(h['instruction']),math.isclose(fp(pol),target,rel_tol=1e-12,abs_tol=1e-12))
     ck(n+': raw period '+str(h['instruction']),rawperiod==int(u(e,0x200025dc)/abs(target)))
     ck(n+': scaled CC0 '+str(h['instruction']),cc==((rawperiod>>7 if rawperiod>60000 else rawperiod)&65535))
     samples.append({'instruction':h['instruction'],'relative_live_instructions':h['instruction']-live,'profile_age_ms':elapsed,'target_position':target,'software_position':int.from_bytes(memory(e,0x20002064,4),'little',signed=True),'raw_period':rawperiod,'CC0':cc})
   if im!='original' and case=='analog-500':
    manifest=json.loads(((P if im=='optimized'else P.parent/'stateful-trigger-patch-2026-10-22')/'modification-manifest.json').read_text());arm=int(manifest['symbols']['armed'],16)
    ck(n+': analog inactive arms while live',any(h['memory']['0x20001b14'].startswith('01')for h in hits(d,arm)))
   if im=='optimized':
    update=int(json.loads((P/'modification-manifest.json').read_text())['symbols']['observation_update'],16);observed=hits(d,update)
    ck(n+': observation provenance present',bool(observed))
    ck(n+': only current mode observations',all(u(h,0x2000531c+36)==(1 if case.startswith('analog')else 2)for h in observed))
    ck(n+': actual acquisition age <=20',all(0<=u(h,0x200052ec)-u(h,0x2000531c+44)<=20 for h in observed))
    if case.startswith('analog'):
     ck(n+': filtered return same invocation',all(int(h['registers']['r0'],16)==u(h,0x2000531c+28)for h in observed))
     ck(n+': raw matches modeled ADC',all(u(h,0x2000531c+24)==int.from_bytes(memory(h,0x43002040,2),'little')for h in observed))
   rate=hits(d,0x5f8c)[0]['instruction'];initial=[{k:x[k]for k in ['pc','address','size','value']}for x in d['mem_write_hits']if x['range']=='0x40003800:32'and rate<=x['instruction']<=live]
   serial=[x for x in d['mem_write_hits']if x['range']=='0x43000428:4'and x['instruction']>=rate];pcvalues=collections.defaultdict(set)
   for x in serial:pcvalues[x['pc']].add(x['value'])
   first=hits(d,0x6368)[0]
   group[im]={'whole_poll_live':stats(spans),'analog_call_live':stats(acqspans),'first_CC0':samples[0],'samples':samples,'first_evaluator_age_ms':(int(first['registers']['r0'],16)-int(first['registers']['r3'],16))/1000,'record':d['memory']['0x20001b40'],'coefficients':[db(first,a)for a in [0x20000850,0x20000e90,0x200014d0]],'initial_TC0_stores':initial,'driver_values_by_pc':{k:sorted(v)for k,v in pcvalues.items()},'full_TC0_writes':sum(x['range']=='0x40003800:32'for x in d['mem_write_hits']),'full_serial_writes':sum(x['range']=='0x43000428:4'for x in d['mem_write_hits'])}
  if len(group)==3:
   for im in ['phase3','optimized']:
    ck(case+im+': program unchanged',group[im]['record']==group['original']['record']);ck(case+im+': coefficients unchanged',group[im]['coefficients']==group['original']['coefficients'])
    ck(case+im+': initial TC0 structure unchanged',[{k:x[k]for k in ['pc','address','size']}for x in group[im]['initial_TC0_stores']]==[{k:x[k]for k in ['pc','address','size']}for x in group['original']['initial_TC0_stores']])
  motor[case]=group
 for route in ['B1-full-reset','G-to-enable','W1-nonzero-to-enable']:
  f=P/(route+'-optimized.json')
  if not f.exists():pending.append(route);continue
  d=load(f);b=load(P.parent/'stateful-trigger-patch-2026-10-22'/(route+'-stateful.json'))
  ck(route+': native success',d['error_free']and d['completed']);ck(route+': timer/live same Phase3',d['memory']['0x40003800']==b['memory']['0x40003800']and d['memory']['0x20001b14']==b['memory']['0x20001b14']);ck(route+': no external grant',d['memory']['0x2000531c'][80:88]=='00000000')
 for age in [51,52,53]:
  f=P/('frozen-optimized-elapsed'+str(age)+'.json')
  if not f.exists():pending.append(f.stem);continue
  d=load(f);b=load(P.parent/'stateful-motor-timing-2026-10-23'/('frozen-original-elapsed'+str(age)+'.json'))
  ck('frozen'+str(age)+': native return',d['error_free']and d['call']['returned'])
  ck('frozen'+str(age)+': TC0 and ordered stores same',d['memory']['0x40003800']==b['memory']['0x40003800']and [{k:x[k]for k in ['pc','address','size','value']}for x in d['mem_write_hits']]==[{k:x[k]for k in ['pc','address','size','value']}for x in b['mem_write_hits']])
 for mode in ['digital','analog']:
  f=P/('frame-'+mode+'.json')
  if not f.exists():pending.append(f.stem);continue
  d=load(f);hs=d['watch_hits'];ck(mode+': frame witness accepted',d['error_free']and d['mem_write_dropped']==0 and len(hits(d,0x8f9c))==1)
  for entry,end,helper in ([(0x9228,0x922c,int(M['symbols']['digital_native_return'],16))]if mode=='digital'else [(0x8e76,0x8e7a,int(M['symbols']['analog_native_return'],16))]):
   pairs=[];values=[]
   for i,h in enumerate(hs):
    if int(h['address'],16)!=end:continue
    a=next(x for x in reversed(hs[:i])if int(x['address'],16)==entry);z=next(x for x in reversed(hs[:i])if int(x['address'],16)==helper)
    pairs.append(all(a['registers'][r]==h['registers'][r]for r in ['r'+str(j)for j in range(4,12)]+['sp']))
    values.append(all(z['registers'][r]==h['registers'][r]for r in ['r0','r1','r2','r3','r12'])and ((int(z['registers']['cpsr'],16)^int(h['registers']['cpsr'],16))&0xf8000000)==0)
   ck(mode+': wrapper callee/stack',bool(pairs)and all(pairs));ck(mode+': native outputs and NZCVQ',bool(values)and all(values))
  accepted=hits(d,0x8f9c)[0];before=next(h for h in reversed(hs[:hs.index(accepted)])if int(h['address'],16)==0x8f98)
  ck(mode+': common gate framed registers',all(accepted['registers'][r]=={'r2':'0x00000003','r3':'0x200025bc'}.get(r,before['registers'][r])for r in ['r'+str(j)for j in range(13)]+['sp','lr']))
  ck(mode+': reserved state writers confined',all(x['pc']=='0x0000cc82'or 0x15470<=int(x['pc'],16)<0x15864 for x in d['mem_write_hits']if x['range']=='0x2000531c:64'))
 for item in json.loads((P/'fragment-commands.json').read_text()):
  f=Path(item['argv'][item['argv'].index('--out')+1])
  if not f.exists():pending.append(f.stem);continue
  d=load(f);ck(f.stem+': native return',d['error_free']and d['call']['returned'])
  ck(f.stem+': expected native classification/state',int(d['registers']['r0'],16)==item['expected_return']if item['kind']=='classify'else int.from_bytes(bytes.fromhex(d['memory']['0x2000531c'])[:4],'little')==item['expected_state'])
 if (P/'frame-analog.json').exists():
  d=load(P/'frame-analog.json');raw_pairs=[]
  for i,h in enumerate(d['watch_hits']):
   if int(h['address'],16)!=0x42da:continue
   z=next(x for x in reversed(d['watch_hits'][:i])if int(x['address'],16)==0x42d4)
   raw_pairs.append(all(h['registers'][r]==z['registers'][r]for r in ['r0','r1','r2','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr'])and h['registers']['r3']=='0x20003118'and ((int(h['registers']['cpsr'],16)^int(z['registers']['cpsr'],16))&0xf8000000)==0)
  ck('raw ADC detour frames and NZCVQ',bool(raw_pairs)and all(raw_pairs))
 else:pending.append('frame-analog-raw')
 if (P/'reset-state-clear.json').exists():ck('reset64 cleared',load(P/'reset-state-clear.json')['memory']['0x2000531c']=='00'*64)
 else:pending.append('reset')
 if (P/'allocator.json').exists():ck('heap starts above state',load(P/'allocator.json')['registers']['r0']=='0x2000535c')
 else:pending.append('allocator')
 m=json.loads((P/'modification-manifest.json').read_text());original=(P.parents[4]/'cases/performing-rigs/research/firmware/originals/firmware_autopilot915.bin').read_bytes();patched=(P/m['patched_file']).read_bytes();restored=bytearray(patched[:len(original)])
 ck('source and derived image identities',hashlib.sha256(original).hexdigest()==m['source_sha256']and hashlib.sha256(patched).hexdigest()==m['patched_sha256'])
 for change in m['modifications']:
  off=int(change['file_offset'],16);b=bytes.fromhex(change['before']);a=bytes.fromhex(change['after']);ck('listed bytes '+change['address'],restored[off:off+len(a)]==a);restored[off:off+len(b)]=b
 ck('no unlisted original-region changes',bytes(restored)==original)
 for name,digest in json.loads((P/'protected-baselines.json').read_text()).items():ck('immutable '+name,hashlib.sha256(Path(name).read_bytes()).hexdigest()==digest)
 edge={}
 if (P/'optimized-return-edge.json.gz').exists():
  for im in ['phase3','optimized']:
   d=load((P if im=='optimized'else A)/(im+'-return-edge.json.gz'));events=[e for e in d['external_fixture']['events']if e['kind']=='active edge at return-phase poll entry before idle9']
   ck(im+': edge armed/ineligible witness',len(events)==1 and events[0]['pre_policy']=='02000000'and events[0]['pre_idle']!='09'and events[0]['pre_channels']=='00000000')
   edge[im]={'starts':len(hits(d,0x5fa4)),'events':d['external_fixture']['events'],'milestones':d['external_fixture']['milestones']}
  ck('return-edge: no newly accepted Phase3-excluded activation',edge['optimized']['starts']==edge['phase3']['starts'])
  rejected=load(A/'optimized-return-edge.json.gz');ck('initial candidate regression preserved',len(hits(rejected,0x5fa4))==2)
 late={}
 for im in ['phase3','optimized']:
  d=load(P/(im+'-return-edge-late.json.gz'));late[im]={'starts':len(hits(d,0x5fa4)),'events':d['external_fixture']['events']}
 ck('return-edge-late: preserve fresh500 post-idle9 activation',late['optimized']['starts']==late['phase3']['starts']==2)
 failed=[x for x in checks if not x['pass']]
 (P/'outcomes.json').write_text(json.dumps({'runs':summary,'motor':motor,'return_edge_counterexample':edge,'late_edge_regression':late,'pending':pending,'failures':failed,'scope':'Bounded native software observations, not physical timing or safety certification'},indent=2)+'\n');(P/'checks.json').write_text(json.dumps(checks,indent=2)+'\n')
 print(json.dumps({'records':len(data),'checks':len(checks),'failed_count':len(failed),'failures':failed[:15],'pending_count':len(pending),'pending':pending},indent=2));raise SystemExit(bool(failed)or(bool(pending)and not arg.partial))
