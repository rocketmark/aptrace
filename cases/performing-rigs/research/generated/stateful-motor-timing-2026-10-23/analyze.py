"""Saved-artifact arithmetic and comparison only; no firmware execution/semantics."""
import collections,gzip,hashlib,json,math,statistics,struct
from pathlib import Path
P=Path(__file__).resolve().parent
checks=[]
def check(name,ok):checks.append({'check':name,'pass':bool(ok)})
def load(path):return json.loads(gzip.decompress(path.read_bytes())) if path.suffix=='.gz' else json.loads(path.read_text())
def hits(d,pc):return [h for h in d['watch_hits'] if int(h['address'],16)==pc]
def mem(h,a,n):
 for k,v in h['memory'].items():
  lo=int(k,16);b=bytes.fromhex(v)
  if lo<=a and a+n<=lo+len(b):return b[a-lo:a-lo+n]
 raise KeyError(hex(a))
def u(h,a):return int.from_bytes(mem(h,a,4),'little')
def db(h,a):return struct.unpack('<d',mem(h,a,8))[0]
def fp(r):return struct.unpack('<d',struct.pack('<II',int(r['r0'],16),int(r['r1'],16)))[0]
def stats(v):return {'n':len(v),'min':min(v),'median':statistics.median(v),'max':max(v),'sum':sum(v)} if v else None
runs={};data={}
for path in sorted(P.glob('*-500-tick4000.json.gz')):
 if path.name.startswith(('capture-','resume-')):continue
 d=load(path);data[path.stem]=d;name=path.name.removesuffix('.json.gz');hs=d['watch_hits'];setup=d['external_fixture']['setup_tick']
 check(name+': complete native bound',d['error_free'] and 16000000<=d['instructions_executed']<=16000008 and d['stop_reason']=='instruction limit reached')
 check(name+': untruncated',d['mem_write_dropped']==0 and len(hs)<100000)
 live=hits(d,0x5fa4)[0]['instruction'];accepted=hits(d,0x8f9c)[0]
 timeline={hex(pc):[{'instruction':h['instruction'],'tick':u(h,0x200052ec),'elapsed_setup':u(h,0x200052ec)-setup}for h in hits(d,pc)]for pc in [0x8f9c,0x6b50,0x6368,0x5f8c,0x5c44,0x5fa4]}
 polls={'prelive':[],'postlive':[]}
 for i,h in enumerate(hs):
  if int(h['address'],16)==0x8e18:
   nxt=next((x for x in hs[i+1:]if int(x['address'],16)==0x8e1c),None)
   if nxt:polls['postlive' if h['instruction']>live else 'prelive'].append(nxt['instruction']-h['instruction'])
 before=max((h for h in hits(d,0x8f98)if h['instruction']<accepted['instruction']),key=lambda h:h['instruction'])
 rows=[];latest={}
 for h in hs:
  pc=int(h['address'],16)
  if pc in [0x6368,0x6420,0x66ee]:latest[pc]=h
  if pc!=0x5c44:continue
  e=latest[0x6368];p=latest[0x6420];raw=latest[0x66ee];elapsed=(int(e['registers']['r0'],16)-int(e['registers']['r3'],16))/1000
  coeff=[db(e,a)for a in [0x20000850,0x20000e90,0x200014d0]];tau=elapsed+u(e,0x20002954)
  target=((coeff[0]*tau+coeff[1])*tau+coeff[2])*tau+db(e,0x20002908)
  requested=fp(p['registers']);period=int(raw['registers']['r0'],16);calculated=int(u(e,0x200025dc)/abs(target));cc=int(h['registers']['r1'],16)
  check(name+': polynomial at '+str(h['instruction']),math.isclose(requested,target,rel_tol=1e-12,abs_tol=1e-12))
  check(name+': raw period at '+str(h['instruction']),period==calculated)
  check(name+': scaled CC0 at '+str(h['instruction']),cc==(period>>7 if period>60000 else period)&65535)
  rows.append({'instruction':h['instruction'],'instructions_from_live':h['instruction']-live,'profile_elapsed_ms':elapsed,'lookahead_ms':u(e,0x20002954),'target_position':target,'software_position':int.from_bytes(mem(e,0x20002064,4),'little',signed=True),'raw_period':period,'CC0':cc})
 first=hits(d,0x6368)[0];firstcc=hits(d,0x5c44)[0];firstpos=hits(d,0x6420)[0]
 output_writes=[x for x in d['mem_write_hits']if x['instruction']>=hits(d,0x5f8c)[0]['instruction']]
 streams={}
 for rng in ['0x40003800:32','0x43000428:4','0x41008094:12','0x41008014:12']:
  xs=[x for x in output_writes if x['range']==rng];streams[rng]={'count':len(xs),'pc_values':dict((k,sorted(v))for k,v in sorted((lambda dd:dd.items())(__import__('functools').reduce(lambda dd,x:(dd[x['pc']].add(x['value'])or dd),xs,collections.defaultdict(set)))))}
 runs[name]={'timeline':timeline,'first_profile_elapsed_ms':(int(first['registers']['r0'],16)-int(first['registers']['r3'],16))/1000,'first_calculated_target':fp(firstpos['registers']),
  'first_CC0':rows[0],'coefficients':[db(first,a)for a in [0x20000850,0x20000e90,0x200014d0]],'grant_gate_instructions':accepted['instruction']-before['instruction'],
  'poll_work':{k:stats(v)for k,v in polls.items()},'postlive_extra_poll_instructions':sum(v-1 for v in polls['postlive']),
  'postlive_instruction_window':16000000-live,'acquisitions':d['external_fixture']['acquisitions'],'profile_samples_at_CC0':rows,'streams_after_rate_start':streams}
# Freeze all globals/TC0/clock inputs, compare native evaluator outputs across binaries.
frozen={}
for elapsed in [51,52,53]:
 group={}
 for im in ['original','first','stateful']:
  d=load(P/('frozen-'+im+'-elapsed'+str(elapsed)+'.json'));check('frozen '+im+str(elapsed)+': clean return',d['error_free']and d['call']['returned'])
  group[im]={'instructions':d['instructions_executed'],'period':int(d['memory']['0x2000007c'],16) if False else int.from_bytes(bytes.fromhex(d['memory']['0x2000007c']),'little'),'CC0':int(hits(d,0x5c44)[0]['registers']['r1'],16),'TC0':d['memory']['0x40003800'],'writes':[{k:x[k]for k in ['pc','address','size','value']}for x in d['mem_write_hits']]}
 check('frozen identical all images '+str(elapsed),group['original']==group['first']==group['stateful']);frozen[str(elapsed)]=group
# Native prepared state includes complete RAM; compare motion parameters, not absolute clocks/heap pointers.
prepared={}
for im in ['original','first','stateful']:
 d=load(P/('capture-'+im+'-digital-500-tick4000.json.gz'));check('capture '+im+': native stop',d['error_free']and d['stop_reason']=='reached stop address 0x00006362')
 ram=bytes.fromhex(d['memory']['0x20000000']);regions={hex(a):ram[a:a+n].hex()for a,n in [(0x850,1600),(0xe90,1600),(0x14d0,1600),(0x1b40,80),(0x2064,16),(0x201c,16),(0x94,16),(0x25e8,800),(0x2908,32),(0x2954,4),(0x310c,8),(0x180,16),(0x25dc,4),(0x7c,16),(0x2078,32),(0x30e8,28)]}
 prepared[im]={'regions':regions,'timestamp':int.from_bytes(ram[0x30cc:0x30d0],'little')}
check('prepared motion regions identical',prepared['original']['regions']==prepared['first']['regions']==prepared['stateful']['regions'])
continuations={}
for im in ['original','stateful']:
 for period in [2000,4000]:
  name='resume-'+im+'-digital-500-tick'+str(period);d=load(P/(name+'.json.gz'));prefix=load(P/d['continuation_control']['prefix'])
  check(name+': native prepared prefix',prefix['error_free']and prefix['stop_reason']=='reached stop address 0x0000635e')
  check(name+': bounded untruncated continuation',d['error_free']and 2000000<=d['instructions_executed']<=2000008 and d['mem_write_dropped']==0 and len(d['watch_hits'])<100000)
  first=hits(d,0x6368)[0];check(name+': normalized first age3ms',int(first['registers']['r0'],16)-int(first['registers']['r3'],16)==3000)
  rows=[];last=None
  for h in d['watch_hits']:
   if int(h['address'],16)==0x6368:last=h
   if int(h['address'],16)==0x5c44:rows.append({'instruction':h['instruction'],'profile_age_ms':(int(last['registers']['r0'],16)-int(last['registers']['r3'],16))/1000,'CC0':int(h['registers']['r1'],16)})
  continuations[name]={'first_CC0':rows[0],'samples':rows,'profile_origin':d['continuation_control']['profile_timestamp'],'first_age_ms':3}
(P/'analysis.json').write_text(json.dumps({'runs':runs,'frozen':frozen,'prepared':prepared,'continuations':continuations},indent=2)+'\n');(P/'checks.json').write_text(json.dumps(checks,indent=2)+'\n')
failed=[c for c in checks if not c['pass']];print(json.dumps({'runs':len(runs),'checks':len(checks),'failed_count':len(failed),'first_failures':failed[:8]},indent=2));raise SystemExit(bool(failed))
