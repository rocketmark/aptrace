"""Case artifact projection only. No firmware execution or filter implementation.
Read native watch snapshots/PC-timed external writes, emit TLA input histories
and separately observed output checkpoints. Original snapshots remain untouched.
"""
import json, pathlib, shlex, hashlib
ROOT=pathlib.Path(__file__).resolve().parents[4]
HERE=pathlib.Path(__file__).resolve().parent
BASE=ROOT/'cases/performing-rigs/research/generated'
selection={
 'trigger-request-campaign-2026-10-21': ['profile-held','profile-inactive','profile-single-pulse','profile-sample-aligned-pulses','profile-opposite-phase-pulses','profile-startup-active','profile-x2','profile-tail','profile-release-continuation','profile-held-extended','profile-low-excursion'],
 'powered-trigger-connection-2026-10-21':['digital-idle','digital-low-before-eligibility','digital-acquired-transient','digital-unsampled-transient','digital-setup-only-transient','digital-connection-after-inactive-sample','analog-setup-only-low','analog-startup-transient-tail','analog-marginal600']}
def le(v): return int.from_bytes(bytes.fromhex(v),'little')
def tl(v):
 if isinstance(v,bool):return str(v).upper()
 if isinstance(v,str):return json.dumps(v)
 if isinstance(v,int):return str(v)
 if isinstance(v,list):return '<<'+', '.join(map(tl,v))+'>>'
 return '['+', '.join(k+' |-> '+tl(x) for k,x in v.items())+']'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
fixtures={};meta=[]
for folder,names in selection.items():
 commands={r['name']:r['command'] for r in json.loads((BASE/folder/'commands.json').read_text())}
 for name in names:
  p=BASE/folder/(name+'.json'); d=json.loads(p.read_text());words=shlex.split(commands[name]);seeds={}
  for k,w in enumerate(words):
   if w=='--seed-mem':
    a,b=words[k+1].split(':');seeds[int(a,16)]=le(b)
  first=d['watch_hits'][0]['memory'];mode=le(first['0x20001fc0'])
  raw=seeds.get(0x43002040,0) if mode==1 else (1 if seeds.get(0x410080a0,0)&32 else 0)
  events=[]; alignment=[]; counts=[0,0,0]; channels=0;idle=9;live=0
  def add(kind,value=0,anchor=None,**kw):
   events.append(dict(kind=kind,value=value,accepts=kw.get('accepts',0),requests=kw.get('requests',0),starts=kw.get('starts',0),channels=kw.get('channels',0),idle=kw.get('idle',9),live=kw.get('live',0),timer=kw.get('timer',2)))
   alignment.append(dict(step=len(events),kind=kind,anchor=anchor))
  timeline=[]
  for h in d['force_mem_hits']:
   for w in h['writes']:
    addr=int(w['addr'],16)
    if addr==(0x43002040 if mode==1 else 0x410080a0):
     val=le(w['bytes']); val=val if mode==1 else int(bool(val&32))
     timeline.append((h['instruction'],0,'raw',val,h))
  for h in d['watch_hits']:timeline.append((h['instruction'],1,'watch',0,h))
  last={'program':255,'setup':0,'x':1,'tr':0}
  for ins,_,kind,val,h in sorted(timeline,key=lambda r:(r[0],r[1])):
   anchor={'instruction':ins,'pc':h['address']}
   if kind=='raw':add('raw',val,anchor);continue
   m=h['memory'];pc=int(h['address'],16)
   # Upper-layer native outputs become inputs at this subsystem's boundary.
   for key,addr in [('program','0x20001b38'),('setup','0x20000060'),('x','0x20000194'),('tr','0x20003120')]:
    if addr not in m:continue
    v=le(m[addr]);v=int(v==0) if key=='setup' else v
    if v!=last[key]:add(key,v,anchor);last[key]=v
   if pc==0x42d4:
    add('adc',int(h['registers']['r0'],16),anchor)
   elif pc in [0x8e7a,0x922c]:
    add('analog' if pc==0x8e7a else 'digital',int(h['registers']['r0'],16),anchor)
    add('classify',anchor=anchor)
   elif pc==0x8f98:
    counts[0]+=1
    add('check',anchor=anchor,accepts=counts[0],requests=counts[1],starts=counts[2],channels=channels,idle=idle,live=live)
   elif pc==0x6e4c:
    add('reload',anchor=anchor);channels=1;idle=0
   elif pc==0x5f8c:
    add('rate',anchor=anchor);counts[1]+=1
   elif pc==0x5810:add('enable',anchor=anchor)
   elif pc==0x5fa4:
    add('live',anchor=anchor);counts[2]+=1;live=1
   if pc in [0x6338,0x5f8c,0x5810]:
    # Independent watch state, not assigned to the modeled state.
    add('check',anchor=anchor,accepts=counts[0],requests=counts[1],starts=counts[2],channels=le(m['0x20002524']),idle=le(m['0x200000d8'])&255,live=le(m['0x20001b14'])&255)
  final=d['memory']
  add('check',anchor={'instruction':d['instructions_executed'],'pc':d['registers']['pc']},accepts=counts[0],requests=counts[1],starts=counts[2],channels=le(final['0x20002524']),idle=le(final['0x200000d8'])&255,live=le(final['0x20001b14'])&255,timer=int(bool(le(final['0x40003800'][:8])&2)))
  fixtures[name]=dict(mode=mode,raw=raw,events=events)
  meta.append(dict(name=name,snapshot=str(p.relative_to(ROOT)),sha256=digest(p),commands=str((BASE/folder/'commands.json').relative_to(ROOT)),instructions=d['instructions_executed'],expected=dict(zip(['accepts','requests','starts'],counts)),alignment=alignment))
(HERE/'NativeFixtures.tla').write_text('------------------------- MODULE NativeFixtures -------------------------\nFixtures == [n \\in {'+', '.join(map(tl,fixtures))+'} |->\n CASE '+'\n [] '.join('n='+tl(k)+' -> '+tl(v) for k,v in fixtures.items())+']\n=============================================================================\n')
(HERE/'trace-correspondence.json').write_text(json.dumps(meta,indent=2)+'\n')
# Configurations never use observed expected output counts as transition inputs.
base='SPECIFICATION Spec\nCHECK_DEADLOCK FALSE\nCONSTANTS\n RequireRaw = FALSE\n FreezeFilter = FALSE\n'
def config(file,names,checks,raw=False,freeze=False):
 text=base.replace('RequireRaw = FALSE','RequireRaw = '+str(raw).upper()).replace('FreezeFilter = FALSE','FreezeFilter = '+str(freeze).upper())
 text+=' Selected = {'+', '.join(map(tl,names))+'}\n'+checks+'\n'
 (HERE/(file+'.cfg')).write_text(text)
config('Correspondence',list(fixtures),'INVARIANTS Correspondence OneStartInObservedWindow AcceptedProgramGuard ProfileProvenance\nPROPERTIES ReplayCompletes AcceptedEventuallyStarts')
for file,names,prop in [
 ('Startup',['profile-startup-active'],'FreshQualifiedInitiation'),
 ('Reclassification',['profile-x2'],'FreshQualifiedInitiation'),
 ('FilterTail',['profile-tail'],'ActiveRawAtInitiation'),
 ('StartupTail',['analog-startup-transient-tail'],'ActiveRawAtInitiation'),
 ('SampledRelease',['digital-acquired-transient'],'ActiveRawAtInitiation'),
 ('AcceptedRelease',['profile-release-continuation'],'ActiveRawAtInitiation'),
 ('DecayedClassification',['profile-tail'],'ActiveClassificationAtInitiation')]:
 config(file,names,'INVARIANT '+prop)
config('ShortPulse',['profile-single-pulse'],'PROPERTY EveryPulseStarts')
config('UnsampledPulse',['digital-unsampled-transient'],'PROPERTY EveryPulseStarts')
config('WrongRawGuard',['digital-acquired-transient'],'INVARIANT Correspondence',raw=True)
config('WrongFrozenFilter',['profile-held'],'INVARIANT Correspondence',freeze=True)
config('WrongRawAnalogGuard',['profile-tail'],'INVARIANT Correspondence',raw=True)
(HERE/'verification/source-hashes.json').write_text(json.dumps({str(p.relative_to(ROOT)):digest(p) for p in sorted((ROOT/'cases/performing-rigs/specifications/trigger-acceptance').rglob('*')) if p.is_file()},indent=2)+'\n')
print(len(fixtures),'native fixtures;',sum(len(v['events']) for v in fixtures.values()),'projection steps')
# Bounded direct-G branch: native endpoint comparison; rate is a native oracle.
b=BASE/'bring-up-pass2-2026-10-21';direct={};directmeta=[]
for name,has_g,sequence in [('program-causal-repeat',True,1),('program-g-trigger-high',True,1),('program-without-g',False,0),('program-g-duplicate-sequence',True,0)]:
 p=b/(name+'.json');d=json.loads(p.read_text());hits=[h for h in d['watch_hits'] if int(h['address'],16)==0x6fd8]
 expected=[int(hits[0]['registers']['r'+str(i)],16) for i in range(4)] if hits else []
 st=bytes.fromhex(d['memory']['0x200025e0'])
 direct[name]=dict(hasG=has_g,sequence=sequence,readsync=True,target=500,current=0,rate=8119,expected=expected,arm=st[1],phase=st[0])
 directmeta.append(dict(name=name,path=str(p.relative_to(ROOT)),sha256=digest(p),expected=expected,instructions=d['instructions_executed'],stop=d['stop_reason']))
(HERE/'DirectFixtures.tla').write_text('-------------------------- MODULE DirectFixtures --------------------------\nDirectFixtures == [n \\in {'+', '.join(map(tl,direct))+'} |-> CASE '+'\n [] '.join('n='+tl(k)+' -> '+tl(v) for k,v in direct.items())+']\n=============================================================================\n')
(HERE/'direct-correspondence.json').write_text(json.dumps(directmeta,indent=2)+'\n')
