"""Evaluate saved APTrace results only. No firmware execution or instruction model."""
import argparse, gzip, hashlib, json, statistics, struct
from pathlib import Path

P=Path(__file__).resolve().parent
CORE=['digital-500','digital-10','startup-active','pc-transient','before-commit',
      'analog-500','analog-startup-fault','analog-fault-after-arm','held-w','running-w','repress-w']
EXTRA=['digital-49','digital-51','after-commit','analog-10','analog-x2-500','analog-x-change','invalid-state']
EXPECTED={'digital-500':1,'digital-10':0,'startup-active':0,'pc-transient':0,'before-commit':0,
 'analog-500':1,'analog-startup-fault':0,'analog-fault-after-arm':1,'held-w':1,
 'running-w':1,'repress-w':2,'digital-49':0,'after-commit':1,'analog-10':0,
 'analog-x2-500':1,'analog-x-change':0,'invalid-state':0}

def load(n):
    f=P/(n+'.json.gz')
    return json.loads(gzip.decompress(f.read_bytes())) if f.exists() else json.loads((P/(n+'.json')).read_text())
def hits(d,pc):return [h for h in d['watch_hits']if int(h['address'],16)==pc]
checks=[]
def check(name,value):checks.append({'check':name,'pass':bool(value)})

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--partial',action='store_true');a=ap.parse_args()
    data={};summary={};missing=[]
    for im in ['original','first','stateful']:
        for case in CORE+(EXTRA if im=='stateful' else []):
            name=im+'-'+case
            if not (P/(name+'.json.gz')).exists():missing.append(name);continue
            d=load(name);data[name]=d
            expected_fixture=P/('run-experiments.py' if im=='stateful' and case=='analog-x2-500' else 'run-experiments-initial.py')
            check(name+': fixture identity',d['external_fixture']['fixture_sha256']==hashlib.sha256(expected_fixture.read_bytes()).hexdigest())
            check(name+': native success and complete bound',d['error_free']and d['stop_reason']=='instruction limit reached')
            check(name+': untruncated',d['mem_write_dropped']==0 and len(d['watch_hits'])<20000)
            count=len(hits(d,0x8f9c));starts=len(hits(d,0x5fa4))
            if im=='stateful':
                want=EXPECTED.get(case)
                check(name+': intended acceptance count',count==want if want is not None else count in [0,1])
                check(name+': intended initiation count',starts==want if want is not None else starts in [0,1])
                if want==0:
                    for pc in [0x5f8c,0x571c,0x5810,0x5fa4]:
                        check(name+': rejected before '+hex(pc),not hits(d,pc))
            else:
                want=0 if im=='first'and case in ['pc-transient','before-commit']else 2 if case in ['held-w','running-w','repress-w']else 1
                check(name+': baseline characterized',starts==want)
            if case in ['held-w','running-w','repress-w']:
                packets=[x for x in d['external_fixture']['events']if x.get('rx_hex')=='577c']
                check(name+': one supplied W only',len(packets)==1)
                check(name+': return request executed',bool(hits(d,0x6fd8)))
                if im=='stateful'and case!='repress-w':check(name+': W restores eligibility',d['memory']['0x200000d8'].startswith('09'))
            e=d['external_fixture'];gaps=[y-x for x,y in zip(e['poll_ticks'],e['poll_ticks'][1:])]
            times={hex(pc):[x['elapsed']for x in e['milestones']if int(x['pc'],16)==pc]for pc in [0x8f9c,0x5f8c,0x5fa4,0x6056,0x9088]}
            summary[name]={'starts':starts,'acceptances':count,'instructions':d['instructions_executed'],
                'error':d['error'],'drops':d['mem_write_dropped'],'times':times,'input_events':e['events'],
                'poll_gap_ticks':{'min':min(gaps),'median':statistics.median(gaps),'max':max(gaps)}if gaps else None,
                'poll_drops':e['dropped_poll_ticks'],'firmware_sha256':e['firmware_sha256'],
                'final_idle':d['memory']['0x200000d8'][:2],
                'final_patch_state':d['memory']['0x2000531c']if im=='stateful'else None}
    comparisons={}
    for case in ['digital-500','analog-500']:
        names=[im+'-'+case for im in ['original','first','stateful']]
        if not all(n in data for n in names):continue
        source=data[names[0]];cs={}
        for name in names:
            d=data[name];st=hits(d,0x5f8c)[0]['instruction'];en=hits(d,0x5fa4)[0]['instruction']
            stream=[{k:x[k]for k in ['pc','address','size','value']}for x in d['mem_write_hits']if x['range']=='0x40003800:32'and st<=x['instruction']<=en]
            cs[name]={'TC0_first_initiation_stores':stream,'record':d['memory']['0x20001b40'],
                'full_TC0_count':sum(x['range']=='0x40003800:32'for x in d['mem_write_hits']),
                'full_driver_serial_count':sum(x['range']=='0x43000428:4'for x in d['mem_write_hits'])}
            check(name+': same program record',d['memory']['0x20001b40']==source['memory']['0x20001b40'])
        comparisons[case]=cs
    for route in ['B1-full-reset','G-to-enable','W1-nonzero-to-enable']:
        f=P/(route+'-stateful.json')
        if not f.exists():missing.append(route);continue
        d=json.loads(f.read_text());base=json.loads(gzip.decompress((P.parent/'trigger-patch-2026-10-22'/(route+'-original.json.gz')).read_bytes()))
        check(route+': native live boundary',d['error_free']and d['completed'])
        check(route+': same final TC0/live',d['memory']['0x40003800']==base['memory']['0x40003800']and d['memory']['0x20001b14']==base['memory']['0x20001b14'])
        check(route+': no trigger grant consumed',d['memory']['0x2000531c'][80:88]=='00000000')
    m=json.loads((P/'modification-manifest.json').read_text());original=(P.parents[4]/'cases/performing-rigs/research/firmware/originals/firmware_autopilot915.bin').read_bytes();patched=(P/m['patched_file']).read_bytes()
    first=(P.parent/'trigger-patch-2026-10-22/RESEARCH_ONLY_NOT_FOR_HARDWARE_autopilot915_freshness.bin').read_bytes()
    check('first patch baseline identity',hashlib.sha256(first).hexdigest()=='ae9e6a749426fc3d800a0e26d016cc58f818ce8f84d5a7ba12c41d6d727bc616')
    check('original and patched identity',hashlib.sha256(original).hexdigest()==m['source_sha256']and hashlib.sha256(patched).hexdigest()==m['patched_sha256'])
    restored=bytearray(patched[:len(original)])
    for change in m['modifications']:
        off=int(change['file_offset'],16);before=bytes.fromhex(change['before']);after=bytes.fromhex(change['after'])
        check('listed bytes '+change['address'],restored[off:off+len(after)]==after)
        restored[off:off+len(before)]=before
    check('no unlisted original-region changes',bytes(restored)==original)
    reset=load('reset-state-clear');check('reset clears reserved64 bytes',reset['memory']['0x2000531c']=='00'*64)
    allocator=load('reserved-heap-allocator');check('heap begins above new state',allocator['registers']['r0']=='0x2000535c')
    if (P/'frame-preservation-cli.json').exists():
        d=load('frame-preservation-cli')
        for i,h in enumerate(d['watch_hits']):
            if h['address']!='0x00008f9c':continue
            previous=next(z for z in reversed(d['watch_hits'][:i])if z['address']=='0x00008f98')
            check('accepted inline frame preserved',all(h['registers'][r]=={'r2':'0x00000003','r3':'0x200025bc'}.get(r,previous['registers'][r])for r in ['r'+str(n)for n in range(13)]+['sp','lr']))
    smoke=load('initial-qualified-cli')
    check('bounded new-state write ownership',all(x['pc']=='0x0000cc82'or 0x15470<=int(x['pc'],16)<0x156d8 for x in smoke['mem_write_hits']if x['range']=='0x2000531c:64'))
    failed=[x for x in checks if not x['pass']]
    (P/'outcomes.json').write_text(json.dumps({'runs':summary,'motor_comparisons':comparisons,'missing':missing,'failed_checks':failed,
        'scope':'Bounded software observations; NOT physical safety, complete waveform equivalence, or field repair'},indent=2)+'\n')
    (P/'checks.json').write_text(json.dumps(checks,indent=2)+'\n')
    print(json.dumps({'records':len(data),'checks':len(checks),'failures':failed,'pending':missing},indent=2))
    raise SystemExit(bool(failed)or(bool(missing)and not a.partial))
