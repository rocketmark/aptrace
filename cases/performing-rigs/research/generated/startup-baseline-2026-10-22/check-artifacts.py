# Artifact checks only: no firmware execution or instruction interpretation.
import pathlib,json,collections,hashlib,struct
P=pathlib.Path('cases/performing-rigs/research/generated/startup-baseline-2026-10-22')
rows=json.loads((P/'commands.json').read_text());checks=[];summary=[];snap={}
def check(name,ok):checks.append(dict(check=name,passed=bool(ok)))
for r in rows:
 n=r['name'];d=json.loads((P/(n+'.json')).read_text());snap[n]=d;h=d['watch_hits'];counts=collections.Counter(x['address'] for x in h)
 end=next(x['instruction'] for x in h if int(x['address'],16)==0x5db0);start=next(x['instruction'] for x in h if int(x['address'],16)==0x5d44)
 base=next(x for x in h if int(x['address'],16)==0x5db0)
 events=[dict(pc=x['address'],instruction=x['instruction'],filtered=int.from_bytes(bytes.fromhex(x['memory']['0x20000190'])[:4],'little')) for x in h if int(x['address'],16) in [0x8f98,0x5f8c,0x5810,0x5fa4]]
 value=lambda addr:int.from_bytes(bytes.fromhex(d['memory'][addr]),'little',signed=True)
 expect=n in ['natural900','natural900-915','average-reversed']
 check(n+': error-free corrected hooks',d['error_free'] and d['execution_mode']=='memory-hook-single-step')
 check(n+': 128 filter calls',counts['0x00005d8c']==128)
 check(n+': three actual baseline acquisitions',sum(start<x['instruction']<end and int(x['address'],16)==0x42d4 for x in h)==3)
 check(n+': acceptance expectation',counts['0x00008f98']==int(expect))
 check(n+': start expectation',counts['0x00005f8c']==int(expect) and counts['0x00005fa4']==int(expect))
 check(n+': no dropped logs',not d['mem_write_dropped'] and len(h)<4000)
 summary.append(dict(name=n,variant=r['variant'],startup_ADC=r['startup_ADC'],post_baseline_ADC=225,average=value('0x20003128'),low_flag=value('0x200023c0'),baseline_return_instruction=end,filter_float_at_baseline_return=struct.unpack('<f',bytes.fromhex(base['memory']['0x20003118'])[4:8])[0],filter_call_count=counts['0x00005d8c'],baseline_acquisitions=3,first_runtime_returns=[int(x['registers']['r0'],16) for x in h if int(x['address'],16)==0x8e7a][:4],accepts=counts['0x00008f98'],starts=counts['0x00005f8c'],stop=d['stop_reason'],instructions=d['instructions_executed'],events=events,CPU_writes_to_baseline=d['mem_write_hits']))
 r['exit_status']=0;r['sha256']=hashlib.sha256((P/(n+'.json')).read_bytes()).hexdigest()
# Both mean/flag causal interventions leave every other recorded watch state,
# register, instruction index and final memory byte identical in these pairs.
def projection(d):
 def strip(m):return {k:v for k,v in m.items() if k not in ['0x20003128','0x200023c0']}
 return dict(instructions=d['instructions_executed'],stop=d['stop_reason'],registers=d['registers'],memory=strip(d['memory']),watch_hits=[dict(x,memory=strip(x['memory'])) for x in d['watch_hits']])
for a,b in [('natural225','average-injected'),('natural900','average-reversed')]:check(a+' versus '+b+': identical recorded execution except mean/flag',projection(snap[a])==projection(snap[b]))
(P/'commands.json').write_text(json.dumps(rows,indent=2)+'\n');(P/'outcomes.json').write_text(json.dumps(summary,indent=2)+'\n');(P/'checks.json').write_text(json.dumps(checks,indent=2)+'\n')
print(len(checks),'checks;',sum(c['passed'] for c in checks),'pass')
for c in checks:
 if not c['passed']:print(c)
for r in summary:print(r['name'],r['average'],r['low_flag'],r['first_runtime_returns'],r['accepts'],r['starts'])
