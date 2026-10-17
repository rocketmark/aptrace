"""One-off documentary interpretation of recorded MMIO, not execution infrastructure.
Run from repository root. Raw input records are never modified.
"""
import json, hashlib, collections
from pathlib import Path
root=Path('cases/performing-rigs')
prior=root/'research/runs/tmc5160-interface-reconciliation'
out=root/'research/generated/tmc5160-startup-transactions.json'
a=json.loads((prior/'boot-sercom5-observation.json').read_text())
b=json.loads((prior/'boot-configuration-calls.json').read_text())
fwsha='6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3'
drivers=[dict(driver='TMC1',channel=0,object='0x200020a0',pad='PB08',port=1,mask=0x100),dict(driver='TMC2',channel=1,object='0x200021d8',pad='PA18',port=0,mask=0x40000),dict(driver='TMC3',channel=2,object='0x2000213c',pad='PB09',port=1,mask=0x200),dict(driver='TMC4',channel=3,object='0x20002274',pad='PA19',port=0,mask=0x80000)]
names={0:'GCONF',0xb:'GLOBALSCALER',0x10:'IHOLD_IRUN',0x11:'TPOWERDOWN',0x21:'XACTUAL',0x2d:'XTARGET',0x6c:'CHOPCONF',0x6d:'COOLCONF',0x6f:'DRV_STATUS',0x70:'PWMCONF'}
fields={0:[('en_pwm_mode',2,1),('shaft',4,1),('direct_mode',16,1)],0xb:[('GLOBALSCALER',0,8)],0x10:[('IHOLD',0,5),('IRUN',8,5),('IHOLDDELAY',16,4)],0x11:[('TPOWERDOWN',0,8)],0x6c:[('TOFF',0,4),('HSTRT',4,3),('HEND',7,4),('FD3',11,1),('DISFDCC',12,1),('CHM',14,1),('TBL',15,2),('vhighfs',18,1),('vhighchm',19,1),('TPFD',20,4),('MRES',24,4),('INTPOL',28,1),('DEDGE',29,1),('DISS2G',30,1),('DISS2VS',31,1)],0x6d:[('SEMIN',0,4),('SEUP',5,2),('SEMAX',8,4),('SEDN',13,2),('SEIMIN',15,1),('SGT_raw',16,7),('SFILT',24,1)],0x70:[('PWM_OFS',0,8),('PWM_GRAD',8,8),('pwm_freq',16,2),('pwm_autoscale',18,1),('pwm_autograd',19,1),('freewheel',20,2),('PWM_REG',24,4),('PWM_LIM',28,4)]}
refs={0:'§6.1 pp32–33',0xb:'§6.1 p36',0x10:'§6.2 p38; §9 p74',0x11:'§6.2 p38',0x21:'§6.3.1 p40',0x2d:'§6.3.1 p41',0x6c:'§6.5.2 pp51–52',0x6d:'§6.5.3 p53',0x6f:'§6.5.5 p56',0x70:'§6.5.4 pp54–55'}
calls=[x for x in b['watch_hits'] if int(x['address'],16) in (0xacd8,0xac28)]
active={};frames=[];orphans=[];events=[];anomalies=[]
for i,x in enumerate(a['mmio_log']):
 if x['direction']!='write':continue
 addr=int(x['address'],16);value=int(x['value'],16)
 for d in drivers:
  base=0x41008000+0x80*d['port']
  if addr in (base+0x14,base+0x18) and value & d['mask']:
   low=addr==base+0x14
   events.append(dict(mmio_index=i,**x,driver=d['driver'],requested_level=0 if low else 1))
   if low:
    if d['driver'] in active:anomalies.append(dict(kind='repeated_low',mmio_index=i))
    if active:anomalies.append(dict(kind='overlapping_select',mmio_index=i))
    active[d['driver']]=dict(driver=d['driver'],channel=d['channel'],object=d['object'],cs_pad=d['pad'],assertion=dict(mmio_index=i,**x),data=[])
   elif d['driver'] in active:
    f=active.pop(d['driver']);f['release']=dict(mmio_index=i,**x)
    if f['data']:frames.append(f)
 if addr==0x43000428:
  if len(active)!=1:orphans.append(dict(mmio_index=i,**x))
  else:next(iter(active.values()))['data'].append(dict(mmio_index=i,**x))
for n,f in enumerate(frames,1):
 raw=[int(x['value'],16)&255 for x in f['data']];reg=raw[0]&127;write=bool(raw[0]&128)
 f.update(id=f'T{n:03}',raw_mosi_hex=' '.join(f'{v:02x}' for v in raw),raw_bytes=raw,classification='complete_recorded_logical_datagram' if len(raw)==5 else 'incomplete_recorded_bytes',direction='write' if write else 'read_request',register=dict(address=f'0x{reg:02x}',name=names.get(reg,'UNKNOWN'),datasheet='TMC5160/TMC5160A rev1.18 '+refs.get(reg,'')),payload_hex=f'0x{int.from_bytes(bytes(raw[1:]),"big"):08x}',hardware_response=None,confidence='high for recorded software request',verification_status=None,aptrace_grade='UNKNOWN',validation_note='documentary export; not a VERIFIED ledger claim')
 cs=f['assertion']['instruction'];call=max((x for x in calls if x['instruction']<cs),key=lambda x:x['instruction'])
 f['method_call']=dict(hit=call['hit'],instruction=call['instruction'],entry=call['address'],caller_return_address=call['registers']['lr'],object=call['registers']['r0'],register_argument=call['registers']['r1'],payload_argument=call['registers']['r2'],source='boot-configuration-calls.json; matched repeated deterministic execution by instruction ordinal')
 assert call['registers']['r0']==f['object'] and int(call['registers']['r1'],16)==reg
 if write:
  v=int(f['payload_hex'],16);assert int(call['registers']['r2'],16)==v
  f['fields']={k:(v>>bit)&((1<<width)-1) for k,bit,width in fields.get(reg,[])}
  if reg==0x6c:f['meaning']=dict(microsteps_per_fullstep=256>>f['fields']['MRES'],interpolation_to_256=bool(f['fields']['INTPOL']),bridges_disabled_by_toff=f['fields']['TOFF']==0,hysteresis_start=f['fields']['HSTRT']+1,hysteresis_end=f['fields']['HEND']-3,blank_time_clocks=[16,24,36,54][f['fields']['TBL']],chopper='SpreadCycle' if not f['fields']['CHM'] else 'constant_off_time')
 else:f['fields']=None;f['meaning']='Read request; four dummy MOSI bytes are not register contents. Pipeline response is synthetic/unmodeled in this trace.'
readgroups=collections.defaultdict(list)
for f in frames:
 if f['direction']=='read_request':readgroups[f['method_call']['hit']].append(f)
for group in readgroups.values():
 for j,f in enumerate(group):f['read_method_phase']=j+1;f['pipeline']='requests DRV_STATUS for subsequent datagram' if j==0 else 'requests again; firmware consumes response to phase1, but no valid hardware response exists'
assert not active and not orphans and not anomalies
assert len(frames)==124 and all(len(f['raw_bytes'])==5 for f in frames)
assert sum(len(f['raw_bytes']) for f in frames)==620
assert len(readgroups)==8 and all(len(v)==2 for v in readgroups.values())
result=dict(schema='case documentary reconstruction v1',firmware_sha256=fwsha,repository_head_at_interpretation='6b331521d2c20e24fdf16cfd9f975fa67dd3d607',sources={str(prior/n):hashlib.sha256((prior/n).read_bytes()).hexdigest() for n in ['boot-sercom5-observation.json','boot-configuration-calls.json','execution-manifest.json']},scope=dict(entry='0xcc24',stop='0x8960',instructions=378402,firmware_load_base='0x4000',original_execution_revision='66f2cf9f2c6206b20cf8e4b22addbc0bf952f301'),assumptions=json.loads((prior/'execution-manifest.json').read_text())['harness_assumptions'],interpretation='PORT OUTCLR/OUTSET requests bound each datagram; DATA low8 bits in order; active CS joined to measured endpoint via MCU datasheet. MMIO alias writes are logical requests, not physical CS waveforms. Method-call metadata comes from a separate matched deterministic run; raw framing is entirely within the MMIO run.',summary=dict(sercom5_byte_writes=620,complete_datagrams=124,register_writes=108,read_request_datagrams=16,read_method_calls=8,orphan_bytes=0,incomplete_datagrams=0,overlapping_select_requests=0,validated_physical_transfers=0),drivers=drivers,chip_select_events=events,unframed_bytes=orphans,anomalies=anomalies,transactions=frames)
out.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result['summary'],indent=2))
for d in drivers:
 fs=[f for f in frames if f['driver']==d['driver']];print(d['driver'],len(fs),' '.join(f"{f['id']}:{f['register']['name']}={f['payload_hex']}" for f in fs))
