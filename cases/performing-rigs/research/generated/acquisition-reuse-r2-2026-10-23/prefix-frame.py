"""Case-owned external-input recipes over APTrace ConcreteMachine.

No qualification decision is supplied by this fixture. It changes GPIO/ADC
inputs and real RX-ring packet delivery, and observes native instructions.
Counter ticks are instruction-paced model time, not calibrated milliseconds.
"""
import argparse, gc, gzip, hashlib, json, shlex, struct, sys
from pathlib import Path

P=Path(__file__).resolve().parent
ROOT=P.parents[4]
sys.path.insert(0,str(ROOT/'tools/unicorn'))
from concrete import ConcreteMachine
from run_concrete import (build_argparser,parse_addr_len,parse_addr_bytes,
    parse_addr_hexmask,parse_addr_addr_bytes,parse_addr_reg_hexvalue,parse_hexaddr)
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0

OLD=ROOT/'cases/performing-rigs/research/generated/trigger-patch-2026-10-22'
IMAGES={'original':ROOT/'cases/performing-rigs/research/firmware/originals/firmware_autopilot915.bin',
        'phase3':P.parent/'stateful-trigger-patch-2026-10-22/RESEARCH_ONLY_NOT_FOR_HARDWARE_autopilot915_stateful.bin',
        'optimized':P/'RESEARCH_ONLY_NOT_FOR_HARDWARE_autopilot915_reuse_r2.bin'}
CORE=['digital-500','digital-10','startup-active','pc-transient','before-commit',
      'analog-500','analog-startup-fault','analog-fault-after-arm','held-w','running-w','repress-w']
ADVERSARIAL=['return-edge','cached-no-raw','cache-forged-filter','stale-observation','gap20','gap21','gate-age20','gate-age21','mode-flip-active','release-during-motion']
EXTRA=['digital-49','digital-51','after-commit','analog-10','analog-x2-500','analog-x-change','invalid-state']

def run(image,case):
    tokens=shlex.split((OLD/'intentional-original-command.txt').read_text())
    args=build_argparser().parse_args(tokens[2:])
    analog=case.startswith('analog') or case in ['cached-no-raw','cache-forged-filter','stale-observation','mode-flip-active']
    seeds=[parse_addr_bytes(s)for s in args.seed_mem]
    seeds=[(a,b)for a,b in seeds if a not in [0x41008020,0x410080a0,0x43002040]]
    baseline=517 if case in ['analog-startup-fault','analog-fault-after-arm','analog-x2-500'] else 225
    seeds += [(0x41008020,struct.pack('<I',0x400004 if analog else 0x400000)),
              (0x410080a0,struct.pack('<I',0 if case in ['startup-active','mode-flip-active'] else 32)),
              (0x43002040,struct.pack('<H',baseline))]
    forces=[parse_addr_addr_bytes(s)for s in args.force_mem]
    forces=[x for x in forces if x[1]not in [0x410080a0,0x43002040]]
    machine=ConcreteMachine(IMAGES[image],mmio_size=0x4000000,
        extra_maps=[parse_addr_len(s)for s in args.map_page],track_dirty=False)
    acquisitions={};patch_work={};live_at=None;perturbed=False
    external=[];polls=[];marks=[];setup=None;completed=None;sent_w=False;changed_x=False;corrupted=False
    current=None;latest_t=0;poll_dropped=0
    symbols=json.loads(((P if image=='optimized' else P.parent/'stateful-trigger-patch-2026-10-22')/'modification-manifest.json').read_text())['symbols']
    commit=int(symbols['commit'],16)
    def tick(uc):return int.from_bytes(uc.mem_read(0x200052ec,4),'little')
    def input_value(uc,value,pc,why):
        nonlocal current
        if value==current:return
        a=0x43002040 if analog else 0x410080a0
        raw=value if analog else (0 if value else 32)
        uc.mem_write(a,raw.to_bytes(2 if analog else 4,'little'))
        current=value
        external.append({'tick':tick(uc),'elapsed':latest_t,'pc':hex(pc),'kind':why,
                         'address':hex(a),'value':raw})
    def packet(uc,payload,pc,why):
        uc.mem_write(0x2000245c,payload)
        uc.mem_write(0x200024c0,b'\0'*4)
        uc.mem_write(0x200024c4,struct.pack('<I',len(payload)))
        external.append({'tick':tick(uc),'elapsed':latest_t,'pc':hex(pc),'kind':why,
                         'rx_hex':payload.hex()})
    def hook(uc,pc,size,user):
        nonlocal setup,completed,sent_w,changed_x,current,latest_t,poll_dropped,corrupted,live_at,perturbed
        now=tick(uc)
        if pc==0x94e4 and setup is None:
            setup=now
            if case=='analog-x2-500':packet(uc,b'X2|',pc,'configuration input')
        if setup is None:return
        if pc==0x5fa4 and live_at is None:live_at=now
        if pc in [0x42a4,0xd1b4,0xd3dc]:
            pin=uc.reg_read(UC_ARM_REG_R0) if pc!=0x42a4 else 0
            key=('live'if live_at is not None else 'prelive')+':'+hex(pc)+':'+str(pin)
            acquisitions[key]=acquisitions.get(key,0)+1
        latest_t=(now-setup)&0xffffffff
        t=latest_t
        if pc in [0x8f9c,0x5f8c,0x571c,0x5fa4,0x6056,0x9088,commit]:
            marks.append({'pc':hex(pc),'tick':now,'elapsed':t})
        if pc==0x6056 and completed is None:
            completed=now
            if case in ['held-w','repress-w','release-during-motion']:
                packet(uc,b'W|',pc,'one supplied Remote W after completion');sent_w=True
        if pc==0x5fa4 and case=='running-w' and not sent_w:
            packet(uc,b'W|',pc,'one supplied Remote W while live');sent_w=True
        if pc==0x8e18:
            if len(polls)<20000:polls.append(now)
            else:poll_dropped+=1
            if analog:
                active=900
                if case=='analog-startup-fault':value=600
                elif case=='analog-fault-after-arm':value=600 if t>=100 else baseline
                else:
                    width=10 if case=='analog-10' else 500
                    value=active if 100<=t<100+width else baseline
                if case=='analog-x-change' and t>=125 and not changed_x:
                    packet(uc,b'X2|',pc,'configuration during candidate');changed_x=True
            else:
                width={'digital-10':10,'digital-49':49,'digital-51':51}.get(case,500)
                value=(t>=100) if case in ['held-w','running-w','repress-w','release-during-motion'] else 100<=t<100+width
                if case=='startup-active':value=True
                if case=='pc-transient':value=False
                if case=='release-during-motion' and live_at is not None and ((now-live_at)&0xffffffff)>=100:value=False
                if case in ['repress-w','release-during-motion'] and completed is not None:
                    dt=(now-completed)&0xffffffff;value=200<=dt<700
                if case in ['before-commit','after-commit']:value=t>=100
            if case=='return-edge':
                value=t>=100 if live_at is None else ((now-live_at)&0xffffffff)<100
                if live_at is not None and ((now-live_at)&0xffffffff)>=300 and not sent_w:
                    packet(uc,b'W|',pc,'one W after busy inactive arming');sent_w=True
                if sent_w and not perturbed and uc.mem_read(0x20002318,1)==b'\x03' and uc.mem_read(0x200000d8,1)!=b'\x09' and uc.mem_read(0x20001b14,1)==b'\x00':
                    external.append({'tick':now,'elapsed':t,'pc':hex(pc),'kind':'active edge at return-phase poll entry before idle9','pre_idle':uc.mem_read(0x200000d8,1).hex(),'pre_phase':uc.mem_read(0x20002318,1).hex(),'pre_channels':uc.mem_read(0x20002524,4).hex(),'pre_policy':uc.mem_read(0x2000531c,4).hex()});perturbed=True
                if perturbed:value=True
            input_value(uc,value,pc,'scheduled electrical input')
            if case in ['cached-no-raw','cache-forged-filter'] and t>=165:
                uc.mem_write(0x20003124,struct.pack('<I',now*1000+100000000))
                if case=='cache-forged-filter':uc.mem_write(0x2000311c,struct.pack('<f',900.0))
                if not perturbed:external.append({'tick':now,'elapsed':t,'pc':hex(pc),'kind':case+' explicit filter deadline/history perturbation'});perturbed=True
            if case=='mode-flip-active' and t>=125 and not perturbed:
                uc.mem_write(0x20001fc0,b'\x02');external.append({'tick':now,'elapsed':t,'pc':hex(pc),'kind':'explicit mode1->2 with GPIO alreadyLOW'});perturbed=True
            if case in ['gap20','gap21'] and t>=125 and not perturbed:
                last=int.from_bytes(uc.mem_read(0x2000531c+32,4),'little');desired=last+(20 if case=='gap20' else 21)
                if image!='original':uc.mem_write(0x200052ec,struct.pack('<I',desired))
                external.append({'tick':now,'elapsed':t,'pc':hex(pc),'kind':'explicit observation clock gap','target_tick':desired});perturbed=True
            if case=='invalid-state' and image in ['phase3','optimized'] and t>=125 and not corrupted:
                uc.mem_write(0x2000531c,struct.pack('<I',0xffffffff));corrupted=True
                external.append({'tick':now,'elapsed':t,'pc':hex(pc),
                                 'kind':'explicit invalid-state perturbation','value':'ffffffff'})
        if case=='pc-transient' and t>=100 and pc in [0x9228,0x922c]:
            input_value(uc,pc==0x9228,pc,'PC-timed connection history')
        if case=='before-commit':
            target=0x922c if image=='original' else int(symbols['accept_hook'],16)
            if pc==target:input_value(uc,False,pc,'release before final authorization check')
        if case in ['gate-age20','gate-age21'] and image!='original' and pc==int(symbols['accept_hook'],16) and not perturbed and t>=150 and int.from_bytes(uc.mem_read(0x2000531c,4),'little')==4:
            last=int.from_bytes(uc.mem_read(0x2000531c+32,4),'little');desired=last+(20 if case=='gate-age20' else 21)
            uc.mem_write(0x200052ec,struct.pack('<I',desired));external.append({'tick':now,'elapsed':t,'pc':hex(pc),'kind':'explicit grant clock age','target_tick':desired});perturbed=True
        if case=='stale-observation' and image=='optimized' and pc==int(symbols['observation_update'],16) and t>=125:
            uc.mem_write(0x2000531c+44,struct.pack('<I',now-21))
            if not perturbed:external.append({'tick':now,'elapsed':t,'pc':hex(pc),'kind':'explicit repeatedly stale observation timestamp'});perturbed=True
        if case=='after-commit':
            target=commit+4 if image in ['phase3','optimized'] else 0x8f9c
            if pc==target:input_value(uc,False,pc,'release after authorization; no cancellation policy')
    hook_sites={0x42a4,0xd1b4,0xd3dc,0x94e4,0x8e18,0x9228,0x922c,0x8f9c,0x5f8c,0x571c,0x5fa4,0x6056,0x9088}
    if image in ['phase3','optimized']:hook_sites|={commit,commit+4,int(symbols['accept_hook'],16)}
    if image=='optimized':hook_sites|={int(symbols['observation_update'],16)}
    
    for pc in hook_sites:machine.uc.hook_add(UC_HOOK_CODE,hook,begin=pc,end=pc)
    watches={0x8e1c,0x8f9c,0x5f8c,0x571c,0x5810,0x5fa4,0x6056,0x6fd8,0x865a,0x5274}
    if image in ['phase3','optimized']:watches|={int(symbols[x],16)for x in ['armed','qualified','commit']}
    fields=[(0x200052ec,4),(0x200030cc,16),(0x200025dc,32),(0x20000094,16),(0x2000201c,16),(0x20000000,128),
            (0x20000850,128),(0x20000e90,128),(0x200014d0,128),(0x20002840,400),
            (0x20001b40,80),(0x200000d8,4),(0x20001b14,4),(0x20002524,4),
            (0x20002318,4),(0x20002064,16),(0x20003118,16),(0x20000190,8),
            (0x20000194,4),(0x20005308,4),(0x2000531c,64),(0x410080a0,4),(0x43002040,2)]
    writes=[(0x20001b14,4)]
    motor=case in ['digital-500','analog-500']
    if motor:
        watches|={0x8e18,0x8e1c,0x8e76,0x8e7a,0x9228,0x922c,0x9232,0x943e,0x8f98,0x6368,0x6420,0x66ee,0x5c44}
    if image=='optimized':watches|={0x8e18,int(symbols['observation_update'],16)}
    if image!='original':
        def count_patch(uc,pc,size,user):
            if setup is None:return
            key='live'if live_at is not None else 'prelive';patch_work[key]=patch_work.get(key,0)+1
        end=0x15470+json.loads(((P if image=='optimized' else P.parent/'stateful-trigger-patch-2026-10-22')/'modification-manifest.json').read_text())['extension']['size']
        machine.uc.hook_add(UC_HOOK_CODE,count_patch,begin=0x15470,end=end-1)
    if motor:writes += [(0x40003800,32),(0x43000428,4),(0x41008094,12),(0x41008014,12)]
    bound=20000000 if case=='return-edge' else 65000000 if case in ['held-w','repress-w','release-during-motion'] else 16000000
    result=machine.run(0xcc24,seed_mem=seeds,
        stub_calls=[parse_hexaddr(s)for s in args.stub_call],force_mem=forces,
        force_reg=[parse_addr_reg_hexvalue(s)for s in args.force_reg],
        fake_tick=[parse_addr_len(s)for s in args.fake_tick],
        mmio_force_bits=[parse_addr_hexmask(s)for s in args.mmio_force_bits],
        mmio_clear_bits=[parse_addr_hexmask(s)for s in args.mmio_clear_bits],
        watch=sorted(watches),watch_mem=fields,dump_mem=fields+[(0x40003800,32)],
        watch_mem_write=writes,max_mem_write_log=150000,max_watch_hits=100000,max_instructions=bound)
    d=result.to_dict();d['external_fixture']={'acquisitions':acquisitions,'patch_instructions':patch_work,'case':case,'image':image,'setup_tick':setup,
        'events':external,'milestones':marks,'poll_ticks':polls,'dropped_poll_ticks':poll_dropped,
        'clock':'firmware millis counter; fake tick every4000 guest instructions; not physical time',
        'fixture_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'firmware_sha256':hashlib.sha256(IMAGES[image].read_bytes()).hexdigest(),
        'source_recipe_sha256':hashlib.sha256((OLD/'intentional-original-command.txt').read_bytes()).hexdigest()}
    path=P/'prefix-frame-digital.json.gz'
    path.write_bytes(gzip.compress((json.dumps(d,indent=2)+'\n').encode(),mtime=0))
    counts={hex(pc):sum(int(h['address'],16)==pc for h in d['watch_hits'])for pc in [0x8f9c,0x5f8c,0x5fa4,0x6056]}
    print(json.dumps({'file':path.name,'counts':counts,'error':d['error'],'drop':d['mem_write_dropped']}),flush=True)
    del machine;gc.collect()
    return d['error'] is None

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--image',choices=IMAGES,required=True)
    parser.add_argument('--case',choices=CORE+EXTRA+ADVERSARIAL);parser.add_argument('--suite',action='store_true');parser.add_argument('--adversarial',action='store_true');parser.add_argument('--campaign',action='store_true')
    a=parser.parse_args();cases=CORE+EXTRA+ADVERSARIAL if a.campaign else ADVERSARIAL if a.adversarial else CORE+(EXTRA if a.image in ['phase3','optimized'] else [])if a.suite else [a.case]
    if cases==[None]:parser.error('choose --case or --suite')
    sys.exit(0 if all(run(a.image,c)for c in cases)else 1)
