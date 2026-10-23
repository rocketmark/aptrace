"""Exact-image firmware authoring; not an analysis backend. RESEARCH ONLY."""
import hashlib, json, struct, subprocess
from pathlib import Path

P = Path(__file__).resolve().parent
ROOT = P.parents[4]
SOURCE = ROOT / 'cases/performing-rigs/research/firmware/originals/firmware_autopilot915.bin'
EXPECTED = '0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920'
BASE, EXT = 0x4000, 0x15470

def branch(pc, target):
    off = target - pc - 4
    assert off % 2 == 0 and -(1<<24) <= off < (1<<24)
    s, i1, i2 = (off>>24)&1, (off>>23)&1, (off>>22)&1
    return struct.pack('<HH',0xf000|(s<<10)|((off>>12)&0x3ff),
                       0x9000|((1^i1^s)<<13)|((1^i2^s)<<11)|((off>>1)&0x7ff))

def sha(b): return hashlib.sha256(b).hexdigest()

original = SOURCE.read_bytes()
assert sha(original) == EXPECTED and len(original) == EXT-BASE
subprocess.run(['/usr/bin/clang','--target=arm-none-eabi','-mcpu=cortex-m4','-mthumb',
                '-c',str(P/'reuse.S'),'-o',str(P/'RESEARCH_ONLY_NOT_FOR_HARDWARE_reuse.o')], check=True)
# Extract only the assembler's resolved .text and symbols from its ELF32 object.
# This is patch packaging, not instruction decoding/lifting.
obj=(P/'RESEARCH_ONLY_NOT_FOR_HARDWARE_reuse.o').read_bytes()
assert obj[:6] == b'\x7fELF\x01\x01'
shoff=struct.unpack_from('<I',obj,32)[0]
ents,n,strings=struct.unpack_from('<HHH',obj,46)
sections=[struct.unpack_from('<10I',obj,shoff+i*ents)for i in range(n)]
def contents(s):return obj[s[4]:s[4]+s[5]]
names=contents(sections[strings])
def string(b,i):return b[i:b.index(b'\0',i)].decode()
text_index=next(i for i,s in enumerate(sections)if string(names,s[0])=='.text')
assert not any(s[1]in(4,9)and s[5]for s in sections),'unresolved assembler relocations'
code=contents(sections[text_index]); symbols={}
for s in sections:
    if s[1]!=2:continue
    table=contents(s); strs=contents(sections[s[6]])
    for i in range(0,len(table),s[9]):
        name,value,size,info,other,idx=struct.unpack_from('<IIIBBH',table,i)
        if name and idx==text_index:
            symbols[string(strs,name)]=EXT+(value&~1)
def bl(pc,target):
    a,b=struct.unpack('<HH',branch(pc,target))
    return struct.pack('<HH',a,b|0x4000)
patched=bytearray(original);changes=[]
def put(addr,b,expected):
    off=addr-BASE;before=bytes(patched[off:off+len(b)])
    assert before==expected,(hex(addr),before.hex(),expected.hex())
    patched[off:off+len(b)]=b
    changes.append({'address':hex(addr),'file_offset':hex(off),'before':before.hex(),'after':b.hex()})
put(0x8e18,branch(0x8e18,symbols['poll_hook']),bytes.fromhex('2de9f74f'))
put(0x8f98,branch(0x8f98,symbols['accept_hook']),bytes.fromhex('6b4b0322'))
put(0x81d0,branch(0x81d0,symbols['program_hook']),branch(0x81d0,0xb2fe))
put(0x8e76,bl(0x8e76,symbols['analog_hook']),bl(0x8e76,0x42a4))
put(0x9228,bl(0x9228,symbols['digital_hook']),bl(0x9228,0xd3dc))
put(0x42d4,branch(0x42d4,symbols['raw_hook'])+bytes.fromhex('00bf'),original[0x42d4-BASE:0x42da-BASE])
put(0x9232,branch(0x9232,symbols['busy_hook'])+bytes.fromhex('00bf'),original[0x9232-BASE:0x9238-BASE])
for addr in [0xcca0,0x11050]:
    put(addr,struct.pack('<I',0x2000535c),struct.pack('<I',0x2000531c))
patched.extend(code)
assert patched[0x12000-BASE:0x13001-BASE]==original[0x12000-BASE:0x13001-BASE]
output=P/'RESEARCH_ONLY_NOT_FOR_HARDWARE_autopilot915_reuse_r2.bin'
output.write_bytes(patched)
manifest={'warning':'SIMULATION RESEARCH ONLY; NOT FOR HARDWARE DEPLOYMENT',
 'source_path':str(SOURCE),'source_sha256':EXPECTED,'original_size':len(original),
 'patched_file':output.name,'patched_size':len(patched),'patched_sha256':sha(patched),
 'load_base':hex(BASE),'extension':{'address':hex(EXT),'size':len(code),'bytes':code.hex()},
 'modifications':changes,'symbols':{k:hex(v)for k,v in symbols.items()},
 'new_state':{'start':'0x2000531c','end_exclusive':'0x2000535c','bytes':64,
 'reservation':'Extend reset BSS end at cca0 AND allocator initial-break literal at11050; preserve existing heap cursor20005308'},
 'observation_metadata':{'type_offset':36,'actual_acquisition_tick_offset':44,'X_at_acquisition_offset':48,'prefix_observed_offset':52,'prefix_classification_offset':56,'prefix_mode_offset':60,'type':'0 invalid,1 native filtered ADC,2 native/fallback digital,3 fresh pre-phase fallback; reset each poll'},
 'policy':{'inactive_ticks':50,'active_ticks':50,'maximum_poll_gap_ticks':20,
 'states':{'0':'need inactive','1':'qualifying inactive','2':'armed','3':'qualifying active','4':'qualified'},
 'analog':'Current-poll native raw AND result of same native filter invocation; X1/X2 only; unchanged fresh reacquisition at grant',
 'lifecycle_epoch':'While W/return phase bytes are nonzero and entry ineligible, preserve Phase3 fresh pre-phase observation and skip a second policy update; no extra eligibility predicate',
 'commit':'fresh classification, stable context/eligibility and atomic consume before original queue1 store'},
 'compatibility':'Exact original915 only. Appended executable extent allocated for simulation; no physical flash ownership/bootloader claim.',
 'assembly_sha256':sha((P/'reuse.S').read_bytes()),'object_sha256':sha(obj)}
(P/'modification-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'sha256':sha(patched),'symbols':manifest['symbols'],'bytes':len(patched)},indent=2))
