"""Replay recorded public CLI commands only; no firmware or emulator semantics."""
import json,subprocess
from pathlib import Path
p=Path(__file__).resolve().parent
for item in json.loads((p/'frozen-commands.json').read_text()):
 print(item['name'],flush=True)
 result=subprocess.run(item['argv'])
 if result.returncode:raise SystemExit('CLI returned '+str(result.returncode)+' for '+item['name'])
