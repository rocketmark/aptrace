"""Run saved public native CLI fragment controls; no firmware semantics."""
import json,subprocess
from pathlib import Path
p=Path(__file__).resolve().parent
for item in json.loads((p/'fragment-commands.json').read_text()):
 result=subprocess.run(item['argv'])
 if result.returncode:raise SystemExit(result.returncode)
