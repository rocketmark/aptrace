"""Replay exact saved public CLI commands; no firmware semantics."""
import json,subprocess
from pathlib import Path
p=Path(__file__).resolve().parent
for cmd in json.loads((p/'direct-commands.json').read_text()):
 result=subprocess.run(cmd)
 if result.returncode:raise SystemExit(result.returncode)
