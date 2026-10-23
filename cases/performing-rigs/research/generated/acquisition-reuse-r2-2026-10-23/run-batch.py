"""Independent case batching over the saved APTrace input recipe; no emulator semantics."""
import json,subprocess,sys
from pathlib import Path
p=Path(__file__).resolve().parent
for item in json.loads((p/'batches.json').read_text())[int(sys.argv[1])]:
 cmd=[sys.executable,str(p/item['script']),'--image','optimized','--case',item['case']]
 result=subprocess.run(cmd)
 if result.returncode:raise SystemExit(result.returncode)
