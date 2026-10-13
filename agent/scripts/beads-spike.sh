#!/usr/bin/env bash
# Beads spike experiments H (history/backup/portability), I (resources),
# J (formulas). Everything runs in a throwaway directory with a sandbox HOME,
# outside any git tree, with usage metrics disabled.
#
#   BD=/path/to/bd agent/scripts/beads-spike.sh [workdir]
set -euo pipefail

BD=${BD:-$(command -v bd)}
ROOT=${1:-$(mktemp -d -t beads-spike)}
export DO_NOT_TRACK=1 HOME="$ROOT/home" BD_NON_INTERACTIVE=1 BD_NO_DEP_TYPE_WARNING=1
mkdir -p "$HOME"

bd() { "$BD" "$@" 2> >(grep -vE 'beads.role|git config beads.role' >&2); }
ms() { python3 -c 'import time; print(int(time.time()*1000))'; }
section() { printf '\n=== %s\n' "$*"; }

init_store() { # dir prefix
  mkdir -p "$1/.beads"
  (cd "$1" && BEADS_DIR="$1/.beads" bd init --non-interactive --skip-agents --skip-hooks --quiet -p "$2")
}

section "version"
"$BD" version

# -- H: history, backup, restore, portability ----------------------------------
A="$ROOT/a"; init_store "$A" apt
export BEADS_DIR="$A/.beads"
cd "$A"
INV=$(bd create "Investigate USB_OTHER dispatch" --metadata '{"aptrace_kind":"investigation","aptrace_case":"performing-rigs","aptrace_run_ids":["R-20261013T000000-abcdef"]}' --silent)
FU=$(bd create "Follow up CHALLENGED audit of C1:v1" --id apt-fu0123456789 --deps "discovered-from:$INV" --metadata '{"aptrace_claim_version":"C1:v1","aptrace_audit_id":"A-x"}' --silent)
bd update "$INV" --claim --actor controller --json >/dev/null
bd close "$INV" --reason "work completed: ledger run R-20261013T000000-abcdef recorded" --actor controller --json >/dev/null

section "H history (events) for $INV"
bd history "$INV" --events --json | python3 -c 'import json,sys; [print(e["event_type"], e["actor"], e["created_at"]) for e in json.load(sys.stdin)]'
section "H history (Dolt commit snapshots) for $INV"
bd history "$INV" --json | python3 -c 'import json,sys; [print(h["CommitHash"][:12], h["CommitDate"], h["Issue"]["status"]) for h in json.load(sys.stdin)]'

section "H restart survival (new process)"
bd show "$INV" --json | python3 -c 'import json,sys; d=json.load(sys.stdin)[0]; print(d["status"], d["close_reason"], d["metadata"])'

section "H tracked vs ignored files in .beads (bd's own .gitignore)"
(cd "$A/.beads" && ls -A && grep -E '^(embeddeddolt|dolt|backup)/' .gitignore)

section "H Dolt-native backup to filesystem + restore into a fresh store"
bd backup init "$ROOT/backup" --json 2>&1 | tail -3 || true
bd backup sync --json 2>&1 | tail -3 || true
du -sh "$ROOT/backup" || true
B="$ROOT/b"; init_store "$B" apt
(cd "$B" && BEADS_DIR="$B/.beads" bd backup restore "$ROOT/backup" --force --json 2>&1 | tail -5) || echo "restore exit $?"
(cd "$B" && BEADS_DIR="$B/.beads" bd list --all --json | python3 -c 'import json,sys; [print("restored", i["id"], i["status"], i.get("metadata")) for i in json.load(sys.stdin)]') || true

section "H JSONL export -> import into a fresh store"
bd export -o "$ROOT/export.jsonl"
wc -l "$ROOT/export.jsonl"
C="$ROOT/c"; init_store "$C" apt
(cd "$C" && BEADS_DIR="$C/.beads" bd import "$ROOT/export.jsonl" --json | tail -3)
(cd "$C" && BEADS_DIR="$C/.beads" bd show "$FU" --json | python3 -c 'import json,sys; d=json.load(sys.stdin)[0]; print(d["id"], d["metadata"], [(x["id"], x["dependency_type"]) for x in d.get("dependencies", [])])')

# -- I: resources ---------------------------------------------------------------
section "I latency (ms, 10 runs each, embedded mode)"
for op in "show $INV" "ready" "list --all"; do
  t0=$(ms); for _ in $(seq 10); do bd $op --json >/dev/null; done; t1=$(ms)
  echo "$op: $(( (t1 - t0) / 10 )) ms/op"
done
t0=$(ms); for n in $(seq 10); do bd create "latency $n" --silent >/dev/null; done; t1=$(ms)
echo "create: $(( (t1 - t0) / 10 )) ms/op"
t0=$(ms); for n in $(seq 10); do bd update "$INV" --metadata "{\"k\":$n}" --json >/dev/null; done; t1=$(ms)
echo "update metadata: $(( (t1 - t0) / 10 )) ms/op"

section "I peak RSS of one bd invocation"
/usr/bin/time -l "$BD" ready --json 2>&1 >/dev/null | grep -E 'maximum resident|real' || true

section "I resident processes after commands (embedded mode should leave none)"
pgrep -lx bd || echo "no resident bd process"
pgrep -lx dolt || echo "no dolt process"

section "I footprint"
du -sh "$A/.beads" "$A/.beads/embeddeddolt"
for n in $(seq 200); do echo "{\"title\":\"bulk $n\",\"metadata\":{\"aptrace_kind\":\"investigation\",\"n\":$n}}"; done > "$ROOT/bulk.jsonl"
t0=$(ms); bd import "$ROOT/bulk.jsonl" --json >/dev/null; t1=$(ms)
echo "import 200 items: $((t1 - t0)) ms"
du -sh "$A/.beads/embeddeddolt"
t0=$(ms); bd ready --limit 0 --json >/dev/null; t1=$(ms)
echo "ready over ~215 items: $((t1 - t0)) ms"

section "I 8 concurrent readers"
t0=$(ms); for _ in $(seq 8); do bd ready --limit 0 --json >/dev/null & done; wait; t1=$(ms)
echo "8 parallel ready: $((t1 - t0)) ms wall"

# -- J: formulas ----------------------------------------------------------------
section "J formula: investigate -> audit -> follow-up (if challenged) -> verify"
mkdir -p "$A/.beads/formulas"
cat > "$A/.beads/formulas/aptrace-investigation.formula.toml" <<'TOML'
formula = "aptrace-investigation"
description = "Work skeleton for one APTrace investigation. Research semantics stay in APTrace."
version = 1
type = "workflow"

[vars.objective]
description = "Research objective"
required = true

[vars.challenged]
description = "Whether the audit challenged the claim"
default = "false"

[[steps]]
id = "investigate"
title = "Investigate: {{objective}}"

[[steps]]
id = "audit"
title = "Audit claims proposed by the investigation"
needs = ["investigate"]

[[steps]]
id = "followup"
title = "Follow up challenged claim"
needs = ["audit"]
condition = "{{challenged}} == true"

[[steps]]
id = "verify"
title = "Run APTrace deterministic verification"
needs = ["audit"]
TOML
bd formula list 2>&1 | tail -4
for challenged in false true; do
  echo "-- cook with challenged=$challenged"
  bd cook aptrace-investigation --var objective=USB --var challenged=$challenged --json \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print([s.get("id") for s in d.get("steps", [])])' || true
done
echo "-- pour (challenged=false) and inspect the ready frontier"
bd mol pour aptrace-investigation --var objective=USB --json 2>&1 | python3 -c 'import json,sys; d=json.load(sys.stdin); print({k: d[k] for k in d if k in ("new_epic_id","created","id_mapping","root_id")})' || true
bd ready --limit 0 --json | python3 -c 'import json,sys; print("ready:", [i["title"] for i in json.load(sys.stdin) if i["id"].startswith("apt-mol")])'
bd list --all --limit 0 --json | python3 -c 'import json,sys; print("molecule issues:", sorted((i["title"], i["status"]) for i in json.load(sys.stdin) if i["id"].startswith("apt-mol")))'
echo "-- pour (challenged=true)"
bd mol pour aptrace-investigation --var objective=SERCOM --var challenged=true --json 2>&1 | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("created"), sorted(d.get("id_mapping", {})))' || true

section "done: $ROOT"
