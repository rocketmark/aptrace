# Gate 2 differential replay evidence

Research only; NOT FOR HARDWARE DEPLOYMENT. [Report](../../../docs/investigations/trigger-patch-gate2.md).

This directory preserves 16 fresh direct CLI executions: seven original/patched
history pairs plus an intentional pair with only write-watch arguments removed.
Every command is recorded as `*-command.txt`. Invoke these directly from the
repository root using the documented venv; choose a new --out path when replaying.
Do not wrap native execution, add Python -u, redirect its output, or change policy
to bypass the macOS initialization restriction. Use the CLI's --out facility.

`source-identities.txt` records firmware/backend hashes. Python is 3.9.6, Unicorn
2.1.4. Baseline HEAD is `6cf2bd904a3fdbfcab7e198ad28c9196e2067ef3`.
`paired-command-differences.txt` shows that each authoritative original/patched
pair differs only in firmware and output path. `historical-replay-byte-comparison.txt`
records standard gzip-decompression / cmp against the corresponding preserved
authoring snapshot: all 14 return 0, including every checkpoint and trace field.

The original 20 gzip records, modification manifest, binary, and **unchanged**
existing `check-artifacts.py` are staged copies from `trigger-patch-2026-10-22`.
No new analysis, comparator, test, or harness code was written. Staging is required
because the checker derives ROOT from its own location and writes fixed output
names. Its current run generated `checks.json` and `outcomes.json` here, preserving
the original packet. See `checker-execution.txt` for the exact fresh/historical
split: 138/138 includes six old records and is not a new 20-run safety campaign.

`transient-checkpoint-inspection.txt`, `direct-controls-inspection.txt` and
`instrumentation-state-inspection.txt` are field displays of native snapshots for
operator interpretation, not additional verification algorithms. The no-write-watch
observations remain single-step because MMIO read hooks are still active.

Original and patched 14M histories deliberately exhaust their instruction budget;
they are finite observations, not completed applications. Direct controls stop
at 0x5fa6 before that instruction executes. No new adversarial histories or Gate 3
experiments were launched. Known held/W and post-read release witnesses remain
historical counterexamples.

Packet digests are in packet-sha256.txt (excluding itself). Original source packet,
Gate 1 report, and both authoritative images remain unchanged.
