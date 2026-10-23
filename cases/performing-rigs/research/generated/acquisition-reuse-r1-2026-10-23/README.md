# Acquisition-reuse R1 — REJECTED

SIMULATION RESEARCH ONLY. NOT FOR HARDWARE DEPLOYMENT.

R1 preserves the initial candidate's before-idle9 rejection by requiring active
qualification to be eligible at poll entry and observation time. A fresh500-tick
input immediately after native idle9 restoration is nevertheless lost: Phase3
starts twice, R1 once. This conservative correction therefore changes legitimate
trigger behavior and is not promoted.

All initial candidate files remain in the sibling acquisition-reuse packet.
The main corrected-image regressions use run-batch.py with batches.json; exact
public CLI support commands are in support-commands.json. The late-edge companion
is reproducible via return-edge-late.py --image phase3|optimized --case
return-edge-late. check-artifacts.py retains the deliberately failing preservation
assertion. See the case acquisition-reuse report for the final bounded correction.
