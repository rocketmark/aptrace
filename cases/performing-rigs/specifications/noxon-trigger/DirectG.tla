----------------------------- MODULE DirectG -----------------------------
EXTENDS Naturals, Sequences, TLC, DirectFixtures
VARIABLES n, step, g
vars == <<n,step,g>>
D == DirectFixtures[n]
Init == /\ n \in DOMAIN DirectFixtures /\ step=0
 /\ g=[arm |-> 0, phase |-> 0, request |-> <<>>, aligned |-> TRUE]
Parse == /\ step=0 /\ step'=1 /\ UNCHANGED n
 /\ g'=[g EXCEPT !.arm=IF D.hasG /\ D.sequence#0 THEN 2 ELSE 0]
sArm == g.arm=2
Select == /\ step=1 /\ step'=2 /\ UNCHANGED n
 /\ g'=[g EXCEPT !.phase=IF sArm THEN 1 ELSE 0]
Request == /\ step=2 /\ step'=3 /\ UNCHANGED n
 /\ g'=[g EXCEPT !.request=IF g.phase=1 /\ D.readsync
        THEN <<0,30,D.target-D.current,D.rate>> ELSE <<>>]
Check == /\ step=3 /\ step'=4 /\ UNCHANGED n
 /\ g'=[g EXCEPT !.aligned=(g.request=D.expected /\ g.arm=D.arm /\ g.phase=D.phase)]
Next == Parse \/ Select \/ Request \/ Check
Spec == Init /\ [][Next]_vars /\ WF_vars(Next)
Correspondence == g.aligned
CompleteReplay == <>(step=4)
=============================================================================
