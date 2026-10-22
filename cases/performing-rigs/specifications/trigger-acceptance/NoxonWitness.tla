-------------------------- MODULE NoxonWitness ---------------------------
EXTENDS Naturals
CONSTANT Scenario
ASSUME Scenario \in {"startup", "reclassification", "filterTail"}
VARIABLE w
vars == <<w>>
Init == w = [step |-> 0, eligible |-> FALSE,
 active |-> (Scenario # "reclassification"), freshEpisode |-> FALSE, starts |-> 0]
Expose == /\ w.step=0
          /\ w'=[w EXCEPT !.step=1, !.eligible=TRUE,
                   !.active=TRUE]
\* Expose abstracts respectively MC4/eligibility, X1->X2, and TR1->TR0.
\* None of those changes is a new inactive->active electrical episode.
Recognize == /\ w.step=1 /\ w.active
             /\ w'=[w EXCEPT !.step=2]
Initiate == /\ w.step=2 /\ w.eligible /\ w.active
            /\ w'=[w EXCEPT !.step=3, !.starts=1]
Next == Expose \/ Recognize \/ Initiate
Spec == Init /\ [][Next]_vars
NewEpisodeRequired == w.starts=0 \/ w.freshEpisode
=============================================================================
