-------------------------- MODULE NoxonTrigger ---------------------------
EXTENDS Naturals, Sequences, TLC, NativeFixtures
CONSTANTS Selected, RequireRaw, FreezeFilter
VARIABLES name, i, s
vars == <<name, i, s>>
F == Fixtures[name]
Active(v,x) == IF x=1 THEN v<200 \/ v>580 ELSE v<250 \/ v>750
RawActive == IF s.mode=2 THEN s.raw=0 ELSE Active(s.raw,s.x)
Eligible == s.setup /\ s.marker=123 /\ s.channels=0 /\ s.idle=9 /\ s.tr=0
Init == /\ name \in Selected /\ i=1
 /\ s=[mode |-> F.mode, raw |-> F.raw, filtered |-> 522, sampled |-> 1,
        acquired |-> 0, acquisitionSeq |-> 0, returnedSeq |-> 0,
        x |-> 1, tr |-> 0, setup |-> FALSE, marker |-> 255,
        channels |-> 0, idle |-> 9, profile |-> FALSE, live |-> FALSE,
        active |-> FALSE, pending |-> FALSE, accepts |-> 0,
        requests |-> 0, starts |-> 0, timer |-> FALSE,
        qualified |-> FALSE, episode |-> FALSE, allFresh |-> TRUE,
        allClass |-> TRUE, allRaw |-> TRUE, aligned |-> TRUE, last |-> "Boot"]
\* Acquisition arithmetic and evaluator deadline are native oracles, not outputs.
\* Ordinary state/output updates below are independent of checkpoint expectations.
Apply(e) ==
 CASE e.kind="raw" -> [s EXCEPT !.raw=e.value,
       !.episode=@ \/ (Eligible /\ s.qualified /\ ~RawActive /\
           (IF s.mode=2 THEN e.value=0 ELSE Active(e.value,s.x))),
       !.last="PhysicalInput"]
 [] e.kind="setup" -> [s EXCEPT !.setup=(e.value=1), !.last="MC4Boundary"]
 [] e.kind="program" -> [s EXCEPT !.marker=e.value, !.last="ProgramBoundary"]
 [] e.kind="x" -> [s EXCEPT !.x=e.value, !.last="XChange"]
 [] e.kind="tr" -> [s EXCEPT !.tr=e.value, !.last="TRChange"]
 [] e.kind="adc" -> [s EXCEPT !.acquired=e.value,
       !.acquisitionSeq=@+1, !.last="ADCAcquisition"]
 [] e.kind="analog" -> [s EXCEPT
       !.returnedSeq=s.acquisitionSeq,
       !.filtered=IF FreezeFilter THEN s.filtered ELSE e.value,
       !.last="FilterReturn"]
 [] e.kind="digital" -> [s EXCEPT !.sampled=e.value, !.last="DigitalReadReturn"]
 [] e.kind="classify" ->
    LET a == IF s.mode=2 THEN s.sampled=0 ELSE Active(s.filtered,s.x)
        consistentInactive == ~RawActive /\ ~a
        q == s.qualified \/ (Eligible /\ consistentInactive)
        ep == s.episode
        ok == Eligible /\ a /\ (~RequireRaw \/ RawActive)
    IN [s EXCEPT !.active=a, !.qualified=q, !.episode=ep,
        !.pending=IF ok THEN TRUE ELSE s.pending,
        !.accepts=IF ok THEN @+1 ELSE @, !.last="ClassifyAndGate"]
 [] e.kind="reload" -> [s EXCEPT
       !.aligned=@ /\ s.pending,
       !.channels=IF s.pending THEN 1 ELSE s.channels,
       !.idle=IF s.pending THEN 0 ELSE s.idle,
       !.profile=s.pending, !.pending=FALSE, !.last="Reload"]
 [] e.kind="rate" ->
    LET ok == s.profile /\ s.channels=1 /\ ~s.live
    IN [s EXCEPT !.aligned=@ /\ ok,
       !.requests=IF ok THEN @+1 ELSE @, !.last="ProfileRateStart"]
 [] e.kind="enable" -> [s EXCEPT
       !.aligned=@ /\ (s.requests>s.starts),
       !.timer=(s.requests>s.starts), !.last="TimerEnable"]
 [] e.kind="live" -> [s EXCEPT
       !.aligned=@ /\ s.timer /\ ~s.live,
       !.starts=IF s.timer /\ ~s.live THEN @+1 ELSE @,
       !.live=TRUE, !.allFresh=@ /\ s.episode,
       !.allClass=@ /\ s.active,
       !.allRaw=@ /\ RawActive, !.last="LiveWrite"]
 [] e.kind="check" -> [s EXCEPT
       !.aligned=@ /\ s.accepts=e.accepts /\ s.requests=e.requests
                   /\ s.starts=e.starts /\ s.channels=e.channels
                   /\ s.idle=e.idle /\ s.live=(e.live=1)
                   /\ (e.timer=2 \/ s.timer=(e.timer=1)),
       !.last="NativeCheckpoint"]
 [] OTHER -> s
Advance == /\ i<=Len(F.events) /\ s'=Apply(F.events[i]) /\ i'=i+1
           /\ UNCHANGED name
Spec == Init /\ [][Advance]_vars /\ WF_vars(Advance)
Correspondence == s.aligned
OneStartInObservedWindow == s.starts<=1 /\ s.accepts<=1
AcceptedProgramGuard == s.accepts=0 \/ s.marker=123
ProfileProvenance == s.starts=0 \/ (s.profile /\ s.requests>0 /\ s.timer)
FreshQualifiedInitiation == s.allFresh
ActiveRawAtInitiation == s.allRaw
ActiveClassificationAtInitiation == s.allClass
NoInitiation == s.starts=0
Done == i>Len(F.events)
ReplayCompletes == <>Done
AcceptedEventuallyStarts == (s.accepts>0) ~> (s.starts>0)
EveryPulseStarts == <>(s.starts>0)
=============================================================================
