------------------------- MODULE ReferenceReplay -------------------------
EXTENDS TriggerAcceptance, NativeFixtures
CONSTANT RefSelected
VARIABLES n, cursor, stage, rr
allvars == <<s,n,cursor,stage,rr>>
RF == Fixtures[n]
A(v,x) == IF x=1 THEN v<200 \/ v>580 ELSE v<250 \/ v>750
Label(v,x) == IF A(v,x) THEN "A" ELSE "I"
Expected == IF n="digital-connection-after-inactive-sample" THEN 1 ELSE 0
RefInit == /\ Init /\ n \in RefSelected /\ cursor=1 /\ stage=0
 /\ rr=[x |-> 1, acquired |-> 0, serial |-> 0, used |-> 0]
Fresh(e) == e.kind="digital" \/ (e.kind="analog" /\ rr.serial>rr.used)
Feed == /\ stage=0 /\ cursor<=Len(RF.events)
 /\ LET e == RF.events[cursor] IN
    /\ CASE e.kind="program" -> Invalidate(e.value=123,s.reference,s.driver)
         [] e.kind="setup" -> Invalidate(s.program,e.value=1,e.value=1)
         [] e.kind="x" -> Invalidate(s.program,s.reference,s.driver)
         [] e.kind="digital" ->
              Acquire(IF e.value=0 THEN "A" ELSE "I",
                      IF e.value=0 THEN "A" ELSE "I",TRUE,0)
         [] e.kind="analog" /\ Fresh(e) ->
              Acquire(Label(rr.acquired,rr.x),Label(e.value,rr.x),TRUE,0)
         [] OTHER -> UNCHANGED s
    /\ rr'=CASE e.kind="x" -> [rr EXCEPT !.x=e.value]
           [] e.kind="adc" -> [rr EXCEPT !.acquired=e.value, !.serial=@+1]
           [] e.kind="analog" -> [rr EXCEPT !.used=rr.serial]
           [] OTHER -> rr
    /\ stage'=IF Fresh(e) THEN 1 ELSE 0
    /\ cursor'=IF Fresh(e) THEN cursor ELSE cursor+1
 /\ UNCHANGED n
Consume == /\ stage=1 /\ Process /\ stage'=2 /\ UNCHANGED <<n,cursor,rr>>
Grant == /\ stage=2
 /\ (IF s.phase="Recognized" /\ LiveToken THEN Accept ELSE UNCHANGED s)
 /\ stage'=3 /\ UNCHANGED <<n,cursor,rr>>
Launch == /\ stage=3
 /\ (IF s.phase="Authorized" /\ LiveToken THEN Start("profile") ELSE UNCHANGED s)
 /\ stage'=0 /\ cursor'=cursor+1 /\ UNCHANGED <<n,rr>>
RefNext == Feed \/ Consume \/ Grant \/ Launch
RefSpec == RefInit /\ [][RefNext]_allvars /\ WF_allvars(RefNext)
OutcomeMatches == cursor>Len(RF.events) => Len(s.starts)=Expected
ReferenceReplayCompletes == <>(cursor>Len(RF.events))
=============================================================================
