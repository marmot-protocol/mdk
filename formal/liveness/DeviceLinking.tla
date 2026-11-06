-------------------------- MODULE DeviceLinking --------------------------
EXTENDS Naturals, TLC

CONSTANT FairRun
VARIABLE s
vars == <<s>>

(* A bounded first-link lifecycle, not MLS or a cryptographic proof.
   Two attempts deliberately reuse the group id and signer but use fresh
   KeyPackageRefs. Crypto-valid transcript comparison is an assumption owned
   by pairing's separate security model and real Rust role tests.
   App awaiting-row writes, engine expectation writes, atomic Welcome join,
   and app trust promotion are separate actions because Rust separates them. *)

Phases == {"request", "answer", "compare", "record", "wait", "ended"}
Init == s = [attempt |-> 1, phase |-> "request",
    existingTap |-> FALSE, newTap |-> FALSE, existingConfirm |-> FALSE,
    verifiedExisting |-> FALSE, newConfirmReady |-> FALSE,
    newConfirmSent |-> FALSE, durableBeforeSend |-> FALSE,
    sentConfirms |-> {}, peerConfirms |-> {}, acceptedConfirms |-> {},
    confirmedAdds |-> {},
    waiting |-> FALSE, expected |-> FALSE, expired |-> FALSE,
    emitted |-> {}, joined |-> FALSE,
    joinRecorded |-> FALSE, trusted |-> FALSE, firstSelected |-> FALSE,
    made |-> FALSE, cancel |-> FALSE, crashed |-> FALSE,
    crashUsed |-> FALSE, resetRequested |-> FALSE,
    admission |-> <<0, 0, 0, FALSE, FALSE>>, refusals |-> {}]

Live == ~s.crashed
Answer == /\ Live /\ s.phase = "request"
          /\ s' = [s EXCEPT !.phase = "answer"]
Reveal == /\ Live /\ s.phase = "answer"
          /\ s' = [s EXCEPT !.phase = "compare"]
CompareExisting == /\ Live /\ s.phase = "compare" /\ ~s.existingTap
                   /\ s' = [s EXCEPT !.existingTap = TRUE]
CompareNew == /\ Live /\ s.phase = "compare" /\ ~s.newTap
              /\ s' = [s EXCEPT !.newTap = TRUE]
ConfirmExisting == /\ Live /\ s.phase = "compare" /\ s.existingTap
                   /\ ~s.existingConfirm
                   /\ s' = [s EXCEPT !.existingConfirm = TRUE,
                                !.peerConfirms = @ \cup {s.attempt}]
DeliverExistingConfirm == /\ Live /\ s.phase = "compare"
                          /\ s.existingConfirm /\ ~s.verifiedExisting
                          /\ s' = [s EXCEPT !.verifiedExisting = TRUE]
ConfirmNew == /\ Live /\ s.phase = "compare"
              /\ s.newTap /\ s.verifiedExisting
              /\ s' = [s EXCEPT !.newConfirmReady = TRUE, !.phase = "record"]

RecordAwaiting == /\ Live /\ s.phase = "record" /\ ~s.waiting
                  /\ s' = [s EXCEPT !.waiting = TRUE]
RecordExpectation == /\ Live /\ s.phase = "record" /\ s.waiting
                     /\ ~s.expected /\ ~s.cancel /\ ~s.expired
                     /\ s' = [s EXCEPT !.expected = TRUE]
PublishNewConfirm == /\ Live /\ s.phase = "record"
                     /\ s.waiting /\ s.expected /\ ~s.cancel /\ ~s.expired
                     /\ s' = [s EXCEPT !.newConfirmSent = TRUE,
                         !.durableBeforeSend = s.waiting /\ s.expected,
                         !.phase = "wait",
                         !.sentConfirms = @ \cup {s.attempt}]
(* Peer work is indexed by attempt and survives the new device's local
   cancellation, crash, reset and retry. Old Adds can finish after retry. *)
DeliverNewConfirm(ref) == /\ ref \in s.sentConfirms \cap s.peerConfirms
                          /\ ref \notin s.acceptedConfirms
                          /\ s' = [s EXCEPT !.acceptedConfirms = @ \cup {ref}]
ConfirmAdd(ref) == /\ ref \in s.acceptedConfirms /\ ref \notin s.confirmedAdds
                   /\ s' = [s EXCEPT !.confirmedAdds = @ \cup {ref}]
ReleaseWelcome(ref) == /\ ref \in s.confirmedAdds /\ ref \notin s.emitted
                       /\ s' = [s EXCEPT !.emitted = @ \cup {ref}]

(* Public traffic from another signer/group may be cryptographically valid.
   Matching-signer traffic for this group must come from an emitted Welcome.
   A rejected Welcome does not consume the reserved KeyPackage or expectation. *)
TryWelcome(ref, group, signer, roster) ==
    /\ Live /\ s.waiting /\ ~s.joined
    /\ (signer # 1 \/ group # 1 \/ ref \in s.emitted)
    /\ IF s.expected /\ ~s.expired
           /\ ref = s.attempt /\ group = 1 /\ signer = 1 /\ roster
       THEN s' = [s EXCEPT !.joined = TRUE, !.expected = FALSE,
                           !.admission = <<ref, group, signer, roster,
                                           s.expected /\ ~s.expired>>]
       ELSE s' = [s EXCEPT !.refusals = @ \cup
                    {IF ref # s.attempt THEN "key" ELSE
                     IF group # 1 THEN "group" ELSE
                     IF signer # 1 THEN "signer" ELSE
                     IF ~roster THEN "roster" ELSE "inactive"}]
RecordJoin == /\ Live /\ s.joined /\ s.waiting /\ ~s.joinRecorded
              /\ s' = [s EXCEPT !.joinRecorded = TRUE]
PromoteTrust == /\ Live /\ s.joined /\ s.waiting /\ s.joinRecorded
                /\ s' = [s EXCEPT !.trusted = TRUE, !.waiting = FALSE]
SelectFirstCommit == /\ Live /\ s.trusted /\ ~s.firstSelected
                     /\ s' = [s EXCEPT !.firstSelected = TRUE]
ObserveMade == /\ s.firstSelected /\ ~s.made
               /\ s' = [s EXCEPT !.made = TRUE]

(* A Cancel after atomic admission cannot roll the joined copy back. *)
Cancel == /\ Live /\ ~s.cancel
          /\ s' = [s EXCEPT !.cancel = TRUE,
               !.phase = IF s.joined THEN @ ELSE "ended"]
Expire == /\ Live /\ ~s.expired /\ ~s.joined
          /\ s' = [s EXCEPT !.expired = TRUE,
               !.phase = IF s.waiting THEN @ ELSE "ended"]
WithdrawExpectation == /\ Live /\ (s.cancel \/ s.expired)
                       /\ s.expected /\ ~s.joined
                       /\ s' = [s EXCEPT !.expected = FALSE]
CleanWaitingRow == /\ Live /\ s.waiting /\ ~s.expected /\ ~s.joined
                  /\ (s.cancel \/ s.expired \/ s.phase = "ended")
                  /\ s' = [s EXCEPT !.waiting = FALSE, !.phase = "ended"]

(* Crash loses the ephemeral exchange, not completed storage transactions.
   Startup sweeps an app row left without an engine expectation. A joined
   copy can be recorded/promoted after restart even if its wait then expires. *)
Crash == /\ Live /\ ~s.crashUsed
         /\ s' = [s EXCEPT !.crashed = TRUE, !.crashUsed = TRUE,
             !.phase = IF s.waiting \/ s.joined THEN @ ELSE "ended"]
Restart == /\ s.crashed
           /\ s' = [s EXCEPT !.crashed = FALSE,
               !.phase = IF s.waiting /\ s.expected THEN "wait"
                         ELSE IF s.joined THEN @ ELSE "ended"]
RequestReset == /\ Live /\ s.trusted /\ ~s.resetRequested
                /\ s' = [s EXCEPT !.resetRequested = TRUE]
Reset == /\ Live /\ s.resetRequested /\ s.trusted
         /\ s' = [s EXCEPT !.trusted = FALSE, !.joined = FALSE,
             !.joinRecorded = FALSE, !.phase = "ended"]
Retry == /\ Live /\ s.phase = "ended" /\ ~s.waiting /\ ~s.joined
         /\ s.attempt = 1
         /\ s' = [s EXCEPT !.attempt = 2, !.phase = "request",
             !.existingTap = FALSE, !.newTap = FALSE,
             !.existingConfirm = FALSE, !.verifiedExisting = FALSE,
             !.newConfirmReady = FALSE, !.newConfirmSent = FALSE,
             !.durableBeforeSend = FALSE,
             !.expected = FALSE, !.expired = FALSE,
             !.firstSelected = FALSE, !.made = FALSE, !.cancel = FALSE,
             !.resetRequested = FALSE, !.admission = <<0, 0, 0, FALSE, FALSE>>]

Next == Answer \/ Reveal \/ CompareExisting \/ CompareNew \/ ConfirmExisting
        \/ DeliverExistingConfirm \/ ConfirmNew \/ RecordAwaiting
        \/ RecordExpectation \/ PublishNewConfirm
        \/ (\E ref \in 1..2:
                DeliverNewConfirm(ref) \/ ConfirmAdd(ref) \/ ReleaseWelcome(ref))
        \/ (\E ref \in 1..2, group \in 1..2, signer \in 1..2, roster \in BOOLEAN:
                TryWelcome(ref, group, signer, roster))
        \/ RecordJoin \/ PromoteTrust \/ SelectFirstCommit \/ ObserveMade
        \/ Cancel \/ Expire \/ WithdrawExpectation \/ CleanWaitingRow
        \/ Crash \/ Restart \/ RequestReset \/ Reset \/ Retry

Fairness == /\ SF_vars(Restart)
            /\ SF_vars(Expire)
            /\ SF_vars(WithdrawExpectation)
            /\ SF_vars(CleanWaitingRow)
            /\ SF_vars(RecordJoin)
            /\ SF_vars(PromoteTrust)
Spec == Init /\ [][Next]_vars /\ (IF FairRun THEN Fairness ELSE TRUE)

TypeOK == /\ s.attempt \in 1..2 /\ s.phase \in Phases
          /\ s.emitted \subseteq s.confirmedAdds
          /\ s.confirmedAdds \subseteq s.acceptedConfirms
          /\ s.acceptedConfirms \subseteq s.sentConfirms
          /\ s.sentConfirms \subseteq s.peerConfirms
          /\ s.peerConfirms \subseteq 1..2
          /\ s.refusals \subseteq {"key", "group", "signer", "roster", "inactive"}
          /\ s.admission \in {<<r, g, k, b, live>>:
                    r \in 0..2, g \in 0..2, k \in 0..2,
                    b \in BOOLEAN, live \in BOOLEAN}
OrderedConfirm == s.newConfirmReady => s.verifiedExisting /\ s.existingConfirm
DurableBeforeNewConfirm == s.newConfirmSent => s.newConfirmReady /\ s.durableBeforeSend
WelcomeBound == s.joined =>
    <<s.admission[1], s.admission[2], s.admission[3], s.admission[4]>>
        = <<s.attempt, 1, 1, TRUE>>
TrustRequiresJoined == s.trusted => s.joined /\ s.joinRecorded
ExpectationConsumed == s.joined => ~s.expected
MadeRequiresFirstCommit == s.made => s.firstSelected
(* History monitor records the pre-admission expectation/deadline. It is not
   an extra implementation field. Cancellation linearizes at withdrawal,
   not at the user's first tap; atomic admission consumes the expectation. *)
AdmissionRequiresLiveExpectation == s.joined => s.admission[5]
WaitingEventuallyResolved == s.waiting ~> (~s.waiting \/ s.trusted)

(* These are expected-failure reachability probes, not safety guarantees. *)
NoSuccessfulJoin == ~s.trusted
NoFreshSameGroupJoin == ~(s.trusted /\ s.attempt = 2 /\ 1 \in s.emitted)
NoPartialRecordCrash == ~(s.crashed /\ s.waiting /\ ~s.expected /\ ~s.joined)
NoLateOldPeerWork == ~(s.attempt = 2 /\ 1 \in s.sentConfirms /\ 1 \notin s.emitted)
=============================================================================
