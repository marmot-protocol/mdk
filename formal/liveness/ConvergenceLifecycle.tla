------------------------ MODULE ConvergenceLifecycle ------------------------
EXTENDS Naturals, TLC

CONSTANT FairRun

VARIABLES historyA, historyB, inputOpen, phase, frozenRevision, stagedRevision,
          crashed, resourceAvailable, adminPending, adminApplied,
          joiner, selfUpdates, crashOccurred, resourceFailureOccurred

vars == <<historyA, historyB, inputOpen, phase, frozenRevision, stagedRevision,
          crashed, resourceAvailable, adminPending, adminApplied,
          joiner, selfUpdates, crashOccurred, resourceFailureOccurred>>

Init ==
    /\ historyA = 1
    /\ historyB = 0
    /\ inputOpen = TRUE
    /\ phase = "collecting"
    /\ frozenRevision = 0
    /\ stagedRevision = 0
    /\ crashed = FALSE
    /\ resourceAvailable = TRUE
    /\ adminPending = TRUE
    /\ adminApplied = FALSE
    /\ joiner = "none"
    /\ selfUpdates = 0
    /\ crashOccurred = FALSE
    /\ resourceFailureOccurred = FALSE

DeliverHistory ==
    /\ ~crashed /\ resourceAvailable /\ historyA # historyB
    /\ historyB' = historyA
    /\ UNCHANGED <<historyA, inputOpen, phase, frozenRevision, stagedRevision, crashed,
                    resourceAvailable, adminPending, adminApplied, joiner,
                    selfUpdates, crashOccurred, resourceFailureOccurred>>

CloseInput ==
    /\ inputOpen
    /\ inputOpen' = FALSE
    /\ UNCHANGED <<historyA, historyB, phase, frozenRevision, stagedRevision, crashed,
                    resourceAvailable, adminPending, adminApplied, joiner,
                    selfUpdates, crashOccurred, resourceFailureOccurred>>

SelfUpdate ==
    /\ inputOpen /\ ~crashed /\ resourceAvailable /\ selfUpdates < 3
    /\ historyA' = historyA + 1
    /\ selfUpdates' = selfUpdates + 1
    /\ phase' = "collecting"
    /\ frozenRevision' = 0
    /\ stagedRevision' = 0
    /\ UNCHANGED <<historyB, inputOpen, crashed, resourceAvailable,
                    adminPending, adminApplied, joiner, crashOccurred,
                    resourceFailureOccurred>>

FreezePass ==
    /\ ~inputOpen /\ ~crashed /\ resourceAvailable
    /\ historyA = historyB /\ phase = "collecting"
    /\ phase' = "frozen"
    /\ frozenRevision' = historyA
    /\ stagedRevision' = historyA
    /\ UNCHANGED <<historyA, historyB, inputOpen, crashed,
                    resourceAvailable, adminPending, adminApplied, joiner,
                    selfUpdates, crashOccurred, resourceFailureOccurred>>

SettlePass ==
    /\ ~crashed /\ resourceAvailable /\ phase = "frozen"
    /\ frozenRevision = historyA /\ stagedRevision = frozenRevision
    /\ historyA = historyB
    /\ phase' = "settled"
    /\ adminApplied' = (adminApplied \/ adminPending)
    /\ adminPending' = FALSE
    /\ joiner' = IF joiner = "pending_losing" THEN "stranded" ELSE joiner
    /\ UNCHANGED <<historyA, historyB, inputOpen, frozenRevision, stagedRevision, crashed,
                    resourceAvailable, selfUpdates, crashOccurred,
                    resourceFailureOccurred>>

Crash ==
    /\ ~crashed /\ ~crashOccurred
    /\ crashed' = TRUE
    /\ crashOccurred' = TRUE
    /\ stagedRevision' = 0
    /\ UNCHANGED <<historyA, historyB, inputOpen, phase, frozenRevision,
                    resourceAvailable, adminPending, adminApplied, joiner,
                    selfUpdates, resourceFailureOccurred>>

Restart ==
    /\ crashed
    /\ crashed' = FALSE
    /\ stagedRevision' = IF phase = "frozen" THEN frozenRevision ELSE stagedRevision
    /\ UNCHANGED <<historyA, historyB, inputOpen, phase, frozenRevision,
                    resourceAvailable, adminPending, adminApplied, joiner,
                    selfUpdates, crashOccurred, resourceFailureOccurred>>

FailResource ==
    /\ resourceAvailable /\ ~resourceFailureOccurred
    /\ resourceAvailable' = FALSE
    /\ resourceFailureOccurred' = TRUE
    /\ UNCHANGED <<historyA, historyB, inputOpen, phase, frozenRevision, stagedRevision,
                    crashed, adminPending, adminApplied, joiner, selfUpdates,
                    crashOccurred>>

RecoverResource ==
    /\ ~resourceAvailable
    /\ resourceAvailable' = TRUE
    /\ UNCHANGED <<historyA, historyB, inputOpen, phase, frozenRevision, stagedRevision,
                    crashed, adminPending, adminApplied, joiner, selfUpdates,
                    crashOccurred, resourceFailureOccurred>>

InviteLosingJoiner ==
    /\ joiner = "none" /\ phase # "settled"
    /\ joiner' = "pending_losing"
    /\ UNCHANGED <<historyA, historyB, inputOpen, phase, frozenRevision, stagedRevision,
                    crashed, resourceAvailable, adminPending, adminApplied,
                    selfUpdates, crashOccurred, resourceFailureOccurred>>

RepairJoiner ==
    /\ joiner = "stranded"
    /\ joiner' = "rejoined_fresh"
    /\ UNCHANGED <<historyA, historyB, inputOpen, phase, frozenRevision, stagedRevision,
                    crashed, resourceAvailable, adminPending, adminApplied,
                    selfUpdates, crashOccurred, resourceFailureOccurred>>

Next == DeliverHistory \/ CloseInput \/ SelfUpdate \/ FreezePass \/ SettlePass
        \/ Crash \/ Restart \/ FailResource \/ RecoverResource
        \/ InviteLosingJoiner \/ RepairJoiner

Fairness ==
    /\ SF_vars(CloseInput)
    /\ SF_vars(DeliverHistory)
    /\ SF_vars(Restart)
    /\ SF_vars(RecoverResource)
    /\ SF_vars(FreezePass)
    /\ SF_vars(SettlePass)
    /\ SF_vars(RepairJoiner)

Spec == Init /\ [][Next]_vars /\ (FairRun => Fairness)

TypeOK ==
    /\ historyA \in Nat /\ historyB \in Nat
    /\ inputOpen \in BOOLEAN
    /\ phase \in {"collecting", "frozen", "settled"}
    /\ frozenRevision \in Nat /\ stagedRevision \in Nat
    /\ crashed \in BOOLEAN /\ resourceAvailable \in BOOLEAN
    /\ adminPending \in BOOLEAN /\ adminApplied \in BOOLEAN
    /\ joiner \in {"none", "pending_losing", "stranded", "rejoined_fresh"}
    /\ selfUpdates \in Nat
    /\ crashOccurred \in BOOLEAN /\ resourceFailureOccurred \in BOOLEAN

FrozenRevisionPartitioned ==
    phase = "frozen" =>
        /\ frozenRevision > 0
        /\ (crashed => stagedRevision = 0)
        /\ (~crashed => stagedRevision = frozenRevision)
FrozenCrashRecovers ==
    (phase = "frozen" /\ crashed /\ frozenRevision > 0 /\ stagedRevision = 0)
        ~> (~crashed /\ phase = "frozen" /\ stagedRevision = frozenRevision)
SettledHistoriesEqual == phase = "settled" => historyA = historyB
InputClosureLeadsToSettlement == ~inputOpen ~> phase = "settled"
AdminEventuallyApplies == adminPending ~> adminApplied
StrandedJoinerCanRepair == joiner = "stranded" ~> joiner = "rejoined_fresh"
=============================================================================
