------------------------ MODULE ConvergenceLifecycle ------------------------
EXTENDS Naturals, TLC

CONSTANT FairRun

VARIABLES historyA, historyB, inputOpen, phase, frozenRevision,
          crashed, resourceAvailable, adminPending, adminApplied,
          joiner, selfUpdates, crashOccurred, resourceFailureOccurred

vars == <<historyA, historyB, inputOpen, phase, frozenRevision,
          crashed, resourceAvailable, adminPending, adminApplied,
          joiner, selfUpdates, crashOccurred, resourceFailureOccurred>>

Init ==
    /\ historyA = 1
    /\ historyB = 0
    /\ inputOpen = TRUE
    /\ phase = "collecting"
    /\ frozenRevision = 0
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
    /\ UNCHANGED <<historyA, inputOpen, phase, frozenRevision, crashed,
                    resourceAvailable, adminPending, adminApplied, joiner,
                    selfUpdates, crashOccurred, resourceFailureOccurred>>

CloseInput ==
    /\ inputOpen
    /\ inputOpen' = FALSE
    /\ UNCHANGED <<historyA, historyB, phase, frozenRevision, crashed,
                    resourceAvailable, adminPending, adminApplied, joiner,
                    selfUpdates, crashOccurred, resourceFailureOccurred>>

SelfUpdate ==
    /\ inputOpen /\ ~crashed /\ resourceAvailable /\ selfUpdates < 3
    /\ historyA' = historyA + 1
    /\ selfUpdates' = selfUpdates + 1
    /\ phase' = "collecting"
    /\ frozenRevision' = 0
    /\ UNCHANGED <<historyB, inputOpen, crashed, resourceAvailable,
                    adminPending, adminApplied, joiner, crashOccurred,
                    resourceFailureOccurred>>

FreezePass ==
    /\ ~inputOpen /\ ~crashed /\ resourceAvailable
    /\ historyA = historyB /\ phase = "collecting"
    /\ phase' = "frozen"
    /\ frozenRevision' = historyA
    /\ UNCHANGED <<historyA, historyB, inputOpen, crashed,
                    resourceAvailable, adminPending, adminApplied, joiner,
                    selfUpdates, crashOccurred, resourceFailureOccurred>>

SettlePass ==
    /\ ~crashed /\ resourceAvailable /\ phase = "frozen"
    /\ frozenRevision = historyA /\ historyA = historyB
    /\ phase' = "settled"
    /\ adminApplied' = adminPending
    /\ adminPending' = FALSE
    /\ joiner' = IF joiner = "pending_losing" THEN "stranded" ELSE joiner
    /\ UNCHANGED <<historyA, historyB, inputOpen, frozenRevision, crashed,
                    resourceAvailable, selfUpdates, crashOccurred,
                    resourceFailureOccurred>>

Crash ==
    /\ ~crashed /\ ~crashOccurred
    /\ crashed' = TRUE
    /\ crashOccurred' = TRUE
    /\ UNCHANGED <<historyA, historyB, inputOpen, phase, frozenRevision,
                    resourceAvailable, adminPending, adminApplied, joiner,
                    selfUpdates, resourceFailureOccurred>>

Restart ==
    /\ crashed
    /\ crashed' = FALSE
    /\ UNCHANGED <<historyA, historyB, inputOpen, phase, frozenRevision,
                    resourceAvailable, adminPending, adminApplied, joiner,
                    selfUpdates, crashOccurred, resourceFailureOccurred>>

FailResource ==
    /\ resourceAvailable /\ ~resourceFailureOccurred
    /\ resourceAvailable' = FALSE
    /\ resourceFailureOccurred' = TRUE
    /\ UNCHANGED <<historyA, historyB, inputOpen, phase, frozenRevision,
                    crashed, adminPending, adminApplied, joiner, selfUpdates,
                    crashOccurred>>

RecoverResource ==
    /\ ~resourceAvailable
    /\ resourceAvailable' = TRUE
    /\ UNCHANGED <<historyA, historyB, inputOpen, phase, frozenRevision,
                    crashed, adminPending, adminApplied, joiner, selfUpdates,
                    crashOccurred, resourceFailureOccurred>>

InviteLosingJoiner ==
    /\ joiner = "none" /\ phase # "settled"
    /\ joiner' = "pending_losing"
    /\ UNCHANGED <<historyA, historyB, inputOpen, phase, frozenRevision,
                    crashed, resourceAvailable, adminPending, adminApplied,
                    selfUpdates, crashOccurred, resourceFailureOccurred>>

RepairJoiner ==
    /\ joiner = "stranded"
    /\ joiner' = "rejoined_fresh"
    /\ UNCHANGED <<historyA, historyB, inputOpen, phase, frozenRevision,
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
    /\ frozenRevision \in Nat
    /\ crashed \in BOOLEAN /\ resourceAvailable \in BOOLEAN
    /\ adminPending \in BOOLEAN /\ adminApplied \in BOOLEAN
    /\ joiner \in {"none", "pending_losing", "stranded", "rejoined_fresh"}
    /\ selfUpdates \in Nat
    /\ crashOccurred \in BOOLEAN /\ resourceFailureOccurred \in BOOLEAN

FrozenRevisionDurable == phase = "frozen" => frozenRevision > 0
SettledHistoriesEqual == phase = "settled" => historyA = historyB
InputClosureLeadsToSettlement == ~inputOpen ~> phase = "settled"
AdminEventuallyApplies == adminPending ~> adminApplied
StrandedJoinerCanRepair == joiner = "stranded" ~> joiner = "rejoined_fresh"
=============================================================================
