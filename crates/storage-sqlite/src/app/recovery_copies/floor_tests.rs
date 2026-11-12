//! The rejoin floor holds by construction (mdk#2660 row 11): on a route a
//! rejoin settled, with relays or without, no ledger writer makes what lay
//! before the new copy owed or parked again, unless it names loss or explicit
//! repair as its reason or gives back one second the device held. A route no
//! rejoin settled owes as it always did.

use super::*;
use crate::{
    CopyFloorReason, RecoveryCause, RecoveryCoverageProof, RecoveryLossCause, RecoveryStagedSlice,
    RecoveryUnitOutcome, RecoveryUnitPolicy, SqliteAccountStorage, StoredEpochBackfillIntent,
    TransportReconciliationItem,
};
use cgka_traits::transport::{TransportEnvelope, TransportMessage, TransportSource};
use cgka_traits::{
    MemberId, MessageId, TransportDelivery, TransportDeliveryPlane, TransportDeliverySource,
};

const RELAY: &str = "wss://a.example";
const OTHER: &str = "wss://b.example";
const GROUP: &[u8] = &[7; 16];
/// What [`Rejoined::owed`] calls a route's parked remainder.
const REMAINDER: &str = "remainder";

const POLICY: RecoveryUnitPolicy = RecoveryUnitPolicy {
    backoff_base_seconds: 30,
    backoff_cap_seconds: 3_600,
    break_after_no_progress: 2,
    unreachable_retry_seconds: 30,
    cooldown_after_unreachable: 3,
    cooldown_base_seconds: 60,
    cooldown_cap_seconds: 3_600,
    max_attempts_per_hour: 720,
    max_event_bytes_per_hour: 256 << 20,
    recheck_after_cooldown_seconds: 3_600,
};

/// A group a rejoin settled, in wall-clock time so that the release and
/// give-back paths treat its seconds as retained. `route` is carried by
/// `RELAY` and `OTHER`; `bare` by no relay at all (all of its relays were
/// refused). In [`Rejoined::new`], both routes' goal lies below the floor;
/// before the rejoin, `RELAY` dismissed what it owed and then lost what lay
/// after `now - 4_500`, so below the floor it holds a dismissal and the
/// rejoin's retirement, and `OTHER` holds the rejoin's retirement alone. In
/// [`Rejoined::young`], both goals start at the floor and nothing lies below
/// it.
struct Rejoined {
    storage: SqliteAccountStorage,
    app: SqliteAppStorage,
    route: TransportReconciliationRoute,
    bare: TransportReconciliationRoute,
    goal: u64,
    floor: u64,
    now: u64,
}

/// How the device gives back a second it held.
#[derive(Clone, Copy, Debug)]
enum GiveBack {
    /// A released receipt (`cross/release.rs`).
    Released,
    /// A staged event that no longer decodes.
    Undecodable,
    /// A staged event whose route the runner reclaimed.
    Reclaimed,
}

impl Rejoined {
    fn new() -> Self {
        Self::settled(false)
    }

    fn young() -> Self {
        Self::settled(true)
    }

    fn settled(young: bool) -> Self {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        let now = i64_to_u64(crate::base::codec::unix_now_seconds_i64()).unwrap();
        let (route, bare) = (
            TransportReconciliationRoute::Group([1; 32]),
            TransportReconciliationRoute::Group([3; 32]),
        );
        let floor = now - 3_000;
        let goal = if young { floor } else { now - 6_000 };
        app.lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_groups (id, epoch, record) VALUES (?1, 1, x'00')",
                [GROUP],
            )
            .unwrap();
        app.widen_recovery_coverage_goals(
            &[route.clone(), bare.clone()],
            goal,
            CopyFloorReason::Clamp,
        )
        .unwrap();
        if !young {
            let parked = park(&app, &route, now);
            assert!(app.dismiss_recovery_route_park(&route, parked).unwrap());
            app.uncover_recovery_coverage(
                std::slice::from_ref(&route),
                now - 4_500,
                CopyFloorReason::Loss,
            )
            .unwrap();
        }
        assert!(
            app.settle_recovery_rejoin(&RecoveryRejoin {
                group_id: GROUP,
                install_epoch: 5,
                routes: &[
                    (route.clone(), vec![RELAY.to_owned(), OTHER.to_owned()]),
                    (bare.clone(), Vec::new()),
                ],
                floor_seconds: floor,
                now_seconds: now,
            })
            .unwrap()
        );
        let rejoined = Self {
            storage,
            app,
            route,
            bare,
            goal,
            floor,
            now,
        };
        assert_eq!(rejoined.owed(), []);
        rejoined
    }

    fn routes(&self) -> &[TransportReconciliationRoute] {
        std::slice::from_ref(&self.route)
    }

    /// What the group owes or parked below the floor: on `route`, each
    /// relay's debt and what it parked, which a probe sweeps; on both routes,
    /// a parked remainder, which a notice shows.
    fn owed(&self) -> Vec<(&'static str, (u64, u64))> {
        let mut owed = self.owed_below(&self.route, &[RELAY, OTHER]);
        owed.extend(self.owed_below(&self.bare, &[]));
        owed
    }

    /// What `route`'s `relays` owe or parked below the floor, and its parked
    /// remainder there.
    fn owed_below(
        &self,
        route: &TransportReconciliationRoute,
        relays: &[&'static str],
    ) -> Vec<(&'static str, (u64, u64))> {
        let below = |ranges: Vec<RecoveryCoverageRange>| {
            union(ranges)
                .into_iter()
                .filter(|range| range.since_seconds < self.floor)
                .map(|range| (range.since_seconds, range.until_seconds.min(self.floor - 1)))
                .collect::<Vec<_>>()
        };
        let mut owed = Vec::new();
        for &relay in relays {
            let mut ranges = self.app.recovery_unit_debt(route, relay, self.now).unwrap();
            ranges.extend(
                self.app
                    .recovery_unit_spans(route, relay)
                    .unwrap()
                    .into_iter()
                    .filter(|span| span.retired.is_none())
                    .map(|span| span.range),
            );
            owed.extend(below(ranges).into_iter().map(|range| (relay, range)));
        }
        let remainders = self
            .app
            .recovery_coverage_remainders()
            .unwrap()
            .into_iter()
            .filter(|remainder| remainder.route == *route)
            .map(|remainder| remainder.range)
            .collect();
        owed.extend(
            below(remainders)
                .into_iter()
                .map(|range| (REMAINDER, range)),
        );
        owed
    }

    /// Begin an epoch-gap visit to the group from `since`, as sync's stall
    /// arm and the runner both do.
    fn visit(&self, since: u64) {
        let ticket = self
            .app
            .pending_recovery_demands()
            .unwrap()
            .into_iter()
            .find(|demand| demand.cause == RecoveryCause::EpochGap)
            .expect("an armed epoch gap")
            .ticket;
        assert!(
            self.app
                .begin_recovery_epoch_gap_retry(ticket, &[(self.route.clone(), since)], self.now)
                .unwrap()
        );
    }

    /// Give back the event the device held on `route` at `second`.
    fn give_back(&self, route: &TransportReconciliationRoute, how: GiveBack, second: u64) {
        match how {
            GiveBack::Released => {
                let released = TransportReconciliationItem {
                    event_id: [9; 32],
                    created_at: second,
                };
                self.app
                    .record_reconciliation_items(std::iter::once((route, &released)))
                    .unwrap();
                self.storage
                    .connection
                    .with_transaction(|| {
                        let conn = self.storage.lock()?;
                        crate::cross::release::retire_transport_receipts(
                            &conn,
                            &MessageId::new(released.event_id.to_vec()),
                        )
                    })
                    .unwrap();
            }
            GiveBack::Undecodable => {
                self.stage(route, 3, second);
                assert!(
                    self.app
                        .discard_undecodable_staged_recovery_event(&[3; 32])
                        .unwrap()
                );
            }
            GiveBack::Reclaimed => {
                self.stage(route, 3, second);
                assert_eq!(
                    self.app
                        .reclaim_staged_recovery_routes(std::slice::from_ref(route))
                        .unwrap(),
                    1
                );
            }
        }
    }

    /// Stage one event sent at `second` on `route` from `RELAY`, as a sweep
    /// below the floor (the re-check) finds it.
    fn stage(&self, route: &TransportReconciliationRoute, id: u8, second: u64) {
        let delivery = TransportDelivery {
            account_id: MemberId::new(vec![0xAA; 32]),
            group_id_hint: None,
            message: TransportMessage {
                id: MessageId::new(vec![id; 32]),
                payload: vec![id; 64],
                timestamp: cgka_traits::transport::Timestamp(second),
                causal_deps: Vec::new(),
                source: TransportSource("nostr".to_owned()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: vec![1; 32],
                },
            },
            received_at: cgka_traits::transport::Timestamp(self.now),
            source: TransportDeliverySource {
                transport: TransportSource("nostr".to_owned()),
                plane: TransportDeliveryPlane::Group,
                endpoint: None,
                subscription_id: Some("recovery".to_owned()),
                wire: None,
            },
        };
        let staged = self
            .app
            .stage_recovery_slice(
                &RecoveryStagedSlice {
                    route,
                    relay: RELAY,
                    events: &[delivery],
                    fetched_bytes: 1_000,
                    covered: &[RecoveryCoverageRange {
                        since_seconds: second,
                        until_seconds: second,
                    }],
                    proof: RecoveryCoverageProof::SweepSlice,
                    mark: self.app.recovery_coverage_mark().unwrap(),
                },
                self.now,
            )
            .unwrap();
        assert_eq!(staged.staged, 1);
    }
}

/// Break `route`'s unit on `RELAY`, which parks what it owes.
fn park(app: &SqliteAppStorage, route: &TransportReconciliationRoute, now: u64) -> u64 {
    let mut revision = None;
    for _ in 0..POLICY.break_after_no_progress {
        app.begin_recovery_unit_attempt(route, RELAY, None, now)
            .unwrap();
        revision = app
            .settle_recovery_unit(route, RELAY, RecoveryUnitOutcome::NoProgress, &POLICY, now)
            .unwrap()
            .park
            .map(|park| park.revision);
    }
    revision.expect("the budget breaks the unit")
}

/// A named ledger write on a rejoined group.
type Writer = (&'static str, fn(&Rejoined));

/// Every public ledger writer that can widen a goal, un-cover coverage,
/// rewrite a retired span or park a remainder, driven on a rejoined group
/// from below its floor, leaves nothing below the floor owed or parked: what
/// the rejoin retired and what was dismissed before it stay as they were, and
/// a route no relay carries parks nothing from before the copy. The same
/// writers on a route no rejoin settled, in the same account, owe from below
/// that floor as before, and a second given back there still owes from it.
#[test]
fn no_writer_reopens_what_lay_before_a_rejoined_copy() {
    let writers: [Writer; 8] = [
        ("a goal widening", |rejoined| {
            rejoined
                .app
                .widen_recovery_coverage_goals(
                    rejoined.routes(),
                    rejoined.goal - 3_000,
                    CopyFloorReason::Clamp,
                )
                .unwrap();
        }),
        ("a post-join un-cover", |rejoined| {
            rejoined
                .app
                .uncover_recovery_coverage(
                    rejoined.routes(),
                    rejoined.goal - 3_000,
                    CopyFloorReason::Clamp,
                )
                .unwrap();
        }),
        ("an epoch-gap visit armed by a stall", |rejoined| {
            rejoined
                .app
                .arm_epoch_backfill_intents(&[StoredEpochBackfillIntent {
                    group_id_hex: hex::encode(GROUP),
                    stalled_epoch: 1,
                }])
                .unwrap();
            rejoined.visit(rejoined.goal - 3_000);
        }),
        (
            "an epoch-gap visit armed by a release that invalidated the inventory",
            |rejoined| {
                let now = i64::try_from(rejoined.now).unwrap();
                rejoined
                    .storage
                    .connection
                    .with_transaction(|| {
                        let conn = rejoined.storage.lock()?;
                        crate::cross::release::invalidate_recovery_inventory(&conn)?;
                        crate::cross::release::arm_released_epoch(&conn, GROUP, 1, now)
                    })
                    .unwrap();
                rejoined.visit(rejoined.goal - 3_000);
            },
        ),
        ("a relay leaving and returning", |rejoined| {
            let relays = [RELAY.to_owned()];
            rejoined
                .app
                .retire_gone_recovery_units(&rejoined.route, Some(&relays), rejoined.now)
                .unwrap();
            rejoined
                .app
                .reopen_returned_recovery_units(|_, _| true)
                .unwrap();
        }),
        ("the route ending and returning", |rejoined| {
            rejoined
                .app
                .retire_gone_recovery_units(&rejoined.route, None, rejoined.now)
                .unwrap();
            rejoined
                .app
                .reopen_returned_recovery_units(|_, _| true)
                .unwrap();
        }),
        ("a unit breaking, re-armed, then dismissed", |rejoined| {
            park(&rejoined.app, &rejoined.route, rejoined.now);
            assert!(
                rejoined
                    .app
                    .rearm_recovery_unit(&rejoined.route, RELAY)
                    .unwrap()
            );
            let parked = park(&rejoined.app, &rejoined.route, rejoined.now);
            assert!(
                rejoined
                    .app
                    .dismiss_recovery_route_park(&rejoined.route, parked)
                    .unwrap()
            );
        }),
        // Retention overtakes the floor, as it does a month after the rejoin:
        // what each route still owes from the floor up is parked, and nothing
        // from before the copy.
        ("the retention prune overtaking the floor", |rejoined| {
            rejoined
                .app
                .prune_recovery_coverage(
                    rejoined.floor + 100,
                    &[
                        (
                            rejoined.route.clone(),
                            vec![RELAY.to_owned(), OTHER.to_owned()],
                        ),
                        (rejoined.bare.clone(), Vec::new()),
                    ],
                )
                .unwrap();
        }),
    ];
    let reopened = writers
        .into_iter()
        .filter_map(|(writer, write)| {
            let rejoined = Rejoined::new();
            write(&rejoined);
            let owed = rejoined.owed();
            (!owed.is_empty()).then(|| format!("{writer}: {owed:?}"))
        })
        .collect::<Vec<_>>();
    assert_eq!(reopened, Vec::<String>::new());

    let rejoined = Rejoined::new();
    let never = TransportReconciliationRoute::Group([2; 32]);
    let lowest = rejoined.goal - 3_000;
    rejoined
        .app
        .widen_recovery_coverage_goals(
            std::slice::from_ref(&never),
            rejoined.goal,
            CopyFloorReason::Clamp,
        )
        .unwrap();
    for relay in [RELAY, OTHER] {
        rejoined
            .app
            .begin_recovery_unit_attempt(&never, relay, None, rejoined.now)
            .unwrap();
    }
    rejoined
        .app
        .uncover_recovery_coverage(std::slice::from_ref(&never), lowest, CopyFloorReason::Clamp)
        .unwrap();
    let below = (lowest, rejoined.floor - 1);
    assert_eq!(
        rejoined.owed_below(&never, &[RELAY, OTHER]),
        [(RELAY, below), (OTHER, below)],
        "a route no rejoin settled owes from where it was un-covered"
    );
    let second = lowest - 1_000;
    rejoined.give_back(&never, GiveBack::Released, second);
    let below = (second, rejoined.floor - 1);
    assert_eq!(
        rejoined.owed_below(&never, &[RELAY, OTHER]),
        [(RELAY, below), (OTHER, below)],
        "a second given back there owes from it"
    );
}

/// Loss and explicit repair reach below a rejoined copy's floor, each from
/// its own floor: imported loss through the real import, and repair widening
/// to the window and re-arming every span.
#[test]
fn loss_and_repair_reach_before_a_rejoined_copy() {
    let rejoined = Rejoined::new();
    let lowest = rejoined.goal - 3_000;
    rejoined.app.ensure_account_projection("alice").unwrap();
    crate::app::account_recovery::finish_conversion_for_test(&rejoined.app, rejoined.now);
    rejoined
        .app
        .record_account_recovery_loss_routed(
            "alice",
            RecoveryLossCause::Queue,
            41,
            1,
            rejoined.now,
            Some(lowest),
            Some(&[(rejoined.route.clone(), lowest)]),
        )
        .unwrap();
    assert!(
        crate::app::account_recovery::import_loss_for_test(&rejoined.app, rejoined.now).unwrap()
    );
    let below = (lowest, rejoined.floor - 1);
    assert_eq!(rejoined.owed(), [(RELAY, below), (OTHER, below)], "loss");

    // A fresh copy reads the clock again, so its window can start a second
    // later than the first one's.
    let rejoined = Rejoined::new();
    let lowest = rejoined.goal - 3_000;
    let below = (lowest, rejoined.floor - 1);
    rejoined
        .app
        .widen_recovery_coverage_goals(rejoined.routes(), lowest, CopyFloorReason::Repair)
        .unwrap();
    rejoined.app.rearm_all_recovery_units().unwrap();
    assert_eq!(rejoined.owed(), [(RELAY, below), (OTHER, below)], "repair");
}

/// A second the device held and gives back, by a released receipt or a
/// staged event that no longer decodes or whose route was reclaimed, is owed
/// again below a rejoined copy's floor, so a late event or a re-check's
/// finding there is fetched again, and it is the only second owed: where it
/// lies below the route's goal, the seconds between it and the goal (or the
/// floor, when lower) that the widening opens lay outside the goal, so they
/// retire as before the copy, while what loss reopened above them stays owed.
#[test]
fn a_held_second_given_back_before_a_rejoined_copy_owes_only_itself() {
    type Case = (&'static str, fn() -> Rejoined, fn(&Rejoined) -> u64, bool);
    let cases: [Case; 4] = [
        (
            "between the goal and the floor",
            Rejoined::new,
            |rejoined| rejoined.floor - 100,
            false,
        ),
        (
            "below the goal",
            Rejoined::new,
            |rejoined| rejoined.goal - 1_000,
            false,
        ),
        (
            "below a goal at the floor",
            Rejoined::young,
            |rejoined| rejoined.floor - 1_000,
            false,
        ),
        (
            "below the goal, after loss reopened the copy's past",
            Rejoined::new,
            |rejoined| rejoined.goal - 1_000,
            true,
        ),
    ];
    for (case, rejoined, second, lost) in cases {
        for how in [
            GiveBack::Released,
            GiveBack::Undecodable,
            GiveBack::Reclaimed,
        ] {
            let rejoined = rejoined();
            let lost = lost.then(|| {
                rejoined
                    .app
                    .uncover_recovery_coverage(
                        rejoined.routes(),
                        rejoined.floor - 500,
                        CopyFloorReason::Loss,
                    )
                    .unwrap();
                (rejoined.floor - 500, rejoined.floor - 1)
            });
            let second = second(&rejoined);
            rejoined.give_back(&rejoined.route, how, second);
            let expected = [RELAY, OTHER]
                .into_iter()
                .flat_map(|relay| {
                    std::iter::once((relay, (second, second))).chain(lost.map(|lost| (relay, lost)))
                })
                .collect::<Vec<_>>();
            assert_eq!(rejoined.owed(), expected, "{case}, {how:?}");
        }
    }
}

/// The retention prune parks nothing from before a rejoined copy, on a route
/// relays carry or one no relay carries (mdk#2660 row 11). A route keeps one
/// remainder, so a held second given back below the floor must not join what
/// is still owed above it: the remainder would hold the retired history
/// between and raise a history notice beside the rejoin's. What the new copy
/// itself still owes when retention overtakes it parks as before, and a
/// route whose relays proved everything from the floor parks nothing at all.
/// The held second, unfetched when retention passes it, drops without a
/// remainder; so it does on a route no relay carries, where nothing could
/// fetch it.
#[test]
fn the_retention_prune_parks_nothing_from_before_a_rejoined_copy() {
    type Prunes = fn(u64, u64) -> Vec<u64>;
    let schedules: [(&str, Prunes); 2] = [
        ("one prune above the floor", |_, floor| vec![floor + 100]),
        (
            "a prune past the held second, then one above the floor",
            |second, floor| vec![second + 500, floor + 100],
        ),
    ];
    for (schedule, prunes) in schedules {
        for carried in [
            "owing above the floor",
            "proved above the floor",
            "no relay",
        ] {
            let rejoined = Rejoined::young();
            let (route, carriers): (_, &[&'static str]) = if carried == "no relay" {
                (&rejoined.bare, &[])
            } else {
                (&rejoined.route, &[RELAY, OTHER])
            };
            let relays = carriers
                .iter()
                .map(|relay| relay.to_string())
                .collect::<Vec<_>>();
            let proved = carried == "proved above the floor";
            if proved {
                for &relay in carriers {
                    rejoined
                        .app
                        .record_recovery_coverage(
                            &[crate::RecoveryCoverageSlice {
                                route,
                                relay,
                                since_seconds: rejoined.floor,
                                until_seconds: rejoined.now,
                                proof: RecoveryCoverageProof::SweepSlice,
                            }],
                            rejoined.now,
                        )
                        .unwrap();
                }
            }
            let second = rejoined.floor - 1_000;
            rejoined.give_back(route, GiveBack::Released, second);
            let held = carriers
                .iter()
                .map(|&relay| (relay, (second, second)))
                .collect::<Vec<_>>();
            assert_eq!(
                rejoined.owed(),
                held,
                "{schedule}, {carried}: the held second"
            );
            for at in prunes(second, rejoined.floor) {
                rejoined
                    .app
                    .prune_recovery_coverage(at, &[(route.clone(), relays.clone())])
                    .unwrap();
                let remainder = rejoined
                    .app
                    .recovery_coverage_remainders()
                    .unwrap()
                    .into_iter()
                    .filter(|remainder| remainder.route == *route)
                    .map(|remainder| (remainder.range.since_seconds, remainder.range.until_seconds))
                    .collect::<Vec<_>>();
                let expected = if at > rejoined.floor && !proved {
                    vec![(rejoined.floor, at - 1)]
                } else {
                    Vec::new()
                };
                assert_eq!(
                    remainder, expected,
                    "{schedule}, {carried}: the remainder after a prune at {at}"
                );
            }
            assert_eq!(
                rejoined.owed(),
                [],
                "{schedule}, {carried}: the held second drops once retention passes it"
            );
        }
    }
}
