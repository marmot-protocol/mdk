# Recovery admission and interruption qualification

Status: focused test evidence on the default-off bounded exact-ID worker path,
2026-09-24. This note qualifies only the returned-result admission and
completion fences of [#1947](https://github.com/marmot-protocol/mdk/issues/1947)
and [#1948](https://github.com/marmot-protocol/mdk/issues/1948). It does not
activate bounded recovery in production or close P5.

The new cases live in
`crates/marmot-app/src/runtime/account_worker/tests/real_sdk_bounded_tests/admission_interruption_tests.rs`.
They hold `BOUNDED_WORKER_FIXTURE_LOCK` through worker shutdown because bounded
acquisition credits are process global.

| Case | Evidence | Limit |
| --- | --- | --- |
| Receipt release during a returned batch | A controlled transport result is owned by the real worker while admission is paused. SQLCipher `release_message_for_replay` removes an unrelated seeded retained row, invalidates inventory, and journals receipt release. The worker rejects the result under its stale inventory fence; the known-event demand remains. | The released row is synthetic, and this case does not prove eventual redelivery of that row or a resource-refusal path. The transport result is controlled rather than produced by a real SDK. |
| Receipt release with a real SDK result | [The two-relay qualification](recovery-interruption-redelivery-qualification.md) binds an actual returned event to the account, attempt, and requested ID before admission. Releasing a distinct seeded receipt advances inventory; the worker leaves target retention, the known-event demand, and the persisted cursor unchanged. The installed scope has no retained-known-event or admission-complete checkpoint. | The released receipt is synthetic. Nonexhaustive endpoint evidence may still be recorded under the compatible installed scope. The case stops after rejection and does not prove a second bounded reacquisition or SDK ordinary seen-state. |
| Replaced attempt after a returned batch | A fault-injected durable reservation and replacement scope plan retire the old scope token while the worker owns its valid result. The worker can retain valid ciphertext under the unchanged route/inventory fence, but the old token cannot clear the known-event demand at completion. | Reservation and replacement are injected through storage outside normal owner serialization; this proves the conditional fence, not a production scheduling interleaving. A reservation without scope replacement intentionally permits compatible late evidence. |

Existing adjacent tests cover other seams:
`bounded_stale_loss_and_route_results_cannot_clear_known_demand` changes the
route revision before admission and confirms that stale bytes cannot be retained
or clear demand; the route fence is checked at admission, so changing it after
the result returns reaches the same code path.
`bounded_shutdown_after_durable_prefix_preserves_pending_demand_on_reopen`
uses a controlled duplicate exact-ID result and a test pause after first
admission. `bounded_real_sdk_cancel_reopen_reacquires_unretained_exact_id` uses
the real SDK, cancels an outstanding exact request, and checks durable demand
and fresh retry across SQLCipher reopen; it has no prior admitted event.
Storage-level release, inventory-revision, route, loss, and scope-token tests
validate their transactions independently. These results do not claim
same-request durable-prefix or process-kill durability.

## Acquisition and ordinary delivery overlap

At the prior rust-nostr revision `0efbb4ee`, an acquisition
REQ's validated first-seen EVENT also emits a global
`ClientNotification::Event`. MDK's
`NostrSdkRelayClient::spawn_notification_forwarder` forwards that notification
to `NostrTransportAdapter::handle_relay_event`, which routes by event envelope
and endpoint, not by acquisition subscription identity. Consequently ordinary
account delivery may retain a valid event before the bounded acquisition
result or EOSE. A controlled attempt observed that ordering while the bounded
result was still pending; relay transmission alone was not used as proof of
SDK acceptance. The SDK/adapter boundary and its accounting are being
qualified separately. The merged [fork correction](https://github.com/erskingardner/rust-nostr/pull/2)
is now pinned at `63384e485d55097cb3d9e57a2146f453a5742570` in MDK. The
new real-SDK receipt-release case observes request-local result content; it
does not attribute ordinary retention to bounded result admission.

## Remaining acceptance work

- One bounded attempt with a nonempty durable prefix and a distinct unretained
  eligible suffix; current production selection requests one known ID per
  attempt.
- Released and resource-refused event redelivery through real relay/worker
  paths. Same-live-SDK ordinary-seen redelivery is qualified separately in
  [the focused fixture](recovery-ordinary-seen-redelivery-qualification.md).
- In-flight receipt-release and inventory revisions for a real retained
  transport row, and session-generation changes around valid partial progress
  and completion.
- Abrupt process-kill recovery, device measurements, broad P5 workload and
  migration/rollback campaigns under their separate acceptance gates.

EOSE, socket delivery, and SDK cache state do not establish durable account
admission. Retention does not establish successful MLS projection or engine
readiness. The production activation switch remains off.
