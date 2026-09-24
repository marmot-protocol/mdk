# Recovery admission and interruption qualification

Status: focused test evidence on the default-off bounded exact-ID worker path,
2026-09-24. This note qualifies only the admission/interruption slice of
[#1947](https://github.com/marmot-protocol/mdk/issues/1947) and
[#1948](https://github.com/marmot-protocol/mdk/issues/1948). It does not activate
bounded recovery in production or close P5.

The new cases live in
`crates/marmot-app/src/runtime/account_worker/tests/real_sdk_bounded_tests/admission_interruption_tests.rs`.
They hold `BOUNDED_WORKER_FIXTURE_LOCK` for each worker lifetime, including
shutdown, because bounded acquisition credits are process global.

| Case | Evidence | Limit |
| --- | --- | --- |
| Prior valid progress, interrupted exact request, reopen | A real local NIP-77 relay, rust-nostr SDK, account worker, and SQLCipher store retain a valid encrypted Bob message while Alice's account recovers. A second exact request is held at the relay; its demand and absent bytes survive deadline-relative `shutdown_and_close` and account-store reopen. After conforming comparison and publication, a new exact request retains the second transport event and clears its demand. | The first message may be admitted by startup comparison rather than the bounded exact-ID attempt. The second is transport-shaped, not valid MLS; it is unpublished during cancellation. This is not a same-request durable-prefix or SDK-seen-unretained proof. Reopen uses a fresh SDK client. |
| Receipt release during a returned batch | A controlled transport result is owned by the real worker while admission is paused. SQLCipher `release_message_for_replay` removes an unrelated seeded retained row, invalidates inventory, and journals receipt release. The worker rejects the result under its stale inventory fence; the known-event demand remains. | The released row is synthetic, and this case does not prove eventual redelivery of that row or a resource-refusal path. The transport result is controlled rather than produced by a real SDK. |
| Route revision after a returned batch | The worker owns a valid controlled result when the durable route revision changes. Subsequent admission and completion cannot retain the old-route event or clear its known-event demand. | This is the returned-result seam; session lifetime changes and valid progress on unaffected endpoints require separate evidence. |
| Replaced attempt after a returned batch | A fault-injected durable reservation and replacement scope plan retire the old scope token while the worker owns its valid result. The worker can retain valid ciphertext under the unchanged route/inventory fence, but the old token cannot clear the known-event demand at completion. | Reservation and replacement are injected through storage outside normal owner serialization; this proves the conditional fence, not a production scheduling interleaving. A reservation without scope replacement intentionally permits compatible late evidence. |

Existing adjacent evidence is narrower in different ways:
`bounded_shutdown_after_durable_prefix_preserves_pending_demand_on_reopen`
uses a controlled duplicate exact-ID result and a test pause after its first
admission; `bounded_real_sdk_cancel_reopen_reacquires_unretained_exact_id`
uses the real SDK but has no prior admitted event. Storage-level release,
inventory-revision, route, loss, and scope-token tests validate their
transactions independently. The new cases compose selected seams without
claiming process-kill durability or all endpoint/history coverage.

## Acquisition and ordinary delivery overlap

In the pinned rust-nostr fork, an acquisition REQ's validated first-seen EVENT
also emits a global `ClientNotification::Event`. MDK's
`NostrSdkRelayClient::spawn_notification_forwarder` forwards that notification
to `NostrTransportAdapter::handle_relay_event`, which routes by event envelope
and endpoint, not by acquisition subscription identity. Consequently ordinary
account delivery may retain a valid event before the bounded acquisition
result or EOSE. A controlled attempt observed exactly this ordering while
the bounded result was still pending; relay transmission alone was not used
as proof of SDK acceptance. The SDK/adapter boundary and its accounting are
being qualified separately. The tests here preserve ordinary delivery and do
not suppress it to manufacture an unretained suffix.

## Remaining acceptance work

- One bounded attempt with a nonempty durable prefix and a distinct unretained
  eligible suffix; current production selection requests one known ID per
  attempt.
- SDK-seen but unretained event redelivery with the same live SDK cache, plus
  released and resource-refused event redelivery through real relay/worker
  paths.
- In-flight receipt-release and inventory revisions for a real retained
  transport row, and session-generation changes around valid partial progress
  and completion.
- Abrupt process-kill recovery, device measurements, broad P5 workload and
  migration/rollback campaigns under their separate acceptance gates.

EOSE, socket delivery, and SDK cache state do not establish durable account
admission. Retention does not establish successful MLS projection or engine
readiness. The production activation switch remains off.
