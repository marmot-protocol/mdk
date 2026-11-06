# Device-pairing authentication model

`device_pairing_v1.spthy` describes the symbolic security boundary between
code comparison, the ordered confirmations and a device-group Welcome. It is
separate from the convergence model in [`../tamarin`](../tamarin/): that model
starts with already-validated input. Temporal linking, restart and progress
properties belong to TLA+, not this theory.

The protocol source is Marmot's
[`features/device-pairing.md`](https://github.com/marmot-protocol/marmot/blob/98171929665451d48c1ca1cf6dd9666a38e6ec0e/features/device-pairing.md),
especially "Derivations", "Confirmation order" and the Welcome sender rule.
The model introduces no protocol behavior or wire format.

## Claims and attacker

The attacker reads, changes, delays, replays and injects all network traffic.
This includes the capabilities of an account-key holder: the account's gift
wrapping is deliberately not treated as authentication between devices. The
attacker can choose its own DH exponents and signing keys and can construct
validly signed Welcomes under those keys, including under the confirmed group
id. Honest device-local ephemeral and MLS leaf-signing secrets are not
compromised.

The theory uses one configured account, unbounded fresh honest role instances
and Tamarin's built-in DH, hash and signing theories. HKDF and HMAC are public
uninterpreted function symbols: an attacker may compute them when it knows
their inputs. Multiple honest existing identities may share a device-group
id with distinct leaf-signing keys. Each identity keeps its group, slot and
leaf key across sessions; changing those values, including a Move, is outside
the model. Each role independently derives its SAS term from the shared
secret, session, account, KeyPackageRef, approver slot and both public keys.
`CodeCompare` checks equality of those actual derived terms. It does not
assume equality of the desired confirmed group or Welcome signer; those are
learned later from the authenticated existing-device confirmation.

This is an ideal comparison assumption. The real seven-emoji code has only
42 bits. The theory neither proves the one-in-2^42 guessing bound nor models
truncation collisions, repeated guessing budgets, human comparison mistakes
or a compromised display. It also does not verify X25519, HKDF, HMAC,
constant-time code, MLS cryptography or parsing of bytes.

| Lemma | Contract |
| --- | --- |
| `pairing_successful_link_and_welcome` | A complete honest exchange and Welcome admission are reachable. |
| `pairing_distinct_honest_approvers_share_a_group` | Two distinct honest devices can approve separate links into the same group. |
| `pairing_same_session_mismatched_codes_reachable` | Substituted network keys can produce different codes for the same session. |
| `pairing_other_sender_welcome_then_real_one_reachable` | A valid attacker-signed same-id Welcome can be rejected before the real one joins. |
| `pairing_new_confirmation_follows_existing_confirmation` | A new-device confirmation has a prior matching existing-device confirmation. |
| `pairing_confirmed_group_and_sender_agree` | The existing confirmation verified by the new device agrees on session, account, publication event, KeyPackageRef, approver slot, group and signer. |
| `pairing_existing_link_requires_new_confirmation` | An existing device establishes the matching link only after the new device sends its confirmation. |
| `pairing_welcome_sender_matches_confirmation` | The expected-sender guard holds on accepted Welcomes; the authenticated-link theorem below establishes the origin. |
| `pairing_welcome_requires_authenticated_existing_link` | Accepted Welcome evidence traces back to an established matching existing-device link. |

The state space is not a bounded Rust execution. The symbolic rules permit
unbounded fresh role instances and attacker traffic. A completed all-traces
proof is about those rules under their assumptions, not arbitrary execution of
the Rust runtime. An incomplete or timed-out search establishes no property.

## Implementation correspondence

Correspondence was read at MDK `2e0c9859c3f344b8f746d903fde9307b9a3b892d`.

| Modeled action or fact | Production owner | Existing implementation evidence |
| --- | --- | --- |
| `NewRequest`, `ExistingCheckReveal` | `marmot-pairing/src/sas.rs::commitment`; the two role state machines | `pairing_attack_substituted_reveal_key_fails_the_commitment`, `pairing_attack_swapped_key_package_ref_fails_the_commitment` |
| Independent code derivations and `CodeCompare` | `sas.rs::SharedSecret::code`, `sas_info`; actual user comparison is a host obligation | `pairing_attack_substituted_answer_key_shows_different_codes`, `pairing_attack_swapped_key_package_ref_changes_the_code`, independent `pairing-v1.json` vectors |
| `ExistingConfirm`, `NewVerifyAndConfirm` | `ExistingDevicePairing::confirm_link`; `NewDevicePairing::on_confirm`, `confirm_match`, `confirm_and_link`; `SharedSecret::mac`, `verify_mac` | `pairing_confirmations_go_in_a_fixed_order`, `pairing_attack_wrong_group_id_fails_the_confirmation`, `pairing_swapped_welcome_signer_fails_the_confirmation`, `pairing_attack_replayed_confirmation_from_another_session_fails` |
| `ExistingVerifyNewConfirm` | `ExistingDevicePairing::on_confirm` and `link_tracked` | `pairing_lost_existing_device_confirmation_adds_nothing`, `pairing_lost_new_device_confirmation_adds_nothing_and_drops_the_link` |
| `NewLink`, `AcceptWelcome` | `ConfirmedLink::allows_welcome_for`; engine `group_lifecycle.rs` admission against `DeviceGroupWelcomeExpectation` | `pairing_linked_new_device_accepts_only_the_confirmed_sender`, `the_link_welcome_joins_and_consumes_its_expectation`, `a_welcome_from_another_leaf_is_refused_and_the_real_one_still_joins` |

These named Rust tests execute production pairing or OpenMLS/storage paths.
They are correspondence witnesses, not a mechanically checked refinement
between every Tamarin transition and Rust. The theory does not run Rust.

The pairing crate has no storage or async suspension: a role call is modeled
as one transition. `CodeCompare` combines the two honest user approvals after
comparing independently derived codes; it does not claim to preserve the
timing of the taps relative to message receipt. `NewVerifyAndConfirm` combines
verification and sending, so their action facts share a timepoint. The runtime
must durably record the expected link before publishing that confirmation;
that crash boundary is not modeled here.

`NewLink` is persistent historical evidence of an authenticated link, not a
model of a retained database row. A separate linear `JoinPermit` represents
the one-shot pending admission. Rejected Welcomes do not consume it.
`AcceptWelcome` abstracts a successfully validated MLS Welcome as an
unforgeable signed binding of the group, consumed KeyPackageRef and synthetic
body, and consumes that permit once. This combines GroupInfo signature
validation with Welcome/KeyPackage processing; it does not assert that the
real GroupInfo signature directly covers a KeyPackageRef. That combined MLS
binding is assumed, not proved here. Rust also checks required roster capability,
expiry, other outstanding reservations and transaction rollback. Their
implementation tests retain ownership; this theory does not prove them.

Other exclusions are cancellation, expiry, competing-request refusal, rate
limits, roster admission policy, device-group moves/reset, publication
acknowledgement, removal, persistence and liveness. Omitting the request
limits permits more honest answers; no availability claim follows.

## Checking and sensitivity

Use the installed/pinned Tamarin toolchain used for the existing model; no
additional verifier or dependency is needed. The development compatibility
probe used Tamarin 1.12.0 and Maude 3.5.1.

```sh
just tamarin
```

This runs the existing convergence theory first, then this verifier's timeout
regression and pairing model/control gate. The same checks run in the existing
formal CI job. To select only the pairing theory and controls, run
`python3 formal/pairing/verify_pairing.py --out target/formal-pairing`.

The gate runs the whole theory, requires a verified result for every declared
lemma, then requires the named falsification for each control below. It keeps
the original source untouched and writes synthetic mutant theories, prover
logs, command/timing/hash receipts and a report in a fresh timestamped output
directory. Compact named outcomes and hashes are also printed in the job log;
formal CI uploads the complete synthetic evidence even when a check fails.
A timeout, tool error, missing summary, omitted lemma, incomplete
proof or unexpected control result fails the gate. Default budgets are 600
seconds for the whole theory and 180 seconds per control; command-line options
may change those wall-time budgets, not the theory or proof domain.
On timeout the runner sends SIGTERM, waits at most two seconds, then escalates
to SIGKILL with a bounded reap wait. Its separate process-control regression
uses a synthetic prover that demonstrably ignores SIGTERM; a killed process
is never counted as proof. If even the final reap wait expires, the receipt
records `SIGKILL-unreaped` with no exit status and fails the check; it does not
claim that an unresponsive process has exited.

The confirmed-group/sender lemma is marked `reuse`; later lemmas can use its
conclusion. The gate requires that lemma's own proof in the same whole-theory
run, so it is not an unchecked authentication assumption. The four
exists-trace lemmas establish reachability and keep the safety antecedents
from being the only evidence. Tamarin may exit zero with an incomplete or
falsified lemma; successful process exit alone is not the gate.

Sensitivity checks mutate the symbolic model in isolated scratch files:

- Remove the Welcome sender from the existing confirmation's MAC value at
  both derivation/verification sites. A network rewrite of the advertised
  sender must falsify `pairing_confirmed_group_and_sender_agree`.
- Remove the expected-sender equality in `AcceptWelcome`. A valid
  attacker-signed Welcome must falsify both the guard-presence lemma
  `pairing_welcome_sender_matches_confirmation` and the substantive theorem
  `pairing_welcome_requires_authenticated_existing_link`, in separate selected
  runs of the same mutant.
- Allow `NewApproved` to send its confirmation before receiving and verifying
  the existing device's confirmation, using the matching honest identity's
  actual group and public signing key. This must falsify
  `pairing_new_confirmation_follows_existing_confirmation` because of the
  missing earlier event, rather than invented metadata. This mutant reads the
  identity fact's public projection and reveals no secret key.

These three mutation types require four named falsifications. The ordering
and confirmed-binding lemmas deliberately share the same authenticated input
in the baseline's atomic verification-and-confirmation rule; they are not
independent cryptographic arguments.

These are model mutations, not mutations of production Rust. The independent
runtime tests remain necessary. Preserve the exact model hash, tool versions,
individual lemma results, commands, time budgets and counterexamples with each
verification run; a previous result does not cover later model edits.
