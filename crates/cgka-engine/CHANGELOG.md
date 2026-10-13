# Changelog

## Unreleased

- Allow an admin device to leave when another canonical leaf of its account remains. Proposal admission, auto-commit
  and commit validation preserve the account's admin rights; the last admin-account leaf still gets
  `AdminCannotSelfRemove`.
- `GroupAuthorityFacts::self_has_sibling_leaf` supplies the canonical sibling fact used by leave capability hints.
- Concurrent admin sibling leaves now select a deterministic batch that retains an admin-account leaf. The shared
  resulting-admin coupling validator runs before auto-publication and on publish confirmation.
- Compatibility requirement: admin sibling SelfRemove requires support from every group member. Older MDK receivers
  (`origin/master` at `c27300be`) reject the active-admin proposal and cannot adopt a commit consuming it, even when
  a sibling survives; new clients publishing such a commit can split a mixed-version group. Demotion must commit in
  a prior epoch before a fresh non-admin SelfRemove to avoid this mismatch. No capability gate is added yet; see
  [the receiver analysis and proposed negotiation contract](README.md#compatibility-of-admin-sibling-departures).
