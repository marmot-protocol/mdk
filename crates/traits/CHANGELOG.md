# Changelog

## Unreleased

### Breaking changes

- Remove D90-only authenticated device-group source types and `MessageStorage` observation/content-association
  methods; ordinary processed-wrapper markers remain. `PublicationObservation` retains only immutable actual
  acceptance time, with the retired serialized order ignored on read (D100).

- `GroupStorage` now requires `invitation_admission` and `put_invitation_admission` for native transactional
  admission metadata (mdk#2628 D96). `InvitationAdmission` binds the original generation to founding origin or its
  exact successful local Welcome output; no transport id is used as the shared generation seed.

- Remove `AnnouncedKeyPackage`, `AnnouncedKeyPackageStorage`, its retention
  and per-slot limits, and `StorageProvider::announced_key_package_storage`
  (mdk#2863, D81). The unused announcement history has no replacement.
