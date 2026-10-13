# Changelog

## Unreleased

### Changed

- Partial invite recovery queues each replacement for one missing leaf and atomically retains unresolved sibling obligations.

- Invite recovery accepts multiple fresh packages for an account and compares leaf signing keys for satisfaction. Pending rosters retain sibling Add leaves; KeyPackage metadata exposes the device signing key separately from the account identity.

