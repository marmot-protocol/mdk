### Fixed

- Stopped the account worker from retrying epoch-pinned invitation-decision sends on every unrelated loop turn while the trusted device group is still settling a local commit or pending convergence inputs.
