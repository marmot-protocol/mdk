### Added

- Terminal harnesses sharing a chat can use `/agent NAME` to switch the active backend.
  Configure a shared routing file to opt in.

### Breaking changes

- `/agent` is a reserved harness command. Use `/cd ~/agent` to select a directory with that name.
