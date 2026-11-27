### Fixed

- Reconnecting a relay now immediately clears per-unit unreachable retry waits on that relay (while keeping timed
  probes for parked broken units intact), so live-fenced groups resume history recovery and message delivery without
  stalling for the 30-second unreachable retry wait.
