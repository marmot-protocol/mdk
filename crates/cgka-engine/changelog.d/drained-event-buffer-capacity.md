### Fixed

- `drain_events` no longer keeps the peak allocation of a large event backlog: a drain larger than one background
  replay sweep (128 events) hands its buffer to the caller and leaves a bounded one behind, while routine drains still
  reuse the buffer (mdk#3585).
