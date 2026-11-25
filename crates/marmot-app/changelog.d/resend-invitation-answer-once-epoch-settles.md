### Fixed

- An invitation answer that a linked device must send again after a fork between linked devices goes out on the
  worker turn after the device group's epoch settles, instead of waiting up to 15 s for the next maintenance pass
  (mdk#3573).
