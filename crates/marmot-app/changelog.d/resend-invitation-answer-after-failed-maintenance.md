### Fixed

- An invitation answer refused while the device group's epoch settles goes out on the worker turn after it settles
  also when a maintenance pass in between ends early on a failed read, instead of waiting for the 15 s maintenance
  retry (mdk#3573).
