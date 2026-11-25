### Breaking changes

- Rust callers can inject an `EntropySource` for engine draws and kind-445 sealing and signing (mdk#3497).
  `NostrMlsPeeler::new` takes an entropy source and a wall clock. Use `Default` for system sources.
  Pass a clock to `NostrTransportEvent::new_unsigned`, or use `new_unsigned_at` with an explicit timestamp.
