### Breaking changes

- Implement `EntropySource::fill_bytes` to supply engine randomness. The system default is `OsEntropy`.
  Direct callers of `Identity::load_or_generate` pass the MLS crypto provider used to generate new signers (mdk#3497).
