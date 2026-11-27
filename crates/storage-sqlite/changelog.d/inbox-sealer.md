### Breaking changes

- Schema migration 0229 gates the stored-message payload tag 17, which carries a Welcome the engine staged before the
  session sealed it (mdk#3498). The migration changes no table; older binaries refuse schema 229, because they cannot
  decode that tag. Downgrade is not supported.
