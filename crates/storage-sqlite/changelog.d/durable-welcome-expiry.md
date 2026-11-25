### Breaking changes

- Schema migration 0227 gates the stored-message payload tags 16 and 17, which carry an outbound Welcome's expiry
  mark (mdk#3589). The migration changes no table; older binaries refuse schema 227, because they cannot decode those
  tags and would read a Welcome marked expired as withdrawn. Downgrade is not supported.
