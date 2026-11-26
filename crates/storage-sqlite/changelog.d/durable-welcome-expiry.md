### Breaking changes

- Schema migration 0227 gates the stored-message payload tag 16, which carries an owed outbound Welcome's expiry mark
  (mdk#3589). The migration changes no table; older binaries refuse schema 227, because they cannot decode that tag
  and would read a Welcome marked expired as withdrawn. Downgrade is not supported.
