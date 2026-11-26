### Fixed

- A device-group message pinned to an epoch is refused before it writes its withdrawal record while this device's
  own device-group commit is still unpublished. Before, each retry in that window wrote a record that could push
  older ones out of the bounded record table.
