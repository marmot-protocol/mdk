### Fixed

- A finite history read whose caller stops polling it while its REQ waits to be queued no longer holds up live
  events on that relay connection. Before, the read could hold the SDK's subscription lock until it was polled
  again.
