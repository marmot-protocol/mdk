### Fixed

- An agent item whose first event this device lacks is shown from the first edit of it this device received, not the
  one with the earliest `created_at`. Any member can send such an edit and choose its timestamp, so a backdated one
  could take the item from its agent.
