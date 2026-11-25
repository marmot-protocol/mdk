### Fixed

- When a live receive's state save fails, the worker's short retry still runs if a route sync succeeds in between.
  Before, an activity delivered once by that receive waited up to 15 s for the next maintenance pass.
