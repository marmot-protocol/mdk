### Fixed

- `marmot-app`: Disappearing-message retention sweeps now query SQLite directly for groups with expiring rows instead of skipping groups whose current policy is `0` or omitting non-chat-list groups, so previously sent disappearing messages still expire after retention is turned off. `RetentionSweepReport.groups` now lists only visible groups that had expired rows at sweep time.
- `marmot-app`: Backup passes now require complete multi-relay pointer discovery before condemning blobs or replacing pointers, and bound replacement pointer timestamps (including persisted replaceable-record floors) against excessive future clock skew.
- `marmot-app`: Blossom uploads and deletions now complete host and dial-safety validation before signing BUD-01 authorization events.
- `marmot-app`: Host-facing Welcome redelivery now enforces group visibility so internal device-group Welcomes remain hidden from host redelivery calls.
