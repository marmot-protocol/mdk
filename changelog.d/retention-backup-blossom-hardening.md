### Fixed

- `marmot-app`: Disappearing-message retention sweeps now query SQLite directly for groups with expiring rows instead of skipping groups whose current policy is `0` or omitting non-chat-list groups, so previously sent disappearing messages still expire after retention is turned off.
- `marmot-app`: Backup passes now require complete multi-relay pointer discovery before condemning blobs or replacing pointers, restrict condemned-blob deletion requests to configured backup Blossom servers, and bound replacement pointer timestamps against excessive future clock skew.
- `marmot-app`: Blossom uploads and deletions now complete host and dial-safety validation before signing BUD-01 authorization events.
- `marmot-app`: Host-facing Welcome redelivery now enforces group visibility so internal device-group Welcomes remain hidden from host redelivery calls.
