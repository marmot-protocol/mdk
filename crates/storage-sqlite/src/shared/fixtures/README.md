# Shared-store historical fixtures

These SQL files were extracted from repository revisions, independently of the new `../v1.sql`.
They contain synthetic schema only. No installed databases were read.

| Fixture | Evidence |
| --- | --- |
| `original.sql` | `9db9dbc092d52eb7b2d5bc6dcfb1f9beb3125464`, `shared.rs::from_connection`: nine tables, including four now-unused directory tables and inline audit `data_mode`. |
| `five_tables_audit_mode.sql` | `5464b34eb019716b1cbf92bb2864206516477744`: stops creating unused tables, but does not drop existing ones; five live tables with inline audit `data_mode`. |
| `pre_ledger.sql` | `fe133b82f0c2ed29c18861013d56d6dfb3a5e9f1`: removes audit data-mode creation and its additive repair; existing columns remain inert. |
| `legacy_repairs.sql` | Tests `clears_legacy_plaintext_relay_telemetry_endpoint` and `audit_log_settings_data_mode_column_is_added_to_legacy_table` at `9db9dbc092d52eb7b2d5bc6dcfb1f9beb3125464`: nullable endpoint between enabled and interval, and pre-mode audit table. |

History inspection used `git log -p origin/master -- crates/storage-sqlite/src/shared.rs` and `git show <commit>:<path>`.
All six master-lineage revisions touching that file through `6b2b041b` form three identical-DDL pairs:
`9db9dbc0`/`1dfe1907`, `5464b34e`/`dcf27f22`, and `fe133b82`/`6b2b041b`.
The first revision already includes `ensure_audit_log_data_mode_column`; its `ALTER TABLE ... ADD COLUMN` explains
why recognized audit tables can have data_mode either before or after updated_at_ms. The appended variant is tested
by executing that historical ALTER against the independently extracted pre-mode fixture. Partial stores containing
only the older settings tables are supported by the historical tests; missing live tables are created during adoption.

Repository history does not establish which shapes shipped to which devices. In particular, the endpoint and pre-mode
audit shapes are compatibility-test evidence, not a claim about an identified deployed build.

Adoption retains retired columns: endpoints are set to NULL transactionally, while data_mode remains unread and
unchanged by current writes. This avoids rebuilding tables or changing rowids. Retired directory tables are preserved,
including populated synthetic rows, and are neither recreated nor used by the current API.

Normal CI assurance includes 30,003 populated rows with exact typed-value/rowid comparison, all fixture upgrades,
foreign-key and integrity checks, rollback on body/ledger failure, and bounded (20-second child deadline) process-exit
recovery with dirty-page spill under DELETE and WAL journaling. Process exit is not power loss. These tests do not
cover every OS I/O fault, deployment cohort, malicious out-of-band mutation, or prove a numerical failure rate.
Conservative frozen-DDL recognition can refuse equivalent hand-edited schemas; no rows are discarded to repair them.
