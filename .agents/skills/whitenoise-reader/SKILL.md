---
name: whitenoise-reader
description: Query the White Noise V5 audit reader (https://goggles.ipf.dev/v1) to investigate a Marmot/MLS group from MDK audit records. Use when an agent needs a group's per-source epoch history, convergence or fork evidence, Welcome delivery chains, recovery obligations and attempts, or workload counts, or needs to fetch the original audit records behind a finding. Requires a reader bearer token (wnar_...) stored locally.
---

If the repository has its own `.agents/skills/whitenoise-reader/` or `.claude/skills/whitenoise-reader/`, stop and follow that one instead. It is the repo's specific version of this skill. If the file you are reading is already that copy, carry on.

# White Noise audit reader

The audit reader is a read-only, stateless HTTP API over the V5 audit records
that MDK clients send to the White Noise audit receiver. Each request runs a
bounded set of queries against storage, interprets the original record bodies,
and returns conclusions together with the exact records and queries behind
each one.

It can only read. It cannot upload, edit or delete audit data, and it has no
endpoint for listing or discovering groups: you must be given a group
identifier.

Everything it returns is sensitive. Group IDs, refs, source refs, record ids
and record bodies must never go into issues, PRs, commits, chat channels,
telemetry or any external service. Report only what the person who asked
needs, and only to them.

## 1. Find the token

Every `/v1` request needs `Authorization: Bearer <token>`. Tokens look like
`wnar_<16 hex>_<43 base64url chars>`. The helper script
(`scripts/reader.sh`, next to this file) looks for the token in these places,
in order, and uses the first it finds:

1. The `AUDIT_READER_TOKEN` environment variable.
2. macOS Keychain, service `whitenoise-data`
   (`security add-generic-password -U -a "$USER" -s whitenoise-data -w`).
3. Linux Secret Service, attribute `service whitenoise-data`
   (`secret-tool store --label "White Noise reader" service whitenoise-data`).
4. The file `~/.config/whitenoise-data/reader.token` (or under
   `$XDG_CONFIG_HOME`), readable only by its owner.

If the script exits with "no reader token found", or the token is malformed,
stop. Tell the user you could not find a reader token, list the locations
above, and wait for them to store one. Do not look anywhere else and do not
continue without it.

Handle the token only through the script:

- Never ask for the token in chat, and never read, print, echo or log it.
- Never put it in a URL, a command-line argument, a file in the repository or
  this skill.
- Every valid token can read all audit data. If one may have leaked, tell the
  user so it can be revoked, and do not repeat it anywhere.

`AUDIT_READER_URL` overrides the base URL (default `https://goggles.ipf.dev`),
for example `http://127.0.0.1:4330` on the VM itself.

## 2. Make requests

Use the helper script. It loads the token, checks its shape and passes the
header to curl on stdin, so the token never appears in argv, the process list
or your transcript. The response body goes to stdout and `HTTP <status>` to
stderr.

```bash
SKILL_DIR=<directory containing this SKILL.md>
"$SKILL_DIR/scripts/reader.sh" GET /v1/contract > contract.json
"$SKILL_DIR/scripts/reader.sh" POST /v1/investigations request.json > investigation.json
"$SKILL_DIR/scripts/reader.sh" POST /v1/records records-request.json > records.json
```

Write request bodies to files and save responses to files in a scratch
directory outside any repository, then inspect them with `jq`. A full
investigation can be many megabytes; do not dump it into your context.

Rules the API enforces:

- Identifiers go only in JSON bodies. Any query string is rejected
  (`query_string_not_supported`).
- Request bodies are limited to 64 KB.
- An investigation can take up to about two minutes before the response
  starts. The helper allows 300 s; do not use a client timeout below 150 s.
- Only `/v1/*` is public. `/healthz`, `/readyz` and `/status` exist only on the
  VM's loopback and return 404 through `goggles.ipf.dev`.

### Check the token and read the contract first

`GET /v1/contract` returns 200 for a valid token and 401 otherwise, so use it
as the token check. Read it once per session. It is the authoritative source
for what this deployment accepts:

- `contract`: the MDK commit and schema the reader interprets, and `kinds`,
  the record kind catalog.
- `endpoints`, `entry_paths`, `questions`: what each endpoint, group entry
  path and question does.
- `limits`: maximum window, retention, page size and budgets.
- `request_examples`: a minimal valid body for each POST endpoint.
- `enums`: every value of every field you branch on (questions, details,
  finding bases, query statuses, truncation and skip reasons, resolution,
  convergence and welcome statuses, recovery dispositions, integrity flags,
  record select keys).
- `errors.codes`: every error `code` and its HTTP status.

Prefer values from the live contract over the lists in this skill if they
differ.

## 3. What the reader can do

### Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /v1/contract` | Pins, kind catalog, limits, request examples, enums, error codes. No investigation slot is used and it never returns 429. |
| `POST /v1/investigations` | Answers questions about one group over a time window, with findings, structured answers, coverage and the records behind them. |
| `POST /v1/records` | Retrieves original records and every stored occurrence, by id, identity, group, outer event or source. Paginated. |

### Investigations

```json
{
  "group": {"mls_group_id": "<hex>"},
  "window": {"from": "2026-09-22T00:00:00Z", "until": "2026-09-29T00:00:00Z"},
  "questions": ["history", "convergence", "welcome", "recovery", "workload"],
  "detail": "summary"
}
```

**`group`** takes exactly one entry path:

| Key | Value | Notes |
| --- | --- | --- |
| `mls_group_id` | Raw MLS group ID bytes as hex | The reader hashes it into a `group_ref`. The usual choice. |
| `nostr_group_id` | The 32-byte Nostr routing ID (kind 445 `h` tag), 64 hex | A different domain. It resolves only through records that carry both its transport ref and an explicit `group_ref`, and the scan costs more. Resolution can be `resolved`, `ambiguous` (all candidates listed, none chosen) or `unresolved`. |
| `group_ref` | A V5 `group_ref` (64 hex) already taken from records | |

Use only identifiers the person gave you or that came from reader responses.
Never guess or enumerate them.

**`window`** has `from` (inclusive) and `until` (exclusive), as RFC 3339
with up to 9 fraction digits, or decimal Unix nanoseconds. It is **server
receipt time** (when the receiver accepted the record), not device wall time.
The span may be at most `limits.max_window_days` (30 days), and data older
than the retention (30 days) is gone. Use the narrowest window that covers
the problem: wide windows are slower and more likely to hit budgets.

**`questions`** (default: all five):

| Question | What comes back in `answers.<question>` |
| --- | --- |
| `history` | Per source (`source_ref`): sessions and seq ranges, epochs reported, last epoch report, last engine-state report. Which sources agree or disagree on their last reported epoch. A timeline. |
| `convergence` | Convergence runs and phases, decisions with candidate branches, legacy fork resolutions, sources that confirmed the same epoch with different commits, and sources whose last state is `recovering`, `merging` or `unrecoverable`. A summary `status`. |
| `welcome` | One chain per outer event with each step kept separate: prepared, event size class (`event_size`), publish attempts (one per pass over the relays: `route_source` first send or retry, policy, per-endpoint results, `retained_state`), not started, `withdrawn` (the sender's terminal reason, with the oversized size class for a too-large refusal), and per recipient source: observed, unwrapped, join finished, app checkpoint. Prepared Welcomes that never got an outer event. To ask whether an invite left the sender and why not, read `prepared`, `publish_attempts`, `publish_not_started` and `withdrawn`, and the `source_ref`, `session_id` and `seq` of the records they cite in `records`. Only `withdrawn` says the sender will never send it. Prepared rows with no pass, not-started row or withdrawal are never a withdrawal: the commit may be held, or the later rows may be outside the window or never written (MDK writes no withdrawal for a Welcome that settles while nothing watches it). Rows are ordered only by `seq` within one session; rows of different sessions have no known order. |
| `recovery` | Recovery obligations (cause, changes, reassessments, disposition), attempts linked to the group (duration, outcome, event and relay counts), totals, repeated work, epoch-gap backfills, and attempts that could not be linked. |
| `workload` | Counts of recorded events, routes, relay outcomes, drains, cursor spills, EOSE repairs and recovery retrievals, by source and split into group-scoped and account-scoped work. Not a battery, energy or CPU measure. |

Optional fields:

- `detail`: `summary` or `full` (default). **Start with `summary`.** It keeps
  `resolution`, `coverage` and `answers`, trims the history timeline to 20
  entries, keeps only the findings for the questions you asked, samples each
  finding's `evidence.records` to 10 ids (`evidence.record_count` has the full
  number, `evidence.records_truncated` marks sampling), and lists cited
  records in compact form without bodies. Repeat with `full`, or fetch
  records, only for what you need.
- `include_bodies` (default `true`): set `false` to drop original bodies from
  a `full` response.
- `extra_sources`: a short list of 32-hex `source_ref` values to add
  source-scoped context for devices that have no linked rows in the window.

### Records

```json
{
  "window": {"from": "2026-09-22T00:00:00Z", "until": "2026-09-29T00:00:00Z"},
  "select": {"record_ids": ["sha256:<64 hex>", "..."]},
  "limit": 100
}
```

`select` holds exactly one of:

| Key | Returns |
| --- | --- |
| `record_ids` | Up to 50 `sha256:` record ids from `findings[].evidence.records` or `records[].id`. |
| `identity` | `{"source_ref", "session_id", "seq"}`: every body that claims that identity, across all buckets. Use it to inspect identity conflicts. |
| `group_ref`, `mls_group_id` | Every record of a group, paged. Use it when an investigation hit its row budget. |
| `outer_event_ref` | Records linked to one outer (Nostr) event, such as a Welcome. |
| `source_ref` | Records from one source. |

Also `limit` (1 to `limits.loki_page_limit`), `include_bodies`, and `cursor`.
When a response has `next_cursor`, send it back with the **same** `select`
and `window`, unchanged, to get the next page. `complete` is true only when
there are no more pages and nothing was truncated. An `invalid_cursor` error
means restart without the cursor.

## 4. Read a response

Work in this order:

1. **`resolution.status`.** `ambiguous` or `unresolved` means there are no
   answers, only the linking evidence. Report the candidates; do not pick
   one.
2. **Coverage before absence.** Check `coverage.complete_within_rules`,
   `coverage.window` (`effective` vs `requested`, `not_queried`,
   `retention_edge_uncertain`), every entry in `coverage.queries` (status
   `complete`, `truncated`, `failed` or `skipped`, with the reason), and each
   answer's `inputs.complete`. Even `complete_within_rules: true` is not a
   completeness claim.
3. **Findings for conclusions.** Each `findings[]` item has `statement`,
   `basis`, `evidence.records` (record ids → `records[].id`),
   `evidence.queries` (query ids → `coverage.queries[].id`), `caveats` and
   `evidence_complete`. Bases:
   - `source_report`: what one source said about itself.
   - `cross_source_comparison`: a comparison across sources.
   - `explicit_link`: records joined by a shared reference.
   - `absent_in_scope`: nothing matched within the rules. Not proof of
     absence.
   - `not_evaluated`: the deciding query failed, was skipped or never ran.
   - `integrity`: a property of the stored evidence (invalid line, replay,
     identity conflict).
   - `derived_count`: counts of retrieved records, or of stored rows from a
     query's row plan.
4. **Answers for structure.** `answers.history.sources`,
   `answers.convergence.runs`, `answers.welcome.chains`,
   `answers.recovery.obligations` and so on.
5. **Records for bodies.** `records[]` holds each record's id, `source_ref`,
   `session_id`, `seq`, kind, `group_ref`, outer event, integrity flags, and
   (in `full`) the original body byte for byte plus every stored occurrence.
   Bodies that did not fit are listed in `records_meta.bodies_omitted_for_size`;
   fetch them with `/v1/records`.

An HTTP 200 does not mean the data was read: a query that could not reach
storage is reported in `coverage.queries` as `failed`, with its error
category, and anything that depended on it is `not_evaluated`.

When a budget was hit (`truncated` with `row_budget`,
`loki_request_budget` or `deadline`, or `skipped` expansions), narrow the
window, page through `/v1/records`, or say the answer is partial. The reader
never drops data silently; it always reports what it could not read.

**Floods.** A device that writes far more rows than the rest no longer uses
up the row budget. The group and source-context queries count their rows
first (`coverage.queries[].plan`): `stored_rows_by_kind`, for the group
`stored_rows_by_source`, and `not_fetched_kinds`, the most numerous kinds
left out so that every rarer kind fits. Such a query is `truncated` with
`row_budget`, and a `derived_count` coverage finding names the left-out
kinds with their counts and, for the group, the largest sources. Report the
flood itself as a finding about the evidence, and treat conclusions from the
left-out kinds as partial. If you need those rows, page through
`/v1/records` with `select: source_ref` over a narrow window.
`plan.counted: false` means counting failed (`plan.count_error`) and the
query ran the old way: first rows first until the budget ran out.

## 5. Errors

Every error body has `error` and a stable snake_case `code`. Branch on
`code`; never parse `detail`.

| Status | Codes | What to do |
| --- | --- | --- |
| 400 | `unknown_field`, `invalid_group`, `invalid_window`, `invalid_instant`, `window_exceeds_max_span`, `invalid_questions`, `unknown_question`, `invalid_include_bodies`, `invalid_detail`, `invalid_extra_sources`, `invalid_select`, `invalid_limit`, `invalid_cursor`, `invalid_request`, `query_string_not_supported`, `invalid_json` | Fix the request against `request_examples` and `enums`. Do not retry unchanged. |
| 401 | `unauthorized` | The token is missing, unknown, expired or revoked. Stop and tell the user their stored reader token was rejected. |
| 404 | `not_found` | Wrong method or path. |
| 413 | `request_too_large` | Shrink the body (for example fewer `record_ids`). |
| 429 | `busy` | All investigation slots are busy. Wait `retry_after_seconds` (also in `Retry-After`) and retry, a few times at most. |
| 500 | `internal_error` | Report it; try a narrower window once. |
| 503 | `token_store_unavailable` | Wait `retry_after_seconds` and retry. |

A 502 or 504 from the proxy means the reader is down or took too long; narrow
the window before retrying.

## 6. What a conclusion may say

The reader is built so that every conclusion cites evidence. Keep that
property in your own report.

- **Cite.** Every claim names the finding id, record ids or query ids it
  rests on. Short prefixes of ids are fine in a report to the person who
  asked.
- **Absence proves nothing.** A missing record does not show that delivery
  failed, that sources agree, that anything is healthy, or that capture was
  complete. Recording is best-effort. Say "not found in scope" (or "not
  evaluated" when the query failed), never "did not happen".
- **Source reports are not group truth.** An epoch or state value is what
  that `source_ref` reported. A `source_ref` is a pseudonymous per-engine
  hash, not an authenticated account or device, and not proof of membership.
- **Never pick a winner between conflicting bodies.** Records with the same
  `(source_ref, session_id, seq)` and different bodies are flagged
  `identity_conflict`; report all of them. Replays keep every occurrence.
- **Welcome steps are separate.** Prepared, event size, publish started and
  finished, withdrawn, observed, unwrapped, join finished and app checkpoint
  each prove only themselves. A relay acknowledgement is not recipient
  arrival, a sender row never shows the recipient joined, and a missing pass
  is not a withdrawal.
- **Fork evidence is what sources recorded.** Two sources confirming the same
  epoch with different commit refs is a disagreement signal, not proof of a
  fork.
- **Recovery.** A missing reassessment means "unsettled in the evidence",
  not "failed".
- **Workload is counts,** not battery, energy, CPU or radio use. Prometheus
  metrics are not joined.
- **Refs are one-way hashes in separate domains.** Equal values in one domain
  (group, transport group, Nostr event, engine message, operation,
  obligation, branch, run) say nothing about another.
- **Time.** Windows and `received_ns` are server receipt time. Device clocks
  and receipt order do not establish causality across sources.

### Report shape

```markdown
## Question
What was asked, entry path type (not the ID), window, questions.

## Coverage
complete_within_rules, any truncated/failed/skipped queries, window clipping.

## Findings
- <conclusion> — basis, finding id, records <id prefixes>, queries <ids>.
  Caveats.

## Not established
What the evidence cannot show, and why (absent in scope, not evaluated,
budget, retention).

## Next step
The smallest extra query, window or source that would settle it.
```
