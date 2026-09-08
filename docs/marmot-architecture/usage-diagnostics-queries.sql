-- Stock ClickHouse events schema, inspected at Aptabase
-- 9982140a5313bbc92bc32dbe66d76b94cdd042be. Bind app and UTC range explicitly.
-- Query outputs are aggregate and never expose user_id or session_id.

-- Observed foreground sessions; aggregate UUIDs are excluded.
SELECT toDate(timestamp) AS day, uniqExact(session_id) AS observed_foreground_sessions
FROM events
WHERE app_id = {app:String} AND timestamp >= {from:DateTime} AND timestamp < {until:DateTime}
  AND event_name = 'mdk_session_started'
GROUP BY day ORDER BY day;

-- Observed opted-in funnel, not a full-install funnel or population opt-in rate.
SELECT JSONExtractString(string_props, 'step') AS step,
       JSONExtractString(string_props, 'path') AS path,
       JSONExtractString(string_props, 'outcome') AS outcome,
       count() AS observed_steps
FROM events
WHERE app_id = {app:String} AND timestamp >= {from:DateTime} AND timestamp < {until:DateTime}
  AND event_name = 'mdk_onboarding_step'
GROUP BY step, path, outcome ORDER BY step, path, outcome;

-- Feature, publication, media, maintenance, recovery, storage and preview distributions.
-- Rows are reporting cells, NOT exact activity counts. Bucket bounds define intervals.
-- Keep attempts, transitions and backlog separate, and split partial windows.
SELECT event_name,
       JSONExtractString(string_props, 'operation') AS operation,
       JSONExtractString(string_props, 'outcome') AS outcome,
       JSONExtractString(string_props, 'unit') AS unit,
       JSONExtractString(string_props, 'duration_bucket') AS duration_bucket,
       JSONExtractString(string_props, 'count_bucket') AS count_bucket,
       JSONExtractString(string_props, 'partial') AS partial,
       count() AS reporting_cells
FROM events
WHERE app_id = {app:String} AND timestamp >= {from:DateTime} AND timestamp < {until:DateTime}
  AND JSONExtractString(string_props, 'schema_version') = 'mdk-product-v1'
  AND JSONExtractString(string_props, 'count_bucket') != ''
GROUP BY event_name, operation, outcome, unit, duration_bucket, count_bucket, partial
ORDER BY event_name, operation, outcome, unit, duration_bucket, count_bucket, partial;

-- Directory resolution attribution (path only; no relay identity).
SELECT event_name, JSONExtractString(string_props, 'operation') AS operation,
       JSONExtractString(string_props, 'source') AS source,
       JSONExtractString(string_props, 'outcome') AS outcome,
       JSONExtractString(string_props, 'count_bucket') AS count_bucket,
       JSONExtractString(string_props, 'partial') AS partial, count() AS reporting_rows
FROM events
WHERE app_id = {app:String}
  AND timestamp >= {from:DateTime} AND timestamp < {until:DateTime}
  AND event_name = 'mdk_directory_summary'
GROUP BY event_name, operation, source, outcome, count_bucket, partial;
