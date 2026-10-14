-- Verified public Nostr events referenced from message content, keyed by
-- canonical reference: `event:<id>` or `coordinate:<kind>:<pubkey>:<d>`.
-- `deleted = 1` rows are deletion markers: an author-signed NIP-09 request was
-- seen, so a stale relay must not restore the event. For a coordinate,
-- `created_at` is the deletion's timestamp and only a newer version replaces it.
CREATE TABLE public_event_previews (
    cache_key TEXT PRIMARY KEY NOT NULL,
    event_json TEXT,
    created_at INTEGER NOT NULL,
    event_id_hex TEXT NOT NULL,
    deleted INTEGER NOT NULL CHECK (deleted IN (0, 1)),
    bytes INTEGER NOT NULL,
    fetched_at INTEGER NOT NULL,
    touched_at INTEGER NOT NULL,
    CHECK ((deleted = 1) = (event_json IS NULL))
);
CREATE INDEX public_event_previews_touched_idx
    ON public_event_previews(touched_at);
