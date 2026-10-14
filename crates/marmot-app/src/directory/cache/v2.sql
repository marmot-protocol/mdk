-- Verified public Nostr events referenced from message content, keyed by
-- canonical reference: `event:<id>` or `coordinate:<kind>:<pubkey>:<d>`.
-- `event_json` is the shown event, NULL once the referenced event is deleted.
-- `deleted_through` is the newest author-signed NIP-09 deletion time seen; it
-- outlives a newer shown version so an older version is never restored.
-- `complete` is 0 when the row came from a fetch where a relay did not finish.
CREATE TABLE public_event_previews (
    cache_key TEXT PRIMARY KEY NOT NULL,
    event_json TEXT,
    deleted_through INTEGER,
    complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
    bytes INTEGER NOT NULL,
    fetched_at INTEGER NOT NULL,
    touched_at INTEGER NOT NULL,
    CHECK (event_json IS NOT NULL OR deleted_through IS NOT NULL)
);
CREATE INDEX public_event_previews_touched_idx
    ON public_event_previews(touched_at);
