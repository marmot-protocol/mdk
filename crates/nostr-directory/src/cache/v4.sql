-- Track kind-3 contact-list event recency on both promoted directory users and
-- un-promoted search-graph users so stale kind-3 replays cannot overwrite newer
-- follow sets across restarts. Zero denotes unknown/legacy recency.
ALTER TABLE directory_users
    ADD COLUMN follows_created_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE directory_search_graph_users
    ADD COLUMN follows_created_at INTEGER NOT NULL DEFAULT 0;
