-- Track the kind-3 contact-list event timestamp independently of profile and
-- KeyPackage recency so stale kind-3 replays cannot overwrite newer follow
-- lists (including newer empty contact lists with zero rows in
-- directory_user_follows). Zero denotes unknown/legacy recency.
ALTER TABLE directory_users
    ADD COLUMN follows_created_at INTEGER NOT NULL DEFAULT 0;
