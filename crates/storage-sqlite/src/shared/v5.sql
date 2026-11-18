-- NIP-01 replacement winner observed for each account's KeyPackage slot.
CREATE TABLE directory_key_package_replacements (
    account_id_hex TEXT NOT NULL,
    key_package_id TEXT NOT NULL,
    event_id_hex TEXT NOT NULL,
    event_created_at INTEGER NOT NULL,
    observed_at INTEGER NOT NULL,
    PRIMARY KEY (account_id_hex, key_package_id)
);

-- A deletion event fences either one publication or a whole KeyPackage slot.
CREATE TABLE public_key_package_barriers (
    account_id_hex TEXT NOT NULL,
    key_package_id TEXT NOT NULL,
    event_id_hex TEXT NOT NULL,
    deleted_event_id TEXT,
    event_created_at INTEGER NOT NULL,
    observed_at INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('replacement', 'deletion', 'exact_deletion')),
    PRIMARY KEY (account_id_hex, key_package_id, deleted_event_id, kind)
);

CREATE UNIQUE INDEX public_key_package_slot_barriers
    ON public_key_package_barriers (account_id_hex, key_package_id, kind)
    WHERE deleted_event_id IS NULL;

-- One retained eviction fence per account, with a global conservative fallback.
CREATE TABLE public_key_package_eviction_watermarks (
    account_id_hex TEXT PRIMARY KEY,
    key_package_id TEXT NOT NULL,
    event_id_hex TEXT NOT NULL,
    deleted_event_id TEXT,
    event_created_at INTEGER NOT NULL,
    evicted_at INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('replacement', 'deletion', 'exact_deletion'))
);

CREATE TABLE public_key_package_eviction_fallback (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    event_id_hex TEXT NOT NULL,
    event_created_at INTEGER NOT NULL,
    evicted_at INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('replacement', 'deletion', 'exact_deletion'))
);

-- Orders availability checks against later evidence, even within one second.
CREATE TABLE public_key_package_evidence_revisions (
    account_id_hex TEXT PRIMARY KEY,
    revision INTEGER NOT NULL
);

-- Store-wide counter keeps revisions unique when per-account rows are pruned.
CREATE TABLE public_key_package_evidence_clock (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL
);
