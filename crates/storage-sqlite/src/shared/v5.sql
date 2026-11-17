-- NIP-01 replacement winner observed for each account's KeyPackage slot.
CREATE TABLE directory_key_package_replacements (
    account_id_hex TEXT NOT NULL,
    key_package_id TEXT NOT NULL,
    event_id_hex TEXT NOT NULL,
    event_created_at INTEGER NOT NULL,
    observed_at INTEGER NOT NULL,
    PRIMARY KEY (account_id_hex, key_package_id)
);
