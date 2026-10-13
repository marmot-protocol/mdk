-- Synthetic fixture written by c27300be. Do not regenerate with HEAD.
BEGIN TRANSACTION;
CREATE TABLE account_delivery_loss_evidence (
    account_label TEXT NOT NULL REFERENCES account_state(label) ON DELETE CASCADE,
    cause INTEGER NOT NULL CHECK(cause IN (0, 1)),
    marker_token INTEGER NOT NULL CHECK(typeof(marker_token) = 'integer' AND marker_token >= 0),
    pending_since INTEGER NOT NULL CHECK(typeof(pending_since) = 'integer' AND pending_since >= 0),
    dropped_count INTEGER NOT NULL CHECK(typeof(dropped_count) = 'integer' AND dropped_count >= 0),
    imported_count INTEGER CHECK(imported_count IS NULL OR (imported_count >= 0 AND imported_count <= dropped_count)),
    legacy_retired_count INTEGER CHECK(legacy_retired_count IS NULL OR
        (typeof(legacy_retired_count) = 'integer' AND legacy_retired_count >= 0 AND legacy_retired_count <= imported_count)), bound_state INTEGER NOT NULL
             DEFAULT 2 CHECK(bound_state IN (1, 2)), bound_seconds INTEGER
             CHECK(bound_seconds IS NULL OR (typeof(bound_seconds)='integer' AND bound_seconds>=0)), retired_count INTEGER
             CHECK(retired_count IS NULL OR (typeof(retired_count)='integer' AND retired_count>=0
                 AND retired_count<=imported_count)),
    PRIMARY KEY(account_label, cause, marker_token)
);
CREATE TABLE account_delivery_spill (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id BLOB NOT NULL UNIQUE CHECK(typeof(event_id)='blob' AND length(event_id)>0),
            payload BLOB NOT NULL CHECK(typeof(payload)='blob'),
            metadata BLOB NOT NULL CHECK(typeof(metadata)='blob'),
            format INTEGER NOT NULL CHECK(format=1),
            bytes INTEGER NOT NULL CHECK(typeof(bytes)='integer' AND bytes>=0),
            spilled_at INTEGER NOT NULL CHECK(typeof(spilled_at)='integer' AND spilled_at>=0),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(typeof(attempts)='integer' AND attempts>=0),
            not_before INTEGER NOT NULL DEFAULT 0 CHECK(typeof(not_before)='integer' AND not_before>=0)
        );
CREATE TABLE account_group_app_components (
    group_id_hex TEXT NOT NULL,
    component_id INTEGER NOT NULL,
    component_name TEXT NOT NULL,
    component_data_hex TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, component_id),
    FOREIGN KEY (group_id_hex) REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);
CREATE TABLE account_groups (
    group_id_hex TEXT PRIMARY KEY NOT NULL,
    endpoint TEXT NOT NULL,
    profile_name TEXT NOT NULL DEFAULT '',
    profile_description TEXT NOT NULL DEFAULT '',
    image_hash_hex TEXT NOT NULL DEFAULT '',
    image_key_hex TEXT NOT NULL DEFAULT '',
    image_nonce_hex TEXT NOT NULL DEFAULT '',
    image_upload_key_hex TEXT NOT NULL DEFAULT '',
    image_media_type TEXT,
    admin_keys_hex TEXT NOT NULL DEFAULT '',
    archived INTEGER NOT NULL DEFAULT 0,
    pending_confirmation INTEGER NOT NULL DEFAULT 0,
    welcomer_account_id_hex TEXT,
    via_welcome_message_id_hex TEXT,
    updated_at INTEGER NOT NULL
, self_membership TEXT NOT NULL DEFAULT 'member', nostr_routing_last_epoch INTEGER NOT NULL DEFAULT 0, prior_nostr_routes_json TEXT NOT NULL DEFAULT '[]', conversation_created_at INTEGER NOT NULL DEFAULT 0, member_count INTEGER);
CREATE TABLE account_import_markers (
    name TEXT PRIMARY KEY NOT NULL,
    completed_at_unix_seconds INTEGER NOT NULL
);
CREATE TABLE account_recovery_comparison (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(revision)='integer' AND revision>=0),
            settled_revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(settled_revision)='integer' AND settled_revision>=0 AND settled_revision<=revision),
            request_key BLOB CHECK(request_key IS NULL OR (typeof(request_key)='blob' AND length(request_key)=16)),
            requested_at_ms INTEGER NOT NULL DEFAULT 0 CHECK(typeof(requested_at_ms)='integer' AND requested_at_ms>=0),
            requested_until_seconds INTEGER NOT NULL DEFAULT 0 CHECK(typeof(requested_until_seconds)='integer' AND requested_until_seconds>=0),
            blocked_route_revision INTEGER CHECK(blocked_route_revision IS NULL OR (typeof(blocked_route_revision)='integer' AND blocked_route_revision>=0)),
            blocked_capability_key BLOB,
            attempt_serial INTEGER NOT NULL DEFAULT 0 CHECK(typeof(attempt_serial)='integer' AND attempt_serial>=0),
            frozen_revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(frozen_revision)='integer' AND frozen_revision>=0),
            plan_format INTEGER NOT NULL DEFAULT 1,
            plan_payload BLOB,
            last_outcome INTEGER CHECK(last_outcome BETWEEN 0 AND 3),
            CHECK((blocked_route_revision IS NULL)=(blocked_capability_key IS NULL))
        );
INSERT INTO "account_recovery_comparison" VALUES(1,0,0,NULL,0,0,NULL,NULL,0,0,1,NULL,NULL);
CREATE TABLE account_recovery_obligations (
    id BLOB PRIMARY KEY NOT NULL DEFAULT(randomblob(16)) CHECK(typeof(id) = 'blob' AND length(id) = 16),
    demand_key TEXT NOT NULL UNIQUE,
    cause INTEGER NOT NULL CHECK(cause BETWEEN 0 AND 6),
    group_id BLOB REFERENCES cgka_groups(id) ON DELETE CASCADE,
    account_label TEXT REFERENCES account_state(label) ON DELETE CASCADE,
    stalled_epoch INTEGER CHECK(stalled_epoch IS NULL OR (typeof(stalled_epoch) = 'integer' AND stalled_epoch >= 0)),
    marker_token INTEGER CHECK(marker_token IS NULL OR (typeof(marker_token) = 'integer' AND marker_token >= 0)),
    pending_since INTEGER CHECK(pending_since IS NULL OR (typeof(pending_since) = 'integer' AND pending_since >= 0)),
    dropped_count INTEGER CHECK(dropped_count IS NULL OR (typeof(dropped_count) = 'integer' AND dropped_count >= 0)),
    revision INTEGER NOT NULL DEFAULT 1 CHECK(typeof(revision) = 'integer' AND revision > 0),
    predicate INTEGER NOT NULL DEFAULT 0 CHECK(predicate BETWEEN 0 AND 2),
    urgency INTEGER NOT NULL DEFAULT 0 CHECK(urgency BETWEEN 0 AND 2),
    created_at_ms INTEGER NOT NULL CHECK(typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(typeof(updated_at_ms) = 'integer' AND updated_at_ms >= 0),
    state INTEGER NOT NULL DEFAULT 0 CHECK(state BETWEEN 0 AND 2),
    eligibility INTEGER NOT NULL DEFAULT 0 CHECK(eligibility BETWEEN 0 AND 4),
    incomplete_reason INTEGER CHECK(incomplete_reason BETWEEN 0 AND 7),
    caller_origin INTEGER NOT NULL DEFAULT 0 CHECK(caller_origin IN (0, 1)), parked_at_ms INTEGER
             CHECK(parked_at_ms IS NULL OR (typeof(parked_at_ms)='integer' AND parked_at_ms>=0)), dismissed_scopes BLOB
             CHECK(dismissed_scopes IS NULL OR typeof(dismissed_scopes)='blob'),
    CHECK((cause NOT IN (0, 6)) OR (account_label IS NOT NULL AND marker_token IS NOT NULL
          AND pending_since IS NOT NULL AND dropped_count IS NOT NULL)),
    CHECK((cause != 1) OR (group_id IS NOT NULL AND stalled_epoch IS NOT NULL))
);
CREATE TABLE account_recovery_scopes (
    obligation_id BLOB NOT NULL REFERENCES account_recovery_obligations(id) ON DELETE CASCADE,
    scope_id INTEGER NOT NULL CHECK(typeof(scope_id) = 'integer' AND scope_id >= 0),
    route_kind INTEGER CHECK(route_kind BETWEEN 0 AND 2),
    route_role INTEGER CHECK(route_role BETWEEN 0 AND 2),
    group_id BLOB,
    transport_group_id BLOB CHECK(transport_group_id IS NULL OR (typeof(transport_group_id) = 'blob' AND length(transport_group_id) = 32)),
    route_revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(route_revision) = 'integer' AND route_revision >= 0),
    since_seconds INTEGER CHECK(since_seconds IS NULL OR (typeof(since_seconds) = 'integer' AND since_seconds >= 0)),
    until_seconds INTEGER CHECK(until_seconds IS NULL OR (typeof(until_seconds) = 'integer' AND until_seconds >= 0)),
    known_event_id BLOB CHECK(known_event_id IS NULL OR (typeof(known_event_id) = 'blob' AND length(known_event_id) = 32)),
    scope_revision INTEGER NOT NULL DEFAULT 1 CHECK(typeof(scope_revision) = 'integer' AND scope_revision > 0),
    snapshot_state INTEGER NOT NULL DEFAULT 0 CHECK(snapshot_state IN (0, 1)),
    inventory_floor INTEGER CHECK(inventory_floor IS NULL OR (typeof(inventory_floor) = 'integer' AND inventory_floor >= 0)),
    progress_after BLOB CHECK(progress_after IS NULL OR (typeof(progress_after) = 'blob' AND length(progress_after) = 32)),
    scope_format INTEGER NOT NULL DEFAULT 1 CHECK(scope_format > 0),
    scope_payload BLOB,
    CHECK(snapshot_state = 0 OR (until_seconds IS NOT NULL AND scope_payload IS NOT NULL)),
    CHECK(since_seconds IS NULL OR until_seconds IS NULL OR since_seconds <= until_seconds),
    PRIMARY KEY(obligation_id, scope_id)
);
CREATE TABLE account_recovery_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    next_attempt INTEGER NOT NULL DEFAULT 0 CHECK(typeof(next_attempt) = 'integer' AND next_attempt >= 0),
    loss_revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(loss_revision) = 'integer' AND loss_revision >= 0),
    route_revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(route_revision) = 'integer' AND route_revision >= 0),
    inventory_revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(inventory_revision) = 'integer' AND inventory_revision >= 0),
    retry_ordinal INTEGER NOT NULL DEFAULT 0 CHECK(typeof(retry_ordinal) = 'integer' AND retry_ordinal >= 0),
    retry_recorded_at_ms INTEGER NOT NULL DEFAULT 0 CHECK(typeof(retry_recorded_at_ms) = 'integer' AND retry_recorded_at_ms >= 0),
    retry_delay_ms INTEGER NOT NULL DEFAULT 0 CHECK(typeof(retry_delay_ms) = 'integer' AND retry_delay_ms >= 0),
    retry_not_before_ms INTEGER NOT NULL DEFAULT 0 CHECK(typeof(retry_not_before_ms) = 'integer' AND retry_not_before_ms >= 0)
, route_snapshot BLOB
         CHECK(route_snapshot IS NULL OR (typeof(route_snapshot)='blob' AND length(route_snapshot)=32)), next_engine_observation INTEGER NOT NULL DEFAULT 0 CHECK(typeof(next_engine_observation)='integer' AND next_engine_observation >= 0), next_stall_sample INTEGER NOT NULL DEFAULT 0 CHECK(typeof(next_stall_sample)='integer' AND next_stall_sample >= 0));
INSERT INTO "account_recovery_state" VALUES(1,0,0,0,0,0,0,0,0,NULL,0,0);
CREATE TABLE account_state (
    label TEXT PRIMARY KEY NOT NULL,
    updated_at INTEGER NOT NULL,
    last_transport_timestamp INTEGER
, local_account_id_hex TEXT);
CREATE TABLE agent_stream_publisher_sequences (
    context_id BLOB PRIMARY KEY NOT NULL CHECK(length(context_id) = 32),
    next_seq INTEGER NOT NULL CHECK(next_seq >= 1),
    transcript_hash BLOB NOT NULL CHECK(length(transcript_hash) = 32),
    chunk_count INTEGER NOT NULL CHECK(chunk_count >= 0),
    reservation_token BLOB CHECK(reservation_token IS NULL OR length(reservation_token) = 16),
    disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0, 1)),
    updated_at_ms INTEGER NOT NULL
);
CREATE TABLE agent_stream_starts (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    source_message_id_hex TEXT,
    sender TEXT NOT NULL,
    stream_id_hex TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, message_id_hex)
);
CREATE TABLE app_epoch_stall_evidence (
    group_id              BLOB PRIMARY KEY
                          REFERENCES cgka_groups(id) ON DELETE CASCADE,
    stalled_epoch         INTEGER NOT NULL CHECK (stalled_epoch >= 0),
    fruitless_completions INTEGER NOT NULL CHECK (fruitless_completions >= 0),
    fruitless_reported    INTEGER NOT NULL CHECK (fruitless_reported IN (0, 1)),
    last_arm_at_ms        INTEGER NOT NULL CHECK (last_arm_at_ms >= 0),
    updated_at            INTEGER NOT NULL
, qualified_certificate BLOB, last_engine_observation INTEGER NOT NULL DEFAULT 0 CHECK(typeof(last_engine_observation)='integer' AND last_engine_observation >= 0), last_sample_sequence INTEGER NOT NULL DEFAULT 0 CHECK(typeof(last_sample_sequence)='integer' AND last_sample_sequence >= 0), last_sample_at_ms INTEGER);
CREATE TABLE app_events (
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    source_message_id_hex TEXT,
    direction TEXT NOT NULL,
    sender TEXT NOT NULL,
    plaintext TEXT NOT NULL,
    kind INTEGER NOT NULL,
    tags_json TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    invalidated INTEGER NOT NULL DEFAULT 0,
    invalidation_reason TEXT, source_epoch INTEGER, origin_commit_id TEXT, moderation_grant INTEGER NOT NULL DEFAULT 0, retention_seconds INTEGER, retention_expires_at INTEGER, authority_state INTEGER NOT NULL DEFAULT 0, authority_context BLOB,
    UNIQUE (group_id_hex, message_id_hex)
);
CREATE TABLE app_group_recovery_failures (
             group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE
         );
CREATE TABLE app_pending_welcome_delivery (
    message_id_hex TEXT PRIMARY KEY,
    group_id_hex   TEXT NOT NULL,
    recipient_hex  TEXT NOT NULL,
    recorded_at    INTEGER NOT NULL
);
CREATE TABLE app_prepared_group_image_upload (
    upload_id          TEXT PRIMARY KEY,
    state              TEXT NOT NULL CHECK (state IN ('staged', 'uploaded', 'failed', 'consumed')),
    component_data     BLOB NOT NULL,
    encrypted_blob     BLOB,
    upload_secret      BLOB,
    group_id_hex       TEXT,
    attempt_count      INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_kind    TEXT,
    recorded_at        INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    CHECK (
        (state = 'consumed' AND group_id_hex IS NOT NULL)
        OR (state != 'consumed' AND group_id_hex IS NULL)
    ),
    CHECK (
        (state = 'consumed' AND length(component_data) = 0
            AND encrypted_blob IS NULL AND upload_secret IS NULL)
        OR (state != 'consumed' AND length(component_data) > 0
            AND length(encrypted_blob) > 0 AND length(upload_secret) = 32)
    )
);
CREATE TABLE attachment_acquisition (
    token BLOB PRIMARY KEY NOT NULL CHECK(length(token)=16),
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    attachment_index INTEGER NOT NULL CHECK(attachment_index>=0),
    source_message_id_hex TEXT NOT NULL,
    source_epoch INTEGER NOT NULL,
    slot_json TEXT NOT NULL CHECK(length(CAST(slot_json AS BLOB))<=16384),
    plaintext_digest BLOB NOT NULL CHECK(length(plaintext_digest)=32),
    expires_at INTEGER,
    state INTEGER NOT NULL DEFAULT 0 CHECK(state BETWEEN 0 AND 5),
    due INTEGER DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
    attempt BLOB CHECK(attempt IS NULL OR length(attempt)=16), cancelled INTEGER NOT NULL DEFAULT 0 CHECK(cancelled IN (0,1)), explicit_request INTEGER NOT NULL DEFAULT 0 CHECK(explicit_request IN (0,1)), size_blocked_max INTEGER, priority_at INTEGER NOT NULL DEFAULT 0, progress_epoch INTEGER NOT NULL DEFAULT 0 CHECK(progress_epoch>=0), progress_received INTEGER NOT NULL DEFAULT 0 CHECK(progress_received>=0), progress_total INTEGER CHECK(progress_total>=progress_received), progress_phase INTEGER NOT NULL DEFAULT 0 CHECK(progress_phase BETWEEN 0 AND 4), acquisition_attempts INTEGER NOT NULL DEFAULT 0 CHECK(acquisition_attempts>=0), network_attempts INTEGER NOT NULL DEFAULT 0 CHECK(network_attempts>=0), body_completed INTEGER NOT NULL DEFAULT 0 CHECK(body_completed IN (0,1)), automatic_history INTEGER NOT NULL DEFAULT 0 CHECK(automatic_history IN (0,1)), permission_paused INTEGER NOT NULL DEFAULT 0 CHECK(permission_paused IN (0,1)), retry_not_before INTEGER NOT NULL DEFAULT 0 CHECK(retry_not_before>=0), permission_category INTEGER NOT NULL DEFAULT 3 CHECK(permission_category BETWEEN 0 AND 3), preparation_deferrals INTEGER NOT NULL
             DEFAULT 0 CHECK(preparation_deferrals>=0),
    UNIQUE(group_id_hex,message_id_hex,attachment_index),
    FOREIGN KEY(group_id_hex,message_id_hex) REFERENCES app_events(group_id_hex,message_id_hex) ON DELETE CASCADE,
    CHECK((state IN (0,1,2) AND due IS NOT NULL AND due>=0)
       OR (state IN (3,4,5) AND due IS NULL)),
    CHECK((state=1 AND attempt IS NOT NULL) OR (state<>1 AND attempt IS NULL))
);
CREATE TABLE attachment_chunk_bodies (nonce BLOB PRIMARY KEY NOT NULL CHECK(length(nonce)=16));
CREATE TABLE attachment_download_policy (
 id INTEGER PRIMARY KEY CHECK(id=1),
 automatic INTEGER NOT NULL CHECK(automatic IN (0,1)),
 retained_bytes INTEGER NOT NULL CHECK(retained_bytes>0),
 disk_reserve INTEGER NOT NULL CHECK(disk_reserve>=0),
 transfer_limit INTEGER NOT NULL CHECK(transfer_limit BETWEEN 1 AND 536870912)
);
CREATE TABLE attachment_history (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    attachment_index INTEGER NOT NULL,
    attachment_order INTEGER GENERATED ALWAYS AS (-attachment_index) VIRTUAL,
    source_message_id_hex TEXT NOT NULL,
    source_epoch INTEGER,
    sender TEXT NOT NULL,
    timeline_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    order_class INTEGER NOT NULL,
    order_primary INTEGER NOT NULL,
    order_phase INTEGER NOT NULL,
    order_at INTEGER NOT NULL,
    slot_json TEXT NOT NULL,
    visible INTEGER NOT NULL,
    PRIMARY KEY(group_id_hex,message_id_hex,attachment_index)
);
CREATE TABLE attachment_history_versions (
    group_id_hex TEXT PRIMARY KEY,
    generation BLOB NOT NULL DEFAULT (randomblob(16)),
    revision INTEGER NOT NULL DEFAULT 0,
    additions INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE "attachment_partial" (
            token BLOB PRIMARY KEY NOT NULL REFERENCES attachment_acquisition(token) ON DELETE CASCADE,
            ciphertext_digest BLOB NOT NULL CHECK(length(ciphertext_digest)=32),
            locator_digest BLOB NOT NULL CHECK(length(locator_digest)=32),
            etag TEXT NOT NULL CHECK(length(CAST(etag AS BLOB)) BETWEEN 2 AND 1024),
            total INTEGER NOT NULL CHECK(total BETWEEN 1 AND 943718400),
            received INTEGER NOT NULL DEFAULT 0 CHECK(received>=0 AND received<=total),
            expires_at INTEGER NOT NULL CHECK(expires_at>=0)
        );
CREATE TABLE attachment_partial_chunk (
 token BLOB NOT NULL REFERENCES attachment_partial(token) ON DELETE CASCADE,
 offset INTEGER NOT NULL CHECK(offset>=0),
 bytes BLOB NOT NULL CHECK(typeof(bytes)='blob' AND length(bytes) BETWEEN 1 AND 1048576),
 digest BLOB NOT NULL CHECK(length(digest)=32),
 PRIMARY KEY(token,offset)
);
CREATE TABLE attachment_partial_usage (
 id INTEGER PRIMARY KEY CHECK(id=1),
 reserved_bytes INTEGER NOT NULL DEFAULT 0 CHECK(reserved_bytes>=0)
);
INSERT INTO "attachment_partial_usage" VALUES(1,0);
CREATE TABLE attachment_removal_suppression (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    attachment_index INTEGER NOT NULL CHECK(attachment_index>=0),
    PRIMARY KEY(group_id_hex,message_id_hex,attachment_index),
    FOREIGN KEY(group_id_hex,message_id_hex) REFERENCES app_events(group_id_hex,message_id_hex) ON DELETE CASCADE
);
CREATE TABLE attachment_retention_usage (
    id INTEGER PRIMARY KEY CHECK(id=1),
    byte_count INTEGER NOT NULL DEFAULT 0 CHECK(byte_count>=0)
);
INSERT INTO "attachment_retention_usage" VALUES(1,0);
CREATE TABLE attachment_worker_demand (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    attachment_index INTEGER NOT NULL,
    generation BLOB NOT NULL CHECK(length(generation)=16),
    PRIMARY KEY(group_id_hex,message_id_hex,attachment_index),
    FOREIGN KEY(group_id_hex,message_id_hex,attachment_index)
        REFERENCES attachment_history(group_id_hex,message_id_hex,attachment_index) ON DELETE CASCADE,
    FOREIGN KEY(group_id_hex,message_id_hex) REFERENCES app_events(group_id_hex,message_id_hex) ON DELETE CASCADE
);
CREATE TABLE avatar_access (
            token BLOB PRIMARY KEY NOT NULL REFERENCES avatar_assets(token) ON DELETE CASCADE ON UPDATE CASCADE,
            accessed INTEGER NOT NULL CHECK(typeof(accessed) = 'integer' AND accessed >= 0)
        );
CREATE TABLE avatar_acquisition (
            token BLOB PRIMARY KEY NOT NULL REFERENCES avatar_assets(token) ON DELETE CASCADE,
            descriptor BLOB NOT NULL CHECK(typeof(descriptor) = 'blob' AND length(descriptor) BETWEEN 1 AND 16384),
            state INTEGER NOT NULL DEFAULT 1 CHECK(state IN (0, 1, 2, 3, 4)),
            due INTEGER CHECK(due IS NULL OR (typeof(due) = 'integer' AND due >= 0)),
            failures INTEGER NOT NULL DEFAULT 0 CHECK(typeof(failures) = 'integer' AND failures BETWEEN 0 AND 16),
            priority INTEGER NOT NULL DEFAULT 0 CHECK(priority IN (0, 1)),
            attempt BLOB CHECK(attempt IS NULL OR (typeof(attempt) = 'blob' AND length(attempt) = 16))
        );
CREATE TABLE avatar_acquisition_bootstrap (
            group_id_hex TEXT PRIMARY KEY NOT NULL REFERENCES chat_list_rows(group_id_hex) ON DELETE CASCADE
        );
CREATE TABLE avatar_assets (
            owner_key TEXT PRIMARY KEY NOT NULL CHECK(length(owner_key) BETWEEN 1 AND 512),
            source_key TEXT NOT NULL CHECK(length(source_key) BETWEEN 1 AND 512),
            token BLOB NOT NULL UNIQUE CHECK(length(token) = 16),
            content_revision INTEGER NOT NULL DEFAULT 0
                CHECK(typeof(content_revision) = 'integer' AND content_revision >= 0),
            bytes BLOB CHECK(bytes IS NULL OR
                (typeof(bytes) = 'blob' AND length(bytes) BETWEEN 1 AND 10485760)),
            digest BLOB CHECK(digest IS NULL OR
                (typeof(digest) = 'blob' AND length(digest) = 32)),
            media_type TEXT,
            width INTEGER,
            height INTEGER,
            refresh_at INTEGER CHECK(refresh_at IS NULL OR
                (typeof(refresh_at) = 'integer' AND refresh_at >= 0)),
            CHECK((bytes IS NULL AND digest IS NULL AND media_type IS NULL AND width IS NULL
                    AND height IS NULL AND refresh_at IS NULL)
                OR (bytes IS NOT NULL AND digest IS NOT NULL AND media_type IS NOT NULL
                    AND media_type IN ('image/png', 'image/jpeg', 'image/gif', 'image/webp')
                    AND width IS NOT NULL AND height IS NOT NULL
                    AND typeof(width) = 'integer' AND typeof(height) = 'integer'
                    AND width BETWEEN 1 AND 4096 AND height BETWEEN 1 AND 4096))
        );
CREATE TABLE avatar_cache_meta (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            access_seq INTEGER NOT NULL DEFAULT 0
                CHECK(typeof(access_seq) = 'integer' AND access_seq >= 0)
        );
INSERT INTO "avatar_cache_meta" VALUES(1,0);
CREATE TABLE avatar_identity_demand (
            owner_key TEXT PRIMARY KEY NOT NULL,
            group_id_hex TEXT NOT NULL REFERENCES chat_list_rows(group_id_hex) ON DELETE CASCADE,
            member_id_hex TEXT NOT NULL,
            profile_epoch BLOB NOT NULL CHECK(typeof(profile_epoch) = 'blob' AND length(profile_epoch) = 16),
            profile_revision INTEGER NOT NULL CHECK(typeof(profile_revision) = 'integer' AND profile_revision >= 0),
            accessed INTEGER NOT NULL CHECK(typeof(accessed) = 'integer' AND accessed >= 0)
        );
CREATE TABLE blocked_notification_suppressions (group_id TEXT NOT NULL, message_id TEXT NOT NULL, PRIMARY KEY(group_id,message_id));
CREATE TABLE blocked_pending_invites (group_id_hex TEXT PRIMARY KEY);
CREATE TABLE blocked_welcome_dismissals (message_id TEXT PRIMARY KEY);
CREATE TABLE cgka_account_device_signers (
    marmot_identity BLOB PRIMARY KEY,
    record BLOB NOT NULL
);
CREATE TABLE cgka_convergence_passes (
    group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE,
    record BLOB NOT NULL
);
CREATE TABLE "cgka_convergence_policies" (
    group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE,
    policy BLOB NOT NULL
);
CREATE TABLE cgka_deferred_peel_generations (
    group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE,
    record BLOB NOT NULL
);
CREATE TABLE cgka_disband_candidates (
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    commit_id BLOB NOT NULL,
    record BLOB NOT NULL,
    PRIMARY KEY (group_id, commit_id)
);
CREATE TABLE cgka_disband_requests (
    group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE,
    record BLOB NOT NULL
);
CREATE TABLE cgka_disband_tombstones (
    group_id BLOB PRIMARY KEY,
    record BLOB NOT NULL
);
CREATE TABLE cgka_features (
    feature TEXT PRIMARY KEY,
    requirement BLOB NOT NULL
);
CREATE TABLE cgka_group_evolutions (
    id BLOB PRIMARY KEY,
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    insert_order INTEGER NOT NULL UNIQUE,
    record BLOB NOT NULL
);
CREATE TABLE cgka_group_maintenance (
    group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE,
    record BLOB NOT NULL
);
CREATE TABLE "cgka_group_snapshots" (
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    snapshot BLOB NOT NULL,
    PRIMARY KEY (group_id, name)
);
INSERT INTO "cgka_group_snapshots" VALUES(X'01010101','master-snapshot',X'4d444b530002416e7b226964223a5b312c312c312c315d2c226e616d65223a2273616d706c65222c226465736372697074696f6e223a2264657363222c2265706f6368223a372c226d656d62657273223a5b7b226964223a5b302c302c302c305d2c2263726564656e7469616c223a5b302c302c302c302c302c302c302c305d7d2c7b226964223a5b312c312c312c315d2c2263726564656e7469616c223a5b312c312c312c312c312c312c312c315d7d5d2c2272657175697265645f6361706162696c6974696573223a7b2270726f706f73616c73223a5b5d2c22657874656e73696f6e73223a5b5d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d2c2270726f746f636f6c5f70726f66696c65223a226c6567616379222c2272656d6f766564223a66616c73652c22756e7265636f76657261626c65223a66616c73652c226a6f696e5f65706f6368223a302c226c6f63616c5f636f70795f696e7374616c6c5f65706f6368223a307d01000100408e040000000040407b2270726f706f73616c73223a5b31305d2c22657874656e73696f6e73223a5b34325d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d040101010140407b2270726f706f73616c73223a5b31305d2c22657874656e73696f6e73223a5b34325d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d000000');
INSERT INTO "cgka_group_snapshots" VALUES(X'02020202','master-snapshot',X'4d444b530002416e7b226964223a5b322c322c322c325d2c226e616d65223a2273616d706c65222c226465736372697074696f6e223a2264657363222c2265706f6368223a372c226d656d62657273223a5b7b226964223a5b302c302c302c305d2c2263726564656e7469616c223a5b302c302c302c302c302c302c302c305d7d2c7b226964223a5b312c312c312c315d2c2263726564656e7469616c223a5b312c312c312c312c312c312c312c315d7d5d2c2272657175697265645f6361706162696c6974696573223a7b2270726f706f73616c73223a5b5d2c22657874656e73696f6e73223a5b5d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d2c2270726f746f636f6c5f70726f66696c65223a226c6567616379222c2272656d6f766564223a66616c73652c22756e7265636f76657261626c65223a66616c73652c226a6f696e5f65706f6368223a302c226c6f63616c5f636f70795f696e7374616c6c5f65706f6368223a307d01000100408e040000000040407b2270726f706f73616c73223a5b31305d2c22657874656e73696f6e73223a5b34325d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d040101010140407b2270726f706f73616c73223a5b31305d2c22657874656e73696f6e73223a5b34325d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d000000');
CREATE TABLE cgka_group_state_checkpoints (
    group_id BLOB NOT NULL,
    checkpoint_id TEXT NOT NULL,
    resulting_epoch INTEGER NOT NULL,
    checkpoint BLOB NOT NULL,
    PRIMARY KEY (group_id, checkpoint_id),
    FOREIGN KEY (group_id) REFERENCES cgka_groups(id) ON DELETE CASCADE
);
INSERT INTO "cgka_group_state_checkpoints" VALUES(X'01010101','master-checkpoint',7,X'4d444b530002416e7b226964223a5b312c312c312c315d2c226e616d65223a2273616d706c65222c226465736372697074696f6e223a2264657363222c2265706f6368223a372c226d656d62657273223a5b7b226964223a5b302c302c302c305d2c2263726564656e7469616c223a5b302c302c302c302c302c302c302c305d7d2c7b226964223a5b312c312c312c315d2c2263726564656e7469616c223a5b312c312c312c312c312c312c312c315d7d5d2c2272657175697265645f6361706162696c6974696573223a7b2270726f706f73616c73223a5b5d2c22657874656e73696f6e73223a5b5d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d2c2270726f746f636f6c5f70726f66696c65223a226c6567616379222c2272656d6f766564223a66616c73652c22756e7265636f76657261626c65223a66616c73652c226a6f696e5f65706f6368223a302c226c6f63616c5f636f70795f696e7374616c6c5f65706f6368223a307d0000408e040000000040407b2270726f706f73616c73223a5b31305d2c22657874656e73696f6e73223a5b34325d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d040101010140407b2270726f706f73616c73223a5b31305d2c22657874656e73696f6e73223a5b34325d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d000000');
INSERT INTO "cgka_group_state_checkpoints" VALUES(X'02020202','master-checkpoint',7,X'4d444b530002416e7b226964223a5b322c322c322c325d2c226e616d65223a2273616d706c65222c226465736372697074696f6e223a2264657363222c2265706f6368223a372c226d656d62657273223a5b7b226964223a5b302c302c302c305d2c2263726564656e7469616c223a5b302c302c302c302c302c302c302c305d7d2c7b226964223a5b312c312c312c315d2c2263726564656e7469616c223a5b312c312c312c312c312c312c312c315d7d5d2c2272657175697265645f6361706162696c6974696573223a7b2270726f706f73616c73223a5b5d2c22657874656e73696f6e73223a5b5d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d2c2270726f746f636f6c5f70726f66696c65223a226c6567616379222c2272656d6f766564223a66616c73652c22756e7265636f76657261626c65223a66616c73652c226a6f696e5f65706f6368223a302c226c6f63616c5f636f70795f696e7374616c6c5f65706f6368223a307d0000408e040000000040407b2270726f706f73616c73223a5b31305d2c22657874656e73696f6e73223a5b34325d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d040101010140407b2270726f706f73616c73223a5b31305d2c22657874656e73696f6e73223a5b34325d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d000000');
CREATE TABLE cgka_groups (
    id BLOB PRIMARY KEY,
    epoch INTEGER NOT NULL,
    record BLOB NOT NULL
);
INSERT INTO "cgka_groups" VALUES(X'01010101',7,X'7b226964223a5b312c312c312c315d2c226e616d65223a2273616d706c65222c226465736372697074696f6e223a2264657363222c2265706f6368223a372c226d656d62657273223a5b7b226964223a5b302c302c302c305d2c2263726564656e7469616c223a5b302c302c302c302c302c302c302c305d7d2c7b226964223a5b312c312c312c315d2c2263726564656e7469616c223a5b312c312c312c312c312c312c312c315d7d5d2c2272657175697265645f6361706162696c6974696573223a7b2270726f706f73616c73223a5b5d2c22657874656e73696f6e73223a5b5d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d2c2270726f746f636f6c5f70726f66696c65223a226c6567616379222c2272656d6f766564223a66616c73652c22756e7265636f76657261626c65223a66616c73652c226a6f696e5f65706f6368223a302c226c6f63616c5f636f70795f696e7374616c6c5f65706f6368223a307d');
INSERT INTO "cgka_groups" VALUES(X'02020202',7,X'7b226964223a5b322c322c322c325d2c226e616d65223a2273616d706c65222c226465736372697074696f6e223a2264657363222c2265706f6368223a372c226d656d62657273223a5b7b226964223a5b302c302c302c305d2c2263726564656e7469616c223a5b302c302c302c302c302c302c302c305d7d2c7b226964223a5b312c312c312c315d2c2263726564656e7469616c223a5b312c312c312c312c312c312c312c315d7d5d2c2272657175697265645f6361706162696c6974696573223a7b2270726f706f73616c73223a5b5d2c22657874656e73696f6e73223a5b5d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d2c2270726f746f636f6c5f70726f66696c65223a226c6567616379222c2272656d6f766564223a66616c73652c22756e7265636f76657261626c65223a66616c73652c226a6f696e5f65706f6368223a302c226c6f63616c5f636f70795f696e7374616c6c5f65706f6368223a307d');
CREATE TABLE cgka_ingress_dedup (
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    id BLOB NOT NULL UNIQUE
);
CREATE TABLE cgka_key_package_lifecycle (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    record BLOB NOT NULL
);
CREATE TABLE cgka_leave_requests (
    group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE,
    record BLOB NOT NULL
);
CREATE TABLE cgka_maintenance_obligations (
    id BLOB PRIMARY KEY,
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    insert_order INTEGER NOT NULL UNIQUE,
    record BLOB NOT NULL
);
CREATE TABLE cgka_maintenance_settings (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    periodic_policy INTEGER NOT NULL
);
INSERT INTO "cgka_maintenance_settings" VALUES(1,1);
CREATE TABLE "cgka_member_capabilities" (
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    member_id BLOB NOT NULL,
    capabilities BLOB NOT NULL,
    PRIMARY KEY (group_id, member_id)
);
INSERT INTO "cgka_member_capabilities" VALUES(X'01010101',X'00000000',X'7b2270726f706f73616c73223a5b31305d2c22657874656e73696f6e73223a5b34325d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d');
INSERT INTO "cgka_member_capabilities" VALUES(X'01010101',X'01010101',X'7b2270726f706f73616c73223a5b31305d2c22657874656e73696f6e73223a5b34325d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d');
INSERT INTO "cgka_member_capabilities" VALUES(X'02020202',X'00000000',X'7b2270726f706f73616c73223a5b31305d2c22657874656e73696f6e73223a5b34325d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d');
INSERT INTO "cgka_member_capabilities" VALUES(X'02020202',X'01010101',X'7b2270726f706f73616c73223a5b31305d2c22657874656e73696f6e73223a5b34325d2c226170705f636f6d706f6e656e7473223a7b22696473223a5b5d7d7d');
CREATE TABLE cgka_member_validation_cache (
    group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE,
    marker BLOB NOT NULL
);
CREATE TABLE "cgka_messages" (
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    id BLOB NOT NULL UNIQUE,
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    epoch INTEGER NOT NULL,
    state INTEGER NOT NULL,
    storage_format INTEGER NOT NULL DEFAULT 1,
    record BLOB,
    payload BLOB,
    deferred_peel BLOB,
    CHECK (
        (storage_format = 1 AND record IS NOT NULL AND payload IS NULL)
        OR
        (storage_format = 2 AND record IS NULL AND payload IS NOT NULL)
    )
);
CREATE TABLE cgka_outbound_fanout (
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id BLOB NOT NULL UNIQUE,
    group_id BLOB,
    record BLOB NOT NULL,
    FOREIGN KEY(group_id) REFERENCES cgka_groups(id) ON DELETE CASCADE
);
CREATE TABLE cgka_own_commit_intents (
    commit_id BLOB PRIMARY KEY,
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    insert_order INTEGER NOT NULL UNIQUE,
    record BLOB NOT NULL
);
CREATE TABLE cgka_processed_transport_ids (
    id       BLOB PRIMARY KEY,
    group_id BLOB NOT NULL
             REFERENCES cgka_groups(id) ON DELETE CASCADE
);
CREATE TABLE "cgka_queued_outbound" (
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    id BLOB NOT NULL UNIQUE,
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    created_at_ms INTEGER NOT NULL,
    record BLOB NOT NULL
);
CREATE TABLE cgka_released_transport_receipts (
    id BLOB PRIMARY KEY,
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    epoch INTEGER NOT NULL CHECK (epoch >= 0)
, inventory_invalidated INTEGER NOT NULL DEFAULT 0 CHECK(inventory_invalidated IN (0,1)));
CREATE TABLE cgka_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at_unix_seconds INTEGER NOT NULL
);
INSERT INTO "cgka_schema_migrations" VALUES(1,'0001_initial_schema',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(2,'0002_account_device_signers',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(3,'0003_group_foreign_keys',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(4,'0004_app_timeline',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(5,'0005_account_projection',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(6,'0006_chat_list_projection',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(7,'0007_timeline_projection_indexes',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(8,'0008_timeline_invalidation_status',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(9,'0009_app_event_source_epoch',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(10,'0010_encrypted_media_epoch_secrets',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(11,'0011_chat_list_avatar_url',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(12,'0012_app_event_origin_commit',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(13,'0013_app_event_kind_order_index',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(14,'0014_message_timeline_reply_lookup_index',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(15,'0015_member_validation_cache',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(16,'0016_leave_requests',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(17,'0017_notification_settings_default_on',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(18,'0018_account_group_self_membership',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(19,'0019_chat_list_unread_mention_count',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(20,'0020_message_modifier_edges',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(21,'0021_push_token_owner_signatures',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(22,'0022_chat_list_self_membership',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(23,'0023_chat_list_projection_version',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(24,'0024_pending_welcome_delivery',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(25,'0025_chat_notification_settings',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(26,'0026_message_drafts',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(27,'0027_app_event_moderation_grant',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(28,'0028_ingress_dedup',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(29,'0029_app_event_retention_decision',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(30,'0030_prior_nostr_routes',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(31,'0031_outbound_fanout',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(32,'0032_encrypted_media_secret_references',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(33,'0033_push_registration_gossip_outbox',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(34,'0034_maintenance_publication',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(35,'0035_durable_convergence_passes',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(36,'0036_agent_stream_publisher_sequences',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(37,'0037_chat_list_semantic_timestamps',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(38,'0038_chat_list_interaction_state',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(39,'0039_chat_pin_positions',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(40,'0040_disband_requests',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(41,'0041_secure_delete_checkpoint_intents',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(42,'0042_group_state_checkpoints',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(43,'0043_transport_group_routes',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(44,'0044_local_group_deletion_frontiers',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(45,'0045_timeline_canonical_order',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(46,'0046_message_group_state_epoch_index',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(47,'0047_normalized_message_records',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(48,'0048_deferred_peel_generations',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(49,'0049_pending_invite_index',1791862220);
INSERT INTO "cgka_schema_migrations" VALUES(50,'0050_direct_conversation_members',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(51,'0051_prepared_group_image_uploads',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(52,'0052_epoch_backfill_intents',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(53,'0053_account_delivery_recovery',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(54,'0054_transport_reconciliation_items',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(55,'0055_epoch_stall_evidence',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(56,'0056_chat_list_accepted_activity_high_water',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(57,'0057_openmls_values_msgpack',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(58,'0058_processed_transport_ids',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(59,'0059_chat_list_unread_membership',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(60,'0060_released_transport_receipts',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(61,'0061_transport_reconciliation_replay_cursor',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(62,'0062_chat_list_preview_indexes',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(63,'0063_query_indexes',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(64,'0064_own_commit_intents',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(65,'0065_chat_presentation',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(66,'0066_chat_presentation_maintenance',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(67,'0067_invitation_recovery',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(68,'0068_media_epoch_index',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(69,'0069_chat_readiness_index',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(70,'0070_forgotten_groups',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(71,'0071_group_reset_cutoff',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(72,'0072_chat_list_pages',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(73,'0073_message_draft_revisions',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(74,'0074_chat_list_invite_attention',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(75,'0075_user_blocks',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(76,'0076_accepted_edits',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(77,'0077_avatar_cache',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(78,'0078_avatar_acquisition',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(79,'0079_content_reports',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(80,'0080_avatar_target_lookup',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(81,'0081_attachment_history',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(82,'0082_deletion_provenance',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(83,'0083_attachment_acquisition',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(84,'0084_attachment_worker_demand',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(85,'0085_attachment_partials',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(86,'0086_attachment_controls',1791862221);
INSERT INTO "cgka_schema_migrations" VALUES(87,'0087_attachment_automatic_history',1791862222);
INSERT INTO "cgka_schema_migrations" VALUES(88,'0088_draft_attachment_descriptors',1791862222);
INSERT INTO "cgka_schema_migrations" VALUES(89,'0089_local_submissions',1791862222);
INSERT INTO "cgka_schema_migrations" VALUES(90,'0090_poll_response_edges',1791862222);
INSERT INTO "cgka_schema_migrations" VALUES(91,'0091_account_local_identity',1791862222);
INSERT INTO "cgka_schema_migrations" VALUES(92,'0092_account_recovery_owner',1791862222);
INSERT INTO "cgka_schema_migrations" VALUES(93,'0093_recovery_route_snapshot',1791862222);
INSERT INTO "cgka_schema_migrations" VALUES(94,'0094_qualified_stall_observations',1791862222);
INSERT INTO "cgka_schema_migrations" VALUES(95,'0095_recovery_comparison',1791862222);
INSERT INTO "cgka_schema_migrations" VALUES(96,'0096_account_delivery_spill',1791862222);
INSERT INTO "cgka_schema_migrations" VALUES(97,'0097_loss_created_at_bound',1791862222);
INSERT INTO "cgka_schema_migrations" VALUES(98,'0098_recovery_history_notices',1791862222);
INSERT INTO "cgka_schema_migrations" VALUES(99,'0099_attachment_preparation_deferrals',1791862223);
INSERT INTO "cgka_schema_migrations" VALUES(100,'0100_attachment_explicit_priority',1791862223);
INSERT INTO "cgka_schema_migrations" VALUES(101,'0101_outgoing_attachment_uploads',1791862223);
INSERT INTO "cgka_schema_migrations" VALUES(102,'0102_attachment_emoji_role',1791862223);
INSERT INTO "cgka_schema_migrations" VALUES(103,'0103_outgoing_attachment_upload_bodies',1791862223);
INSERT INTO "cgka_schema_migrations" VALUES(104,'0104_file_attachment_retention',1791862223);
INSERT INTO "cgka_schema_migrations" VALUES(105,'0105_file_attachment_partials',1791862223);
INSERT INTO "cgka_schema_migrations" VALUES(106,'0106_retained_attachment_chunks',1791862223);
INSERT INTO "cgka_schema_migrations" VALUES(107,'0107_moderation_report_outbox',1791862223);
CREATE TABLE cgka_transport_fanout (
    id BLOB PRIMARY KEY,
    group_id BLOB REFERENCES cgka_groups(id) ON DELETE CASCADE,
    insert_order INTEGER NOT NULL UNIQUE,
    record BLOB NOT NULL
);
CREATE TABLE cgka_transport_group_routes (
    transport_group_id BLOB PRIMARY KEY,
    group_id BLOB NOT NULL,
    source_epoch INTEGER NOT NULL,
    FOREIGN KEY (group_id) REFERENCES cgka_groups(id) ON DELETE CASCADE
);
CREATE TABLE cgka_welcomes (
    message_id BLOB PRIMARY KEY,
    group_id BLOB NOT NULL,
    record BLOB NOT NULL
);
CREATE TABLE chat_list_navigation_meta (
             id INTEGER PRIMARY KEY CHECK(id = 1),
             revision INTEGER NOT NULL DEFAULT 0
                 CHECK(typeof(revision) = 'integer' AND revision >= 0),
             pin_rewrite_in_progress INTEGER NOT NULL DEFAULT 0
                 CHECK(pin_rewrite_in_progress IN (0, 1))
         );
INSERT INTO "chat_list_navigation_meta" VALUES(1,0,0);
CREATE TABLE chat_list_projection_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    mention_counts_version INTEGER NOT NULL DEFAULT 0
);
INSERT INTO "chat_list_projection_meta" VALUES(1,0);
CREATE TABLE chat_list_rows (
    group_id_hex TEXT PRIMARY KEY NOT NULL,
    archived INTEGER NOT NULL DEFAULT 0,
    pending_confirmation INTEGER NOT NULL DEFAULT 0,
    title TEXT NOT NULL DEFAULT '',
    group_name TEXT NOT NULL DEFAULT '',
    avatar_image_hash_hex TEXT NOT NULL DEFAULT '',
    avatar_image_key_hex TEXT NOT NULL DEFAULT '',
    avatar_image_nonce_hex TEXT NOT NULL DEFAULT '',
    avatar_image_upload_key_hex TEXT NOT NULL DEFAULT '',
    avatar_media_type TEXT,
    last_message_id_hex TEXT,
    last_message_sender TEXT,
    last_message_preview TEXT,
    last_message_kind INTEGER,
    last_message_timeline_at INTEGER,
    last_message_deleted INTEGER NOT NULL DEFAULT 0,
    unread_count INTEGER NOT NULL DEFAULT 0,
    first_unread_message_id_hex TEXT,
    last_read_message_id_hex TEXT,
    last_read_timeline_at INTEGER,
    updated_at INTEGER NOT NULL, avatar_url TEXT, unread_mention_count INTEGER NOT NULL DEFAULT 0, self_membership TEXT NOT NULL DEFAULT 'member', conversation_created_at INTEGER NOT NULL DEFAULT 0, activity_sort_at INTEGER NOT NULL DEFAULT 0, retained_activity_sort_at INTEGER NOT NULL DEFAULT 0, manually_marked_unread INTEGER NOT NULL DEFAULT 0, last_message_media_json TEXT, last_message_delivery_state TEXT NOT NULL DEFAULT 'not_applicable', accepted_activity_insert_order INTEGER NOT NULL DEFAULT 0, presentation_json BLOB, presentation_row_epoch BLOB NOT NULL DEFAULT X'', presentation_source_revision INTEGER NOT NULL DEFAULT 0
    CHECK(typeof(presentation_source_revision) = 'integer' AND presentation_source_revision >= 0), presentation_applied_source_revision INTEGER NOT NULL DEFAULT -1
    CHECK(typeof(presentation_applied_source_revision) = 'integer' AND presentation_applied_source_revision >= -1), list_scope INTEGER NOT NULL DEFAULT 0, list_unread INTEGER NOT NULL DEFAULT 0, list_pin_ordinal INTEGER NOT NULL DEFAULT -1, list_pin_position INTEGER, list_pin_section INTEGER
             GENERATED ALWAYS AS (list_pin_ordinal < 0) VIRTUAL, list_pin_order INTEGER
             GENERATED ALWAYS AS (max(list_pin_ordinal, 0)) VIRTUAL, list_activity_order INTEGER
             GENERATED ALWAYS AS (-max(activity_sort_at, 0)) VIRTUAL, list_pending_invite INTEGER NOT NULL DEFAULT 0, last_message_deletion_source TEXT NOT NULL DEFAULT 'unknown',
    FOREIGN KEY (group_id_hex) REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);
CREATE TABLE chat_list_unread_dirty_messages (
    group_id_hex   TEXT NOT NULL
                   REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
    message_id_hex TEXT NOT NULL,
    PRIMARY KEY (group_id_hex, message_id_hex)
);
CREATE TABLE chat_list_unread_messages (
    group_id_hex           TEXT NOT NULL
                           REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
    message_id_hex         TEXT NOT NULL,
    mentions_local         INTEGER NOT NULL CHECK (mentions_local IN (0, 1)),
    timeline_order_class   INTEGER NOT NULL,
    timeline_order_primary INTEGER NOT NULL,
    timeline_order_phase   INTEGER NOT NULL,
    timeline_order_at      INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, message_id_hex)
);
CREATE TABLE chat_list_unread_ready_groups (
    group_id_hex TEXT PRIMARY KEY
                 REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);
CREATE TABLE chat_notification_settings (
    group_id_hex TEXT PRIMARY KEY NOT NULL,
    muted_until_ms INTEGER,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY (group_id_hex) REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);
CREATE TABLE chat_pin_positions (
    group_id_hex TEXT PRIMARY KEY NOT NULL,
    ordinal INTEGER NOT NULL UNIQUE CHECK (ordinal >= 0),
    FOREIGN KEY (group_id_hex) REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);
CREATE TABLE chat_presentation_checkpoint (
        id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL DEFAULT 0
            CHECK(typeof(generation)='integer' AND generation>=0), state BLOB);
INSERT INTO "chat_presentation_checkpoint" VALUES(1,0,NULL);
CREATE TABLE chat_presentation_dependencies (
    group_id_hex TEXT NOT NULL REFERENCES chat_list_rows(group_id_hex) ON DELETE CASCADE,
    member_id_hex TEXT NOT NULL,
    roles INTEGER NOT NULL CHECK(roles BETWEEN 1 AND 3),
    PRIMARY KEY(group_id_hex, member_id_hex)
);
CREATE TABLE chat_presentation_members (
    group_id_hex TEXT NOT NULL REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
    member_id_hex TEXT NOT NULL,
    PRIMARY KEY(group_id_hex, member_id_hex)
);
CREATE TABLE chat_presentation_meta (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    store_epoch BLOB NOT NULL CHECK(length(store_epoch) = 16),
    revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(revision) = 'integer' AND revision >= 0)
);
INSERT INTO "chat_presentation_meta" VALUES(1,X'02ad1a7ada91d0165e78fecf10035068',0);
CREATE TABLE chat_presentation_row_work (
            group_id_hex TEXT PRIMARY KEY REFERENCES account_groups(group_id_hex) ON DELETE CASCADE);
CREATE TABLE content_expired_targets (group_id_hex TEXT NOT NULL, message_id_hex TEXT NOT NULL, PRIMARY KEY(group_id_hex,message_id_hex));
CREATE TABLE content_pruned_controls (group_id_hex TEXT NOT NULL, message_id_hex TEXT NOT NULL, PRIMARY KEY(group_id_hex,message_id_hex));
CREATE TABLE content_report_backfill (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1), after_order INTEGER NOT NULL, through_order INTEGER NOT NULL
);
INSERT INTO "content_report_backfill" VALUES(1,0,0);
CREATE TABLE content_reports (
    group_id_hex TEXT NOT NULL, report_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL, message_author TEXT NOT NULL,
    reporter TEXT NOT NULL, reason TEXT NOT NULL, reported_at INTEGER NOT NULL,
    PRIMARY KEY(group_id_hex, report_id_hex),
    FOREIGN KEY(group_id_hex, report_id_hex) REFERENCES app_events(group_id_hex, message_id_hex) ON DELETE CASCADE
);
CREATE TABLE conversation_read_state (
    group_id_hex TEXT PRIMARY KEY NOT NULL,
    last_read_message_id_hex TEXT,
    last_read_timeline_at INTEGER,
    initialized_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL, manually_marked_unread INTEGER NOT NULL DEFAULT 0, last_read_order_class INTEGER, last_read_order_primary INTEGER, last_read_order_phase INTEGER, last_read_order_at INTEGER,
    FOREIGN KEY (group_id_hex) REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);
CREATE TABLE direct_conversation_members (
    group_id_hex TEXT NOT NULL,
    member_id_hex TEXT NOT NULL,
    PRIMARY KEY (group_id_hex, member_id_hex),
    FOREIGN KEY (group_id_hex) REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);
CREATE TABLE encrypted_media_epoch_secret_references (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    component_id INTEGER NOT NULL,
    source_epoch INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, message_id_hex, component_id, source_epoch),
    FOREIGN KEY (group_id_hex, message_id_hex)
        REFERENCES app_events (group_id_hex, message_id_hex) ON DELETE CASCADE
);
CREATE TABLE encrypted_media_epoch_secret_retirement_watermarks (
    group_id_hex TEXT PRIMARY KEY,
    retired_through_epoch INTEGER NOT NULL CHECK(retired_through_epoch >= 0),
    retired_at_unix_seconds INTEGER NOT NULL CHECK(retired_at_unix_seconds >= 0)
) WITHOUT ROWID;
CREATE TABLE encrypted_media_epoch_secrets (
    group_id_hex TEXT NOT NULL,
    component_id INTEGER NOT NULL,
    source_epoch INTEGER NOT NULL,
    secret BLOB NOT NULL,
    created_at_unix_seconds INTEGER NOT NULL, retention_managed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id_hex, component_id, source_epoch)
);
CREATE TABLE group_push_token_tombstones (
    group_id_hex TEXT NOT NULL,
    member_id_hex TEXT NOT NULL,
    leaf_index INTEGER NOT NULL,
    platform INTEGER NOT NULL,
    server_pubkey_hex TEXT NOT NULL,
    owner_ts INTEGER NOT NULL,
    record_digest TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, member_id_hex, leaf_index, platform, server_pubkey_hex)
);
CREATE TABLE group_push_tokens (
    group_id_hex TEXT NOT NULL,
    member_id_hex TEXT NOT NULL,
    leaf_index INTEGER NOT NULL,
    platform INTEGER NOT NULL,
    token_fingerprint TEXT NOT NULL,
    server_pubkey_hex TEXT NOT NULL,
    relay_hint TEXT,
    encrypted_token BLOB NOT NULL,
    owner_ts INTEGER NOT NULL,
    owner_sig TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, member_id_hex, leaf_index, platform, server_pubkey_hex)
);
CREATE TABLE local_group_deletion_frontiers (
    group_id_hex TEXT PRIMARY KEY NOT NULL,
    message_insert_order INTEGER NOT NULL CHECK(message_insert_order >= 0),
    prior_nostr_routes_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE local_message_submissions (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id_hex TEXT NOT NULL REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
            client_token TEXT NOT NULL CHECK(length(client_token) BETWEEN 1 AND 128),
            message_id_hex TEXT NOT NULL,
            request_hash BLOB NOT NULL CHECK(length(request_hash) = 32),
            payload_hash BLOB NOT NULL CHECK(length(payload_hash) = 32),
            payload BLOB,
            request_json TEXT,
            state INTEGER NOT NULL DEFAULT 0 CHECK(state IN (0, 1, 3)),
            outcome_json TEXT,
            UNIQUE(group_id_hex, client_token),
            UNIQUE(group_id_hex, message_id_hex)
        );
CREATE TABLE locally_forgotten_groups (group_id BLOB PRIMARY KEY NOT NULL, forgotten_at INTEGER NOT NULL DEFAULT 0 CHECK(forgotten_at >= 0), awaiting_welcome INTEGER NOT NULL DEFAULT 1 CHECK(awaiting_welcome IN (0, 1)));
CREATE TABLE message_draft_attachments (
    group_id_hex TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    attachment_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    media_type TEXT NOT NULL,
    plaintext BLOB NOT NULL,
    dim TEXT,
    thumbhash TEXT,
    duration_seconds REAL,
    waveform_samples_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (group_id_hex, position),
    UNIQUE (group_id_hex, attachment_id),
    FOREIGN KEY (group_id_hex) REFERENCES message_drafts(group_id_hex) ON DELETE CASCADE
);
CREATE TABLE message_draft_revision_clock (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            revision INTEGER NOT NULL CHECK(typeof(revision) = 'integer' AND revision >= 0)
        );
INSERT INTO "message_draft_revision_clock" VALUES(1,0);
CREATE TABLE message_draft_revisions (
            group_id_hex TEXT PRIMARY KEY REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
            revision INTEGER NOT NULL CHECK(revision > 0)
        );
CREATE TABLE message_draft_submissions (
            group_id_hex TEXT PRIMARY KEY REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
            revision INTEGER NOT NULL,
            app_event_id TEXT NOT NULL,
            payload_hash BLOB NOT NULL CHECK(length(payload_hash) = 32)
        );
CREATE TABLE message_drafts (
    group_id_hex TEXT PRIMARY KEY NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    reply_to_message_id_hex TEXT
        CHECK (
            reply_to_message_id_hex IS NULL OR (
                length(reply_to_message_id_hex) = 64
                AND reply_to_message_id_hex NOT GLOB '*[^0-9a-f]*'
            )
        ),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY (group_id_hex) REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);
CREATE TABLE message_modifier_edges (
    group_id_hex TEXT NOT NULL,
    modifier_message_id_hex TEXT NOT NULL,
    target_message_id_hex TEXT NOT NULL,
    kind INTEGER NOT NULL,
    sender TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, modifier_message_id_hex, target_message_id_hex),
    FOREIGN KEY (group_id_hex, modifier_message_id_hex)
        REFERENCES app_events (group_id_hex, message_id_hex) ON DELETE CASCADE
);
CREATE TABLE message_timeline (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    source_message_id_hex TEXT,
    direction TEXT NOT NULL,
    sender TEXT NOT NULL,
    plaintext TEXT NOT NULL,
    kind INTEGER NOT NULL,
    tags_json TEXT NOT NULL,
    timeline_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    reply_to_message_id_hex TEXT,
    media_json TEXT,
    agent_stream_json TEXT,
    reactions_json TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    deleted_by_message_id_hex TEXT, invalidation_status TEXT, source_epoch INTEGER, timeline_order_class INTEGER GENERATED ALWAYS AS (
    CASE
        WHEN source_epoch IS NOT NULL THEN 1
        WHEN source_message_id_hex IS NULL THEN 2
        ELSE 0
    END
) VIRTUAL, timeline_order_primary INTEGER GENERATED ALWAYS AS (
    CASE
        WHEN source_epoch IS NOT NULL THEN source_epoch
        ELSE timeline_at
    END
) VIRTUAL, timeline_order_phase INTEGER GENERATED ALWAYS AS (
    CASE
        WHEN kind = 1210
         AND source_message_id_hex IS NULL
         AND source_epoch IS NOT NULL THEN 0
        ELSE 1
    END
) VIRTUAL, timeline_order_at INTEGER GENERATED ALWAYS AS (
    CASE
        WHEN kind = 1210
         AND source_message_id_hex IS NULL
         AND source_epoch IS NOT NULL THEN 0
        ELSE timeline_at
    END
) VIRTUAL, edit_json TEXT, deletion_source TEXT NOT NULL DEFAULT 'unknown',
    PRIMARY KEY (group_id_hex, message_id_hex)
);
CREATE TABLE moderation_report_outbox (
    report_id TEXT PRIMARY KEY NOT NULL CHECK(length(report_id) = 32),
    dedupe_key TEXT NOT NULL CHECK(length(dedupe_key) = 64),
    recipient_pubkey_hex TEXT NOT NULL CHECK(length(recipient_pubkey_hex) = 64),
    outcome TEXT NOT NULL
        CHECK(outcome IN ('published', 'accepted_pending', 'completion_unknown')),
    -- Signed kind-1059 wrap awaiting acceptance; NULL once a relay accepted it.
    event_json TEXT,
    created_at_ms INTEGER NOT NULL,
    last_attempt_at_ms INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    -- Set before relay I/O and cleared when the attempt is recorded. A row left
    -- set was interrupted after the wrap may have left the device.
    in_flight INTEGER NOT NULL DEFAULT 0 CHECK(in_flight IN (0, 1)),
    CHECK((outcome = 'published') = (event_json IS NULL))
);
CREATE TABLE "notification_settings" (
    account_label TEXT PRIMARY KEY NOT NULL,
    account_id_hex TEXT NOT NULL,
    local_notifications_enabled INTEGER NOT NULL DEFAULT 1,
    native_push_enabled INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);
CREATE TABLE openmls_values (
    provider_version INTEGER NOT NULL,
    label BLOB NOT NULL,
    storage_key BLOB NOT NULL,
    group_key BLOB,
    value BLOB NOT NULL,
    PRIMARY KEY (provider_version, storage_key)
);
CREATE TABLE outgoing_attachment_recovery_cursor (
        id INTEGER PRIMARY KEY CHECK(id=1),
        group_id_hex TEXT NOT NULL DEFAULT '',
        message_id_hex TEXT NOT NULL DEFAULT '',
        upload_token BLOB NOT NULL DEFAULT x''
    );
INSERT INTO "outgoing_attachment_recovery_cursor" VALUES(1,'','',X'');
CREATE TABLE outgoing_attachment_upload_bodies (
        token BLOB PRIMARY KEY NOT NULL REFERENCES outgoing_attachment_uploads(token) ON DELETE CASCADE,
        byte_len INTEGER NOT NULL CHECK(byte_len>0 AND byte_len<=943718400),
        bytes BLOB NOT NULL CHECK(typeof(bytes)='blob' AND length(bytes)=byte_len)
    );
CREATE TABLE outgoing_attachment_upload_files (
            token BLOB PRIMARY KEY NOT NULL REFERENCES outgoing_attachment_uploads(token) ON DELETE CASCADE,
            nonce BLOB NOT NULL REFERENCES attachment_chunk_bodies(nonce),
            byte_len INTEGER NOT NULL CHECK(byte_len BETWEEN 1 AND 943718400),
            completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN(0,1))
        );
CREATE TABLE outgoing_attachment_upload_owners (
        token BLOB NOT NULL REFERENCES outgoing_attachment_uploads(token) ON DELETE CASCADE,
        group_id_hex TEXT NOT NULL,
        message_id_hex TEXT NOT NULL,
        PRIMARY KEY(token,group_id_hex,message_id_hex),
        FOREIGN KEY(group_id_hex,message_id_hex) REFERENCES app_events(group_id_hex,message_id_hex) ON DELETE CASCADE
    );
CREATE TABLE outgoing_attachment_uploads (
        token BLOB PRIMARY KEY NOT NULL CHECK(length(token)=16),
        group_id_hex TEXT NOT NULL REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
        source_epoch INTEGER NOT NULL CHECK(source_epoch>=0),
        plaintext_digest BLOB NOT NULL CHECK(length(plaintext_digest)=32),
        bytes BLOB NOT NULL CHECK(typeof(bytes)='blob' AND length(bytes)<=536870912),
        slot_json TEXT CHECK(length(slot_json)<=16384),
        quarantined INTEGER NOT NULL DEFAULT 0 CHECK(quarantined IN (0,1)),
        recovery_message_id_hex TEXT NOT NULL DEFAULT '',
        recovery_attachment_index INTEGER NOT NULL DEFAULT -1,
        expires_at INTEGER NOT NULL
    );
CREATE TABLE pending_application_authority (message_id BLOB PRIMARY KEY, group_id BLOB NOT NULL, record BLOB NOT NULL);
CREATE TABLE pending_application_events (
    message_id BLOB PRIMARY KEY NOT NULL,
    group_id BLOB NOT NULL,
    message_insert_order INTEGER NOT NULL CHECK(message_insert_order >= 0),
    record BLOB NOT NULL
);
CREATE TABLE pending_push_registration_removals (
    -- Removal intent must outlive app-local projection deletion. Unlike update
    -- shares, these rows deliberately do not reference account_groups.
    group_id_hex TEXT NOT NULL,
    account_label TEXT NOT NULL,
    account_id_hex TEXT NOT NULL,
    platform INTEGER NOT NULL,
    token_fingerprint TEXT NOT NULL,
    server_pubkey_hex TEXT NOT NULL,
    relay_hint TEXT,
    registration_created_at_ms INTEGER NOT NULL,
    registration_updated_at_ms INTEGER NOT NULL,
    queued_at_ms INTEGER NOT NULL,
    last_attempted_at_ms INTEGER,
    PRIMARY KEY (
        group_id_hex, platform, server_pubkey_hex,
        token_fingerprint, registration_updated_at_ms
    )
);
CREATE TABLE pending_push_registration_shares (
    group_id_hex TEXT PRIMARY KEY
        REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
    token_fingerprint TEXT NOT NULL,
    registration_updated_at_ms INTEGER NOT NULL,
    queued_at_ms INTEGER NOT NULL,
    last_attempted_at_ms INTEGER
);
CREATE TABLE push_registration (
    account_label TEXT PRIMARY KEY NOT NULL,
    account_id_hex TEXT NOT NULL,
    platform INTEGER NOT NULL,
    token_fingerprint TEXT NOT NULL,
    token_bytes BLOB NOT NULL,
    server_pubkey_hex TEXT NOT NULL,
    relay_hint TEXT,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    last_shared_at_ms INTEGER
);
CREATE TABLE retained_attachment_bytes (
    token BLOB PRIMARY KEY NOT NULL REFERENCES attachment_acquisition(token) ON DELETE CASCADE,
    bytes BLOB NOT NULL CHECK(typeof(bytes)='blob' AND length(bytes)<=536870912)
, byte_len INTEGER NOT NULL DEFAULT -1);
CREATE TABLE retained_attachment_chunks (
            token BLOB NOT NULL REFERENCES attachment_chunk_bodies(nonce) ON DELETE CASCADE,
            offset INTEGER NOT NULL CHECK(offset>=0),
            bytes BLOB NOT NULL CHECK(typeof(bytes)='blob' AND length(bytes) BETWEEN 1 AND 65536),
            PRIMARY KEY(token,offset)
        ) WITHOUT ROWID;
CREATE TABLE retained_attachment_files (
            token BLOB PRIMARY KEY NOT NULL REFERENCES retained_attachment_bytes(token) ON DELETE CASCADE,
            nonce BLOB NOT NULL REFERENCES attachment_chunk_bodies(nonce),
            attempt BLOB NOT NULL CHECK(length(attempt)=16),
            byte_len INTEGER NOT NULL CHECK(byte_len BETWEEN 0 AND 943718400),
            completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN(0,1))
        );
CREATE TABLE secure_delete_checkpoint_intents (
    operation_kind TEXT NOT NULL,
    scope TEXT NOT NULL,
    intent_nonce BLOB NOT NULL,
    result_json TEXT NOT NULL,
    PRIMARY KEY (operation_kind, scope)
);
CREATE TABLE seen_events (
    event_id TEXT PRIMARY KEY NOT NULL,
    seen_at INTEGER NOT NULL
);
CREATE TABLE transport_reconciliation_items (
    route_kind  INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
    route_id    BLOB NOT NULL CHECK (
                    (route_kind = 0 AND length(route_id) = 0) OR
                    (route_kind = 1 AND length(route_id) = 32)
                ),
    event_id    BLOB NOT NULL CHECK (length(event_id) = 32),
    created_at  INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (route_kind, route_id, event_id)
) WITHOUT ROWID;
CREATE TABLE transport_reconciliation_route_state (
    route_kind      INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
    route_id        BLOB NOT NULL CHECK (
                        (route_kind = 0 AND length(route_id) = 0) OR
                        (route_kind = 1 AND length(route_id) = 32)
                    ),
    inventory_since INTEGER NOT NULL CHECK (inventory_since >= 0), replay_after BLOB
         CHECK (replay_after IS NULL OR (typeof(replay_after) = 'blob' AND length(replay_after) = 32)),
    PRIMARY KEY (route_kind, route_id)
) WITHOUT ROWID;
CREATE TABLE transport_reconciliation_scheduler (
    singleton       INTEGER PRIMARY KEY CHECK (singleton = 1),
    route_kind      INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
    route_id        BLOB NOT NULL CHECK (
                        (route_kind = 0 AND length(route_id) = 0) OR
                        (route_kind = 1 AND length(route_id) = 32)
                    )
);
CREATE TABLE user_block_list (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            revision INTEGER NOT NULL DEFAULT 0,
            event_id TEXT NOT NULL DEFAULT '',
            event_created_at INTEGER NOT NULL DEFAULT 0,
            public_tags TEXT NOT NULL DEFAULT '[]',
            private_tags TEXT NOT NULL DEFAULT '[]',
            unreadable_event_id TEXT NOT NULL DEFAULT '',
            unreadable_event_created_at INTEGER NOT NULL DEFAULT 0
        );
INSERT INTO "user_block_list" VALUES(1,0,'',0,'[]','[]','',0);
CREATE TABLE user_block_publication (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            target TEXT NOT NULL,
            blocked INTEGER NOT NULL,
            event_json TEXT NOT NULL
        );
CREATE TABLE user_blocks (
            public_key TEXT PRIMARY KEY,
            is_private INTEGER NOT NULL CHECK(is_private IN (0, 1)),
            created_at_ms INTEGER NOT NULL
        );
CREATE INDEX account_recovery_account ON account_recovery_obligations(cause, account_label, marker_token);
CREATE INDEX account_recovery_epoch_order ON account_recovery_obligations(updated_at_ms, group_id) WHERE cause = 1 AND state = 0;
CREATE INDEX account_recovery_group ON account_recovery_obligations(cause, group_id, stalled_epoch);
CREATE INDEX account_recovery_pending ON account_recovery_obligations(state, eligibility);
CREATE UNIQUE INDEX account_recovery_single_explicit ON account_recovery_obligations(cause) WHERE cause=3;
CREATE INDEX app_pending_welcome_delivery_group_idx
    ON app_pending_welcome_delivery (group_id_hex);
CREATE INDEX app_prepared_group_image_upload_state_idx
    ON app_prepared_group_image_upload (state, updated_at, upload_id);
CREATE INDEX attachment_acquisition_active ON attachment_acquisition(state,token) WHERE state=1;
CREATE INDEX attachment_acquisition_due ON attachment_acquisition(due,token) WHERE due IS NOT NULL;
CREATE INDEX attachment_acquisition_expiry ON attachment_acquisition(expires_at,token) WHERE expires_at IS NOT NULL;
CREATE INDEX attachment_acquisition_priority ON attachment_acquisition(explicit_request DESC,due,priority_at DESC,token) WHERE due IS NOT NULL;
CREATE TRIGGER attachment_acquisition_priority_insert AFTER INSERT ON attachment_acquisition BEGIN
 UPDATE attachment_acquisition SET priority_at=COALESCE((SELECT received_at FROM attachment_history
 WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex AND attachment_index=NEW.attachment_index),0) WHERE token=NEW.token;
END;
CREATE TRIGGER attachment_acquisition_priority_update AFTER UPDATE OF received_at ON attachment_history BEGIN
            UPDATE attachment_acquisition SET priority_at=NEW.received_at
            WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex
                AND attachment_index=NEW.attachment_index AND explicit_request=0;
        END;
CREATE TRIGGER attachment_acquisition_retention AFTER UPDATE OF retention_expires_at ON app_events BEGIN
    UPDATE attachment_acquisition SET expires_at=NEW.retention_expires_at
    WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex;
END;
CREATE TRIGGER attachment_acquisition_source_INSERT AFTER INSERT ON message_timeline BEGIN
    DELETE FROM attachment_acquisition
    WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex
      AND NOT EXISTS(SELECT 1 FROM attachment_history_source s
        WHERE s.group_id_hex=attachment_acquisition.group_id_hex
          AND s.message_id_hex=attachment_acquisition.message_id_hex
          AND s.attachment_index=attachment_acquisition.attachment_index
          AND s.source_message_id_hex=attachment_acquisition.source_message_id_hex
          AND s.source_epoch=attachment_acquisition.source_epoch
          AND s.slot_json=attachment_acquisition.slot_json);
END;
CREATE TRIGGER attachment_acquisition_source_UPDATE AFTER UPDATE ON message_timeline BEGIN
    DELETE FROM attachment_acquisition
    WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex
      AND NOT EXISTS(SELECT 1 FROM attachment_history_source s
        WHERE s.group_id_hex=attachment_acquisition.group_id_hex
          AND s.message_id_hex=attachment_acquisition.message_id_hex
          AND s.attachment_index=attachment_acquisition.attachment_index
          AND s.source_message_id_hex=attachment_acquisition.source_message_id_hex
          AND s.source_epoch=attachment_acquisition.source_epoch
          AND s.slot_json=attachment_acquisition.slot_json);
END;
CREATE TRIGGER attachment_acquisition_store_reset AFTER UPDATE OF store_epoch ON chat_presentation_meta
WHEN OLD.store_epoch IS NOT NEW.store_epoch BEGIN
    DELETE FROM attachment_acquisition;
    DELETE FROM attachment_removal_suppression;
END;
CREATE TRIGGER attachment_block_added AFTER INSERT ON user_blocks BEGIN
    UPDATE attachment_history SET visible=0 WHERE sender=NEW.public_key;
END;
CREATE TRIGGER attachment_block_changed AFTER UPDATE OF public_key ON user_blocks BEGIN
    UPDATE attachment_history SET visible=(sender NOT IN (SELECT public_key FROM user_blocks)
        AND group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites))
    WHERE sender IN (OLD.public_key,NEW.public_key);
END;
CREATE TRIGGER attachment_block_removed AFTER DELETE ON user_blocks BEGIN
    UPDATE attachment_history SET visible=(group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites))
    WHERE sender=OLD.public_key;
END;
CREATE TRIGGER attachment_body_metadata_insert BEFORE INSERT ON retained_attachment_bytes
        WHEN NOT (typeof(NEW.byte_len)='integer' AND NEW.byte_len BETWEEN -1 AND 536870912
            AND (NEW.byte_len=-1 OR length(NEW.bytes)=NEW.byte_len)) BEGIN
            SELECT RAISE(ABORT,'invalid retained body length');
        END;
CREATE TRIGGER attachment_body_metadata_update BEFORE UPDATE OF bytes,byte_len ON retained_attachment_bytes
        WHEN NOT (typeof(NEW.byte_len)='integer' AND NEW.byte_len BETWEEN -1 AND 536870912
            AND (NEW.byte_len=-1 OR length(NEW.bytes)=NEW.byte_len)) BEGIN
            SELECT RAISE(ABORT,'invalid retained body length');
        END;
CREATE TRIGGER attachment_bytes_added AFTER INSERT ON retained_attachment_bytes BEGIN
            UPDATE retained_attachment_bytes SET byte_len=length(NEW.bytes)
                WHERE token=NEW.token AND NEW.byte_len<0;
            UPDATE attachment_retention_usage SET byte_count=byte_count+
                CASE WHEN NEW.byte_len<0 THEN length(NEW.bytes) ELSE NEW.byte_len END WHERE id=1;
        END;
CREATE TRIGGER attachment_bytes_removed BEFORE DELETE ON retained_attachment_bytes BEGIN
            UPDATE attachment_retention_usage SET byte_count=byte_count-
                CASE WHEN OLD.byte_len<0 THEN
                    (SELECT length(bytes) FROM retained_attachment_bytes WHERE token=OLD.token)
                ELSE OLD.byte_len END WHERE id=1;
        END;
CREATE TRIGGER attachment_bytes_updated BEFORE UPDATE OF bytes ON retained_attachment_bytes BEGIN
            UPDATE attachment_retention_usage SET byte_count=byte_count-
                CASE WHEN OLD.byte_len<0 THEN
                    (SELECT length(bytes) FROM retained_attachment_bytes WHERE token=OLD.token)
                ELSE OLD.byte_len END+
                CASE WHEN NEW.byte_len<0 THEN length(NEW.bytes) ELSE NEW.byte_len END WHERE id=1;
        END;
CREATE TRIGGER attachment_emoji_tags_changed AFTER UPDATE OF tags_json ON message_timeline
        WHEN OLD.tags_json IS NOT NEW.tags_json AND EXISTS (
            SELECT 1 FROM attachment_history WHERE group_id_hex=NEW.group_id_hex
                AND message_id_hex=NEW.message_id_hex AND visible=1
        ) BEGIN
            UPDATE attachment_history_versions SET revision=revision+1 WHERE group_id_hex=NEW.group_id_hex;
        END;
CREATE TRIGGER attachment_file_chunk_delete_immutable BEFORE DELETE ON retained_attachment_chunks
        WHEN EXISTS(SELECT 1 FROM retained_attachment_files WHERE nonce=OLD.token AND completed=1)
            OR EXISTS(SELECT 1 FROM outgoing_attachment_upload_files WHERE nonce=OLD.token AND completed=1) BEGIN
            SELECT RAISE(ABORT,'verified file chunks are immutable');
        END;
CREATE TRIGGER attachment_file_chunk_insert_immutable BEFORE INSERT ON retained_attachment_chunks
        WHEN EXISTS(SELECT 1 FROM retained_attachment_files WHERE nonce=NEW.token AND completed=1)
            OR EXISTS(SELECT 1 FROM outgoing_attachment_upload_files WHERE nonce=NEW.token AND completed=1) BEGIN
            SELECT RAISE(ABORT,'verified file chunks are immutable');
        END;
CREATE TRIGGER attachment_file_chunk_update_immutable BEFORE UPDATE ON retained_attachment_chunks
        WHEN EXISTS(SELECT 1 FROM retained_attachment_files WHERE nonce=OLD.token AND completed=1)
            OR EXISTS(SELECT 1 FROM outgoing_attachment_upload_files WHERE nonce=OLD.token AND completed=1) BEGIN
            SELECT RAISE(ABORT,'verified file chunks are immutable');
        END;
CREATE TRIGGER attachment_group_deleted AFTER DELETE ON account_groups BEGIN
    -- Snapshot reconciliation may drop account_groups while retaining the
    -- timeline. Preserve that source's index, but fence handles across the group
    -- lifecycle boundary. Ordinary local deletion removes the timeline first.
    UPDATE attachment_history_versions SET generation=randomblob(16),revision=revision+1
    WHERE group_id_hex=OLD.group_id_hex;
    DELETE FROM attachment_history_versions WHERE group_id_hex=OLD.group_id_hex
        AND NOT EXISTS(SELECT 1 FROM attachment_history WHERE group_id_hex=OLD.group_id_hex);
END;
CREATE TRIGGER attachment_history_added AFTER INSERT ON attachment_history BEGIN
    -- Even wholly hidden groups need a version row for a later unblock.
    -- Additions advertise a refresh without invalidating a stable older-page seek.
    INSERT INTO attachment_history_versions(group_id_hex,additions) VALUES(NEW.group_id_hex,NEW.visible)
    ON CONFLICT(group_id_hex) DO UPDATE SET additions=additions+NEW.visible;
END;
CREATE INDEX attachment_history_recent_demand ON attachment_history(received_at DESC,group_id_hex,message_id_hex,attachment_index);
CREATE TRIGGER attachment_history_removed AFTER DELETE ON attachment_history
WHEN OLD.visible=1 BEGIN
    UPDATE attachment_history_versions SET revision=revision+1 WHERE group_id_hex=OLD.group_id_hex;
END;
CREATE VIEW attachment_history_source AS
SELECT t.group_id_hex,t.message_id_hex,CAST(j.key AS INTEGER) AS attachment_index,
       t.source_message_id_hex,t.source_epoch,t.sender,t.timeline_at,t.received_at,
       t.timeline_order_class AS order_class,t.timeline_order_primary AS order_primary,
       t.timeline_order_phase AS order_phase,t.timeline_order_at AS order_at,
       CASE WHEN j.type IN ('array','object') THEN j.value
            WHEN j.type IN ('true','false') THEN j.type
            ELSE json_quote(j.value) END AS slot_json,
       (t.sender NOT IN (SELECT public_key FROM user_blocks)
        AND t.group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites)) AS visible
FROM message_timeline t, json_each(
    CASE WHEN t.media_json IS NULL THEN '[]'
         WHEN NOT json_valid(t.media_json) THEN '[null]'
         WHEN json_type(t.media_json) != 'object' THEN '[null]'
         WHEN json_type(t.media_json,'$.imeta') IS NULL THEN '[]'
         WHEN json_type(t.media_json,'$.imeta') != 'array' THEN '[null]'
         ELSE json_extract(t.media_json,'$.imeta') END
) j
WHERE t.kind=9 AND t.source_message_id_hex IS NOT NULL
  AND t.deleted=0 AND t.invalidation_status IS NULL;
CREATE TRIGGER attachment_history_visibility AFTER UPDATE OF visible ON attachment_history
WHEN OLD.visible IS NOT NEW.visible BEGIN
    UPDATE attachment_history_versions SET revision=revision+1 WHERE group_id_hex=NEW.group_id_hex;
END;
CREATE TRIGGER attachment_invite_blocked AFTER INSERT ON blocked_pending_invites BEGIN
    UPDATE attachment_history SET visible=0 WHERE group_id_hex=NEW.group_id_hex;
END;
CREATE TRIGGER attachment_invite_unblocked AFTER DELETE ON blocked_pending_invites BEGIN
    UPDATE attachment_history SET visible=(sender NOT IN (SELECT public_key FROM user_blocks)) WHERE group_id_hex=OLD.group_id_hex;
END;
CREATE INDEX attachment_partial_expiry ON attachment_partial(expires_at,token);
CREATE TRIGGER attachment_partial_reserved_added AFTER INSERT ON attachment_partial BEGIN
            UPDATE attachment_partial_usage SET reserved_bytes=reserved_bytes+NEW.total WHERE id=1;
        END;
CREATE TRIGGER attachment_partial_reserved_removed AFTER DELETE ON attachment_partial BEGIN
            UPDATE attachment_partial_usage SET reserved_bytes=reserved_bytes-OLD.total WHERE id=1;
        END;
CREATE TRIGGER attachment_partial_terminal AFTER UPDATE OF state ON attachment_acquisition
        WHEN NEW.state=3 OR (NEW.state=5 AND NEW.permission_paused=0)
            OR (NEW.state=4 AND NEW.cancelled=0) BEGIN
            DELETE FROM attachment_partial WHERE token=NEW.token;
        END;
CREATE INDEX attachment_permission_paused ON attachment_acquisition(permission_category,token) WHERE permission_paused=1 AND state=5;
CREATE TRIGGER attachment_source_delete AFTER DELETE ON message_timeline
WHEN OLD.media_json IS NOT NULL BEGIN
    DELETE FROM attachment_history WHERE group_id_hex=OLD.group_id_hex AND message_id_hex=OLD.message_id_hex;
END;
CREATE TRIGGER attachment_source_insert AFTER INSERT ON message_timeline
WHEN NEW.kind=9 AND NEW.source_message_id_hex IS NOT NULL AND NEW.media_json IS NOT NULL
 AND NEW.deleted=0 AND NEW.invalidation_status IS NULL BEGIN
    INSERT INTO attachment_history(group_id_hex,message_id_hex,attachment_index,source_message_id_hex,
        source_epoch,sender,timeline_at,received_at,order_class,order_primary,order_phase,order_at,slot_json,visible)
    SELECT * FROM attachment_history_source WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex;
END;
CREATE TRIGGER attachment_source_update AFTER UPDATE ON message_timeline
WHEN (OLD.media_json IS NOT NULL OR NEW.media_json IS NOT NULL) AND (
     OLD.group_id_hex IS NOT NEW.group_id_hex OR OLD.message_id_hex IS NOT NEW.message_id_hex
  OR OLD.source_message_id_hex IS NOT NEW.source_message_id_hex OR OLD.source_epoch IS NOT NEW.source_epoch
  OR OLD.kind IS NOT NEW.kind OR OLD.deleted IS NOT NEW.deleted
  OR OLD.invalidation_status IS NOT NEW.invalidation_status OR OLD.media_json IS NOT NEW.media_json
  OR OLD.sender IS NOT NEW.sender OR OLD.timeline_at IS NOT NEW.timeline_at OR OLD.received_at IS NOT NEW.received_at)
BEGIN
    DELETE FROM attachment_history WHERE group_id_hex=OLD.group_id_hex AND message_id_hex=OLD.message_id_hex;
    INSERT INTO attachment_history(group_id_hex,message_id_hex,attachment_index,source_message_id_hex,
        source_epoch,sender,timeline_at,received_at,order_class,order_primary,order_phase,order_at,slot_json,visible)
    SELECT * FROM attachment_history_source WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex;
END;
CREATE TRIGGER attachment_worker_accept_INSERT AFTER INSERT ON account_groups
WHEN NEW.pending_confirmation=0 BEGIN
    INSERT INTO attachment_worker_demand
        SELECT *,randomblob(16) FROM attachment_worker_eligible
        WHERE group_id_hex=NEW.group_id_hex
        ON CONFLICT(group_id_hex,message_id_hex,attachment_index)
        DO UPDATE SET generation=excluded.generation;
END;
CREATE TRIGGER attachment_worker_accept_UPDATE AFTER UPDATE ON account_groups
WHEN NEW.pending_confirmation=0 AND OLD.pending_confirmation<>0 BEGIN
    INSERT INTO attachment_worker_demand
        SELECT *,randomblob(16) FROM attachment_worker_eligible
        WHERE group_id_hex=NEW.group_id_hex
        ON CONFLICT(group_id_hex,message_id_hex,attachment_index)
        DO UPDATE SET generation=excluded.generation;
END;
CREATE VIEW attachment_worker_eligible AS
    SELECT h.group_id_hex,h.message_id_hex,h.attachment_index FROM attachment_history h
    JOIN account_groups g USING(group_id_hex)
    JOIN app_events a USING(group_id_hex,message_id_hex)
    WHERE h.visible=1 AND h.source_epoch>=0 AND g.pending_confirmation=0;
CREATE TRIGGER attachment_worker_source_INSERT AFTER INSERT ON attachment_history BEGIN
    INSERT INTO attachment_worker_demand
        SELECT *,randomblob(16) FROM attachment_worker_eligible
        WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex
          AND attachment_index=NEW.attachment_index
        ON CONFLICT(group_id_hex,message_id_hex,attachment_index)
        DO UPDATE SET generation=excluded.generation;
END;
CREATE TRIGGER attachment_worker_source_UPDATE AFTER UPDATE ON attachment_history BEGIN
    INSERT INTO attachment_worker_demand
        SELECT *,randomblob(16) FROM attachment_worker_eligible
        WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex
          AND attachment_index=NEW.attachment_index
        ON CONFLICT(group_id_hex,message_id_hex,attachment_index)
        DO UPDATE SET generation=excluded.generation;
END;
CREATE TRIGGER attachment_worker_store_reset AFTER UPDATE OF store_epoch ON chat_presentation_meta
WHEN OLD.store_epoch IS NOT NEW.store_epoch BEGIN
    DELETE FROM attachment_worker_demand;
    INSERT INTO attachment_worker_demand SELECT *,randomblob(16) FROM attachment_worker_eligible;
END;
CREATE INDEX avatar_access_lru ON avatar_access(accessed, token);
CREATE INDEX avatar_acquisition_due ON avatar_acquisition(priority DESC, due, token) WHERE due IS NOT NULL;
CREATE TRIGGER avatar_acquisition_repair AFTER UPDATE OF bytes ON avatar_assets
        WHEN OLD.bytes IS NOT NULL AND NEW.bytes IS NULL BEGIN
            UPDATE avatar_acquisition SET state = 1, due = 0, attempt = NULL WHERE token = NEW.token;
        END;
CREATE TRIGGER avatar_acquisition_source_changed BEFORE UPDATE OF token ON avatar_assets
        WHEN OLD.token IS NOT NEW.token BEGIN
            DELETE FROM avatar_acquisition WHERE token = OLD.token;
        END;
CREATE TRIGGER avatar_cache_store_reset AFTER UPDATE OF store_epoch ON chat_presentation_meta
        WHEN OLD.store_epoch IS NOT NEW.store_epoch BEGIN
            DELETE FROM avatar_assets;
        END;
CREATE TRIGGER avatar_chat_deleted BEFORE DELETE ON chat_list_rows BEGIN
            DELETE FROM avatar_assets WHERE owner_key = 'chat:' || lower(hex(OLD.presentation_row_epoch))
                OR owner_key IN (SELECT owner_key FROM avatar_identity_demand WHERE group_id_hex = OLD.group_id_hex);
        END;
CREATE INDEX avatar_identity_demand_recency ON avatar_identity_demand(accessed, owner_key);
CREATE TRIGGER avatar_identity_evicted AFTER DELETE ON avatar_assets BEGIN
            DELETE FROM avatar_identity_demand WHERE owner_key = OLD.owner_key;
        END;
CREATE TRIGGER avatar_identity_store_reset AFTER UPDATE OF store_epoch ON chat_presentation_meta
        WHEN OLD.store_epoch IS NOT NEW.store_epoch BEGIN
            DELETE FROM avatar_identity_demand;
            DELETE FROM avatar_acquisition_bootstrap;
        END;
CREATE TRIGGER block_invite_deleted AFTER DELETE ON account_groups BEGIN
            DELETE FROM blocked_pending_invites WHERE group_id_hex=OLD.group_id_hex;
        END;
CREATE TRIGGER block_invite_inserted AFTER INSERT ON account_groups BEGIN
            DELETE FROM blocked_pending_invites WHERE group_id_hex=NEW.group_id_hex;
            INSERT OR IGNORE INTO blocked_pending_invites SELECT NEW.group_id_hex
            WHERE NEW.pending_confirmation != 0 AND NEW.welcomer_account_id_hex IN (SELECT public_key FROM user_blocks);
        END;
CREATE TRIGGER block_invite_updated AFTER UPDATE OF pending_confirmation,welcomer_account_id_hex ON account_groups BEGIN
            DELETE FROM blocked_pending_invites WHERE group_id_hex=OLD.group_id_hex;
            INSERT OR IGNORE INTO blocked_pending_invites SELECT NEW.group_id_hex
            WHERE NEW.pending_confirmation != 0 AND NEW.welcomer_account_id_hex IN (SELECT public_key FROM user_blocks);
        END;
CREATE TRIGGER block_inviter_added AFTER INSERT ON user_blocks BEGIN
            INSERT OR IGNORE INTO blocked_pending_invites
            SELECT group_id_hex FROM account_groups WHERE pending_confirmation != 0 AND welcomer_account_id_hex=NEW.public_key;
        END;
CREATE TRIGGER block_inviter_removed AFTER DELETE ON user_blocks BEGIN
            DELETE FROM blocked_pending_invites WHERE group_id_hex IN (
                SELECT group_id_hex FROM account_groups WHERE pending_confirmation != 0 AND welcomer_account_id_hex=OLD.public_key);
        END;
CREATE INDEX cgka_group_evolutions_group_idx
    ON cgka_group_evolutions (group_id, insert_order);
CREATE INDEX cgka_maintenance_obligations_group_idx
    ON cgka_maintenance_obligations (group_id, insert_order);
CREATE INDEX cgka_own_commit_intents_group_idx
    ON cgka_own_commit_intents (group_id, insert_order);
CREATE INDEX cgka_transport_fanout_group_idx
    ON cgka_transport_fanout (group_id, insert_order);
CREATE INDEX chat_avatar_target_lookup ON chat_list_rows(presentation_row_epoch);
CREATE TRIGGER chat_list_invite_account_groups_DELETE AFTER DELETE ON account_groups 
                 BEGIN UPDATE chat_list_rows SET list_pending_invite =
        COALESCE((SELECT pending_confirmation FROM account_groups
            WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) != 0 WHERE group_id_hex = OLD.group_id_hex; END;
CREATE TRIGGER chat_list_invite_account_groups_INSERT AFTER INSERT ON account_groups 
                 BEGIN UPDATE chat_list_rows SET list_pending_invite =
        COALESCE((SELECT pending_confirmation FROM account_groups
            WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) != 0 WHERE group_id_hex = NEW.group_id_hex; END;
CREATE TRIGGER chat_list_invite_account_groups_UPDATE AFTER UPDATE OF group_id_hex, pending_confirmation ON account_groups WHEN OLD.group_id_hex IS NOT NEW.group_id_hex OR OLD.pending_confirmation IS NOT NEW.pending_confirmation
                 BEGIN UPDATE chat_list_rows SET list_pending_invite =
        COALESCE((SELECT pending_confirmation FROM account_groups
            WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) != 0 WHERE group_id_hex IN (OLD.group_id_hex, NEW.group_id_hex); END;
CREATE TRIGGER chat_list_invite_chat_list_rows_INSERT AFTER INSERT ON chat_list_rows 
                 BEGIN UPDATE chat_list_rows SET list_pending_invite =
        COALESCE((SELECT pending_confirmation FROM account_groups
            WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) != 0 WHERE group_id_hex = NEW.group_id_hex; END;
CREATE TRIGGER chat_list_invite_chat_list_rows_UPDATE AFTER UPDATE OF group_id_hex, pending_confirmation ON chat_list_rows WHEN OLD.group_id_hex IS NOT NEW.group_id_hex OR OLD.pending_confirmation IS NOT NEW.pending_confirmation
                 BEGIN UPDATE chat_list_rows SET list_pending_invite =
        COALESCE((SELECT pending_confirmation FROM account_groups
            WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) != 0 WHERE group_id_hex IN (OLD.group_id_hex, NEW.group_id_hex); END;
CREATE TRIGGER chat_list_keys_account_groups_DELETE
                AFTER DELETE ON account_groups  BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE group_id_hex = OLD.group_id_hex;  END;
CREATE TRIGGER chat_list_keys_account_groups_INSERT
                AFTER INSERT ON account_groups  BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE group_id_hex = NEW.group_id_hex;  END;
CREATE TRIGGER chat_list_keys_account_groups_UPDATE
                AFTER UPDATE OF group_id_hex, archived, pending_confirmation, self_membership ON account_groups WHEN OLD.group_id_hex IS NOT NEW.group_id_hex OR OLD.archived IS NOT NEW.archived OR OLD.pending_confirmation IS NOT NEW.pending_confirmation OR OLD.self_membership IS NOT NEW.self_membership BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE group_id_hex IN (OLD.group_id_hex, NEW.group_id_hex);  END;
CREATE TRIGGER chat_list_keys_cgka_disband_candidates_DELETE
                AFTER DELETE ON cgka_disband_candidates  BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE lower(group_id_hex) = lower(hex(OLD.group_id));  END;
CREATE TRIGGER chat_list_keys_cgka_disband_candidates_INSERT
                AFTER INSERT ON cgka_disband_candidates  BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE lower(group_id_hex) = lower(hex(NEW.group_id));  END;
CREATE TRIGGER chat_list_keys_cgka_disband_candidates_UPDATE
                AFTER UPDATE OF group_id, commit_id ON cgka_disband_candidates WHEN OLD.group_id IS NOT NEW.group_id OR OLD.commit_id IS NOT NEW.commit_id BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE lower(group_id_hex) IN (lower(hex(OLD.group_id)), lower(hex(NEW.group_id)));  END;
CREATE TRIGGER chat_list_keys_cgka_disband_requests_DELETE
                AFTER DELETE ON cgka_disband_requests  BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE lower(group_id_hex) = lower(hex(OLD.group_id));  END;
CREATE TRIGGER chat_list_keys_cgka_disband_requests_INSERT
                AFTER INSERT ON cgka_disband_requests  BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE lower(group_id_hex) = lower(hex(NEW.group_id));  END;
CREATE TRIGGER chat_list_keys_cgka_disband_requests_UPDATE
                AFTER UPDATE OF group_id, record ON cgka_disband_requests WHEN OLD.group_id IS NOT NEW.group_id OR OLD.record IS NOT NEW.record BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE lower(group_id_hex) IN (lower(hex(OLD.group_id)), lower(hex(NEW.group_id)));  END;
CREATE TRIGGER chat_list_keys_cgka_disband_tombstones_DELETE
                AFTER DELETE ON cgka_disband_tombstones  BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE lower(group_id_hex) = lower(hex(OLD.group_id));  END;
CREATE TRIGGER chat_list_keys_cgka_disband_tombstones_INSERT
                AFTER INSERT ON cgka_disband_tombstones  BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE lower(group_id_hex) = lower(hex(NEW.group_id));  END;
CREATE TRIGGER chat_list_keys_cgka_disband_tombstones_UPDATE
                AFTER UPDATE OF group_id ON cgka_disband_tombstones WHEN OLD.group_id IS NOT NEW.group_id BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE lower(group_id_hex) IN (lower(hex(OLD.group_id)), lower(hex(NEW.group_id)));  END;
CREATE TRIGGER chat_list_keys_cgka_leave_requests_DELETE
                AFTER DELETE ON cgka_leave_requests  BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE lower(group_id_hex) = lower(hex(OLD.group_id));  END;
CREATE TRIGGER chat_list_keys_cgka_leave_requests_INSERT
                AFTER INSERT ON cgka_leave_requests  BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE lower(group_id_hex) = lower(hex(NEW.group_id));  END;
CREATE TRIGGER chat_list_keys_cgka_leave_requests_UPDATE
                AFTER UPDATE OF group_id, record ON cgka_leave_requests WHEN OLD.group_id IS NOT NEW.group_id OR OLD.record IS NOT NEW.record BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE lower(group_id_hex) IN (lower(hex(OLD.group_id)), lower(hex(NEW.group_id)));  END;
CREATE TRIGGER chat_list_keys_chat_list_rows_INSERT
                AFTER INSERT ON chat_list_rows  BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE group_id_hex = NEW.group_id_hex; UPDATE chat_list_rows SET list_pin_ordinal = COALESCE((SELECT ordinal FROM chat_pin_positions WHERE group_id_hex = chat_list_rows.group_id_hex), -1),
        list_pin_position = (SELECT (SELECT count(*) FROM chat_pin_positions earlier WHERE earlier.ordinal < pin.ordinal) FROM chat_pin_positions pin WHERE pin.group_id_hex = chat_list_rows.group_id_hex) WHERE group_id_hex = NEW.group_id_hex; END;
CREATE TRIGGER chat_list_keys_chat_list_rows_UPDATE
                AFTER UPDATE OF group_id_hex, archived, pending_confirmation, self_membership, unread_count, manually_marked_unread ON chat_list_rows WHEN OLD.group_id_hex IS NOT NEW.group_id_hex OR OLD.archived IS NOT NEW.archived OR OLD.pending_confirmation IS NOT NEW.pending_confirmation OR OLD.self_membership IS NOT NEW.self_membership OR OLD.unread_count IS NOT NEW.unread_count OR OLD.manually_marked_unread IS NOT NEW.manually_marked_unread BEGIN UPDATE chat_list_rows SET
        list_scope = CASE WHEN COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END) THEN 2 WHEN COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived) != 0 THEN 1 ELSE 0 END,
        list_unread = (COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) = 0 AND (unread_count > 0 OR manually_marked_unread != 0)) WHERE group_id_hex IN (OLD.group_id_hex, NEW.group_id_hex); UPDATE chat_list_rows SET list_pin_ordinal = COALESCE((SELECT ordinal FROM chat_pin_positions WHERE group_id_hex = chat_list_rows.group_id_hex), -1),
        list_pin_position = (SELECT (SELECT count(*) FROM chat_pin_positions earlier WHERE earlier.ordinal < pin.ordinal) FROM chat_pin_positions pin WHERE pin.group_id_hex = chat_list_rows.group_id_hex) WHERE group_id_hex IN (OLD.group_id_hex, NEW.group_id_hex) AND OLD.group_id_hex IS NOT NEW.group_id_hex; END;
CREATE TRIGGER chat_list_keys_chat_pin_positions_DELETE
                AFTER DELETE ON chat_pin_positions WHEN (SELECT pin_rewrite_in_progress = 0 FROM chat_list_navigation_meta WHERE id = 1) BEGIN  UPDATE chat_list_rows SET list_pin_ordinal = COALESCE((SELECT ordinal FROM chat_pin_positions WHERE group_id_hex = chat_list_rows.group_id_hex), -1),
        list_pin_position = (SELECT (SELECT count(*) FROM chat_pin_positions earlier WHERE earlier.ordinal < pin.ordinal) FROM chat_pin_positions pin WHERE pin.group_id_hex = chat_list_rows.group_id_hex) WHERE group_id_hex = OLD.group_id_hex; END;
CREATE TRIGGER chat_list_keys_chat_pin_positions_INSERT
                AFTER INSERT ON chat_pin_positions WHEN (SELECT pin_rewrite_in_progress = 0 FROM chat_list_navigation_meta WHERE id = 1) BEGIN  UPDATE chat_list_rows SET list_pin_ordinal = COALESCE((SELECT ordinal FROM chat_pin_positions WHERE group_id_hex = chat_list_rows.group_id_hex), -1),
        list_pin_position = (SELECT (SELECT count(*) FROM chat_pin_positions earlier WHERE earlier.ordinal < pin.ordinal) FROM chat_pin_positions pin WHERE pin.group_id_hex = chat_list_rows.group_id_hex) WHERE group_id_hex = NEW.group_id_hex; END;
CREATE TRIGGER chat_list_keys_chat_pin_positions_UPDATE
                AFTER UPDATE OF group_id_hex, ordinal ON chat_pin_positions WHEN (SELECT pin_rewrite_in_progress = 0 FROM chat_list_navigation_meta WHERE id = 1) AND (OLD.group_id_hex IS NOT NEW.group_id_hex OR OLD.ordinal IS NOT NEW.ordinal) BEGIN  UPDATE chat_list_rows SET list_pin_ordinal = COALESCE((SELECT ordinal FROM chat_pin_positions WHERE group_id_hex = chat_list_rows.group_id_hex), -1),
        list_pin_position = (SELECT (SELECT count(*) FROM chat_pin_positions earlier WHERE earlier.ordinal < pin.ordinal) FROM chat_pin_positions pin WHERE pin.group_id_hex = chat_list_rows.group_id_hex) WHERE group_id_hex IN (OLD.group_id_hex, NEW.group_id_hex); END;
CREATE TRIGGER chat_list_navigation_changed AFTER UPDATE ON chat_list_rows
        WHEN OLD.list_scope != NEW.list_scope OR OLD.list_unread != NEW.list_unread
          OR OLD.list_pin_ordinal != NEW.list_pin_ordinal OR OLD.activity_sort_at != NEW.activity_sort_at
          OR OLD.group_id_hex != NEW.group_id_hex
        BEGIN UPDATE chat_list_navigation_meta SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER chat_list_navigation_deleted AFTER DELETE ON chat_list_rows
        BEGIN UPDATE chat_list_navigation_meta SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER chat_list_navigation_inserted AFTER INSERT ON chat_list_rows
        BEGIN UPDATE chat_list_navigation_meta SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER chat_list_pin_rank_delete AFTER DELETE ON chat_pin_positions
        WHEN (SELECT pin_rewrite_in_progress = 0 FROM chat_list_navigation_meta WHERE id = 1) BEGIN
            UPDATE chat_list_rows SET list_pin_position = list_pin_position - 1
                WHERE list_pin_ordinal > OLD.ordinal AND group_id_hex != OLD.group_id_hex;
        END;
CREATE TRIGGER chat_list_pin_rank_insert AFTER INSERT ON chat_pin_positions
        WHEN (SELECT pin_rewrite_in_progress = 0 FROM chat_list_navigation_meta WHERE id = 1) BEGIN
            UPDATE chat_list_rows SET list_pin_position = list_pin_position + 1
                WHERE list_pin_ordinal > NEW.ordinal AND group_id_hex != NEW.group_id_hex;
        END;
CREATE TRIGGER chat_list_pin_rank_update AFTER UPDATE OF ordinal ON chat_pin_positions
        WHEN (SELECT pin_rewrite_in_progress = 0 FROM chat_list_navigation_meta WHERE id = 1) BEGIN
            UPDATE chat_list_rows SET list_pin_position = list_pin_position - 1
                WHERE list_pin_ordinal > OLD.ordinal AND group_id_hex != NEW.group_id_hex;
            UPDATE chat_list_rows SET list_pin_position = list_pin_position + 1
                WHERE list_pin_ordinal > NEW.ordinal AND group_id_hex != NEW.group_id_hex;
        END;
CREATE TRIGGER chat_list_unread_dirty_after_timeline_delete
AFTER DELETE ON message_timeline
BEGIN
    INSERT INTO chat_list_unread_dirty_messages (group_id_hex, message_id_hex)
    SELECT OLD.group_id_hex, OLD.message_id_hex
    WHERE EXISTS (
        SELECT 1 FROM account_groups WHERE group_id_hex = OLD.group_id_hex
    )
    ON CONFLICT(group_id_hex, message_id_hex) DO NOTHING;
END;
CREATE TRIGGER chat_list_unread_dirty_after_timeline_insert
AFTER INSERT ON message_timeline
BEGIN
    INSERT INTO chat_list_unread_dirty_messages (group_id_hex, message_id_hex)
    SELECT NEW.group_id_hex, NEW.message_id_hex
    WHERE EXISTS (
        SELECT 1 FROM account_groups WHERE group_id_hex = NEW.group_id_hex
    )
    ON CONFLICT(group_id_hex, message_id_hex) DO NOTHING;
END;
CREATE TRIGGER chat_list_unread_dirty_after_timeline_update
AFTER UPDATE ON message_timeline
BEGIN
    INSERT INTO chat_list_unread_dirty_messages (group_id_hex, message_id_hex)
    SELECT NEW.group_id_hex, NEW.message_id_hex
    WHERE EXISTS (
        SELECT 1 FROM account_groups WHERE group_id_hex = NEW.group_id_hex
    )
    ON CONFLICT(group_id_hex, message_id_hex) DO NOTHING;
END;
CREATE TRIGGER chat_presentation_avatar_DELETE AFTER DELETE ON account_group_app_components
             WHEN OLD.component_id = 32775 BEGIN
                UPDATE chat_list_rows SET presentation_json = CASE WHEN OLD.component_data_hex NOT IN ('', '000000') THEN NULL ELSE presentation_json END,
                    presentation_source_revision = presentation_source_revision + 1
                    WHERE group_id_hex = OLD.group_id_hex;
             END;
CREATE TRIGGER chat_presentation_avatar_INSERT AFTER INSERT ON account_group_app_components
             WHEN NEW.component_id = 32775 BEGIN
                UPDATE chat_list_rows SET presentation_json = CASE WHEN 0 THEN NULL ELSE presentation_json END,
                    presentation_source_revision = presentation_source_revision + 1
                    WHERE group_id_hex = NEW.group_id_hex;
             END;
CREATE TRIGGER chat_presentation_avatar_UPDATE AFTER UPDATE ON account_group_app_components
             WHEN NEW.component_id = 32775 AND OLD.component_data_hex IS NOT NEW.component_data_hex BEGIN
                UPDATE chat_list_rows SET presentation_json = CASE WHEN OLD.component_data_hex NOT IN ('', '000000') AND NEW.component_data_hex IN ('', '000000') THEN NULL ELSE presentation_json END,
                    presentation_source_revision = presentation_source_revision + 1
                    WHERE group_id_hex = NEW.group_id_hex;
             END;
CREATE INDEX chat_presentation_by_member
    ON chat_presentation_dependencies(member_id_hex, group_id_hex);
CREATE TRIGGER chat_presentation_group_changed AFTER UPDATE ON account_groups
WHEN OLD.profile_name IS NOT NEW.profile_name
  OR OLD.member_count IS NOT NEW.member_count
  OR OLD.self_membership IS NOT NEW.self_membership
  OR OLD.image_hash_hex IS NOT NEW.image_hash_hex
  OR OLD.image_key_hex IS NOT NEW.image_key_hex
  OR OLD.image_nonce_hex IS NOT NEW.image_nonce_hex
  OR OLD.image_upload_key_hex IS NOT NEW.image_upload_key_hex
  OR OLD.image_media_type IS NOT NEW.image_media_type
BEGIN
    UPDATE chat_list_rows SET presentation_json = CASE
            WHEN OLD.member_count IS NOT NEW.member_count OR OLD.self_membership IS NOT NEW.self_membership
              OR (trim(OLD.profile_name) != '' AND trim(NEW.profile_name) = '')
              OR (OLD.image_hash_hex != '' AND coalesce(NEW.image_hash_hex, '') = '')
              OR (OLD.image_key_hex != '' AND coalesce(NEW.image_key_hex, '') = '')
              OR (OLD.image_nonce_hex != '' AND coalesce(NEW.image_nonce_hex, '') = '')
              OR (OLD.image_upload_key_hex != '' AND coalesce(NEW.image_upload_key_hex, '') = '')
            THEN NULL ELSE presentation_json END,
        presentation_source_revision = presentation_source_revision + 1
        WHERE group_id_hex = NEW.group_id_hex;
    DELETE FROM chat_presentation_dependencies WHERE group_id_hex = NEW.group_id_hex
        AND (OLD.member_count IS NOT NEW.member_count OR OLD.self_membership IS NOT NEW.self_membership);
    DELETE FROM chat_presentation_members WHERE group_id_hex = NEW.group_id_hex
        AND (OLD.member_count IS NOT NEW.member_count OR OLD.self_membership IS NOT NEW.self_membership);
END;
CREATE TRIGGER chat_presentation_group_created AFTER INSERT ON account_groups BEGIN
            INSERT OR IGNORE INTO chat_presentation_row_work VALUES(NEW.group_id_hex);
        END;
CREATE INDEX chat_presentation_pending ON chat_list_rows(group_id_hex)
    WHERE presentation_json IS NULL OR presentation_applied_source_revision != presentation_source_revision;
CREATE TRIGGER chat_presentation_row_created AFTER INSERT ON chat_list_rows BEGIN
    UPDATE chat_list_rows SET presentation_row_epoch = randomblob(16)
        WHERE group_id_hex = NEW.group_id_hex;
END;
CREATE TRIGGER chat_presentation_row_prepared AFTER INSERT ON chat_list_rows BEGIN
            DELETE FROM chat_presentation_row_work WHERE group_id_hex=NEW.group_id_hex;
        END;
CREATE TRIGGER chat_presentation_value_changed AFTER UPDATE OF presentation_json ON chat_list_rows
WHEN OLD.presentation_json IS NOT NULL AND NEW.presentation_json IS NULL BEGIN
    UPDATE chat_presentation_meta SET revision = revision + 1 WHERE id = 1;
    DELETE FROM chat_presentation_dependencies WHERE group_id_hex = NEW.group_id_hex;
END;
CREATE TRIGGER chat_presentation_value_removed AFTER DELETE ON chat_list_rows
WHEN OLD.presentation_json IS NOT NULL BEGIN
    UPDATE chat_presentation_meta SET revision = revision + 1 WHERE id = 1;
END;
CREATE INDEX content_report_backfill_candidates ON app_events(insert_order) WHERE kind IN (5,1009,1984,1985,4891);
CREATE INDEX content_report_labels ON message_modifier_edges(group_id_hex, target_message_id_hex, modifier_message_id_hex) WHERE kind=1985;
CREATE TRIGGER content_reports_group_deleted AFTER DELETE ON account_groups BEGIN
    DELETE FROM content_expired_targets WHERE group_id_hex = OLD.group_id_hex;
    DELETE FROM content_pruned_controls WHERE group_id_hex = OLD.group_id_hex;
    DELETE FROM content_reports WHERE group_id_hex = OLD.group_id_hex;
END;
CREATE INDEX content_reports_target ON content_reports(group_id_hex, message_id_hex, report_id_hex);
CREATE INDEX idx_account_groups_pending_inviter ON account_groups(welcomer_account_id_hex,group_id_hex) WHERE pending_confirmation != 0;
CREATE INDEX idx_account_groups_pending_invites
    ON account_groups (group_id_hex, welcomer_account_id_hex)
    WHERE pending_confirmation = 1 AND archived = 0;
CREATE INDEX idx_agent_stream_starts_group_stream
    ON agent_stream_starts (group_id_hex, stream_id_hex, started_at, message_id_hex);
CREATE INDEX idx_app_events_accepted_insert_order
    ON app_events (group_id_hex, insert_order DESC)
    WHERE direction != 'sent' OR source_message_id_hex IS NOT NULL;
CREATE INDEX idx_app_events_group_insert_order
    ON app_events (group_id_hex, insert_order DESC);
CREATE INDEX idx_app_events_group_kind_order
    ON app_events (group_id_hex, kind, recorded_at, message_id_hex);
CREATE INDEX idx_app_events_group_order
    ON app_events (group_id_hex, recorded_at, message_id_hex);
CREATE INDEX idx_app_events_group_retention_expiry
ON app_events(group_id_hex, retention_expires_at)
WHERE retention_expires_at IS NOT NULL;
CREATE INDEX idx_app_events_origin_commit
    ON app_events (origin_commit_id)
    WHERE origin_commit_id IS NOT NULL;
CREATE INDEX idx_app_events_pending_sent
    ON app_events(group_id_hex)
    WHERE direction = 'sent' AND source_message_id_hex IS NULL AND invalidated = 0;
CREATE INDEX idx_app_events_recency ON app_events(recorded_at, message_id_hex);
CREATE UNIQUE INDEX idx_app_events_source_message
    ON app_events (source_message_id_hex)
    WHERE source_message_id_hex IS NOT NULL;
CREATE INDEX idx_attachment_history_outgoing_slot ON attachment_history(group_id_hex,source_epoch,slot_json,message_id_hex,attachment_index);
CREATE INDEX idx_attachment_history_page ON attachment_history(
    group_id_hex,order_class,order_primary,order_phase,order_at,message_id_hex,attachment_order
) WHERE visible=1;
CREATE INDEX idx_attachment_history_sender ON attachment_history(sender);
CREATE INDEX idx_cgka_group_state_checkpoints_epoch
    ON cgka_group_state_checkpoints(group_id, resulting_epoch);
CREATE INDEX idx_cgka_messages_group_epoch
    ON cgka_messages (group_id, epoch, insert_order);
CREATE INDEX idx_cgka_messages_group_order ON cgka_messages(group_id, insert_order);
CREATE INDEX idx_cgka_messages_group_state_epoch
    ON cgka_messages (group_id, state, epoch);
CREATE INDEX idx_cgka_messages_legacy_order
    ON cgka_messages(insert_order) WHERE storage_format = 1;
CREATE INDEX idx_cgka_outbound_fanout_group
    ON cgka_outbound_fanout(group_id, insert_order);
CREATE INDEX idx_cgka_processed_transport_ids_group
    ON cgka_processed_transport_ids (group_id);
CREATE INDEX idx_cgka_queued_outbound_group
    ON cgka_queued_outbound (group_id, insert_order);
CREATE INDEX idx_cgka_transport_group_routes_group
    ON cgka_transport_group_routes(group_id, source_epoch);
CREATE INDEX idx_chat_list_group_id_lower ON chat_list_rows(lower(group_id_hex));
CREATE INDEX idx_chat_list_invite_attention ON chat_list_rows(group_id_hex)
            WHERE list_scope = 0 AND list_pending_invite = 1;
CREATE INDEX idx_chat_list_page ON chat_list_rows(list_scope, list_pin_section, list_pin_order, list_activity_order, group_id_hex);
CREATE INDEX idx_chat_list_pin_ordinal ON chat_list_rows(list_pin_ordinal);
CREATE INDEX idx_chat_list_rows_archived_activity_order
    ON chat_list_rows (archived, activity_sort_at DESC, group_id_hex);
CREATE INDEX idx_chat_list_rows_order
    ON chat_list_rows (last_message_timeline_at DESC, group_id_hex);
CREATE INDEX idx_chat_list_unread_messages_first
    ON chat_list_unread_messages (
        group_id_hex,
        timeline_order_class,
        timeline_order_primary,
        timeline_order_phase,
        timeline_order_at,
        message_id_hex
    );
CREATE INDEX idx_chat_list_unread_page ON chat_list_rows(list_pin_section, list_pin_order, list_activity_order, group_id_hex)
            WHERE list_scope = 0 AND list_unread = 1;
CREATE INDEX idx_chat_pin_positions_order
    ON chat_pin_positions (ordinal, group_id_hex);
CREATE INDEX idx_direct_conversation_members_member
    ON direct_conversation_members (member_id_hex, group_id_hex);
CREATE INDEX idx_disband_candidates_hex ON cgka_disband_candidates(lower(hex(group_id)));
CREATE INDEX idx_disband_requests_hex ON cgka_disband_requests(lower(hex(group_id)));
CREATE INDEX idx_disband_tombstones_hex
    ON cgka_disband_tombstones(lower(hex(group_id)));
CREATE INDEX idx_leave_requests_hex ON cgka_leave_requests(lower(hex(group_id)));
CREATE INDEX idx_media_secret_references_secret
    ON encrypted_media_epoch_secret_references (
        group_id_hex, source_epoch, component_id, message_id_hex
    );
CREATE INDEX idx_media_secrets_epoch
             ON encrypted_media_epoch_secrets(group_id_hex, source_epoch);
CREATE INDEX idx_message_timeline_account_order
    ON message_timeline (timeline_at DESC, message_id_hex DESC);
CREATE INDEX idx_message_timeline_chat_preview
    ON message_timeline (
        group_id_hex,
        CASE
            WHEN direction = 'sent'
             AND invalidation_status = 'local_publish_failed' THEN 0
            WHEN direction = 'sent'
             AND source_message_id_hex IS NULL
             AND invalidation_status IS NULL THEN 2
            ELSE 1
        END DESC,
        timeline_order_class DESC,
        timeline_order_primary DESC,
        timeline_order_phase DESC,
        timeline_order_at DESC,
        message_id_hex DESC
    );
CREATE INDEX idx_message_timeline_group_canonical_order
    ON message_timeline (
        group_id_hex,
        timeline_order_class,
        timeline_order_primary,
        timeline_order_phase,
        timeline_order_at,
        message_id_hex
    );
CREATE INDEX idx_message_timeline_group_kind_order
    ON message_timeline (group_id_hex, kind, timeline_at DESC, message_id_hex DESC);
CREATE INDEX idx_message_timeline_group_kind_unread
    ON message_timeline (group_id_hex, kind, deleted, timeline_at, message_id_hex);
CREATE INDEX idx_message_timeline_group_received
             ON message_timeline(group_id_hex, received_at);
CREATE INDEX idx_message_timeline_order
    ON message_timeline (group_id_hex, timeline_at, message_id_hex);
CREATE INDEX idx_message_timeline_reply_lookup
    ON message_timeline (group_id_hex, reply_to_message_id_hex, message_id_hex)
    WHERE reply_to_message_id_hex IS NOT NULL;
CREATE INDEX idx_message_timeline_search
    ON message_timeline (group_id_hex, plaintext COLLATE NOCASE);
CREATE INDEX idx_modifier_edges_target
    ON message_modifier_edges (group_id_hex, target_message_id_hex, kind, recorded_at, modifier_message_id_hex);
CREATE INDEX idx_openmls_values_group
    ON openmls_values(provider_version, group_key, label);
CREATE INDEX idx_openmls_values_label
    ON openmls_values(provider_version, label, storage_key);
CREATE INDEX idx_pending_application_events_group
    ON pending_application_events(group_id, message_insert_order);
CREATE INDEX idx_pending_application_events_order
    ON pending_application_events(message_insert_order, message_id);
CREATE INDEX idx_released_transport_receipts_group
    ON cgka_released_transport_receipts(group_id);
CREATE INDEX idx_seen_events_recency ON seen_events(seen_at);
CREATE INDEX idx_transport_reconciliation_event
    ON transport_reconciliation_items(event_id);
CREATE INDEX local_message_submissions_pending ON local_message_submissions(sequence) WHERE state = 0;
CREATE TRIGGER local_submission_source_deleted AFTER DELETE ON app_events BEGIN
            DELETE FROM local_message_submissions
            WHERE group_id_hex = OLD.group_id_hex AND message_id_hex = OLD.message_id_hex;
        END;
CREATE INDEX message_draft_attachment_descriptors ON message_draft_attachments (
            group_id_hex, position, attachment_id, file_name, media_type,
            length(plaintext), dim, thumbhash, duration_seconds, waveform_samples_json
        );
CREATE TRIGGER message_draft_attachments_revision_DELETE AFTER DELETE ON message_draft_attachments BEGIN
                    UPDATE message_draft_revision_clock SET revision = revision + 1;
                    UPDATE message_draft_revisions SET revision =
                        (SELECT revision FROM message_draft_revision_clock)
                        WHERE group_id_hex = OLD.group_id_hex;
                END;
CREATE TRIGGER message_draft_attachments_revision_INSERT AFTER INSERT ON message_draft_attachments BEGIN
                    UPDATE message_draft_revision_clock SET revision = revision + 1;
                    UPDATE message_draft_revisions SET revision =
                        (SELECT revision FROM message_draft_revision_clock)
                        WHERE group_id_hex = NEW.group_id_hex;
                END;
CREATE TRIGGER message_draft_attachments_revision_UPDATE AFTER UPDATE ON message_draft_attachments BEGIN
                    UPDATE message_draft_revision_clock SET revision = revision + 1;
                    UPDATE message_draft_revisions SET revision =
                        (SELECT revision FROM message_draft_revision_clock)
                        WHERE group_id_hex = NEW.group_id_hex;
                END;
CREATE TRIGGER message_draft_group_insert AFTER INSERT ON account_groups BEGIN
            UPDATE message_draft_revision_clock SET revision = revision + 1;
            INSERT INTO message_draft_revisions
                SELECT NEW.group_id_hex, revision FROM message_draft_revision_clock;
        END;
CREATE TRIGGER message_drafts_revision_DELETE AFTER DELETE ON message_drafts BEGIN
                    UPDATE message_draft_revision_clock SET revision = revision + 1;
                    UPDATE message_draft_revisions SET revision =
                        (SELECT revision FROM message_draft_revision_clock)
                        WHERE group_id_hex = OLD.group_id_hex;
                END;
CREATE TRIGGER message_drafts_revision_INSERT AFTER INSERT ON message_drafts BEGIN
                    UPDATE message_draft_revision_clock SET revision = revision + 1;
                    UPDATE message_draft_revisions SET revision =
                        (SELECT revision FROM message_draft_revision_clock)
                        WHERE group_id_hex = NEW.group_id_hex;
                END;
CREATE TRIGGER message_drafts_revision_UPDATE AFTER UPDATE ON message_drafts BEGIN
                    UPDATE message_draft_revision_clock SET revision = revision + 1;
                    UPDATE message_draft_revisions SET revision =
                        (SELECT revision FROM message_draft_revision_clock)
                        WHERE group_id_hex = NEW.group_id_hex;
                END;
CREATE INDEX moderation_report_outbox_created_idx
    ON moderation_report_outbox (created_at_ms);
CREATE INDEX moderation_report_outbox_dedupe_idx
    ON moderation_report_outbox (dedupe_key, created_at_ms);
CREATE INDEX outgoing_attachment_upload_expiry ON outgoing_attachment_uploads(expires_at,token);
CREATE INDEX outgoing_attachment_upload_files_nonce ON outgoing_attachment_upload_files(nonce);
CREATE INDEX outgoing_attachment_upload_slot ON outgoing_attachment_uploads(group_id_hex,source_epoch,slot_json);
CREATE TRIGGER outgoing_file_added AFTER INSERT ON outgoing_attachment_upload_files BEGIN
            UPDATE attachment_retention_usage SET byte_count=byte_count+NEW.byte_len WHERE id=1;
        END;
CREATE TRIGGER outgoing_file_identity_immutable BEFORE UPDATE OF token,nonce,byte_len ON outgoing_attachment_upload_files BEGIN
            SELECT RAISE(ABORT,'outgoing file identity is immutable');
        END;
CREATE TRIGGER outgoing_file_removed AFTER DELETE ON outgoing_attachment_upload_files BEGIN
            UPDATE attachment_retention_usage SET byte_count=byte_count-OLD.byte_len WHERE id=1;
            DELETE FROM attachment_chunk_bodies WHERE nonce=OLD.nonce
                AND NOT EXISTS(SELECT 1 FROM retained_attachment_files WHERE nonce=OLD.nonce)
                AND NOT EXISTS(SELECT 1 FROM outgoing_attachment_upload_files WHERE nonce=OLD.nonce);
        END;
CREATE TRIGGER outgoing_upload_body_added AFTER INSERT ON outgoing_attachment_upload_bodies BEGIN
        UPDATE attachment_retention_usage SET byte_count=byte_count+NEW.byte_len WHERE id=1;
    END;
CREATE TRIGGER outgoing_upload_body_immutable BEFORE UPDATE ON outgoing_attachment_upload_bodies BEGIN
        SELECT RAISE(ABORT,'outgoing upload body is immutable');
    END;
CREATE TRIGGER outgoing_upload_body_removed AFTER DELETE ON outgoing_attachment_upload_bodies BEGIN
        UPDATE attachment_retention_usage SET byte_count=byte_count-OLD.byte_len WHERE id=1;
    END;
CREATE TRIGGER outgoing_upload_bytes_added AFTER INSERT ON outgoing_attachment_uploads BEGIN
        UPDATE attachment_retention_usage SET byte_count=byte_count+length(NEW.bytes) WHERE id=1;
    END;
CREATE TRIGGER outgoing_upload_bytes_changed AFTER UPDATE OF bytes ON outgoing_attachment_uploads BEGIN
        UPDATE attachment_retention_usage SET byte_count=byte_count-length(OLD.bytes)+length(NEW.bytes) WHERE id=1;
    END;
CREATE TRIGGER outgoing_upload_bytes_removed AFTER DELETE ON outgoing_attachment_uploads BEGIN
        UPDATE attachment_retention_usage SET byte_count=byte_count-length(OLD.bytes) WHERE id=1;
    END;
CREATE INDEX pending_application_authority_group ON pending_application_authority(group_id);
CREATE INDEX pending_push_registration_removals_revision_idx
    ON pending_push_registration_removals (
        token_fingerprint, registration_updated_at_ms
    );
CREATE INDEX pending_push_registration_shares_token_idx
    ON pending_push_registration_shares (
        token_fingerprint, registration_updated_at_ms
    );
CREATE TRIGGER prune_blocked_notification AFTER DELETE ON app_events BEGIN
            DELETE FROM blocked_notification_suppressions
            WHERE group_id=OLD.group_id_hex AND message_id=OLD.message_id_hex;
        END;
CREATE TRIGGER prune_group_blocked_notifications AFTER DELETE ON account_groups BEGIN
            DELETE FROM blocked_notification_suppressions WHERE group_id=OLD.group_id_hex;
        END;
CREATE TRIGGER reject_forgotten_group_insert BEFORE INSERT ON cgka_groups
         WHEN EXISTS(SELECT 1 FROM locally_forgotten_groups
                     WHERE group_id = NEW.id AND awaiting_welcome = 1)
         BEGIN SELECT RAISE(ABORT, 'group awaiting fresh welcome'); END;
CREATE INDEX retained_attachment_files_nonce ON retained_attachment_files(nonce);
CREATE TRIGGER retained_file_added AFTER INSERT ON retained_attachment_files BEGIN
            UPDATE attachment_retention_usage SET byte_count=byte_count+NEW.byte_len WHERE id=1;
        END;
CREATE TRIGGER retained_file_identity_immutable BEFORE UPDATE OF token,nonce,attempt,byte_len ON retained_attachment_files BEGIN
            SELECT RAISE(ABORT,'retained file identity is immutable');
        END;
CREATE TRIGGER retained_file_removed AFTER DELETE ON retained_attachment_files BEGIN
            UPDATE attachment_retention_usage SET byte_count=byte_count-OLD.byte_len WHERE id=1;
            DELETE FROM attachment_chunk_bodies WHERE nonce=OLD.nonce
                AND NOT EXISTS(SELECT 1 FROM retained_attachment_files WHERE nonce=OLD.nonce)
                AND NOT EXISTS(SELECT 1 FROM outgoing_attachment_upload_files WHERE nonce=OLD.nonce);
        END;
CREATE TRIGGER suppress_blocked_notifications AFTER INSERT ON app_events
        WHEN NEW.sender IN (SELECT public_key FROM user_blocks) BEGIN
            INSERT OR IGNORE INTO blocked_notification_suppressions VALUES (NEW.group_id_hex,NEW.message_id_hex);
        END;
CREATE INDEX transport_reconciliation_items_route_order
    ON transport_reconciliation_items (route_kind, route_id, created_at, event_id);
CREATE TRIGGER unfinished_file_attempt_changed AFTER UPDATE OF state,attempt ON attachment_acquisition
        WHEN NEW.state<>1 OR NEW.attempt IS NOT OLD.attempt BEGIN
            DELETE FROM retained_attachment_bytes WHERE token=NEW.token AND EXISTS(
                SELECT 1 FROM retained_attachment_files f WHERE f.token=NEW.token AND f.completed=0);
        END;
CREATE TRIGGER unpin_chat_when_archived
AFTER UPDATE OF archived ON account_groups
WHEN NEW.archived = 1
BEGIN
    DELETE FROM chat_pin_positions WHERE group_id_hex = NEW.group_id_hex;
END;
CREATE VIEW visible_chat_list_rows AS SELECT * FROM chat_list_rows
            WHERE group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites);
CREATE VIEW visible_message_timeline AS SELECT * FROM message_timeline
            WHERE sender NOT IN (SELECT public_key FROM user_blocks)
            AND group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites);
COMMIT;
