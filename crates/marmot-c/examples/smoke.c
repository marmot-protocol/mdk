/*
 * Worked example / smoke test for the marmot-c ABI, in C.
 *
 * Goes beyond a bare liveness check: it drives a realistic slice of the
 * runtime and walks the recursive Markdown DTO tree, so it doubles as a
 * reference for how a C consumer navigates the ABI's tagged unions and
 * owned pointers. Exercised by c-smoke.sh (optionally under valgrind).
 *
 * The steps that need a relay (identity publish) are best-effort: in an
 * offline sandbox they report the runtime's typed error and the run
 * continues. Everything else is asserted hard.
 *
 * Usage: smoke <fresh-empty-home-dir>
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <marmot.h>

_Static_assert(MARMOT_CONVERSATION_OPEN_MODE_AUTOMATIC == 0, "automatic ABI value");
_Static_assert(MARMOT_CONVERSATION_OPEN_MODE_LATEST == 1, "latest ABI value");
_Static_assert(MARMOT_CONVERSATION_OPEN_MODE_MESSAGE == 2, "message ABI value");
_Static_assert(MARMOT_CONVERSATION_PAGE_DIRECTION_OLDER == 0, "older ABI value");
_Static_assert(MARMOT_CONVERSATION_PAGE_DIRECTION_NEWER == 1, "newer ABI value");
_Static_assert(MARMOT_STATUS_CONVERSATION_WINDOW_MESSAGE_NOT_RETAINED == 92, "missing target ABI value");

_Static_assert(MARMOT_REPORT_REASON_NUDITY == 0, "report reason ABI value");
_Static_assert(MARMOT_REPORT_REASON_MALWARE == 1, "report reason ABI value");
_Static_assert(MARMOT_REPORT_REASON_PROFANITY == 2, "report reason ABI value");
_Static_assert(MARMOT_REPORT_REASON_ILLEGAL == 3, "report reason ABI value");
_Static_assert(MARMOT_REPORT_REASON_SPAM == 4, "report reason ABI value");
_Static_assert(MARMOT_REPORT_REASON_IMPERSONATION == 5, "report reason ABI value");
_Static_assert(MARMOT_REPORT_REASON_OTHER == 6, "report reason ABI value");

static int failures = 0;

static void ok(const char *what) {
    printf("smoke: ok: %s\n", what);
}

static void check(bool cond, const char *what) {
    if (cond) {
        ok(what);
    } else {
        fprintf(stderr, "smoke: FAILED: %s\n", what);
        failures++;
    }
}

/* Fetch and free the thread-local detail for the most recent failure. */
static void print_last_error(const char *context) {
    char *msg = marmot_last_error_message();
    printf("smoke:   %s: %s\n", context, msg ? msg : "(no detail)");
    marmot_string_free(msg);
}

/* Reconstruct the plain text of an inline run by concatenating its Text
 * spans — a small walk of the inline tagged union. */
static void print_inline_text(const struct MarmotMarkdownInline *inlines,
                              uintptr_t len) {
    printf("\"");
    for (uintptr_t i = 0; i < len; i++) {
        if (inlines[i].tag == MARMOT_MARKDOWN_INLINE_TEXT) {
            printf("%s", inlines[i].TEXT.content);
        } else if (inlines[i].tag == MARMOT_MARKDOWN_INLINE_CODE) {
            printf("`%s`", inlines[i].CODE.content);
        }
    }
    printf("\"");
}

/* Walk the top-level blocks of a parsed document, classifying each by its
 * tag and reaching into the union body. Returns the heading count seen. */
static int walk_markdown(const struct MarmotMarkdownDocument *doc) {
    int headings = 0;
    for (uintptr_t i = 0; i < doc->blocks_len; i++) {
        const struct MarmotMarkdownBlock *b = &doc->blocks[i];
        switch (b->tag) {
        case MARMOT_MARKDOWN_BLOCK_HEADING:
            headings++;
            printf("smoke:   block %zu: heading (h%u) ", i, b->HEADING.level);
            print_inline_text(b->HEADING.inlines, b->HEADING.inlines_len);
            printf("\n");
            break;
        case MARMOT_MARKDOWN_BLOCK_PARAGRAPH:
            printf("smoke:   block %zu: paragraph ", i);
            print_inline_text(b->PARAGRAPH.inlines, b->PARAGRAPH.inlines_len);
            printf("\n");
            break;
        case MARMOT_MARKDOWN_BLOCK_CODE_BLOCK:
            printf("smoke:   block %zu: code block (lang=%s)\n", i,
                   b->CODE_BLOCK.info ? b->CODE_BLOCK.info : "");
            break;
        case MARMOT_MARKDOWN_BLOCK_LIST_BLOCK:
            printf("smoke:   block %zu: list with %zu items\n", i,
                   b->LIST_BLOCK.items_len);
            break;
        case MARMOT_MARKDOWN_BLOCK_DETAILS:
            printf("smoke:   block %zu: details (open=%d body=%zu)\n", i,
                   b->DETAILS.details ? (int)b->DETAILS.details->open : -1,
                   b->DETAILS.details ? b->DETAILS.details->body_len : 0);
            break;
        default:
            printf("smoke:   block %zu: other (tag %d)\n", i, (int)b->tag);
            break;
        }
    }
    return headings;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <fresh-home-dir>\n", argv[0]);
        return 2;
    }
    const char *home = argv[1];

    /* ---- argument validation + NULL-free discipline (no client) ------- */
    MarmotClient *client = NULL;
    MarmotStatus st = marmot_client_new(NULL, NULL, 0, &client);
    check(st == MARMOT_STATUS_NULL_POINTER, "NULL root_path rejected");

    marmot_client_free(NULL);
    marmot_string_free(NULL);
    marmot_account_summary_list_free(NULL);
    marmot_blocked_user_list_free(NULL);
    marmot_block_list_snapshot_free(NULL);
    marmot_block_list_subscription_free(NULL);
    check(marmot_get_blocked_users(NULL, "alice", NULL) == MARMOT_STATUS_NULL_POINTER, "block list null boundary");
    check(marmot_is_user_blocked(NULL, "alice", "key", NULL) == MARMOT_STATUS_NULL_POINTER, "block boolean null boundary");
    check(marmot_subscribe_blocked_users(NULL, "alice", NULL) == MARMOT_STATUS_NULL_POINTER, "block subscription null boundary");
    marmot_markdown_document_free(NULL);
    marmot_conversation_window_snapshot_free(NULL);
    marmot_selected_message_draft_free(NULL);
    marmot_conversation_window_subscription_free(NULL);
    check(marmot_open_conversation_window(NULL, NULL, NULL, MARMOT_CONVERSATION_OPEN_MODE_AUTOMATIC, NULL, NULL, 0, NULL) == MARMOT_STATUS_NULL_POINTER,
          "conversation open preflights outputs");
    check(marmot_conversation_window_subscription_page(NULL, NULL, MARMOT_CONVERSATION_PAGE_DIRECTION_OLDER, 1, 0, NULL) == MARMOT_STATUS_NULL_POINTER,
          "conversation page preflights outputs");
    check(marmot_conversation_window_subscription_cancel(NULL) == MARMOT_STATUS_NULL_POINTER,
          "conversation cancel rejects NULL handle");
    marmot_chat_list_window_snapshot_free(NULL);
    marmot_account_attention_snapshot_free(NULL);
    marmot_chat_list_window_subscription_free(NULL);
    marmot_account_attention_subscription_free(NULL);
    check(marmot_open_chat_list_window(NULL, NULL, 0, NULL, NULL) == MARMOT_STATUS_NULL_POINTER,
          "window open preflights output");
    check(marmot_chat_list_window_subscription_page(NULL, 0, 0, 1, NULL) == MARMOT_STATUS_NULL_POINTER,
          "window page preflights output");
    check(marmot_account_attention_subscription_next(NULL, 5000, NULL) == MARMOT_STATUS_NULL_POINTER,
          "attention next preflights output");
    marmot_presented_chat_row_free(NULL);
    marmot_presented_chat_list_snapshot_free(NULL);
    marmot_presented_chat_list_update_free(NULL);
    marmot_presented_chat_list_subscription_free(NULL);
    check(marmot_presented_chat_list_subscription_next(NULL, 5000, NULL) ==
              MARMOT_STATUS_NULL_POINTER,
          "presented next validates output before reading");
    check(marmot_open_presented_chat_list(NULL, NULL, 0, NULL) ==
              MARMOT_STATUS_NULL_POINTER,
          "presented open validates output before subscribing");

    ok("NULL frees are no-ops");

    /* ---- construct + lifecycle ---------------------------------------- */
    const char *relays[] = {"wss://relay.example.org"};
    st = marmot_client_new(home, relays, 1, &client);
    if (st == MARMOT_STATUS_KEYSTORE_UNAVAILABLE) {
        /* No platform keychain (headless): a documented limitation. */
        print_last_error("client_new");
        printf("smoke: SKIP: no keystore on this host\n");
        return 0;
    }
    if (st != MARMOT_STATUS_OK) {
        /* Any other construction failure is a regression, not a skip. */
        print_last_error("client_new");
        fprintf(stderr, "smoke: FAILED: client_new status %d\n", (int)st);
        return 1;
    }
    ok("client constructed");

    st = marmot_record_host_performance(client,
        MARMOT_HOST_PERFORMANCE_OPERATION_CONVERSATION_COMPOSER_READY, 125,
        MARMOT_HOST_PERFORMANCE_OUTCOME_CANCELLED);
    check(st == MARMOT_STATUS_OK, "conversation host timing accepted");
    const struct {
        MarmotHostPerformanceOperation operation;
        const char *name;
    } host_stages[] = {
        {MARMOT_HOST_PERFORMANCE_OPERATION_LINUX_STARTUP_BEFORE_VAULT, "host_linux_startup_before_vault"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_LINUX_STARTUP_AFTER_VAULT, "host_linux_startup_after_vault"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_WINDOW_INIT, "host_window_init"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_FONTS_INIT, "host_fonts_init"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_RUNTIME_INIT, "host_runtime_init"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_ACCOUNT_LOAD, "host_account_load"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_ACCOUNT_SWITCH, "host_account_switch"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_FRAME_UPDATE, "host_frame_update"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_FRAME_LAYOUT, "host_frame_layout"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_FRAME_DRAW, "host_frame_draw"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_FRAME_PRESENT, "host_frame_present"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_LINUX_FRAME_POST_PRESENT, "host_linux_frame_post_present"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_LINUX_FRAME_UNTIL_PRESENT, "host_linux_frame_until_present"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_LINUX_FRAME_IDLE_WAIT, "host_linux_frame_idle_wait"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_CHAT_LIST_LOAD, "host_chat_list_load"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_CONTACTS_LOAD, "host_contacts_load"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_ARCHIVED_CHAT_LIST_LOAD, "host_archived_chat_list_load"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_PROFILE_LOAD, "host_profile_load"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_PROFILE_READ, "host_profile_read"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_TIMELINE_OPEN, "host_timeline_open"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_TIMELINE_PAGE, "host_timeline_page"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_TIMELINE_HANDOFF, "host_timeline_handoff"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_TIMELINE_APPLY, "host_timeline_apply"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_MESSAGE_SEND, "host_message_send"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_MESSAGE_SEARCH, "host_message_search"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_CONVERSATION_SEARCH, "host_conversation_search"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_MEDIA_QUEUE_WAIT, "host_media_queue_wait"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_MEDIA_PREPARE, "host_media_prepare"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_MEDIA_LOAD, "host_media_load"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_MEDIA_CACHE_READ, "host_media_cache_read"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_MEDIA_DECODE, "host_media_decode"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_MEDIA_APPLY, "host_media_apply"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_LINUX_VAULT_DERIVE_KEY, "host_linux_vault_derive_key"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_LINUX_VAULT_OPEN, "host_linux_vault_open"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_LINUX_VAULT_CREATE, "host_linux_vault_create"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_LINUX_VAULT_PERSIST, "host_linux_vault_persist"},
        {MARMOT_HOST_PERFORMANCE_OPERATION_SETTINGS_SAVE, "host_settings_save"},
    };
    for (uintptr_t i = 0; i < sizeof(host_stages) / sizeof(host_stages[0]); i++) {
        st = marmot_record_host_performance(client, host_stages[i].operation, i + 1,
            MARMOT_HOST_PERFORMANCE_OUTCOME_FAILURE);
        check(st == MARMOT_STATUS_OK, "host stage accepted");
    }
    MarmotAppPerformanceSnapshot *performance = NULL;
    st = marmot_app_performance_snapshot(client, &performance);
    check(st == MARMOT_STATUS_OK && performance != NULL, "runtime performance snapshot");
    bool found_timing = false;
    if (performance != NULL) {
        for (uintptr_t i = 0; i < sizeof(host_stages) / sizeof(host_stages[0]); i++) {
            const MarmotRuntimePerformanceSnapshot *stage = NULL;
            for (uintptr_t j = 0; j < performance->runtime_operations_len; j++) {
                if (strcmp(performance->runtime_operations[j].operation, host_stages[i].name) == 0) {
                    stage = &performance->runtime_operations[j];
                    break;
                }
            }
            check(stage != NULL && stage->started == 1 && stage->completed == 1 &&
                stage->failures == 1 && stage->duration_ms.sum_ms == i + 1 &&
                stage->duration_ms.buckets_len > 0, "host stage snapshot");
        }
        for (uintptr_t i = 0; i < performance->runtime_operations_len; i++) {
            const MarmotRuntimePerformanceSnapshot *timing = &performance->runtime_operations[i];
            if (strcmp(timing->operation, "host_conversation_composer_ready") == 0) {
                found_timing = timing->started == 1 && timing->completed == 1 &&
                    timing->cancelled == 1 && timing->in_flight == 0 &&
                    timing->duration_ms.sum_ms == 125 && timing->duration_ms.buckets_len > 0;
            }
        }
    }
    check(found_timing, "runtime timing array, outcome and histogram cross C ABI");
    marmot_app_performance_snapshot_free(performance);

    bool stopping = true;
    st = marmot_client_is_stopping(client, &stopping);
    check(st == MARMOT_STATUS_OK && !stopping, "client not stopping");

    MarmotAuditLogTrackerConfigV4 audit_config = {
        .endpoint = NULL,
        .authorization_bearer_token = "test-upload-token",
        .source = {.hardware_model = "TestModel", .platform = "linux", .app_version = "test"},
    };
    MarmotAuditLogTrackerConfigV4 *audit_result = NULL;
    st = marmot_set_audit_log_tracker_config_v4(client, &audit_config, &audit_result);
    check(st == MARMOT_STATUS_OK && audit_result != NULL, "v4 audit config crosses the ABI");
    if (audit_result) {
        check(audit_result->authorization_bearer_token == NULL, "audit token is write-only");
        check(audit_result->source.hardware_model &&
              strcmp(audit_result->source.hardware_model, "TestModel") == 0,
              "v4 audit hardware model survives the ABI");
        marmot_audit_log_tracker_config_v4_free(audit_result);
    }

    MarmotAuditLogTrackerConfig legacy_audit_config = {
        .endpoint = NULL, .authorization_bearer_token = NULL,
        .source = {.device_label = "PRIVATE_DEVICE_NAME", .platform = "linux", .app_version = "test"},
    };
    MarmotAuditLogTrackerConfig *legacy_audit_result = NULL;
    st = marmot_set_audit_log_tracker_config(client, &legacy_audit_config, &legacy_audit_result);
    check(st == MARMOT_STATUS_OK && legacy_audit_result != NULL, "legacy audit config remains callable");
    if (legacy_audit_result) {
        check(legacy_audit_result->source.device_label == NULL, "legacy audit device label is discarded");
        marmot_audit_log_tracker_config_free(legacy_audit_result);
    }

    st = marmot_client_start(client);
    if (st == MARMOT_STATUS_OK) {
        ok("client started");
    } else {
        printf("smoke: ok: client start offline (status %d)\n", (int)st);
        print_last_error("start");
    }

    /* ---- Markdown: parse + walk the recursive DTO tree ---------------- */
    MarmotMarkdownDocument *doc = NULL;
    const char *md =
        "# Marmot\n\n"
        "A **bold** claim with `code` and a [link](https://example.org).\n\n"
        "- [x] dig burrow\n"
        "- [ ] store acorns\n\n"
        "```rust\nfn main() {}\n```\n";
    st = marmot_parse_markdown(client, md, &doc);
    check(st == MARMOT_STATUS_OK && doc != NULL, "markdown parsed");
    /* check() counts a failure without aborting, so bail before the reads
     * below dereference a document that was never produced. */
    if (doc == NULL) {
        return 1;
    }
    check(!doc->truncated, "markdown not truncated");
    check(doc->blocks_len >= 4, "markdown has heading + paragraph + list + code");
    int headings = walk_markdown(doc);
    check(headings == 1, "walked tree found the heading");
    marmot_markdown_document_free(doc);

    doc = NULL;
    st = marmot_parse_markdown(client,
                               "<details>\n<summary>More</summary>\nHidden **bold**\n</details>",
                               &doc);
    check(st == MARMOT_STATUS_OK && doc != NULL, "details markdown parsed");
    if (doc == NULL) {
        return 1;
    }
    check(doc->blocks_len == 1, "details is a single top-level block");
    check(doc->blocks[0].tag == MARMOT_MARKDOWN_BLOCK_DETAILS, "details tag");
    check(doc->blocks[0].DETAILS.details != NULL, "details payload");
    check(!doc->blocks[0].DETAILS.details->open, "details default closed");
    check(doc->blocks[0].DETAILS.details->summary_len == 1, "details summary");
    check(doc->blocks[0].DETAILS.details->body_len == 1, "details body");
    marmot_markdown_document_free(doc);

    /* ---- offline reads ------------------------------------------------ */
    MarmotAccountSummaryList *accounts = NULL;
    st = marmot_list_accounts(client, &accounts);
    check(st == MARMOT_STATUS_OK && accounts != NULL, "list_accounts");
    if (accounts == NULL) {
        return 1;
    }
    check(accounts->len == 0, "fresh home has no accounts");
    marmot_account_summary_list_free(accounts);

    MarmotAccountAttentionSubscription *attention = NULL;
    st = marmot_subscribe_account_attention(client, &attention);
    check(st == MARMOT_STATUS_OK && attention != NULL, "independent attention opens");
    if (attention != NULL) {
        MarmotAccountAttentionSnapshot *snapshot = NULL;
        st = marmot_account_attention_subscription_snapshot(attention, &snapshot);
        check(st == MARMOT_STATUS_OK && snapshot != NULL, "attention initial snapshot");
        if (snapshot != NULL) {
            check(snapshot->accounts_len == 0 && snapshot->sequence == 0, "empty account set");
            marmot_account_attention_snapshot_free(snapshot);
        }
        st = marmot_account_attention_subscription_next(attention, 5, &snapshot);
        check(st == MARMOT_STATUS_TIMEOUT && snapshot == NULL, "attention timeout preserves ownership");
        marmot_account_attention_subscription_free(attention);
    }

    /* Directory lookups for an unknown id resolve to absent (NULL out). */
    char *npub = NULL;
    const char *unknown_id =
        "0000000000000000000000000000000000000000000000000000000000000000";
    st = marmot_npub(client, unknown_id, &npub);
    check(st == MARMOT_STATUS_OK, "npub lookup call succeeds");
    marmot_string_free(npub);

    char *account_hex = NULL;
    const char *bootstrap_id =
        "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
    st = marmot_account_id_hex(client, bootstrap_id, &account_hex);
    check(st == MARMOT_STATUS_OK && account_hex != NULL, "account_id_hex hex");
    marmot_string_free(account_hex);

    char *pseudonym = NULL;
    st = marmot_default_profile_pseudonym(client, bootstrap_id, &pseudonym);
    check(st == MARMOT_STATUS_OK && pseudonym != NULL, "default profile pseudonym");
    marmot_string_free(pseudonym);

    char *random_name = NULL;
    st = marmot_random_profile_pseudonym(client, &random_name);
    check(st == MARMOT_STATUS_OK && random_name != NULL, "random profile pseudonym");
    marmot_string_free(random_name);

    /* Local attachment APIs never turn a missing account into a download. */
    MarmotAttachmentLocalTarget local_target = {unknown_id, unknown_id, 0};
    MarmotAttachmentLocalAssetList *local_assets = NULL;
    st = marmot_attachment_local_assets(client, unknown_id, "abab", &local_target, 1, &local_assets);
    check(st != MARMOT_STATUS_OK && local_assets == NULL, "local assets reject unknown account");
    st = marmot_attachment_local_assets(client, unknown_id, "abab", NULL, 65, &local_assets);
    check(st == MARMOT_STATUS_INVALID_ARGUMENT && local_assets == NULL, "local asset lookup bound");
    MarmotAttachmentLocalBytes *local_bytes = NULL;
    st = marmot_read_attachment_asset(client, unknown_id, "invalid", 0, 65536, &local_bytes);
    check(st != MARMOT_STATUS_OK && local_bytes == NULL, "local attachment reference validation");
    marmot_attachment_local_asset_list_free(local_assets);
    marmot_attachment_local_bytes_free(local_bytes);

    /* ---- boundary validation ------------------------------------------ */
    /* Out-of-range enum discriminants are rejected instead of becoming
     * invalid Rust enum values. */
    MarmotBackgroundNotificationCollection *collection = NULL;
    st = marmot_collect_notifications_after_wake(client, 0, 9999, &collection);
    check(st == MARMOT_STATUS_INVALID_ARGUMENT && collection == NULL,
          "out-of-range wake source -> MARMOT_STATUS_INVALID_ARGUMENT");

    /* A NULL required out-pointer is caught before the command runs. */
    st = marmot_chat_list(client, "no-such-account", 0, NULL);
    check(st == MARMOT_STATUS_NULL_POINTER, "NULL out rejected up front");

    /* ---- error taxonomy ----------------------------------------------- */
    MarmotStringList *relays_out = NULL;
    st = marmot_account_nip65_relays(client, "no-such-account", &relays_out);
    check(st == MARMOT_STATUS_UNKNOWN_ACCOUNT,
          "unknown account -> MARMOT_STATUS_UNKNOWN_ACCOUNT");

    MarmotChatNotificationSettings *mute = NULL;
    st = marmot_chat_notification_settings(client, "no-such-account", "aabb", &mute);
    check(st == MARMOT_STATUS_UNKNOWN_ACCOUNT,
          "chat_notification_settings on unknown account -> UNKNOWN_ACCOUNT");

    uint64_t accepted = 0;
    st = marmot_rotate_key_package(client, "no-such-account", &accepted);
    check(st == MARMOT_STATUS_UNKNOWN_ACCOUNT,
          "rotate_key_package on unknown account -> UNKNOWN_ACCOUNT");

    char *nsec = NULL;
    st = marmot_reveal_nsec(client, "no-such-account", &nsec);
    check(st == MARMOT_STATUS_UNKNOWN_ACCOUNT,
          "reveal_nsec on unknown account -> UNKNOWN_ACCOUNT");
    if (st != MARMOT_STATUS_OK) {
        marmot_string_free(marmot_last_error_message());
    } else {
        marmot_string_free(nsec);
    }

    /* ---- best-effort identity (needs a relay) ------------------------- */
    MarmotAccountSummary *summary = NULL;
    st = marmot_create_identity(client, relays, 1, relays, 1, &summary);
    if (st == MARMOT_STATUS_OK && summary != NULL) {
        printf("smoke: ok: identity created: %s\n", summary->account_id_hex);
        marmot_account_summary_free(summary);
    } else {
        printf("smoke: ok: identity create offline (status %d)\n", (int)st);
        print_last_error("create_identity");
    }

    /* ---- byte-buffer command + NULL-safe bytes free ------------------- */
    uint8_t *img = NULL;
    uintptr_t img_len = 0;
    st = marmot_download_group_blossom_image(client, "no-such-account",
                                             "aabb", &img, &img_len);
    check(st != MARMOT_STATUS_OK,
          "blossom image download on unknown account errors");
    marmot_bytes_free(img, img_len); /* (NULL, 0) on the error path */
    marmot_bytes_free(NULL, 0);      /* no-op */
    ok("bytes free is NULL-safe");

    /* ---- shutdown ----------------------------------------------------- */
    st = marmot_client_shutdown(client);
    check(st == MARMOT_STATUS_OK, "client shutdown");
    st = marmot_client_is_stopping(client, &stopping);
    check(st == MARMOT_STATUS_OK && stopping, "client reports stopping");
    marmot_client_free(client);

    if (failures == 0) {
        printf("smoke: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "smoke: %d checks FAILED\n", failures);
    return 1;
}
