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
    marmot_markdown_document_free(NULL);
    ok("NULL frees are no-ops");

    /* ---- construct + lifecycle ---------------------------------------- */
    const char *relays[] = {"wss://relay.example.org"};
    st = marmot_client_new(home, relays, 1, &client);
    if (st != MARMOT_STATUS_OK) {
        /* No platform keychain (headless): a documented limitation. */
        print_last_error("client_new");
        printf("smoke: SKIP: no client\n");
        return 0;
    }
    ok("client constructed");

    bool stopping = true;
    st = marmot_client_is_stopping(client, &stopping);
    check(st == MARMOT_STATUS_OK && !stopping, "client not stopping");

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
    check(!doc->truncated, "markdown not truncated");
    check(doc->blocks_len >= 4, "markdown has heading + paragraph + list + code");
    int headings = walk_markdown(doc);
    check(headings == 1, "walked tree found the heading");
    marmot_markdown_document_free(doc);

    /* ---- offline reads ------------------------------------------------ */
    MarmotAccountSummaryList *accounts = NULL;
    st = marmot_list_accounts(client, &accounts);
    check(st == MARMOT_STATUS_OK && accounts != NULL, "list_accounts");
    check(accounts->len == 0, "fresh home has no accounts");
    marmot_account_summary_list_free(accounts);

    /* Directory lookups for an unknown id resolve to absent (NULL out). */
    char *npub = NULL;
    const char *unknown_id =
        "0000000000000000000000000000000000000000000000000000000000000000";
    st = marmot_npub(client, unknown_id, &npub);
    check(st == MARMOT_STATUS_OK, "npub lookup call succeeds");
    marmot_string_free(npub);

    /* ---- error taxonomy ----------------------------------------------- */
    MarmotStringList *relays_out = NULL;
    st = marmot_account_nip65_relays(client, "no-such-account", &relays_out);
    check(st == MARMOT_STATUS_UNKNOWN_ACCOUNT,
          "unknown account -> MARMOT_STATUS_UNKNOWN_ACCOUNT");

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
