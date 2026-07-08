<?php

/**
 * Idiomatic PHP consumer of the marmot-c ABI, via the FFI extension.
 *
 * The raw C surface is wrapped in a small `Marmot` object that returns PHP
 * values and throws `MarmotException` on error, so the smoke test at the
 * bottom reads like ordinary PHP rather than transliterated C. It exercises
 * the same behaviour as examples/smoke.c: client lifecycle, markdown parsing,
 * offline reads (account list + directory npub lookup), the error taxonomy
 * (unknown-account reads throw a typed exception), best-effort identity
 * creation, and cleanup (here via the object destructor).
 *
 * Run (see c-smoke.sh for the canonical invocation). Needs the FFI extension:
 *   MARMOT_C_LIB=target/debug/libmarmot_c.so \
 *       php -d extension=ffi -d ffi.enable=1 examples/smoke.php <home-dir>
 */

declare(strict_types=1);

/**
 * Static-analysis view of the C functions the FFI handle defines at runtime.
 * Declaring them as `@method` on an interface, then typing the handle as the
 * intersection `\FFI&MarmotFfi`, lets editors and phpstan resolve calls that
 * FFI would otherwise expose only dynamically.
 *
 * @method int marmot_client_new(?string $root, ?\FFI\CData $relays, int $len, \FFI\CData $out)
 * @method int marmot_client_start(?\FFI\CData $client)
 * @method int marmot_client_shutdown(?\FFI\CData $client)
 * @method int marmot_client_is_stopping(?\FFI\CData $client, \FFI\CData $out)
 * @method void marmot_client_free(?\FFI\CData $client)
 * @method \FFI\CData|null marmot_last_error_message()
 * @method void marmot_string_free(?\FFI\CData $s)
 * @method int marmot_parse_markdown(?\FFI\CData $client, ?string $text, \FFI\CData $out)
 * @method void marmot_markdown_document_free(?\FFI\CData $doc)
 * @method int marmot_list_accounts(?\FFI\CData $client, \FFI\CData $out)
 * @method void marmot_account_summary_list_free(?\FFI\CData $list)
 * @method int marmot_account_nip65_relays(?\FFI\CData $client, ?string $ref, \FFI\CData $out)
 * @method int marmot_npub(?\FFI\CData $client, ?string $accountIdHex, \FFI\CData $out)
 * @method int marmot_reveal_nsec(?\FFI\CData $client, ?string $accountRef, \FFI\CData $out)
 * @method int marmot_create_identity(?\FFI\CData $client, ?\FFI\CData $def, int $defLen, ?\FFI\CData $boot, int $bootLen, \FFI\CData $out)
 * @method void marmot_account_summary_free(?\FFI\CData $summary)
 */
interface MarmotFfi
{
}

/** A non-OK MarmotStatus surfaced as an exception carrying the code + detail. */
final class MarmotException extends RuntimeException
{
    public function __construct(public readonly int $status, string $message)
    {
        parent::__construct($message);
    }
}

/** A parsed markdown document, reduced to what this example inspects. */
final class MarkdownDocument
{
    public function __construct(
        public readonly int $blockCount,
        public readonly bool $truncated,
    ) {
    }
}

final class Marmot
{
    private const CDEF = <<<'CDEF'
        typedef struct MarmotClient MarmotClient;
        typedef struct MarmotStringList MarmotStringList;
        typedef struct MarmotMarkdownBlock MarmotMarkdownBlock;

        typedef struct MarmotMarkdownDocument {
            MarmotMarkdownBlock *blocks;
            uintptr_t blocks_len;
            bool truncated;
        } MarmotMarkdownDocument;

        typedef struct MarmotAccountSummary {
            char *label;
            char *account_id_hex;
            bool local_signing;
            bool signed_out;
            bool running;
        } MarmotAccountSummary;

        typedef struct MarmotAccountSummaryList {
            MarmotAccountSummary *items;
            uintptr_t len;
        } MarmotAccountSummaryList;

        int marmot_client_new(const char *root_path, const char *const *relay_urls,
                              uintptr_t relay_urls_len, MarmotClient **out_client);
        int marmot_client_start(const MarmotClient *client);
        int marmot_client_shutdown(const MarmotClient *client);
        int marmot_client_is_stopping(const MarmotClient *client, bool *out_stopping);
        void marmot_client_free(MarmotClient *client);
        char *marmot_last_error_message(void);
        void marmot_string_free(char *s);
        int marmot_parse_markdown(const MarmotClient *client, const char *text,
                                  MarmotMarkdownDocument **out_document);
        void marmot_markdown_document_free(MarmotMarkdownDocument *document);
        int marmot_list_accounts(const MarmotClient *client, MarmotAccountSummaryList **out_list);
        void marmot_account_summary_list_free(MarmotAccountSummaryList *list);
        int marmot_account_nip65_relays(const MarmotClient *client, const char *account_ref,
                                        MarmotStringList **out_list);
        int marmot_npub(const MarmotClient *client, const char *account_id_hex, char **out_npub);
        int marmot_reveal_nsec(const MarmotClient *client, const char *account_ref, char **out_nsec);
        int marmot_create_identity(const MarmotClient *client,
                                   const char *const *default_relays, uintptr_t default_relays_len,
                                   const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len,
                                   MarmotAccountSummary **out_summary);
        void marmot_account_summary_free(MarmotAccountSummary *summary);
        CDEF;

    // MarmotStatus values referenced by name (stable ABI).
    public const STATUS_OK = 0;
    public const STATUS_UNKNOWN_ACCOUNT = 11;

    /** @var \FFI&MarmotFfi */
    private FFI $ffi;
    private ?FFI\CData $client;

    private function __construct(FFI $ffi, FFI\CData $client)
    {
        /** @var \FFI&MarmotFfi $ffi */
        $this->ffi = $ffi;
        $this->client = $client;
    }

    /**
     * Open a client rooted at $root and connected to $relays. Throws
     * MarmotException if the runtime rejects the configuration.
     *
     * @param list<string> $relays
     */
    public static function open(string $root, array $relays, ?string $libPath = null): self
    {
        /** @var \FFI&MarmotFfi $ffi */
        $ffi = FFI::cdef(self::CDEF, $libPath ?? (getenv('MARMOT_C_LIB') ?: 'libmarmot_c.so'));

        // Marshal the relay list into a C array of NUL-terminated strings.
        $buffers = [];
        $array = self::marshalStrings($ffi, $relays, $buffers);

        $out = $ffi->new('MarmotClient*');
        $status = $ffi->marmot_client_new($root, $array, count($relays), FFI::addr($out));
        if ($status !== self::STATUS_OK) {
            throw new MarmotException($status, self::takeLastError($ffi));
        }
        return new self($ffi, $out);
    }

    /**
     * Start the runtime. Returns null on success, or the runtime's error
     * detail when it fails (e.g. offline, where dial-safety rejects the
     * relay) so the caller can proceed in a degraded mode.
     */
    public function tryStart(): ?string
    {
        $status = $this->ffi->marmot_client_start($this->client);
        return $status === self::STATUS_OK ? null : self::takeLastError($this->ffi);
    }

    public function isStopping(): bool
    {
        $flag = $this->ffi->new('bool');
        $this->check($this->ffi->marmot_client_is_stopping($this->client, FFI::addr($flag)), 'is_stopping');
        return (bool) $flag->cdata;
    }

    public function parseMarkdown(string $text): MarkdownDocument
    {
        $out = $this->ffi->new('MarmotMarkdownDocument*');
        $this->check($this->ffi->marmot_parse_markdown($this->client, $text, FFI::addr($out)), 'parse_markdown');
        try {
            return new MarkdownDocument((int) $out->blocks_len, (bool) $out->truncated);
        } finally {
            $this->ffi->marmot_markdown_document_free($out);
        }
    }

    /** Number of accounts known to this device. */
    public function accountCount(): int
    {
        $out = $this->ffi->new('MarmotAccountSummaryList*');
        $this->check($this->ffi->marmot_list_accounts($this->client, FFI::addr($out)), 'list_accounts');
        try {
            return (int) $out->len;
        } finally {
            $this->ffi->marmot_account_summary_list_free($out);
        }
    }

    /** Throws MarmotException (status STATUS_UNKNOWN_ACCOUNT) for a bad ref. */
    public function nip65Relays(string $accountRef): void
    {
        $out = $this->ffi->new('MarmotStringList*');
        $this->check(
            $this->ffi->marmot_account_nip65_relays($this->client, $accountRef, FFI::addr($out)),
            'nip65_relays',
        );
        // (A real caller would read + free $out here; this example only needs
        // the error path.)
    }

    /**
     * Directory lookup: the npub for a known account id, or null when the id
     * is absent from the directory. Throws MarmotException on a call error.
     */
    public function npub(string $accountIdHex): ?string
    {
        $out = $this->ffi->new('char*');
        $this->check($this->ffi->marmot_npub($this->client, $accountIdHex, FFI::addr($out)), 'npub');
        if (FFI::isNull($out)) {
            return null;
        }
        try {
            return FFI::string($out);
        } finally {
            $this->ffi->marmot_string_free($out);
        }
    }

    /**
     * Reveal the nsec (private key) for a local account. Throws
     * MarmotException (status STATUS_UNKNOWN_ACCOUNT) for an unknown ref.
     */
    public function revealNsec(string $accountRef): string
    {
        $out = $this->ffi->new('char*');
        $this->check($this->ffi->marmot_reveal_nsec($this->client, $accountRef, FFI::addr($out)), 'reveal_nsec');
        try {
            return FFI::isNull($out) ? '' : FFI::string($out);
        } finally {
            $this->ffi->marmot_string_free($out);
        }
    }

    /**
     * Best-effort identity creation: publishes a fresh account to the given
     * relays and returns its account_id_hex. Throws MarmotException when the
     * runtime rejects it (e.g. offline, where the publish cannot reach a relay).
     *
     * @param list<string> $relays default + bootstrap relay set for the account
     */
    public function createIdentity(array $relays): string
    {
        $buffers = [];
        $array = self::marshalStrings($this->ffi, $relays, $buffers);
        $count = count($relays);

        $out = $this->ffi->new('MarmotAccountSummary*');
        $this->check(
            $this->ffi->marmot_create_identity($this->client, $array, $count, $array, $count, FFI::addr($out)),
            'create_identity',
        );
        try {
            return FFI::string($out->account_id_hex);
        } finally {
            $this->ffi->marmot_account_summary_free($out);
        }
    }

    public function shutdown(): void
    {
        if ($this->client !== null) {
            $this->ffi->marmot_client_shutdown($this->client);
        }
    }

    public function __destruct()
    {
        if ($this->client !== null) {
            $this->ffi->marmot_client_free($this->client);
            $this->client = null;
        }
    }

    private function check(int $status, string $op): void
    {
        if ($status !== self::STATUS_OK) {
            throw new MarmotException($status, "$op: " . self::takeLastError($this->ffi));
        }
    }

    /**
     * Marshal a PHP string list into a C `char*[]` of NUL-terminated buffers.
     * The owning buffers are appended to $buffers, which the caller must keep
     * alive for the duration of the FFI call.
     *
     * @param list<string>       $strings
     * @param list<\FFI\CData>   $buffers out-param: backing buffers to pin
     */
    private static function marshalStrings(FFI $ffi, array $strings, array &$buffers): FFI\CData
    {
        $count = max(count($strings), 1); // char*[0] is not a valid type
        $array = $ffi->new("char*[$count]");
        foreach (array_values($strings) as $i => $s) {
            $buf = $ffi->new('char[' . (strlen($s) + 1) . ']', false);
            FFI::memcpy($buf, $s, strlen($s));
            $buffers[] = $buf; // keep alive across the call
            $array[$i] = FFI::cast('char*', FFI::addr($buf));
        }
        return $array;
    }

    private static function takeLastError(FFI $ffi): string
    {
        /** @var \FFI&MarmotFfi $ffi */
        $msg = $ffi->marmot_last_error_message();
        if (FFI::isNull($msg)) {
            return '(no detail)';
        }
        try {
            return FFI::string($msg);
        } finally {
            $ffi->marmot_string_free($msg);
        }
    }
}

// --- smoke test -----------------------------------------------------------

/** @param non-empty-string $what */
function ok(string $what): void
{
    fwrite(STDOUT, "smoke(php): ok: $what\n");
}

function fail(string $what): never
{
    fwrite(STDOUT, "smoke(php): FAILED: $what\n");
    exit(1);
}

$home = $argv[1] ?? null;
if ($home === null) {
    fwrite(STDERR, "usage: smoke.php <fresh-home-dir>\n");
    exit(2);
}

try {
    $marmot = Marmot::open($home, ['ws://127.0.0.1:7777']);
} catch (MarmotException $e) {
    // Headless environments may lack a platform keychain; documented
    // limitation, not an ABI defect.
    fwrite(STDOUT, "smoke(php): SKIP: open failed (status {$e->status}): {$e->getMessage()}\n");
    exit(0);
}
ok('client constructed');

$marmot->isStopping() && fail('fresh client should not be stopping');
ok('client not stopping');

// start() may fail offline (dial-safety rejects loopback relays); that still
// exercises the start + error path. Either outcome is fine.
$startError = $marmot->tryStart();
ok($startError === null ? 'client started' : "client start offline: $startError");

$doc = $marmot->parseMarkdown(
    "# Marmot\n\n"
    . "A **bold** claim with `code` and a [link](https://example.org).\n\n"
    . "- [x] dig burrow\n"
    . "- [ ] store acorns\n\n"
    . "```rust\nfn main() {}\n```\n"
);
$doc->blockCount >= 4 || fail('markdown should have heading + paragraph + list + code');
ok('markdown parsed with ' . $doc->blockCount . ' blocks');
$doc->truncated && fail('markdown should not be truncated');
ok('markdown not truncated');

$marmot->accountCount() === 0 || fail('fresh home should have no accounts');
ok('fresh home has no accounts');

// Directory lookup for an unknown id succeeds (absent id -> null or a
// derived npub); either way it must not raise.
$unknownId = str_repeat('0', 64);
$npub = $marmot->npub($unknownId);
ok('directory npub lookup returns ' . ($npub === null ? 'null (absent)' : $npub));

// Error taxonomy: both reads on an unknown account raise the same typed error.
foreach (['nip65Relays', 'revealNsec'] as $op) {
    try {
        $marmot->{$op}('no-such-account');
        fail("$op on unknown account should throw");
    } catch (MarmotException $e) {
        $e->status === Marmot::STATUS_UNKNOWN_ACCOUNT || fail("$op: unexpected status {$e->status}");
        $e->getMessage() !== '' || fail("$op: exception should carry detail");
        ok("$op unknown account throws typed MarmotException");
    }
}

// Best-effort: creating an identity needs a relay; offline it reports the
// typed error and the run continues.
try {
    $accountId = $marmot->createIdentity(['wss://relay.example.org']);
    ok("identity created: $accountId");
} catch (MarmotException $e) {
    ok("identity create offline (status {$e->status}): {$e->getMessage()}");
}

$marmot->shutdown();
$marmot->isStopping() || fail('client should report stopping after shutdown');
ok('client reports stopping after shutdown');

unset($marmot); // destructor frees the client
ok('client freed via destructor');

fwrite(STDOUT, "smoke(php): all checks passed\n");
