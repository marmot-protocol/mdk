// Shared identity-reference regression corpus.
//
// Test-only data included by app, UniFFI, C, directory-preview, and
// markdown tests. This is not a production export and does not implement
// a decoder.
//
// Structured boundary and malformed nprofile literals were produced with
// the locked nostr 0.44.8 / bech32 0.11.1 encoder from explicit TLV
// bytes. Wrapper, checksum-mutation, and oversized cases are built with
// `std` string construction.

#[allow(dead_code)]
pub struct IdentityReferenceCase {
    pub name: &'static str,
    pub reference: String,
    pub app_account_id_hex: Option<&'static str>,
    pub ffi_account_id_hex: Option<&'static str>,
    /// Markdown recognizer baseline: the recognized NIP-19 HRP, or None when
    /// the reference produces no nostr entity in message content.
    pub md_hrp: Option<&'static str>,
    /// Preview parser baseline: the preview cache key
    /// (`event:<64hex>` / `coordinate:<kind>:<64hex>:<d>`), or None when the
    /// preview parser does not support the reference.
    pub previews_target: Option<&'static str>,
    /// Divergence-decision marker for rows where the baseline parsers
    /// disagree (mdk#2362 slice 1).
    pub target: Option<&'static str>,
}

/// Which parser family owns a corpus row's literal.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceCategory {
    /// Profile account reference: hex account id, npub or nprofile.
    Profile,
    /// Event reference: note, nevent, or a bare 64-hex event id.
    Event,
    /// Addressable-event coordinate reference: naddr.
    Address,
}

/// Canonical lowercase hex account id used by every accepted vector.
pub const ACCOUNT_ID: &str = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
/// Bech32 npub for ACCOUNT_ID.
pub const NPUB: &str = "npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy";
/// nprofile TLV: type-0 ACCOUNT_ID plus two bootstrap relay URLs (wss://relay.eu.whitenoise.chat, wss://relay.us.whitenoise.chat).
pub const BOOTSTRAP_NPROFILE: &str = concat!(
    "nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0dqpremhxue69uhhyet",
    "vv9ujuet49emks6t5v4hx76tnv5hxx6rpwsq3uamnwvaz7tmjv4kxz7fww4ejuamgd96x2mn0d9ek2tn",
    "rdpshggcu28s"
);
/// nprofile TLV: type-0 ACCOUNT_ID only.
pub const NO_RELAY_NPROFILE: &str = "nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0dq7r0nz9";
/// nprofile TLV: type-0 ACCOUNT_ID plus one example.invalid relay hint.
pub const OTHER_RELAY_NPROFILE: &str = concat!(
    "nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0dqprdmhxue69uhhyet",
    "vv9ujuetcv9khqmr99e5kuanpd35kg3k65qt"
);
/// nprofile TLV: type-0 ACCOUNT_ID plus one unknown TLV entry that the SDK ignores.
pub const UNKNOWN_TLV_NPROFILE: &str = "nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0drrq3skycmyxne9kf";
/// nprofile TLV: type-0 ACCOUNT_ID plus a type-1 value that is not a valid relay URL; the SDK discards the hint.
pub const INVALID_RELAY_NPROFILE: &str = "nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0dqpp9hx7apqvys82unvuca0cf";
/// nprofile TLV: type-0 ACCOUNT_ID followed by a second distinct type-0 key (0xbb repeating). SDK first-wins keeps ACCOUNT_ID.
pub const DUPLICATE_TYPE0_NPROFILE: &str = concat!(
    "nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0dqqyzamhwamhwamhwa",
    "mhwamhwamhwamhwamhwamhwamhwamhwamhwamkq4uk7z"
);
/// nprofile TLV: relay hint only; no type-0 pubkey.
pub const MISSING_TYPE0_NPROFILE: &str = "nprofile1qy2hwumn8ghj7etcv9khqmr99e5kuanpd35kghsdudn";
/// nprofile TLV: type-0 value shorter than 32 bytes.
pub const SHORT_TYPE0_NPROFILE: &str = "nprofile1qqg25n7gve04d9hr8km7rftjuwc028ngcqe";
/// nprofile TLV: truncated header (type present, length/value missing).
pub const TRUNCATED_HEADER_NPROFILE: &str = "nprofile1qqqsnhxh";
/// nprofile TLV: type-0 header claims more value bytes than remain.
pub const TRUNCATED_VALUE_NPROFILE: &str = "nprofile1qqs25n7gve04d9hrdfl42d";
/// Valid Bech32 checksum with note HRP over nprofile-shaped data.
pub const WRONG_HRP_NOTE: &str = "note1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0dq4ueyyt";
/// Valid note encoding of a synthetic all-0x22 EventId; not an identity reference.
pub const NOTE_EVENT_HRP: &str = "note1yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3qmtdh3n";
/// Valid nevent for the synthetic EventId authored by ACCOUNT_ID.
pub const NEVENT_EVENT_HRP: &str = concat!(
    "nevent1qqszyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygszyz4yljrxtatfdceak",
    "ls62uhrkr6m84s4sdas7d3devwgq69snrrmg7zexkt"
);
/// Valid naddr for kind 0 / ACCOUNT_ID.
pub const NADDR_EVENT_HRP: &str = "naddr1qqqqyg92flyxvh6kjm3nmdlp54ew8v84k0tptqmmpumzmjcusp5tpxx8kspsgqqqqqqqjuu87v";
/// Synthetic nsec for SecretKey([0x11; 32]). Rejection fixture only; never a real credential.
pub const NSEC_SYNTHETIC_REJECTION: &str = "nsec1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs4rm7hz";
/// Synthetic all-0x22 event id as 64 lowercase hex characters.
pub const EVENT_ID_32_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
/// Valid nevent for the synthetic EventId authored by ACCOUNT_ID with one relay hint.
pub const NEVENT_RELAY_HINT_EVENT_HRP: &str = "nevent1qqszyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygszyz4yljrxtatfdceakls62uhrkr6m84s4sdas7d3devwgq69snrrmgqgmwaehxw309aex2mrp0yhx27rpd4cxcefwd9h8vctvd9jqmvq0h9";
/// Valid naddr for kind 30023 / ACCOUNT_ID with d tag "entry" and no relay hints.
pub const NADDR_KIND30023_ENTRY: &str = "naddr1qqzk2mn5wfusyg92flyxvh6kjm3nmdlp54ew8v84k0tptqmmpumzmjcusp5tpxx8kspsgqqqw4rs444wp9";
/// Valid naddr for kind 10002 / ACCOUNT_ID with an empty d tag.
pub const NADDR_KIND10002: &str = "naddr1qqqqyg92flyxvh6kjm3nmdlp54ew8v84k0tptqmmpumzmjcusp5tpxx8kspsgqqqyufqehsz4a";
/// Valid naddr for kind 1 / ACCOUNT_ID with an empty d tag.
pub const NADDR_KIND1: &str = "naddr1qqqqyg92flyxvh6kjm3nmdlp54ew8v84k0tptqmmpumzmjcusp5tpxx8kspsgqqqqqqs8a5ltl";
/// Valid naddr for kind 41 / ACCOUNT_ID with an empty d tag.
pub const NADDR_KIND41: &str = "naddr1qqqqyg92flyxvh6kjm3nmdlp54ew8v84k0tptqmmpumzmjcusp5tpxx8kspsgqqqqq5s588j6u";
/// Valid naddr for kind 0 / ACCOUNT_ID with d tag "entry".
pub const NADDR_KIND0_WITH_D: &str = "naddr1qqzk2mn5wfusyg92flyxvh6kjm3nmdlp54ew8v84k0tptqmmpumzmjcusp5tpxx8kspsgqqqqqqq2rwc3u";
/// Preview cache key for the synthetic all-0x22 event id.
pub const PREVIEW_EVENT_2222: &str = "event:2222222222222222222222222222222222222222222222222222222222222222";
/// Preview cache key for ACCOUNT_ID parsed as a bare 64-hex event id.
pub const PREVIEW_EVENT_ACCOUNT_ID: &str = "event:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
/// Preview cache key for the kind-0 naddr with an empty d tag.
pub const PREVIEW_COORDINATE_KIND0: &str = "coordinate:0:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4:";
/// Preview cache key for the kind-30023 naddr with d tag "entry".
pub const PREVIEW_COORDINATE_KIND30023_ENTRY: &str = "coordinate:30023:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4:entry";
/// Preview cache key for the kind-10002 naddr with an empty d tag.
pub const PREVIEW_COORDINATE_KIND10002: &str = "coordinate:10002:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4:";
/// Divergence decision: the parsers disagree and the split is kept as-is.
pub const TARGET_KEEP: &str = "keep";
/// Divergence decision: the identity category is chosen by the call-site API.
pub const TARGET_SPLIT_BY_CALL_SITE: &str = "split-by-call-site";
/// Valid 1022-byte nprofile: type-0 ACCOUNT_ID plus unknown 0xff extension padding (629 TLV bytes).
pub const BOUNDARY_1022_NPROFILE: &str = concat!(
    "nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0d8llad95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6ttll7kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd94l60tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95ksutn624"
);
/// Valid 1023-byte nprofile: type-0 ACCOUNT_ID plus unknown 0xff extension padding (630 TLV bytes).
pub const BOUNDARY_1023_NPROFILE: &str = concat!(
    "nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0d8llad95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6ttll7kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd94l6stfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6v7xa0l"
);
/// Valid 1023-byte nprofile: type-0 ACCOUNT_ID, eight wss://r{0-7}.example.invalid relays, plus 0xff extensions (630 TLV bytes).
pub const BOUNDARY_1023_EIGHT_RELAY_NPROFILE: &str = concat!(
    "nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0dqprpmhxue69uhhyvp",
    "wv4uxzmtsd3jju6twweskc6tyqyv8wumn8ghj7u339ejhsctdwpkx2tnfdemxzmrfvsq3samnwvaz7tm",
    "jxghx27rpd4cxcefwd9h8vctvd9jqzxrhwden5te0wgejuetcv9khqmr99e5kuanpd35kgqgcwaehxw3",
    "09aergtn90psk6urvv5hxjmnkv9kxjeqprpmhxue69uhhydfwv4uxzmtsd3jju6twweskc6tyqyv8wum",
    "n8ghj7u3k9ejhsctdwpkx2tnfdemxzmrfvsq3samnwvaz7tmjxuhx27rpd4cxcefwd9h8vctvd9j0ll6",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95khls9d95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj",
    "6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6n8net0"
);

/// Baseline defaults for the markdown/preview/decision columns. Profile rows
/// start from no markdown entity and no preview target, and the rows the
/// recognizers do accept override those below; event and address rows built
/// through `event_ref` carry their preview baseline explicitly (bare and
/// `nostr:`-wrapped forms differ, so there is no single per-category default).
fn new_column_defaults(
    category: ReferenceCategory,
) -> (
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
) {
    match category {
        ReferenceCategory::Profile => (None, None, None),
        ReferenceCategory::Event | ReferenceCategory::Address => (None, None, None),
    }
}

fn accepted(
    category: ReferenceCategory,
    name: &'static str,
    reference: impl Into<String>,
) -> IdentityReferenceCase {
    let (md_hrp, previews_target, target) = new_column_defaults(category);
    IdentityReferenceCase {
        name,
        reference: reference.into(),
        app_account_id_hex: Some(ACCOUNT_ID),
        ffi_account_id_hex: Some(ACCOUNT_ID),
        md_hrp,
        previews_target,
        target,
    }
}

fn rejected(
    category: ReferenceCategory,
    name: &'static str,
    reference: impl Into<String>,
) -> IdentityReferenceCase {
    let (md_hrp, previews_target, target) = new_column_defaults(category);
    IdentityReferenceCase {
        name,
        reference: reference.into(),
        app_account_id_hex: None,
        ffi_account_id_hex: None,
        md_hrp,
        previews_target,
        target,
    }
}

fn app_only(
    category: ReferenceCategory,
    name: &'static str,
    reference: impl Into<String>,
) -> IdentityReferenceCase {
    let (md_hrp, previews_target, target) = new_column_defaults(category);
    IdentityReferenceCase {
        name,
        reference: reference.into(),
        app_account_id_hex: Some(ACCOUNT_ID),
        ffi_account_id_hex: None,
        md_hrp,
        previews_target,
        target,
    }
}

fn ffi_only(
    category: ReferenceCategory,
    name: &'static str,
    reference: impl Into<String>,
) -> IdentityReferenceCase {
    let (md_hrp, previews_target, target) = new_column_defaults(category);
    IdentityReferenceCase {
        name,
        reference: reference.into(),
        app_account_id_hex: None,
        ffi_account_id_hex: Some(ACCOUNT_ID),
        md_hrp,
        previews_target,
        target,
    }
}

/// Event or address reference row: the identity parsers never resolve these,
/// so both identity columns stay None. `previews_target` records the preview
/// parser's baseline (None when it does not support the reference).
fn event_ref(
    name: &'static str,
    reference: impl Into<String>,
    previews_target: Option<&'static str>,
) -> IdentityReferenceCase {
    IdentityReferenceCase {
        name,
        reference: reference.into(),
        app_account_id_hex: None,
        ffi_account_id_hex: None,
        md_hrp: None,
        previews_target,
        target: None,
    }
}

impl IdentityReferenceCase {
    /// Overrides the markdown baseline for a row the recognizer accepts.
    fn with_md_hrp(mut self, hrp: &'static str) -> Self {
        self.md_hrp = Some(hrp);
        self
    }

    /// Overrides the preview baseline for a row the preview parser supports.
    fn with_previews_target(mut self, target: &'static str) -> Self {
        self.previews_target = Some(target);
        self
    }

    /// Records the divergence decision for a row the baseline parsers
    /// disagree on.
    fn with_target(mut self, target: &'static str) -> Self {
        self.target = Some(target);
        self
    }
}

fn damaged_checksum(token: &str) -> String {
    let mut damaged = token.to_owned();
    let last = damaged.len() - 1;
    damaged.replace_range(last.., "x");
    assert_ne!(damaged, token, "checksum mutation must change the input");
    damaged
}

fn oversized_nprofile(len: usize) -> String {
    let prefix = "nprofile1";
    assert!(len >= prefix.len());
    let mut token = String::from(prefix);
    token.push_str(&"q".repeat(len - prefix.len()));
    token
}

pub fn cases() -> Vec<IdentityReferenceCase> {
    let cases = vec![
        accepted(ReferenceCategory::Profile, "hex_lowercase", ACCOUNT_ID)
            .with_previews_target(PREVIEW_EVENT_ACCOUNT_ID)
            .with_target(TARGET_SPLIT_BY_CALL_SITE),
        accepted(ReferenceCategory::Profile, "hex_uppercase", ACCOUNT_ID.to_ascii_uppercase())
            .with_previews_target(PREVIEW_EVENT_ACCOUNT_ID)
            .with_target(TARGET_SPLIT_BY_CALL_SITE),
        accepted(ReferenceCategory::Profile, "npub", NPUB).with_md_hrp("npub"),
        accepted(ReferenceCategory::Profile, "nostr_npub", format!("nostr:{NPUB}"))
            .with_md_hrp("npub"),
        accepted(ReferenceCategory::Profile, "bootstrap_nprofile", BOOTSTRAP_NPROFILE)
            .with_target(TARGET_KEEP),
        accepted(
            ReferenceCategory::Profile,
            "nostr_bootstrap_nprofile",
            format!("nostr:{BOOTSTRAP_NPROFILE}"),
        )
        .with_md_hrp("nprofile"),
        accepted(ReferenceCategory::Profile, "no_relay_nprofile", NO_RELAY_NPROFILE)
            .with_target(TARGET_KEEP),
        accepted(
            ReferenceCategory::Profile,
            "nostr_no_relay_nprofile",
            format!("nostr:{NO_RELAY_NPROFILE}"),
        )
        .with_md_hrp("nprofile"),
        accepted(ReferenceCategory::Profile, "other_relay_nprofile", OTHER_RELAY_NPROFILE)
            .with_target(TARGET_KEEP),
        accepted(ReferenceCategory::Profile, "unknown_tlv_nprofile", UNKNOWN_TLV_NPROFILE)
            .with_target(TARGET_KEEP),
        accepted(ReferenceCategory::Profile, "invalid_relay_nprofile", INVALID_RELAY_NPROFILE)
            .with_target(TARGET_KEEP),
        accepted(
            ReferenceCategory::Profile,
            "duplicate_type0_first_wins",
            DUPLICATE_TYPE0_NPROFILE,
        )
        .with_target(TARGET_KEEP),
        ffi_only(ReferenceCategory::Profile, "whitespace_hex", format!(" {ACCOUNT_ID}"))
            .with_previews_target(PREVIEW_EVENT_ACCOUNT_ID)
            .with_target(TARGET_SPLIT_BY_CALL_SITE),
        ffi_only(
            ReferenceCategory::Profile,
            "trailing_whitespace_npub",
            format!("{NPUB} "),
        )
        .with_md_hrp("npub"),
        ffi_only(ReferenceCategory::Profile, "whitespace_nprofile", format!(" {NO_RELAY_NPROFILE}")),
        ffi_only(
            ReferenceCategory::Profile,
            "profile_link_nprofile_query",
            format!("marmot://profile/{NO_RELAY_NPROFILE}?from=qr"),
        ),
        ffi_only(
            ReferenceCategory::Profile,
            "profile_link_nprofile_fragment",
            format!("marmot://profile/{NO_RELAY_NPROFILE}#frag"),
        ),
        ffi_only(
            ReferenceCategory::Profile,
            "profile_link_nprofile_trailing_slash",
            format!("marmot://profile/{NO_RELAY_NPROFILE}/"),
        ),
        ffi_only(
            ReferenceCategory::Profile,
            "profile_link_npub_query",
            format!("marmot://profile/{NPUB}?from=qr"),
        ),
        ffi_only(
            ReferenceCategory::Profile,
            "double_nostr_npub",
            format!("nostr:nostr:{NPUB}"),
        )
        .with_md_hrp("npub"),
        ffi_only(
            ReferenceCategory::Profile,
            "double_nostr_nprofile",
            format!("nostr:nostr:{NO_RELAY_NPROFILE}"),
        )
        .with_md_hrp("nprofile"),
        app_only(
            ReferenceCategory::Profile,
            "legacy_colon_suffix_npub",
            format!("nostr:{NPUB}:{}", "x".repeat(4096)),
        )
        .with_md_hrp("npub"),
        rejected(ReferenceCategory::Profile, "empty", ""),
        rejected(ReferenceCategory::Profile, "ordinary_invalid", "not-a-public-key"),
        rejected(
            ReferenceCategory::Profile,
            "uppercase_nostr_nprofile",
            format!("NOSTR:{NO_RELAY_NPROFILE}"),
        ),
        rejected(ReferenceCategory::Profile, "damaged_npub_checksum", damaged_checksum(NPUB))
            .with_md_hrp("npub")
            .with_target(TARGET_KEEP),
        rejected(
            ReferenceCategory::Profile,
            "damaged_nprofile_checksum",
            damaged_checksum(NO_RELAY_NPROFILE),
        ),
        rejected(ReferenceCategory::Profile, "wrong_hrp_note_shaped", WRONG_HRP_NOTE),
        rejected(ReferenceCategory::Profile, "note_event_hrp", NOTE_EVENT_HRP)
            .with_previews_target(PREVIEW_EVENT_2222)
            .with_target(TARGET_KEEP),
        rejected(ReferenceCategory::Profile, "nevent_event_hrp", NEVENT_EVENT_HRP)
            .with_previews_target(PREVIEW_EVENT_2222)
            .with_target(TARGET_KEEP),
        rejected(ReferenceCategory::Profile, "naddr_event_hrp", NADDR_EVENT_HRP)
            .with_previews_target(PREVIEW_COORDINATE_KIND0)
            .with_target(TARGET_KEEP),
        rejected(ReferenceCategory::Profile, "nsec_synthetic", NSEC_SYNTHETIC_REJECTION),
        // Event and address references: the identity parsers never resolve
        // these (the nprofile fallback is the only accepted bech32 family);
        // the markdown recognizer renders only the `nostr:`-wrapped forms,
        // and the preview parser supports the coordinate kinds it names.
        event_ref(
            "nostr_note_event_hrp",
            format!("nostr:{NOTE_EVENT_HRP}"),
            Some(PREVIEW_EVENT_2222),
        )
        .with_md_hrp("note")
        .with_target(TARGET_KEEP),
        event_ref(
            "nostr_nevent_event_hrp",
            format!("nostr:{NEVENT_EVENT_HRP}"),
            Some(PREVIEW_EVENT_2222),
        )
        .with_md_hrp("nevent")
        .with_target(TARGET_KEEP),
        event_ref(
            "nostr_naddr_event_hrp",
            format!("nostr:{NADDR_EVENT_HRP}"),
            Some(PREVIEW_COORDINATE_KIND0),
        )
        .with_md_hrp("naddr")
        .with_target(TARGET_KEEP),
        event_ref(
            "naddr_kind30023",
            NADDR_KIND30023_ENTRY,
            Some(PREVIEW_COORDINATE_KIND30023_ENTRY),
        )
        .with_target(TARGET_KEEP),
        event_ref(
            "naddr_kind10002",
            NADDR_KIND10002,
            Some(PREVIEW_COORDINATE_KIND10002),
        )
        .with_target(TARGET_KEEP),
        event_ref("naddr_kind1", NADDR_KIND1, None).with_target(TARGET_KEEP),
        event_ref("naddr_kind0_with_d", NADDR_KIND0_WITH_D, None).with_target(TARGET_KEEP),
        event_ref("naddr_kind41", NADDR_KIND41, None).with_target(TARGET_KEEP),
        event_ref(
            "nevent_with_relay_hint",
            NEVENT_RELAY_HINT_EVENT_HRP,
            Some(PREVIEW_EVENT_2222),
        )
        .with_target(TARGET_KEEP),
        // A bare 64-hex event id: the identity parsers read it as an account
        // id while the preview parser reads it as an event id. The category
        // is chosen by the call-site API, not by the literal.
        IdentityReferenceCase {
            name: "hex_event_id_32",
            reference: EVENT_ID_32_HEX.to_owned(),
            app_account_id_hex: Some(EVENT_ID_32_HEX),
            ffi_account_id_hex: Some(EVENT_ID_32_HEX),
            md_hrp: None,
            previews_target: Some(PREVIEW_EVENT_2222),
            target: Some(TARGET_SPLIT_BY_CALL_SITE),
        },
        // Markdown-only surface: `@` mentions accept the Npub HRP only.
        event_ref("at_npub", format!("@{NPUB}"), None).with_md_hrp("npub"),
        event_ref("at_nprofile", format!("@{NO_RELAY_NPROFILE}"), None)
            .with_target(TARGET_KEEP),
        rejected(ReferenceCategory::Profile, "missing_type0", MISSING_TYPE0_NPROFILE),
        rejected(ReferenceCategory::Profile, "short_type0", SHORT_TYPE0_NPROFILE),
        rejected(ReferenceCategory::Profile, "truncated_header", TRUNCATED_HEADER_NPROFILE),
        rejected(ReferenceCategory::Profile, "truncated_value", TRUNCATED_VALUE_NPROFILE),
        accepted(ReferenceCategory::Profile, "boundary_1022_bare", BOUNDARY_1022_NPROFILE)
            .with_target(TARGET_KEEP),
        accepted(
            ReferenceCategory::Profile,
            "boundary_1022_nostr",
            format!("nostr:{BOUNDARY_1022_NPROFILE}"),
        )
        .with_md_hrp("nprofile"),
        ffi_only(
            ReferenceCategory::Profile,
            "boundary_1022_profile_link",
            format!("marmot://profile/{BOUNDARY_1022_NPROFILE}?from=qr"),
        ),
        accepted(ReferenceCategory::Profile, "boundary_1023_bare", BOUNDARY_1023_NPROFILE)
            .with_target(TARGET_KEEP),
        accepted(
            ReferenceCategory::Profile,
            "boundary_1023_nostr",
            format!("nostr:{BOUNDARY_1023_NPROFILE}"),
        )
        .with_md_hrp("nprofile"),
        ffi_only(
            ReferenceCategory::Profile,
            "boundary_1023_profile_link",
            format!("marmot://profile/{BOUNDARY_1023_NPROFILE}?from=qr"),
        ),
        accepted(
            ReferenceCategory::Profile,
            "boundary_1023_eight_relays_bare",
            BOUNDARY_1023_EIGHT_RELAY_NPROFILE,
        )
        .with_target(TARGET_KEEP),
        accepted(
            ReferenceCategory::Profile,
            "boundary_1023_eight_relays_nostr",
            format!("nostr:{BOUNDARY_1023_EIGHT_RELAY_NPROFILE}"),
        )
        .with_md_hrp("nprofile"),
        ffi_only(
            ReferenceCategory::Profile,
            "boundary_1023_eight_relays_profile_link",
            format!("marmot://profile/{BOUNDARY_1023_EIGHT_RELAY_NPROFILE}?from=qr"),
        ),
        rejected(ReferenceCategory::Profile, "oversized_1024", oversized_nprofile(1024)),
        rejected(ReferenceCategory::Profile, "oversized_4096", oversized_nprofile(4096)),
        rejected(ReferenceCategory::Profile, "oversized_1000000", oversized_nprofile(1_000_000)),
        rejected(
            ReferenceCategory::Profile,
            "oversized_1024_nostr",
            format!("nostr:{}", oversized_nprofile(1024)),
        )
        .with_md_hrp("nprofile")
        .with_target(TARGET_KEEP),
    ];

    assert!(
        !cases.is_empty(),
        "identity-reference corpus must be nonempty"
    );
    let mut names = std::collections::BTreeSet::new();
    for case in &cases {
        assert!(
            names.insert(case.name),
            "duplicate identity-reference case name: {}",
            case.name
        );
    }
    assert_eq!(BOUNDARY_1022_NPROFILE.len(), 1022);
    assert_eq!(BOUNDARY_1023_NPROFILE.len(), 1023);
    assert_eq!(BOUNDARY_1023_EIGHT_RELAY_NPROFILE.len(), 1023);
    assert_eq!(EVENT_ID_32_HEX.len(), 64);
    assert!(EVENT_ID_32_HEX.bytes().all(|byte| byte == b'2'));
    assert_eq!(PREVIEW_EVENT_ACCOUNT_ID, format!("event:{ACCOUNT_ID}"));
    assert_eq!(PREVIEW_EVENT_2222, format!("event:{EVENT_ID_32_HEX}"));
    let colon_suffix = cases
        .iter()
        .find(|case| case.name == "legacy_colon_suffix_npub")
        .expect("legacy colon-suffix case");
    assert_eq!(colon_suffix.reference.len(), 4166);
    cases
}
