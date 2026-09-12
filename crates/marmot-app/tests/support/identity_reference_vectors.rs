// Shared identity-reference regression corpus.
//
// Test-only data included by app, UniFFI, and C tests. This is not a
// production export and does not implement a decoder.
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

fn accepted(name: &'static str, reference: impl Into<String>) -> IdentityReferenceCase {
    IdentityReferenceCase {
        name,
        reference: reference.into(),
        app_account_id_hex: Some(ACCOUNT_ID),
        ffi_account_id_hex: Some(ACCOUNT_ID),
    }
}

fn rejected(name: &'static str, reference: impl Into<String>) -> IdentityReferenceCase {
    IdentityReferenceCase {
        name,
        reference: reference.into(),
        app_account_id_hex: None,
        ffi_account_id_hex: None,
    }
}

fn app_only(name: &'static str, reference: impl Into<String>) -> IdentityReferenceCase {
    IdentityReferenceCase {
        name,
        reference: reference.into(),
        app_account_id_hex: Some(ACCOUNT_ID),
        ffi_account_id_hex: None,
    }
}

fn ffi_only(name: &'static str, reference: impl Into<String>) -> IdentityReferenceCase {
    IdentityReferenceCase {
        name,
        reference: reference.into(),
        app_account_id_hex: None,
        ffi_account_id_hex: Some(ACCOUNT_ID),
    }
}

fn damaged_checksum(token: &str) -> String {
    let mut damaged = token.to_owned();
    let last = damaged.len() - 1;
    damaged.replace_range(last.., "x");
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
        accepted("hex_lowercase", ACCOUNT_ID),
        accepted("hex_uppercase", ACCOUNT_ID.to_ascii_uppercase()),
        accepted("npub", NPUB),
        accepted("nostr_npub", format!("nostr:{NPUB}")),
        accepted("bootstrap_nprofile", BOOTSTRAP_NPROFILE),
        accepted("nostr_bootstrap_nprofile", format!("nostr:{BOOTSTRAP_NPROFILE}")),
        accepted("no_relay_nprofile", NO_RELAY_NPROFILE),
        accepted("nostr_no_relay_nprofile", format!("nostr:{NO_RELAY_NPROFILE}")),
        accepted("other_relay_nprofile", OTHER_RELAY_NPROFILE),
        accepted("unknown_tlv_nprofile", UNKNOWN_TLV_NPROFILE),
        accepted("invalid_relay_nprofile", INVALID_RELAY_NPROFILE),
        accepted("duplicate_type0_first_wins", DUPLICATE_TYPE0_NPROFILE),
        ffi_only("whitespace_hex", format!(" {ACCOUNT_ID}")),
        ffi_only("trailing_whitespace_npub", format!("{NPUB} ")),
        ffi_only("whitespace_nprofile", format!(" {NO_RELAY_NPROFILE}")),
        ffi_only(
            "profile_link_nprofile_query",
            format!("marmot://profile/{NO_RELAY_NPROFILE}?from=qr"),
        ),
        ffi_only(
            "profile_link_nprofile_fragment",
            format!("marmot://profile/{NO_RELAY_NPROFILE}#frag"),
        ),
        ffi_only(
            "profile_link_nprofile_trailing_slash",
            format!("marmot://profile/{NO_RELAY_NPROFILE}/"),
        ),
        ffi_only(
            "profile_link_npub_query",
            format!("marmot://profile/{NPUB}?from=qr"),
        ),
        ffi_only(
            "double_nostr_npub",
            format!("nostr:nostr:{NPUB}"),
        ),
        ffi_only(
            "double_nostr_nprofile",
            format!("nostr:nostr:{NO_RELAY_NPROFILE}"),
        ),
        app_only(
            "legacy_colon_suffix_npub",
            format!("nostr:{NPUB}:{}", "x".repeat(4096)),
        ),
        rejected("empty", ""),
        rejected("ordinary_invalid", "not-a-public-key"),
        rejected("uppercase_nostr_nprofile", format!("NOSTR:{NO_RELAY_NPROFILE}")),
        rejected("damaged_npub_checksum", damaged_checksum(NPUB)),
        rejected("damaged_nprofile_checksum", damaged_checksum(NO_RELAY_NPROFILE)),
        rejected("wrong_hrp_note_shaped", WRONG_HRP_NOTE),
        rejected("note_event_hrp", NOTE_EVENT_HRP),
        rejected("nevent_event_hrp", NEVENT_EVENT_HRP),
        rejected("naddr_event_hrp", NADDR_EVENT_HRP),
        rejected("nsec_synthetic", NSEC_SYNTHETIC_REJECTION),
        rejected("missing_type0", MISSING_TYPE0_NPROFILE),
        rejected("short_type0", SHORT_TYPE0_NPROFILE),
        rejected("truncated_header", TRUNCATED_HEADER_NPROFILE),
        rejected("truncated_value", TRUNCATED_VALUE_NPROFILE),
        accepted("boundary_1022_bare", BOUNDARY_1022_NPROFILE),
        accepted("boundary_1022_nostr", format!("nostr:{BOUNDARY_1022_NPROFILE}")),
        ffi_only(
            "boundary_1022_profile_link",
            format!("marmot://profile/{BOUNDARY_1022_NPROFILE}?from=qr"),
        ),
        accepted("boundary_1023_bare", BOUNDARY_1023_NPROFILE),
        accepted("boundary_1023_nostr", format!("nostr:{BOUNDARY_1023_NPROFILE}")),
        ffi_only(
            "boundary_1023_profile_link",
            format!("marmot://profile/{BOUNDARY_1023_NPROFILE}?from=qr"),
        ),
        accepted("boundary_1023_eight_relays_bare", BOUNDARY_1023_EIGHT_RELAY_NPROFILE),
        accepted(
            "boundary_1023_eight_relays_nostr",
            format!("nostr:{BOUNDARY_1023_EIGHT_RELAY_NPROFILE}"),
        ),
        ffi_only(
            "boundary_1023_eight_relays_profile_link",
            format!("marmot://profile/{BOUNDARY_1023_EIGHT_RELAY_NPROFILE}?from=qr"),
        ),
        rejected("oversized_1024", oversized_nprofile(1024)),
        rejected("oversized_4096", oversized_nprofile(4096)),
        rejected("oversized_1000000", oversized_nprofile(1_000_000)),
        rejected("oversized_1024_nostr", format!("nostr:{}", oversized_nprofile(1024))),
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
    let colon_suffix = cases
        .iter()
        .find(|case| case.name == "legacy_colon_suffix_npub")
        .expect("legacy colon-suffix case");
    assert_eq!(colon_suffix.reference.len(), 4166);
    cases
}
