use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use cgka_engine::app_components::{
    CURRENT_PROFILE_LEAF_ONLY_APP_COMPONENTS, CURRENT_PROFILE_REQUIRED_APP_COMPONENTS,
    CURRENT_PROFILE_REQUIRED_GROUP_CONTEXT_EXTENSIONS,
    CURRENT_PROFILE_REQUIRED_GROUP_CONTEXT_STATE_COMPONENTS, CURRENT_PROFILE_REQUIRED_PROPOSALS,
};
use cgka_traits::engine::WelcomeMetadata;
use cgka_traits::ingest::PeeledContent;
use cgka_traits::transport::EncryptedPayload;
use cgka_traits::{MemberId, MessageId, TransportEndpoint, TransportPeeler};
use nostr::nips::nip44;
use nostr::prelude::{Event, Keys, UnsignedEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use transport_nostr_peeler::{NostrMlsPeeler, NostrTransportEvent};

#[test]
fn vector_manifest_artifacts_exist_and_byte_fixtures_are_well_formed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let vectors = root.join("vectors");
    let manifest_path = vectors.join("manifest.v1.json");
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("manifest exists"))
            .expect("manifest JSON parses");

    assert_eq!(manifest["manifest_version"], "1");
    let entries = manifest["entries"].as_array().expect("entries is an array");
    assert!(!entries.is_empty(), "manifest should name current vectors");

    let mut manifest_artifacts = BTreeSet::new();
    for entry in entries {
        if let Some(artifact) = entry.get("artifact").and_then(Value::as_str) {
            manifest_artifacts.insert(artifact.to_string());
            assert!(
                vectors.join(artifact).exists(),
                "manifest artifact {artifact} should exist"
            );
        }
    }

    for entry in fs::read_dir(&vectors).expect("vectors dir exists") {
        let path = entry.expect("vector dir entry").path();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if !file_name.ends_with(".v1.json") || file_name == "manifest.v1.json" {
            continue;
        }
        assert!(
            manifest_artifacts.contains(file_name),
            "manifest should list top-level vector fixture {file_name}"
        );
        let fixture: Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("fixture exists"))
                .unwrap_or_else(|e| panic!("{} parses: {e}", path.display()));
        assert!(
            fixture.get("expected_trace").is_some()
                || fixture
                    .get("expected_outcomes")
                    .and_then(Value::as_array)
                    .is_some_and(|outcomes| !outcomes.is_empty()),
            "{} should define expected_trace or expected_outcomes",
            path.display()
        );
    }

    let schema_path = vectors.join("byte-fixtures/schema.v1.json");
    let schema: Value =
        serde_json::from_str(&fs::read_to_string(schema_path).expect("byte schema exists"))
            .expect("byte schema JSON parses");
    assert_eq!(schema["title"], "Marmot byte-level vector fixture v1");

    let byte_fixture_dir = vectors.join("byte-fixtures");
    let mut byte_fixture_count = 0usize;
    for entry in fs::read_dir(&byte_fixture_dir).expect("byte fixture dir exists") {
        let entry = entry.expect("byte fixture dir entry");
        let path = entry.path();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if !file_name.ends_with(".v1.json") || file_name == "schema.v1.json" {
            continue;
        }
        byte_fixture_count += 1;
        let fixture: Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("byte fixture exists"))
                .unwrap_or_else(|e| panic!("{} parses: {e}", path.display()));
        assert_eq!(
            fixture["fixture_version"],
            "1",
            "{} has fixture_version 1",
            path.display()
        );
        // Wire-format fixtures carry a relay-delivered event, not component
        // bytes; `nostr_welcome_wire_fixture_unwraps_with_extended_length_nip44`
        // checks the one there is.
        if fixture["vector_type"] == "wire_format" {
            assert!(
                fixture["wire"]["name"].is_string() && fixture["nostr_event"].is_object(),
                "{} names its wire surface and carries a nostr_event",
                path.display()
            );
            continue;
        }
        assert_eq!(
            fixture["component"]["name"],
            "marmot.transport.nostr.routing.v1",
            "{} should cover the first app-component byte vectors",
            path.display()
        );
        let hex = fixture["bytes"]["hex"]
            .as_str()
            .unwrap_or_else(|| panic!("{} has bytes.hex", path.display()));
        assert_even_hex(hex, &path);
    }

    assert!(
        byte_fixture_count >= 2,
        "expected state and update byte fixtures"
    );
}

fn assert_even_hex(hex: &str, path: &Path) {
    assert!(
        hex.len().is_multiple_of(2),
        "{} hex length should be even",
        path.display()
    );
    assert!(
        hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{} hex should contain only hex digits",
        path.display()
    );
}

#[test]
fn current_profile_vector_pins_the_adopted_required_set() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/current-profile-required-set.v1.json");
    let fixture: cgka_conformance_simulator::VectorFixture =
        serde_json::from_str(&fs::read_to_string(&path).expect("profile fixture exists"))
            .expect("profile fixture parses");
    let profile = fixture
        .application_profile
        .expect("current profile contract is present");

    assert_eq!(profile.name, "current");
    assert_eq!(profile.required_group_context_extensions, ["0x0006"]);
    assert_eq!(profile.required_proposals, ["0x0008"]);
    assert_eq!(profile.required_app_components, ["0x8003", "0x8009"]);
    assert_eq!(profile.required_group_context_state_components, ["0x8003"]);
    assert_eq!(profile.leaf_only_app_components, ["0x8009"]);

    assert_eq!(
        parse_registry_values(&profile.required_group_context_extensions),
        CURRENT_PROFILE_REQUIRED_GROUP_CONTEXT_EXTENSIONS
    );
    assert_eq!(
        parse_registry_values(&profile.required_proposals),
        CURRENT_PROFILE_REQUIRED_PROPOSALS
    );
    assert_eq!(
        parse_registry_values(&profile.required_app_components),
        CURRENT_PROFILE_REQUIRED_APP_COMPONENTS
    );
    assert_eq!(
        parse_registry_values(&profile.required_group_context_state_components),
        CURRENT_PROFILE_REQUIRED_GROUP_CONTEXT_STATE_COMPONENTS
    );
    assert_eq!(
        parse_registry_values(&profile.leaf_only_app_components),
        CURRENT_PROFILE_LEAF_ONLY_APP_COMPONENTS
    );
}

fn parse_registry_values(values: &[String]) -> Vec<u16> {
    values
        .iter()
        .map(|value| {
            u16::from_str_radix(
                value
                    .strip_prefix("0x")
                    .expect("registry value has 0x prefix"),
                16,
            )
            .expect("registry value fits in u16")
        })
        .collect()
}

/// The byte fixtures are portable cross-implementation vectors, so they MUST
/// round-trip through the reference Marmot codec — not merely be well-formed hex
/// (closes the gap that let the fixtures drift to a TLS layout the codec rejects).
#[test]
fn nostr_routing_byte_fixtures_round_trip_through_reference_codec() {
    use cgka_traits::app_components::{decode_nostr_routing_v1, encode_nostr_routing_v1};

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("vectors/byte-fixtures");
    let mut checked = 0usize;
    for entry in fs::read_dir(&dir).expect("byte fixture dir exists") {
        let path = entry.expect("byte fixture entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.ends_with(".v1.json") || name == "schema.v1.json" {
            continue;
        }
        let fixture: Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("read fixture"))
                .unwrap_or_else(|e| panic!("{} parses: {e}", path.display()));
        if fixture["component"]["name"] != "marmot.transport.nostr.routing.v1" {
            continue;
        }
        let hex = fixture["bytes"]["hex"]
            .as_str()
            .unwrap_or_else(|| panic!("{} has bytes.hex", path.display()));
        let bytes =
            hex::decode(hex).unwrap_or_else(|e| panic!("{} hex decodes: {e}", path.display()));
        let decoded = decode_nostr_routing_v1(&bytes);
        let expected_valid = fixture["expected"]["valid"]
            .as_bool()
            .unwrap_or_else(|| panic!("{} has expected.valid", path.display()));
        if expected_valid {
            let routing = decoded.unwrap_or_else(|e| {
                panic!(
                    "{} must decode via the reference codec: {e}",
                    path.display()
                )
            });
            let expected_id = fixture["expected"]["fields"]["nostr_group_id_hex"]
                .as_str()
                .unwrap_or_else(|| panic!("{} has nostr_group_id_hex", path.display()));
            assert_eq!(
                hex::encode(routing.nostr_group_id),
                expected_id,
                "{} nostr_group_id",
                path.display()
            );
            let expected_relays: Vec<String> = fixture["expected"]["fields"]["relays"]
                .as_array()
                .unwrap_or_else(|| panic!("{} has relays", path.display()))
                .iter()
                .map(|r| r.as_str().expect("relay string").to_owned())
                .collect();
            assert_eq!(routing.relays, expected_relays, "{} relays", path.display());
            // The fixture bytes are canonical: re-encoding the decoded value
            // reproduces bytes.hex exactly.
            let reencoded = encode_nostr_routing_v1(&routing).expect("re-encode");
            assert_eq!(
                hex::encode(&reencoded),
                hex,
                "{} bytes.hex must be the canonical encoding",
                path.display()
            );
        } else {
            assert!(
                decoded.is_err(),
                "{} must be rejected by the reference codec",
                path.display()
            );
        }
        checked += 1;
    }
    assert!(
        checked >= 3,
        "expected to round-trip the state, update, and invalid fixtures"
    );
}

/// The Welcome wire fixture (#2335): a gift-wrapped Welcome whose seal and gift
/// wrap both take NIP-44 v2's extended length prefix.
const NOSTR_WELCOME_WIRE_FIXTURE: &str =
    "vectors/byte-fixtures/nostr-welcome-nip44-extended-length.v1.json";
/// The shortest NIP-44 v2 plaintext that takes the 6-byte length prefix.
const NIP44_EXTENDED_PREFIX_THRESHOLD: usize = 65_536;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NostrWelcomeWireFixture {
    fixture_name: String,
    fixture_version: String,
    vector_type: String,
    wire: WireSurface,
    encoding: FixtureEncoding,
    recipient_secret_key_hex: String,
    nostr_event: Value,
    expected: NostrWelcomeExpected,
    notes: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireSurface {
    name: String,
    document: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureEncoding {
    format: String,
    notes: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NostrWelcomeExpected {
    valid: bool,
    fields: NostrWelcomeFields,
    errors: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct NostrWelcomeFields {
    gift_wrap_plaintext_len: usize,
    seal_pubkey: String,
    seal_plaintext_len: usize,
    rumor_id: String,
    rumor_kind: u16,
    key_package_event_id: String,
    relays: Vec<String>,
    welcome_len: usize,
    welcome_sha256: String,
}

/// Other implementations unwrap the fixture's event with their own NIP-59 and
/// NIP-44 code; MDK unwraps it here with its Welcome peeler.
#[tokio::test]
async fn nostr_welcome_wire_fixture_unwraps_with_extended_length_nip44() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(NOSTR_WELCOME_WIRE_FIXTURE);
    let fixture: NostrWelcomeWireFixture =
        serde_json::from_str(&fs::read_to_string(&path).expect("read fixture"))
            .expect("fixture parses");
    assert_eq!(fixture.fixture_version, "1");
    assert_eq!(fixture.vector_type, "wire_format");
    assert!(fixture.expected.valid && fixture.expected.errors.is_empty());
    let receiver = Keys::parse(&fixture.recipient_secret_key_hex).expect("recipient key");
    let gift_wrap = Event::from_json(fixture.nostr_event.to_string()).expect("gift wrap parses");

    let fields = open_extended_length_welcome(&receiver, &gift_wrap).await;
    // The seal's plaintext sits on the boundary, where using `>` for `>=`
    // would pick the 2-byte prefix.
    assert_eq!(fields.seal_plaintext_len, NIP44_EXTENDED_PREFIX_THRESHOLD);
    assert_eq!(fields, fixture.expected.fields);
}

/// Rewrites the Welcome wire fixture from MDK's own Welcome wrap, with the
/// Welcome sized so that the rumor JSON, the seal's plaintext, is exactly the
/// shortest plaintext that takes the extended prefix. The wrap's keys, nonces
/// and timestamps are random, so each run writes a new event and rumor id and
/// the same other fields.
#[tokio::test]
#[ignore = "rewrites the committed fixture"]
async fn write_nostr_welcome_wire_fixture() {
    // The NIP-44 test vectors' sec1 and sec2.
    let sender = Keys::parse(&format!("{:064x}", 1)).unwrap();
    let receiver = Keys::parse(&format!("{:064x}", 2)).unwrap();
    // Three Welcome bytes add four base64 characters to the rumor and each
    // relay padding character adds one, so one measured wrap fixes both.
    let probe = wrap_fixture_welcome(&sender, &receiver, 48_900, 0).await;
    let short = NIP44_EXTENDED_PREFIX_THRESHOLD
        .checked_sub(rumor_json_len(&receiver, &probe))
        .expect("probe rumor is below the threshold");
    let gift_wrap =
        wrap_fixture_welcome(&sender, &receiver, 48_900 + 3 * (short / 4), short % 4).await;
    let fields = open_extended_length_welcome(&receiver, &gift_wrap).await;
    assert_eq!(fields.seal_plaintext_len, NIP44_EXTENDED_PREFIX_THRESHOLD);

    let fixture = NostrWelcomeWireFixture {
        fixture_name: "marmot.transport.nostr.welcome/nip44-extended-length/v1".into(),
        fixture_version: "1".into(),
        vector_type: "wire_format".into(),
        wire: WireSurface {
            name: "marmot.transport.nostr.welcome".into(),
            document: "spec/transports/nostr.md#welcome-delivery".into(),
        },
        encoding: FixtureEncoding {
            format: "NIP-59 gift wrap: a kind 1059 event whose content is a NIP-44 v2 encrypted \
                     kind 13 seal, whose content is a NIP-44 v2 encrypted kind 444 Welcome rumor"
                .into(),
            notes: vec![
                "nostr_event is the kind 1059 gift wrap exactly as a relay delivers it, addressed \
                 to the public key of recipient_secret_key_hex."
                    .into(),
                "recipient_secret_key_hex is sec2 from the NIP-44 test vectors; sec1's public key \
                 signs the seal. Both are test keys."
                    .into(),
                "NIP-44 v2 encodes a plaintext of 65,536 bytes or more with a 6-byte length \
                 prefix, two zero bytes and then a big-endian u32 length \
                 (nostr-protocol/nips#1907). Shorter plaintexts keep the 2-byte u16 prefix."
                    .into(),
                "Both layers take the 6-byte prefix. The seal's plaintext, the rumor JSON, is \
                 exactly 65,536 bytes, the shortest plaintext that takes it. The gift wrap's \
                 plaintext, the seal JSON, is longer."
                    .into(),
                "The rumor content is the base64 of synthetic Welcome bytes: byte i is i mod 256. \
                 They are not a valid MLS Welcome, so the vector covers unwrapping, not joining."
                    .into(),
            ],
        },
        recipient_secret_key_hex: receiver.secret_key().to_secret_hex(),
        nostr_event: serde_json::from_str(&gift_wrap.as_json()).unwrap(),
        expected: NostrWelcomeExpected {
            valid: true,
            fields,
            errors: vec![],
        },
        notes: vec![
            "A Welcome's gift wrap needs the extended prefix from about 81 members for one \
             invitee, 69 for ten and 11 for fifty; its seal needs it in larger groups \
             (mdk docs/marmot-architecture/review/e-transport.md, section 2)."
                .into(),
            "A client whose NIP-44 implementation predates the extended prefix cannot unwrap \
             this event, so it cannot join such groups by Welcome."
                .into(),
            "Regenerate with the ignored write_nostr_welcome_wire_fixture test in \
             crates/cgka-conformance-simulator/tests/vector_artifacts.rs. It changes the event \
             and rumor_id and no other expected field."
                .into(),
        ],
    };
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(NOSTR_WELCOME_WIRE_FIXTURE);
    fs::write(path, serde_json::to_string_pretty(&fixture).unwrap() + "\n").unwrap();
}

/// Opens `gift_wrap` twice: layer by layer with NIP-44 directly, checking that
/// both layers take the extended length prefix, and through MDK's Welcome
/// peeler. Returns the fields the fixture pins.
async fn open_extended_length_welcome(receiver: &Keys, gift_wrap: &Event) -> NostrWelcomeFields {
    let seal_json = nip44::decrypt(receiver.secret_key(), &gift_wrap.pubkey, &gift_wrap.content)
        .expect("gift wrap decrypts");
    assert_nip44_extended_length(&gift_wrap.content, seal_json.len());
    let seal = Event::from_json(&seal_json).expect("seal parses");
    let rumor_json =
        nip44::decrypt(receiver.secret_key(), &seal.pubkey, &seal.content).expect("seal decrypts");
    assert_nip44_extended_length(&seal.content, rumor_json.len());
    let rumor = UnsignedEvent::from_json(&rumor_json).expect("rumor parses");
    let relays = rumor
        .tags
        .iter()
        .map(|tag| tag.as_slice())
        .find(|tag| tag.first().map(String::as_str) == Some("relays"))
        .expect("rumor has a relays tag")[1..]
        .to_vec();

    let message = NostrTransportEvent::from_nostr_event(gift_wrap)
        .expect("gift wrap maps to a transport event")
        .to_transport_message()
        .expect("gift wrap id verifies");
    let (peeled, provenance) = NostrMlsPeeler::new()
        .with_welcome_signer(receiver.clone())
        .peel_welcome_with_provenance(&message)
        .await
        .expect("the Welcome peeler unwraps the gift wrap");
    let PeeledContent::Welcome { bytes: welcome, .. } = peeled.content else {
        panic!("the peeler returns a Welcome");
    };
    assert_eq!(
        rumor.id.map(|id| id.to_bytes()),
        Some(provenance.rumor_event_id)
    );
    NostrWelcomeFields {
        gift_wrap_plaintext_len: seal_json.len(),
        seal_pubkey: seal.pubkey.to_hex(),
        seal_plaintext_len: rumor_json.len(),
        rumor_id: hex::encode(provenance.rumor_event_id),
        rumor_kind: u16::from(rumor.kind),
        key_package_event_id: hex::encode(provenance.key_package_event_id),
        relays,
        welcome_len: welcome.len(),
        welcome_sha256: hex::encode(Sha256::digest(&welcome)),
    }
}

async fn wrap_fixture_welcome(
    sender: &Keys,
    receiver: &Keys,
    welcome_len: usize,
    relay_padding: usize,
) -> Event {
    let wrapped = NostrMlsPeeler::new()
        .with_welcome_signer(sender.clone())
        .wrap_welcome_with_metadata(
            &EncryptedPayload {
                ciphertext: (0..welcome_len).map(|i| i as u8).collect(),
                aad: vec![],
            },
            &MemberId::new(receiver.public_key().to_bytes().to_vec()),
            &WelcomeMetadata {
                key_package_event_id: MessageId::new(vec![0x44; 32]),
                relays: vec![TransportEndpoint(format!(
                    "wss://relay{}.example",
                    "x".repeat(relay_padding)
                ))],
            },
        )
        .await
        .expect("wrap succeeds");
    NostrTransportEvent::from_transport_message(&wrapped)
        .unwrap()
        .to_verified_nostr_event()
        .unwrap()
}

fn rumor_json_len(receiver: &Keys, gift_wrap: &Event) -> usize {
    let seal_json =
        nip44::decrypt(receiver.secret_key(), &gift_wrap.pubkey, &gift_wrap.content).unwrap();
    let seal = Event::from_json(seal_json).unwrap();
    nip44::decrypt(receiver.secret_key(), &seal.pubkey, &seal.content)
        .unwrap()
        .len()
}

/// `payload` is NIP-44 v2 base64 of a `plaintext_len`-byte plaintext with the
/// 6-byte extended length prefix: version, nonce, prefix, padded plaintext and
/// MAC.
#[track_caller]
fn assert_nip44_extended_length(payload: &str, plaintext_len: usize) {
    assert!(
        plaintext_len >= NIP44_EXTENDED_PREFIX_THRESHOLD,
        "{plaintext_len}-byte plaintext"
    );
    let padding = payload
        .bytes()
        .rev()
        .take_while(|&byte| byte == b'=')
        .count();
    assert_eq!(
        payload.len() / 4 * 3 - padding,
        1 + 32 + 6 + nip44_padded_len(plaintext_len) + 32
    );
}

/// NIP-44 v2 `calc_padded_len`.
fn nip44_padded_len(len: usize) -> usize {
    if len <= 32 {
        return 32;
    }
    let next_power = 1usize << (usize::BITS - (len - 1).leading_zeros());
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * ((len - 1) / chunk + 1)
}
