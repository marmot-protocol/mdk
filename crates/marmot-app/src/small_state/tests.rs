use super::*;

fn versioned(chat: &str, value: SmallStateValue, version: u64, id: u8) -> SmallStateItem {
    SmallStateItem {
        group_id_hex: chat.to_owned(),
        value,
        version: Some(SmallStateVersion {
            version,
            change_id: [id; 16],
        }),
    }
}

fn read(chat: &str, epoch: u64, at: u64, id: u8) -> SmallStateItem {
    SmallStateItem {
        group_id_hex: chat.to_owned(),
        value: SmallStateValue::Read(ReadPosition {
            epoch,
            at,
            message_id_hex: format!("{id:064x}"),
        }),
        version: None,
    }
}

fn every_kind() -> Vec<SmallStateItem> {
    vec![
        read("0a0b", 7, 1_700_000_000, 1),
        versioned("0a0b", SmallStateValue::Pin(true), 3, 0xab),
        versioned("0a0b", SmallStateValue::Mute(MuteSetting::Unmuted), 1, 1),
        versioned("0c0d", SmallStateValue::Mute(MuteSetting::Muted), 2, 2),
        versioned(
            "0e0f",
            SmallStateValue::Mute(MuteSetting::MutedUntil(1_800_000_000)),
            MAX_SMALL_STATE_NUMBER,
            3,
        ),
        versioned("0e0f", SmallStateValue::Archive(false), 9, 4),
    ]
}

fn many(count: u32) -> Vec<SmallStateItem> {
    (0..count)
        .map(|n| {
            versioned(
                &format!("{n:064x}"),
                SmallStateValue::Pin(n.is_multiple_of(2)),
                u64::from(n) + 1,
                1,
            )
        })
        .collect()
}

const PIN: &str = "{\"chat\":\"0a\",\"item\":\"pin\",\"value\":true,\"version\":1,\"change\":\"01010101010101010101010101010101\"}";

#[test]
fn items_are_written_in_the_wire_form_and_read_back() {
    let pages = encode_small_state_update(&every_kind());
    assert_eq!(pages.len(), 1);
    let (content, carried) = &pages[0];
    assert_eq!(carried, &every_kind());
    let pin_change = "ab".repeat(16);
    assert!(content.starts_with(&format!(
        "{{\"v\":1,\"items\":[{{\"chat\":\"0a0b\",\"item\":\"read\",\"value\":{{\"epoch\":7,\"at\":1700000000,\"id\":\"{:064x}\"}}}},{{\"chat\":\"0a0b\",\"item\":\"pin\",\"value\":true,\"version\":3,\"change\":\"{pin_change}\"}},",
        1
    )));
    assert!(content.contains("\"value\":false,\"version\":1,"));
    assert!(content.contains("\"value\":1800000000,\"version\":9007199254740991,"));
    assert!(!content.contains(' '));
    assert_eq!(decode_small_state_update(content).unwrap(), every_kind());
}

#[test]
fn long_item_lists_split_into_updates_that_each_stand_alone() {
    let items = many(2_000);
    let pages = encode_small_state_update(&items);
    assert!(pages.len() > 1);
    let mut decoded = Vec::new();
    for (content, carried) in &pages {
        assert!(content.len() <= MAX_SMALL_STATE_CONTENT_BYTES);
        let page = decode_small_state_update(content).unwrap();
        assert_eq!(&page, carried);
        decoded.extend(page);
    }
    assert_eq!(decoded, items);

    // An item that cannot fit alone is left out; an invalid one is never sent.
    let huge = versioned(&"ab".repeat(20_000), SmallStateValue::Pin(true), 1, 1);
    let invalid = versioned("0a", SmallStateValue::Pin(true), 0, 1);
    assert!(encode_small_state_update(&[huge, invalid]).is_empty());
}

#[test]
fn a_snapshot_numbers_its_parts_and_may_be_empty() {
    let request = [0x5a; 16];
    let items = many(2_000);
    let pages = encode_small_state_snapshot(&request, &items);
    let parts = pages.len() as u64;
    assert!(parts > 1);
    let mut decoded = Vec::new();
    for (content, part) in pages.iter().zip(1..) {
        assert!(content.len() <= MAX_SMALL_STATE_CONTENT_BYTES);
        assert!(content.starts_with(&format!(
            "{{\"v\":1,\"request\":\"{}\",\"part\":{part},\"parts\":{parts},\"items\":[{{",
            "5a".repeat(16)
        )));
        let snapshot = decode_small_state_snapshot(content).unwrap();
        assert_eq!(
            (snapshot.request, snapshot.part, snapshot.parts),
            (request, part, parts)
        );
        decoded.extend(snapshot.items);
    }
    assert_eq!(decoded, items);

    let empty = encode_small_state_snapshot(&request, &[]);
    assert_eq!(
        empty,
        vec![format!(
            "{{\"v\":1,\"request\":\"{}\",\"part\":1,\"parts\":1,\"items\":[]}}",
            "5a".repeat(16)
        )]
    );
    assert_eq!(
        decode_small_state_snapshot(&empty[0]).unwrap(),
        SmallStateSnapshot {
            request,
            part: 1,
            parts: 1,
            items: Vec::new(),
        }
    );
    // An update is never empty, and a snapshot is not an update.
    assert!(decode_small_state_update(&empty[0]).is_err());
    assert!(decode_small_state_snapshot(&format!("{{\"v\":1,\"items\":[{PIN}]}}")).is_err());

    let request_hex = "5a".repeat(16);
    for (part, parts) in [
        ("0", "1"),
        ("2", "1"),
        ("1", "0"),
        ("1.0", "1"),
        ("1", "9007199254740992"),
    ] {
        let content = format!(
            "{{\"v\":1,\"request\":\"{request_hex}\",\"part\":{part},\"parts\":{parts},\"items\":[]}}"
        );
        assert!(decode_small_state_snapshot(&content).is_err(), "{content}");
    }
    for request_hex in ["5A".repeat(16), "5a".repeat(15)] {
        let content = format!(
            "{{\"v\":1,\"request\":\"{request_hex}\",\"part\":1,\"parts\":1,\"items\":[]}}"
        );
        assert!(decode_small_state_snapshot(&content).is_err(), "{content}");
    }
}

#[test]
fn unknown_and_invalid_items_are_skipped() {
    let change = "01".repeat(16);
    let content = format!(
        "{{\"v\":1,\"items\":[\
         {{\"chat\":\"0a\",\"item\":\"invite\",\"value\":true}},\
         {{\"chat\":\"01\",\"item\":\"pin\",\"value\":1,\"version\":1,\"change\":\"{change}\"}},\
         {{\"chat\":\"02\",\"item\":\"pin\",\"value\":true,\"version\":0,\"change\":\"{change}\"}},\
         {{\"chat\":\"03\",\"item\":\"pin\",\"value\":true,\"version\":9007199254740992,\"change\":\"{change}\"}},\
         {{\"chat\":\"04\",\"item\":\"pin\",\"value\":true,\"version\":1.5,\"change\":\"{change}\"}},\
         {{\"chat\":\"05\",\"item\":\"pin\",\"value\":true,\"version\":1,\"change\":\"{}\"}},\
         {{\"chat\":\"06\",\"item\":\"pin\",\"value\":true,\"version\":1,\"change\":\"0101\"}},\
         {{\"chat\":\"07\",\"item\":\"pin\",\"value\":true}},\
         {{\"chat\":\"0A\",\"item\":\"pin\",\"value\":true,\"version\":1,\"change\":\"{change}\"}},\
         {{\"chat\":\"08\",\"item\":\"mute\",\"value\":-1,\"version\":1,\"change\":\"{change}\"}},\
         {{\"chat\":\"09\",\"item\":\"read\",\"value\":{{\"epoch\":1,\"at\":2,\"id\":\"{}\"}}}},\
         {{\"chat\":\"0b\",\"item\":\"read\",\"value\":{{\"epoch\":1,\"at\":2}}}},\
         {{\"chat\":\"0c\",\"item\":\"read\",\"value\":{{\"epoch\":1,\"at\":2,\"id\":\"{:064x}\",\"x\":1}}}},\
         {{\"chat\":\"0d\",\"item\":\"read\",\"value\":{{\"epoch\":1,\"at\":2,\"id\":\"{:064x}\"}},\"version\":1}},\
         {{\"chat\":\"0e\",\"item\":\"pin\",\"value\":true,\"version\":1,\"change\":\"{change}\",\"x\":1}},\
         {{\"chat\":\"0a\",\"item\":\"archive\",\"value\":true,\"version\":2,\"change\":\"{change}\"}},\
         7\
         ]}}",
        "ab".repeat(16).to_uppercase(),
        format!("{:064x}", 0xab).to_uppercase(),
        1,
        1,
    );
    assert_eq!(
        decode_small_state_update(&content).unwrap(),
        vec![versioned("0a", SmallStateValue::Archive(true), 2, 1)]
    );
}

#[test]
fn content_of_the_wrong_shape_is_refused() {
    for content in [
        String::new(),
        "[]".to_owned(),
        "{\"items\":[]}".to_owned(),
        "{\"v\":1,\"items\":[]}".to_owned(),
        "{\"v\":1}".to_owned(),
        format!("{{\"v\":2,\"items\":[{PIN}]}}"),
        format!("{{\"v\":\"1\",\"items\":[{PIN}]}}"),
        format!("{{\"v\":1,\"items\":{PIN}}}"),
        // Another member.
        format!("{{\"v\":1,\"items\":[{PIN}],\"x\":1}}"),
        // A member name repeated, at the top or in an item or value.
        format!("{{\"v\":1,\"v\":1,\"items\":[{PIN}]}}"),
        format!("{{\"v\":1,\"items\":[{}]}}", PIN.replace("\"value\":true", "\"value\":true,\"value\":false")),
        format!(
            "{{\"v\":1,\"items\":[{{\"chat\":\"0a\",\"item\":\"invite\",\"value\":{{\"a\":1,\"a\":2}}}}]}}"
        ),
        // Two items for the same chat and item, even an unknown one.
        format!("{{\"v\":1,\"items\":[{PIN},{}]}}", PIN.replace("true", "false")),
        "{\"v\":1,\"items\":[{\"chat\":\"0a\",\"item\":\"invite\"},{\"chat\":\"0a\",\"item\":\"invite\"}]}"
            .to_owned(),
        format!(
            "{{\"v\":1,\"items\":[{PIN}],\"pad\":\"{}\"}}",
            "x".repeat(MAX_SMALL_STATE_CONTENT_BYTES)
        ),
    ] {
        assert!(decode_small_state_update(&content).is_err(), "{content}");
    }
    assert_eq!(
        decode_small_state_update(&format!("{{\"v\":1,\"items\":[{PIN}]}}"))
            .unwrap()
            .len(),
        1
    );
    // The same chat under two item names is two items.
    let mute = PIN.replace("\"pin\"", "\"mute\"");
    assert_eq!(
        decode_small_state_update(&format!("{{\"v\":1,\"items\":[{PIN},{mute}]}}"))
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn snapshot_requests_name_one_slot_and_carry_an_id() {
    let slot = [0x5a; 32];
    let request = [0x07; 16];
    let content = encode_snapshot_request(&slot, &request);
    assert_eq!(
        content,
        format!(
            "{{\"v\":1,\"to\":\"{}\",\"request\":\"{}\"}}",
            "5a".repeat(32),
            "07".repeat(16)
        )
    );
    assert_eq!(decode_snapshot_request(&content).unwrap(), (slot, request));
    let to = "5a".repeat(32);
    let id = "07".repeat(16);
    for content in [
        "{\"v\":1}".to_owned(),
        format!("{{\"v\":1,\"to\":\"{to}\"}}"),
        format!("{{\"v\":2,\"to\":\"{to}\",\"request\":\"{id}\"}}"),
        format!(
            "{{\"v\":1,\"to\":\"{}\",\"request\":\"{id}\"}}",
            "5a".repeat(31)
        ),
        format!(
            "{{\"v\":1,\"to\":\"{}\",\"request\":\"{id}\"}}",
            "5A".repeat(32)
        ),
        format!(
            "{{\"v\":1,\"to\":\"{to}\",\"request\":\"{}\"}}",
            "07".repeat(15)
        ),
        format!("{{\"v\":1,\"to\":\"{to}\",\"request\":\"{id}\",\"x\":1}}"),
        format!("{{\"v\":1,\"to\":\"{to}\",\"to\":\"{to}\",\"request\":\"{id}\"}}"),
    ] {
        assert!(decode_snapshot_request(&content).is_err(), "{content}");
    }
}

#[test]
fn the_merge_rule_picks_the_same_winner_in_any_order() {
    let rule = SmallStateMergeRule;
    let low = versioned("0a", SmallStateValue::Pin(true), 2, 1);
    let high_id = versioned("0a", SmallStateValue::Pin(false), 2, 9);
    let newer = versioned("0a", SmallStateValue::Pin(false), 3, 9);
    assert!(rule.wins(&low, &high_id));
    assert!(!rule.wins(&high_id, &low));
    assert!(rule.wins(&newer, &low));
    assert!(!rule.wins(&low, &newer));
    assert!(!rule.wins(&low, &low));

    // The same version and change id with two values: the lower encoding
    // wins, `false` before `true`, a time before both.
    let same_false = versioned("0a", SmallStateValue::Pin(false), 2, 1);
    assert!(rule.wins(&same_false, &low));
    assert!(!rule.wins(&low, &same_false));
    let until = versioned(
        "0a",
        SmallStateValue::Mute(MuteSetting::MutedUntil(5)),
        2,
        1,
    );
    let muted = versioned("0a", SmallStateValue::Mute(MuteSetting::Muted), 2, 1);
    assert!(rule.wins(&until, &muted));
    assert!(!rule.wins(&muted, &until));

    let further = read("0a", 8, 1, 1);
    let earlier = read("0a", 7, 9, 9);
    assert!(rule.wins(&further, &earlier));
    assert!(!rule.wins(&earlier, &further));
    assert!(!rule.wins(&further, &low));

    assert_ne!(rule.new_change_id(), rule.new_change_id());
    assert_eq!(rule.pin_index(&["0b".to_owned()]), 0);
}
