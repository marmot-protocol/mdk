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

#[test]
fn items_are_written_in_the_wire_form_and_read_back() {
    let pages = encode_small_state_items(&every_kind());
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
    assert_eq!(decode_small_state_items(content).unwrap(), every_kind());
}

#[test]
fn long_item_lists_split_into_pages_that_each_stand_alone() {
    let items = (0..2_000_u32)
        .map(|n| {
            versioned(
                &format!("{n:064x}"),
                SmallStateValue::Pin(n % 2 == 0),
                u64::from(n) + 1,
                1,
            )
        })
        .collect::<Vec<_>>();
    let pages = encode_small_state_items(&items);
    assert!(pages.len() > 1);
    let mut decoded = Vec::new();
    for (content, carried) in &pages {
        assert!(content.len() <= MAX_SMALL_STATE_CONTENT_BYTES);
        let page = decode_small_state_items(content).unwrap();
        assert_eq!(&page, carried);
        decoded.extend(page);
    }
    assert_eq!(decoded, items);

    // An item that cannot fit alone is left out; an invalid one is never sent.
    let huge = versioned(&"ab".repeat(20_000), SmallStateValue::Pin(true), 1, 1);
    let invalid = versioned("0a", SmallStateValue::Pin(true), 0, 1);
    assert!(encode_small_state_items(&[huge, invalid]).is_empty());
}

#[test]
fn unknown_and_invalid_items_are_skipped() {
    let change = "01".repeat(16);
    let content = format!(
        "{{\"v\":1,\"items\":[\
         {{\"chat\":\"0a\",\"item\":\"invite\",\"value\":true}},\
         {{\"chat\":\"0a\",\"item\":\"pin\",\"value\":1,\"version\":1,\"change\":\"{change}\"}},\
         {{\"chat\":\"0a\",\"item\":\"pin\",\"value\":true,\"version\":0,\"change\":\"{change}\"}},\
         {{\"chat\":\"0a\",\"item\":\"pin\",\"value\":true,\"version\":9007199254740992,\"change\":\"{change}\"}},\
         {{\"chat\":\"0a\",\"item\":\"pin\",\"value\":true,\"version\":1.5,\"change\":\"{change}\"}},\
         {{\"chat\":\"0a\",\"item\":\"pin\",\"value\":true,\"version\":1,\"change\":\"{}\"}},\
         {{\"chat\":\"0a\",\"item\":\"pin\",\"value\":true,\"version\":1,\"change\":\"0101\"}},\
         {{\"chat\":\"0a\",\"item\":\"pin\",\"value\":true}},\
         {{\"chat\":\"0A\",\"item\":\"pin\",\"value\":true,\"version\":1,\"change\":\"{change}\"}},\
         {{\"chat\":\"0a\",\"item\":\"mute\",\"value\":-1,\"version\":1,\"change\":\"{change}\"}},\
         {{\"chat\":\"0a\",\"item\":\"read\",\"value\":{{\"epoch\":1,\"at\":2,\"id\":\"{}\"}}}},\
         {{\"chat\":\"0a\",\"item\":\"read\",\"value\":{{\"epoch\":1,\"at\":2}}}},\
         {{\"chat\":\"0a\",\"item\":\"archive\",\"value\":true,\"version\":2,\"change\":\"{change}\"}},\
         7\
         ]}}",
        "ab".repeat(16).to_uppercase(),
        format!("{:064x}", 0xab).to_uppercase(),
    );
    assert_eq!(
        decode_small_state_items(&content).unwrap(),
        vec![versioned("0a", SmallStateValue::Archive(true), 2, 1)]
    );
}

#[test]
fn content_of_the_wrong_shape_is_refused() {
    let item = "{\"chat\":\"0a\",\"item\":\"pin\",\"value\":true,\"version\":1,\"change\":\"01010101010101010101010101010101\"}";
    for content in [
        String::new(),
        "[]".to_owned(),
        "{\"items\":[]}".to_owned(),
        "{\"v\":1,\"items\":[]}".to_owned(),
        "{\"v\":1}".to_owned(),
        format!("{{\"v\":2,\"items\":[{item}]}}"),
        format!("{{\"v\":\"1\",\"items\":[{item}]}}"),
        format!("{{\"v\":1,\"items\":{item}}}"),
        format!(
            "{{\"v\":1,\"items\":[{item}],\"pad\":\"{}\"}}",
            "x".repeat(MAX_SMALL_STATE_CONTENT_BYTES)
        ),
    ] {
        assert!(decode_small_state_items(&content).is_err(), "{content}");
    }
    assert_eq!(
        decode_small_state_items(&format!("{{\"v\":1,\"items\":[{item}]}}"))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn snapshot_requests_name_one_slot() {
    let slot = [0x5a; 32];
    let content = encode_snapshot_request(&slot);
    assert_eq!(
        content,
        format!("{{\"v\":1,\"to\":\"{}\"}}", "5a".repeat(32))
    );
    assert_eq!(decode_snapshot_request(&content).unwrap(), slot);
    for content in [
        "{\"v\":1}".to_owned(),
        "{\"v\":2,\"to\":\"00\"}".to_owned(),
        format!("{{\"v\":1,\"to\":\"{}\"}}", "5a".repeat(31)),
        format!("{{\"v\":1,\"to\":\"{}\"}}", "5A".repeat(32)),
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

    let further = read("0a", 8, 1, 1);
    let earlier = read("0a", 7, 9, 9);
    assert!(rule.wins(&further, &earlier));
    assert!(!rule.wins(&earlier, &further));
    assert!(!rule.wins(&further, &low));

    assert_ne!(rule.new_change_id(), rule.new_change_id());
    assert_eq!(rule.pin_index(&["0b".to_owned()]), 0);
}
