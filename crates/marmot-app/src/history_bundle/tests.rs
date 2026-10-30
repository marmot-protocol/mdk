use super::*;
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_REMOVE};

const CHAT: [u8; 16] = [0x5a; 16];

fn event(at: u64, kind: u64, text: &str) -> MarmotAppEvent {
    MarmotAppEvent::new("bb".repeat(32), at, kind, Vec::new(), text)
}

fn bundled(epoch: u64, at: u64, text: &str) -> BundledEvent {
    BundledEvent {
        event: event(at, MARMOT_APP_EVENT_KIND_CHAT, text),
        epoch,
        retention: None,
        grant: None,
        keys: None,
    }
}

fn position(event: &BundledEvent) -> ChatPosition {
    ChatPosition::of(&event.event, event.epoch)
}

fn bundle_of(events: Vec<BundledEvent>) -> HistoryBundle {
    let mut bundle = HistoryBundle::new(
        &CHAT,
        position(events.first().unwrap()),
        position(events.last().unwrap()),
    );
    bundle.events = events;
    bundle
}

fn refusal(result: Result<HistoryBundle, AppError>) -> &'static str {
    match result {
        Err(AppError::DeviceGroupRefused(reason)) => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_bundle_is_written_compact_with_its_members_in_order() {
    let mut first = bundled(3, 10, "hi");
    first.retention = Some(86_400);
    first.keys = Some(vec![FileKey {
        ciphertext_sha256: "cc".repeat(32),
        key: "dd".repeat(32),
    }]);
    let mut removal = bundled(4, 11, "");
    removal.event = event(11, MARMOT_APP_EVENT_KIND_REMOVE, "");
    removal.grant = Some(true);
    let bundle = bundle_of(vec![first.clone(), removal.clone()]);
    let expected = format!(
        concat!(
            r#"{{"v":1,"chat":"{chat}","from":{{"epoch":3,"at":10,"id":"{a}"}},"#,
            r#""to":{{"epoch":4,"at":11,"id":"{b}"}},"events":["#,
            r#"{{"event":{{"id":"{a}","pubkey":"{p}","created_at":10,"kind":9,"tags":[],"content":"hi"}},"#,
            r#""epoch":3,"retention":86400,"keys":[{{"ciphertext_sha256":"{c}","key":"{d}"}}]}},"#,
            r#"{{"event":{{"id":"{b}","pubkey":"{p}","created_at":11,"kind":4891,"tags":[],"content":""}},"#,
            r#""epoch":4,"grant":true}}]}}"#,
        ),
        chat = hex::encode(CHAT),
        a = first.event.id,
        b = removal.event.id,
        p = "bb".repeat(32),
        c = "cc".repeat(32),
        d = "dd".repeat(32),
    );
    assert_eq!(
        String::from_utf8(bundle.encode().unwrap()).unwrap(),
        expected
    );
    assert_eq!(HistoryBundle::decode(expected.as_bytes()).unwrap(), bundle);
}

#[test]
fn a_sealed_bundle_opens_only_with_its_key_and_hash() {
    let bundle = bundle_of(vec![bundled(1, 1, "a"), bundled(1, 2, "b")]);
    let sealed = seal_history_bundle(&bundle).unwrap();
    assert_eq!(
        open_history_bundle(&sealed.key, &sealed.ciphertext_sha256, &sealed.ciphertext).unwrap(),
        bundle
    );
    // Each bundle has its own key.
    assert_ne!(*seal_history_bundle(&bundle).unwrap().key, *sealed.key);

    let mut tampered = sealed.ciphertext.clone();
    tampered[0] ^= 1;
    assert_eq!(
        refusal(open_history_bundle(
            &sealed.key,
            &sealed.ciphertext_sha256,
            &tampered
        )),
        "history_bundle_hash"
    );
    let tampered_hash = Sha256::digest(&tampered).into();
    assert_eq!(
        refusal(open_history_bundle(&sealed.key, &tampered_hash, &tampered)),
        "history_bundle_decrypt"
    );
    assert_eq!(
        refusal(open_history_bundle(
            &[7; 32],
            &sealed.ciphertext_sha256,
            &sealed.ciphertext
        )),
        "history_bundle_decrypt"
    );
    // The label is bound as associated data.
    let plaintext = bundle.encode().unwrap();
    let unlabelled = cipher(&sealed.key)
        .unwrap()
        .encrypt(&Nonce::default(), plaintext.as_slice())
        .unwrap();
    let unlabelled_hash = Sha256::digest(&unlabelled).into();
    assert_eq!(
        refusal(open_history_bundle(
            &sealed.key,
            &unlabelled_hash,
            &unlabelled
        )),
        "history_bundle_decrypt"
    );
}

#[test]
fn a_bundle_that_breaks_the_format_is_refused_whole() {
    let good = String::from_utf8(bundle_of(vec![bundled(1, 1, "a")]).encode().unwrap()).unwrap();
    let id = bundled(1, 1, "a").event.id;
    let chat = hex::encode(CHAT);
    let broken = [
        // Unknown members, at each level.
        good.replacen(r#"{"v":1,"#, r#"{"v":1,"x":0,"#, 1),
        good.replacen(r#""epoch":1,"at":1,"#, r#""epoch":1,"x":0,"at":1,"#, 1),
        good.replacen(r#""content":"a"}"#, r#""content":"a","sig":"00"}"#, 1),
        good.replacen(
            r#""content":"a"},"epoch":1"#,
            r#""content":"a"},"epoch":1,"x":0"#,
            1,
        ),
        // A repeated member.
        good.replacen(r#"{"v":1,"#, r#"{"v":1,"v":1,"#, 1),
        // An optional member written as null.
        good.replacen(
            r#""content":"a"},"epoch":1"#,
            r#""content":"a"},"epoch":1,"retention":null"#,
            1,
        ),
        // Numbers outside the integer range, or not integers.
        good.replacen(
            r#""epoch":1,"at":1,"#,
            r#""epoch":9007199254740992,"at":1,"#,
            1,
        ),
        good.replacen(
            r#""content":"a"},"epoch":1"#,
            r#""content":"a"},"epoch":1,"retention":9007199254740992"#,
            1,
        ),
        good.replacen(r#""epoch":1,"at":1,"#, r#""epoch":1.0,"at":1,"#, 1),
        good.replacen(r#""epoch":1,"at":1,"#, r#""epoch":-1,"at":1,"#, 1),
        good.replacen(r#""epoch":1,"at":1,"#, r#""epoch":01,"at":1,"#, 1),
        // Hexadecimal in the wrong case or length.
        good.replacen(&chat, &chat.to_uppercase(), 1),
        good.replacen(&chat, &chat[1..], 1),
        good.replacen(&chat, "", 1),
        good.replacen(&chat, &"5a".repeat(257), 1),
        good.replacen(
            &format!(r#""id":"{id}","pubkey""#),
            &format!(r#""id":"{}","pubkey""#, id.to_uppercase()),
            0,
        )
        .replacen(
            &format!(r#""at":1,"id":"{id}""#),
            &format!(r#""at":1,"id":"{}""#, id.to_uppercase()),
            1,
        ),
        good.replacen(&"bb".repeat(32), &"bb".repeat(31), 1),
        // An attachment key list that is empty or holds a short key.
        good.replacen(
            r#""content":"a"},"epoch":1"#,
            r#""content":"a"},"epoch":1,"keys":[]"#,
            1,
        ),
        good.replacen(
            r#""content":"a"},"epoch":1"#,
            &format!(
                r#""content":"a"}},"epoch":1,"keys":[{{"ciphertext_sha256":"{}","key":"00"}}]"#,
                "cc".repeat(32)
            ),
            1,
        ),
    ];
    for bytes in &broken {
        assert_ne!(bytes, &good, "each case changes the bundle");
        assert_eq!(
            refusal(HistoryBundle::decode(bytes.as_bytes())),
            "history_bundle_encoding",
            "{bytes}"
        );
    }
    assert_eq!(
        refusal(HistoryBundle::decode(
            good.replacen(r#"{"v":1,"#, r#"{"v":2,"#, 1).as_bytes()
        )),
        "history_bundle_version"
    );
    let mut backwards = bundle_of(vec![bundled(1, 1, "a"), bundled(2, 1, "b")]);
    std::mem::swap(&mut backwards.from, &mut backwards.to);
    assert_eq!(
        refusal(HistoryBundle::decode(&backwards.encode().unwrap())),
        "history_bundle_stretch"
    );
    assert_eq!(
        refusal(HistoryBundle::decode(&vec![
            b' ';
            HISTORY_BUNDLE_MAX_PLAINTEXT + 1
        ])),
        "history_bundle_too_large"
    );
}

#[test]
fn an_event_outside_the_stretch_or_with_a_misplaced_verdict_is_dropped_alone() {
    let inside = bundled(2, 5, "inside");
    let mut bundle = bundle_of(vec![
        bundled(2, 1, "from"),
        inside.clone(),
        bundled(3, 1, "to"),
    ]);
    bundle.events.push(bundled(1, 9, "before"));
    bundle.events.push(bundled(3, 2, "after"));
    let mut misplaced = bundled(2, 6, "a chat message takes no verdict");
    misplaced.grant = Some(true);
    bundle.events.push(misplaced);
    let mut removal = bundled(2, 7, "");
    removal.event = event(7, MARMOT_APP_EVENT_KIND_REMOVE, "");
    removal.grant = Some(false);
    bundle.events.push(removal);
    let kept = bundle
        .events
        .iter()
        .filter(|event| event.in_stretch(&bundle))
        .map(|event| event.event.content.as_str())
        .collect::<Vec<_>>();
    assert_eq!(kept, ["from", "inside", "to", ""]);
}

#[test]
fn a_long_history_splits_into_bundles_over_consecutive_stretches() {
    let rows = (0..40)
        .map(|n| {
            let event = bundled(n / 10, n, &format!("message {n}"));
            // Every fifth row stays out but still lies in the stretch.
            (position(&event), (n % 5 != 0).then_some(event))
        })
        .collect::<Vec<_>>();
    let one = rows[1].1.as_ref().unwrap().encoded_len();
    let budget = HistoryBundle::header_bound(&CHAT) + 6 * one;
    let mut bundles = Vec::new();
    let mut next = 0;
    let mut after = None;
    loop {
        let mut builder = HistoryBundleBuilder::new(&CHAT, after.clone(), budget);
        while next < rows.len() && builder.take(rows[next].0.clone(), rows[next].1.clone()) {
            next += 1;
        }
        let Some(bundle) = builder.finish() else {
            break;
        };
        assert!(bundle.encode().unwrap().len() <= budget);
        after = Some(bundle.to.clone());
        bundles.push(bundle);
    }
    assert!(bundles.len() > 1);
    assert_eq!(bundles[0].from, rows[0].0);
    assert_eq!(bundles.last().unwrap().to, rows.last().unwrap().0);
    for pair in bundles.windows(2) {
        assert_eq!(pair[1].from, pair[0].to);
    }
    let carried = bundles
        .iter()
        .flat_map(|bundle| bundle.events.iter().cloned())
        .collect::<Vec<_>>();
    let expected = rows
        .iter()
        .filter_map(|(_, event)| event.clone())
        .collect::<Vec<_>>();
    assert_eq!(carried, expected);
    for bundle in &bundles {
        assert!(bundle.events.iter().all(|event| event.in_stretch(bundle)));
    }
}

#[test]
fn an_event_too_large_for_any_bundle_stays_out() {
    let small = bundled(1, 1, "small");
    let large = bundled(1, 2, &"x".repeat(400));
    let budget = HistoryBundle::header_bound(&CHAT) + 2 * small.encoded_len();
    let mut builder = HistoryBundleBuilder::new(&CHAT, None, budget);
    assert!(builder.take(position(&small), Some(small.clone())));
    assert!(builder.take(position(&large), Some(large.clone())));
    let bundle = builder.finish().unwrap();
    assert_eq!(bundle.events, [small]);
    assert_eq!(bundle.to, position(&large));
}

#[test]
fn a_builder_that_takes_no_row_has_no_bundle() {
    assert!(
        HistoryBundleBuilder::new(&CHAT, None, HISTORY_BUNDLE_MAX_PLAINTEXT)
            .finish()
            .is_none()
    );
    let after = position(&bundled(1, 1, "a"));
    assert!(
        HistoryBundleBuilder::new(&CHAT, Some(after), HISTORY_BUNDLE_MAX_PLAINTEXT)
            .finish()
            .is_none()
    );
}
