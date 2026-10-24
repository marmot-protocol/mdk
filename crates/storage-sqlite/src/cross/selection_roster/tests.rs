use super::*;
use crate::SqliteAccountStorage;
use crate::base::test_support::{gid, sample_group};
use cgka_traits::storage::GroupStorage;
use cgka_traits::{GroupId, Member, MemberId};
use std::cell::Cell;

fn fixture() -> (SqliteAccountStorage, Group) {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut group = sample_group(gid(1), 3, 0);
    group.members = vec![];
    store.put_group(&group).unwrap();
    (store, group)
}
fn member(bytes: Vec<u8>) -> Member {
    Member {
        id: MemberId::new(bytes),
        credential: vec![],
    }
}
fn read(
    store: &SqliteAccountStorage,
    lookup: &GroupId,
    keys: &SelectedMemberKeys,
    active: Option<[u8; 32]>,
    local: &HashSet<[u8; 32]>,
    cancelled: &impl Fn() -> bool,
) -> Result<ProjectedRosterEvidence, RosterReadError> {
    store.app_storage().connection.with_deferred_read(|conn| {
        projected_roster_selected_keys_tx(
            conn,
            lookup.as_slice(),
            keys,
            PeerInputs {
                active,
                local_profile_ids: local,
            },
            cancelled,
        )
    })
}
fn replace_record(store: &SqliteAccountStorage, lookup: &GroupId, record: &[u8]) {
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE cgka_groups SET record=?1 WHERE id=?2",
            rusqlite::params![record, lookup.as_slice()],
        )
        .unwrap();
}

#[test]
fn strict_key_cardinality_and_distinct_hits_cover_bit63_without_duplicates() {
    for keys in [vec![], vec![[1; 32]; 2], (0..65).map(|n| [n; 32]).collect()] {
        assert!(matches!(
            SelectedMemberKeys::single_condition(&keys),
            Err(RosterReadError::InvalidKeys)
        ));
    }
    let keys = SelectedMemberKeys::new(&(0..64).map(|n| [n; 32]).collect::<Vec<_>>()).unwrap();
    let (store, mut group) = fixture();
    group.members = vec![
        member(vec![63; 32]),
        member(vec![63; 32]),
        member(vec![0; 31]),
        member(vec![]),
        member(vec![0; 33]),
    ];
    store.put_group(&group).unwrap();
    let result = read(&store, &group.id, &keys, None, &HashSet::new(), &|| false).unwrap();
    assert_eq!(result.selected_hits[0], 1u64 << 63);
    assert!(result.roster_nonempty);
    group.members = (0..64).map(|n| member(vec![n; 32])).collect();
    store.put_group(&group).unwrap();
    assert_eq!(
        read(&store, &group.id, &keys, None, &HashSet::new(), &|| false)
            .unwrap()
            .selected_hits[0],
        u64::MAX
    );
    group.members.clear();
    store.put_group(&group).unwrap();
    let empty = read(&store, &group.id, &keys, None, &HashSet::new(), &|| false).unwrap();
    assert!(empty.selected_hits.iter().all(|word| *word == 0));
    assert!(!empty.roster_nonempty);
    assert!(empty.peer.is_none());
}

#[test]
fn typed_reader_preserves_get_group_acceptance_for_defaults_and_bad_fields() {
    let (store, group) = fixture();
    let keys = SelectedMemberKeys::new(&[[1; 32]]).unwrap();
    let base = serde_json::to_value(&group).unwrap();
    let mut records = vec![
        serde_json::to_vec(&base).unwrap(),
        b"{".to_vec(),
        b"not-json".to_vec(),
        vec![255],
    ];
    let mut unknown = base.clone();
    unknown["unknown_field"] = serde_json::json!({"anything":[true,null,"unused"]});
    records.push(serde_json::to_vec(&unknown).unwrap());
    for name in [
        "protocol_profile",
        "removed",
        "unrecoverable",
        "disbanded",
        "join_epoch",
        "local_copy_install_epoch",
        "local_copy_welcome_created_at",
    ] {
        let mut value = base.clone();
        value.as_object_mut().unwrap().remove(name);
        records.push(serde_json::to_vec(&value).unwrap());
    }
    for name in [
        "id",
        "name",
        "description",
        "epoch",
        "members",
        "required_capabilities",
    ] {
        let mut value = base.clone();
        value.as_object_mut().unwrap().remove(name);
        records.push(serde_json::to_vec(&value).unwrap());
    }
    for value in [
        serde_json::json!(-1),
        serde_json::json!(1.25),
        serde_json::json!("wrong"),
        serde_json::Value::Null,
    ] {
        let mut bad = base.clone();
        bad["epoch"] = value;
        records.push(serde_json::to_vec(&bad).unwrap());
    }
    for bad_id in [
        serde_json::json!([-1]),
        serde_json::json!([256]),
        serde_json::json!([1.5]),
        serde_json::json!(["1"]),
        serde_json::json!(true),
    ] {
        let mut bad = base.clone();
        bad["members"] = serde_json::json!([{"id":bad_id,"credential":[]}]);
        records.push(serde_json::to_vec(&bad).unwrap());
    }
    for (field, value) in [
        ("required_capabilities", serde_json::json!(false)),
        (
            "protocol_profile",
            serde_json::json!("invalid-private-sentinel"),
        ),
        (
            "members",
            serde_json::json!([{"id":[1],"credential":[999]}]),
        ),
    ] {
        let mut bad = base.clone();
        bad[field] = value;
        records.push(serde_json::to_vec(&bad).unwrap());
    }
    let valid = serde_json::to_string(&base).unwrap();
    records.push(format!("{{\"name\":\"duplicate\",{}", &valid[1..]).into_bytes());
    records.push(format!("{valid}false").into_bytes());
    records.push(format!("{valid} \n\t").into_bytes());
    for record in records {
        replace_record(&store, &group.id, &record);
        let expected = store.get_group(&group.id);
        let actual = read(&store, &group.id, &keys, None, &HashSet::new(), &|| false);
        match (expected, actual) {
            (Ok(source), Ok(result)) => {
                assert_eq!(result.roster_nonempty, !source.members.is_empty())
            }
            (Err(expected), Err(RosterReadError::Storage(actual))) => assert_eq!(
                std::mem::discriminant(&expected),
                std::mem::discriminant(&actual)
            ),
            _ => panic!("typed acceptance diverged from GroupStorage::get_group"),
        }
    }
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE cgka_groups SET record='text rather than BLOB' WHERE id=?1",
            [group.id.as_slice()],
        )
        .unwrap();
    assert!(matches!(
        store.get_group(&group.id),
        Err(StorageError::Backend(_))
    ));
    assert!(matches!(
        read(&store, &group.id, &keys, None, &HashSet::new(), &|| false),
        Err(RosterReadError::Storage(StorageError::Backend(_)))
    ));
    let missing = GroupId::new(vec![7, 8, 9]);
    assert!(matches!(
        store.get_group(&missing),
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        read(&store, &missing, &keys, None, &HashSet::new(), &|| false),
        Err(RosterReadError::Storage(StorageError::NotFound))
    ));
}

#[test]
fn lookup_record_id_and_sql_epoch_mismatches_remain_accepted() {
    let (store, mut group) = fixture();
    let lookup = group.id.clone();
    group.id = GroupId::new(vec![9, 8, 7]);
    group.epoch = cgka_traits::EpochId(999);
    group.members = vec![member(vec![44; 32])];
    replace_record(&store, &lookup, &crate::serialize(&group).unwrap());
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE cgka_groups SET epoch=1 WHERE id=?1",
            [lookup.as_slice()],
        )
        .unwrap();
    let actual = store.get_group(&lookup).unwrap();
    assert_eq!(actual.id, group.id);
    assert_eq!(actual.epoch, group.epoch);
    let keys = SelectedMemberKeys::new(&[[44; 32], [45; 32]]).unwrap();
    assert_eq!(
        read(&store, &lookup, &keys, None, &HashSet::new(), &|| false)
            .unwrap()
            .selected_hits[0],
        1
    );
    group.members = vec![member(vec![45; 32])];
    replace_record(&store, &lookup, &crate::serialize(&group).unwrap());
    assert_eq!(
        read(&store, &lookup, &keys, None, &HashSet::new(), &|| false)
            .unwrap()
            .selected_hits[0],
        2
    );
    let variable = GroupId::new(vec![0xab]);
    group.id = variable.clone();
    store.put_group(&group).unwrap();
    assert_eq!(
        read(&store, &variable, &keys, None, &HashSet::new(), &|| false)
            .unwrap()
            .selected_hits[0],
        2
    );
}

#[test]
fn ordered_peer_matches_android_first_nonself_nonlocal_then_nonempty() {
    let (store, mut group) = fixture();
    let keys = SelectedMemberKeys::new(&[[1; 32], [2; 32], [3; 32]]).unwrap();
    for (roster, active, locals, expected) in [
        (
            vec![vec![1; 32], vec![2; 32], vec![3; 32]],
            Some([1; 32]),
            vec![[1; 32], [2; 32]],
            Some(Some(1)),
        ),
        (
            vec![vec![3; 32], vec![2; 32], vec![1; 32]],
            Some([1; 32]),
            vec![],
            Some(Some(2)),
        ),
        (
            vec![vec![1; 32], vec![2; 32]],
            None,
            vec![[1; 32]],
            Some(Some(1)),
        ),
        (
            vec![vec![1; 32]],
            Some([1; 32]),
            vec![[1; 32]],
            Some(Some(0)),
        ),
        (
            vec![vec![], vec![1; 32], vec![2; 32]],
            None,
            vec![[1; 32], [2; 32]],
            Some(Some(0)),
        ),
        (vec![vec![], vec![]], None, vec![], None),
        (
            vec![vec![5; 100_000], vec![1; 32]],
            Some([1; 32]),
            vec![],
            Some(None),
        ),
        (
            vec![vec![2; 32], vec![2; 32], vec![1; 32]],
            Some([1; 32]),
            vec![],
            Some(Some(1)),
        ),
    ] {
        group.members = roster.into_iter().map(member).collect();
        store.put_group(&group).unwrap();
        let result = read(
            &store,
            &group.id,
            &keys,
            active,
            &locals.into_iter().collect(),
            &|| false,
        )
        .unwrap();
        assert_eq!(result.peer.map(|p| p.selected_key), expected);
        assert_eq!(result.roster_nonempty, !group.members.is_empty());
    }
}

#[test]
fn cancellation_is_observed_around_fetch_decode_scan_and_result_without_evidence() {
    let (store, mut group) = fixture();
    group.members = (0..5).map(|n| member(vec![n; 32])).collect();
    store.put_group(&group).unwrap();
    let keys = SelectedMemberKeys::new(&[[1; 32]]).unwrap();
    // Calls 1/2/3 bracket fetch and typed decode, 4..8 walk members, 9 precedes result.
    for at in 1..=9 {
        let calls = Cell::new(0);
        assert!(matches!(
            read(&store, &group.id, &keys, None, &HashSet::new(), &|| {
                calls.set(calls.get() + 1);
                calls.get() >= at
            }),
            Err(RosterReadError::Cancelled)
        ));
        assert_eq!(calls.get(), at);
    }
    assert!(read(&store, &group.id, &keys, None, &HashSet::new(), &|| false).is_ok());
}

#[test]
fn baseline_reader_omits_optional_presentation_and_debug_redacts() {
    let (store, mut group) = fixture();
    let sentinel = [0x6b; 32];
    group.members = vec![member(sentinel.to_vec())];
    group.members[0].credential = b"private-credential-sentinel".to_vec();
    store.put_group(&group).unwrap();
    let keys = SelectedMemberKeys::new(&[sentinel]).unwrap();
    let result = read(&store, &group.id, &keys, None, &HashSet::new(), &|| false).unwrap();
    for debug in [format!("{keys:?}"), format!("{result:?}")] {
        assert!(!debug.contains(&hex::encode(sentinel)));
        assert!(!debug.contains("private-credential-sentinel"));
        assert!(!debug.contains("selected_hits:"));
    }
    // The baseline reader must omit optional raw presentation facts. Machine
    // layout is not a privacy or retained-resource contract.
    assert!(result.presentation.is_none());
}

#[test]
fn bounded_roster_work_observations_use_separate_joined_case_processes() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let exe = std::env::current_exe().unwrap();
    for case in 0..6 {
        let mut child = Command::new(&exe)
            .args([
                "--ignored",
                "--exact",
                "cross::selection_roster::tests::roster_work_case_worker",
                "--nocapture",
            ])
            .env("SELECTION_ROSTER_WORK_CASE", case.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("private work case exceeded operational 60s timeout; no performance PASS");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "private work case failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let line = stdout
            .lines()
            .find_map(|line| line.split_once("ROSTER_WORK ").map(|(_, body)| body))
            .expect("actual worker observation");
        println!("ROSTER_WORK {line}");
    }
}

#[test]
#[ignore = "private work-case worker invoked in one fresh joined process per case"]
fn roster_work_case_worker() {
    use std::time::Instant;
    let case: usize = std::env::var("SELECTION_ROSTER_WORK_CASE")
        .expect("explicit private case")
        .parse()
        .unwrap();
    let (count, key_count, extra) = [
        (0, 1, 0),
        (2, 1, 0),
        (100, 64, 0),
        (1000, 64, 4096),
        (10_000, 64, 0),
        (2, 64, 1_048_576),
    ][case];
    let (store, mut group) = fixture();
    group.name = "n".repeat(extra);
    group.members = (0..count)
        .map(|n| {
            let mut id = vec![0xee; 32];
            id[..8].copy_from_slice(&(n as u64).to_be_bytes());
            member(id)
        })
        .collect();
    if let Some(first) = group.members.first_mut() {
        first.credential = vec![7; extra];
    }
    store.put_group(&group).unwrap();
    let selected = (0..key_count).map(|n| [n as u8; 32]).collect::<Vec<_>>();
    let keys = SelectedMemberKeys::new(&selected).unwrap();
    let record_bytes: i64 = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT length(record) FROM cgka_groups WHERE id=?1",
            [group.id.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let start = Instant::now();
    let baseline = store.get_group(&group.id).unwrap();
    let baseline_ns = start.elapsed().as_nanos();
    assert_eq!(baseline.members.len(), count);
    drop(baseline);
    let start = Instant::now();
    let result = read(&store, &group.id, &keys, None, &HashSet::new(), &|| false).unwrap();
    let cross_ns = start.elapsed().as_nanos();
    let returned_hit_words_bytes = result.selected_hits.len() * std::mem::size_of::<u64>();
    assert!(result.selected_hits.iter().all(|word| *word == 0));
    let calls = Cell::new(0);
    let requested = Cell::new(None);
    let observed = Cell::new(None);
    let result = read(&store, &group.id, &keys, None, &HashSet::new(), &|| {
        calls.set(calls.get() + 1);
        if calls.get() == 2 {
            requested.set(Some(Instant::now()));
            false
        } else if calls.get() == 3 {
            observed.set(Some(Instant::now()));
            true
        } else {
            false
        }
    });
    assert!(matches!(result, Err(RosterReadError::Cancelled)));
    let rss = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|line| line.starts_with("VmHWM:"))
                .map(str::to_owned)
        });
    println!(
        "ROSTER_WORK {}",
        serde_json::json!({"case":case,"record_bytes":record_bytes,"roster_entries":count,"selected_keys":key_count,"unrelated_name_and_first_credential_bytes_each":extra,"baseline_fetch_decode_ns":baseline_ns,"cross_fetch_decode_scan_ns":cross_ns,"synthetic_after_fetch_request_observed_after_decode_ns":observed.get().unwrap().duration_since(requested.get().unwrap()).as_nanos(),"fresh_case_process_peak_rss":rss,"rss_scope":"whole case process including fixture setup; not function allocation count","returned_evidence_inline_bytes":std::mem::size_of::<ProjectedRosterEvidence>(),"returned_hit_words_bytes":returned_hit_words_bytes,"allocation_counts":"not measured","vm_steps":"not measured","qualification":"scaling observation only; no performance threshold or decode-preemption claim"})
    );
}

#[test]
fn whole_tree_union_exceeds_leaf_limit_and_hits_word_boundaries() {
    fn key(n: usize) -> [u8; 32] {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&(n as u64).to_le_bytes());
        key
    }
    let raw: Vec<_> = (0..MAX_SELECTED_MEMBER_KEYS).map(key).collect();
    let keys = SelectedMemberKeys::new(&raw).unwrap();
    assert_eq!(keys.len(), 4096);
    assert!(SelectedMemberKeys::single_condition(&raw[..65]).is_err());
    let mut too_many = raw.clone();
    too_many.push(key(4096));
    assert!(SelectedMemberKeys::new(&too_many).is_err());
    let (store, mut group) = fixture();
    let selected = [0, 63, 64, 127, 128, 4095];
    group.members = selected
        .into_iter()
        .chain([64, 4095])
        .map(|n| member(key(n).to_vec()))
        .collect();
    store.put_group(&group).unwrap();
    let evidence = read(&store, &group.id, &keys, None, &HashSet::new(), &|| false).unwrap();
    assert_eq!(evidence.hit_word_count(), 64);
    for n in selected {
        assert!(evidence.contains(n));
        assert_eq!(keys.index_of(&key(n)), Some(n));
    }
    for n in [1, 62, 65, 126, 129, 4094, 4096] {
        assert!(!evidence.contains(n as usize));
    }
    assert_eq!(
        evidence
            .selected_hits
            .iter()
            .map(|word| word.count_ones())
            .sum::<u32>(),
        6
    );
}

#[test]
fn complete_capture_mixed_legacy_keys_and_wide_indices_preserve_peer_facts() {
    let mut raw: Vec<Vec<u8>> = (0u64..65537)
        .map(|n| {
            let mut key = vec![0; 32];
            key[..8].copy_from_slice(&n.to_le_bytes());
            key
        })
        .collect();
    raw.push(vec![0xab; 3]);
    let keys = SelectedMemberKeys::for_legacy_catalog(&raw).unwrap();
    assert_eq!(keys.len(), 65538);
    let (store, mut group) = fixture();
    let active = [7; 32];
    group.members = vec![
        member(active.to_vec()),
        member(active.to_vec()),
        member(vec![]),
        member(vec![]),
        member(vec![0xab; 3]),
        member(vec![0xab; 3]),
        member(raw[65536].clone()),
    ];
    store.put_group(&group).unwrap();
    let local = HashSet::new();
    let evidence = store
        .app_storage()
        .connection
        .with_deferred_read(|conn| {
            projected_roster_selection_context_tx(
                conn,
                group.id.as_slice(),
                &keys,
                PeerInputs {
                    active: Some(active),
                    local_profile_ids: &local,
                },
                Some(1024),
                &|| false,
            )
        })
        .unwrap();
    assert!(evidence.contains(65536));
    assert!(evidence.contains(65537));
    assert!(evidence.peer_present());
    assert_eq!(evidence.active_account_is_member, Some(true));
    let presentation = evidence.presentation.unwrap();
    assert_eq!(presentation.peer_id_hex.as_deref(), Some("ababab"));
    assert_eq!(presentation.member_count, 5);
    assert!(!presentation.active_account_is_sole_member);
    let strict = SelectedMemberKeys::new(&[[1; 32]]).unwrap();
    let evidence = read(&store, &group.id, &strict, Some(active), &local, &|| false).unwrap();
    assert!(evidence.peer_present());
    assert!(!evidence.contains(0));
    assert!(evidence.presentation.is_none());
}
