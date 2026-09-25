use marmot_forensics::v5::*;
use serde_json::{Value, json};

fn fixtures() -> Vec<Value> {
    serde_json::from_str(include_str!("fixtures/v5/valid.json")).unwrap()
}
fn fixture(name: &str) -> Value {
    fixtures().into_iter().find(|f| f["name"] == name).unwrap()["record"].take()
}
fn validator() -> jsonschema::Validator {
    jsonschema::validator_for(&serde_json::from_str(JSON_SCHEMA).unwrap()).unwrap()
}
fn decode(v: &Value) -> Result<Record, ContractError> {
    Record::from_json(&serde_json::to_vec(v).unwrap())
}

#[test]
fn all_contract_fixtures_round_trip_through_rust_and_schema() {
    let schema = validator();
    let mut kinds = std::collections::BTreeSet::new();
    for f in fixtures() {
        let body = &f["record"];
        assert!(
            schema.is_valid(body),
            "schema rejected {}: {:?}",
            f["name"],
            schema.iter_errors(body).collect::<Vec<_>>()
        );
        let record = decode(body).unwrap_or_else(|e| panic!("{}: {e}", f["name"]));
        let encoded = record.to_json().unwrap();
        assert!(encoded.len() <= MAX_BODY_BYTES);
        assert_eq!(serde_json::from_slice::<Value>(&encoded).unwrap(), *body);
        assert_eq!(Record::from_json(&encoded).unwrap(), record);
        kinds.insert(body["event"]["type"].as_str().unwrap().to_owned());
    }
    let schema: Value = serde_json::from_str(JSON_SCHEMA).unwrap();
    let catalog = schema["$defs"]["Event"]["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let name = r["$ref"].as_str().unwrap().rsplit('/').next().unwrap();
            schema["$defs"][name]["properties"]["type"]["const"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(kinds, catalog);
    assert_eq!(kinds.len(), 9);
}

#[test]
fn every_object_field_is_required_and_unknown_fields_are_rejected() {
    fn mutations(value: &Value, root: &Value, path: &str, out: &mut Vec<(String, Value)>) {
        match value {
            Value::Object(map) => {
                let mut extra = root.clone();
                extra
                    .pointer_mut(path)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert(
                        "forbidden_private_detail".into(),
                        json!("CANARY_PRIVATE_VALUE"),
                    );
                out.push((format!("{path}/unknown"), extra));
                for (key, child) in map {
                    let mut missing = root.clone();
                    missing
                        .pointer_mut(path)
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .remove(key);
                    out.push((format!("{path}/{key} missing"), missing));
                    mutations(child, root, &format!("{path}/{key}"), out);
                }
            }
            Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    mutations(child, root, &format!("{path}/{i}"), out);
                }
            }
            _ => {}
        }
    }
    let schema = validator();
    for f in fixtures() {
        let mut cases = Vec::new();
        mutations(&f["record"], &f["record"], "", &mut cases);
        for (mutation, body) in cases {
            assert!(
                !schema.is_valid(&body),
                "schema accepted missing/unknown field in {}",
                f["name"]
            );
            assert!(
                decode(&body).is_err(),
                "Rust accepted {mutation} in {}",
                f["name"]
            );
        }
    }
}

#[test]
fn forbidden_success_combinations_are_rejected_by_both_layers() {
    let schema = validator();
    for (name, path, value) in [
        (
            "prepared_founding",
            "/event/basis",
            json!({"kind":"commit","commit_ref":"c".repeat(64)}),
        ),
        (
            "prepared_invite",
            "/event/basis",
            json!({"kind":"unavailable"}),
        ),
        ("prepared_founding", "/event/outer_event_ref", Value::Null),
        (
            "prepared_founding",
            "/event/key_package_event_ref",
            Value::Null,
        ),
        ("prepared_founding", "/group_ref", Value::Null),
        ("selection_failed", "/event/retention", json!("committed")),
        (
            "selection_failed",
            "/event/reason",
            json!("retention_failed"),
        ),
        ("publish_started", "/event/required_acks", json!(0)),
        ("publish_started", "/event/target_count", json!(0)),
        (
            "publish_finished",
            "/event/results/0/failure_kind",
            json!("possibly_exposed"),
        ),
        (
            "publish_rejected",
            "/event/results/0/failure_kind",
            Value::Null,
        ),
        (
            "publish_rejected",
            "/event/retained_state",
            json!("completed"),
        ),
        ("local_replay", "/event/endpoint_ref", json!("e".repeat(64))),
        ("unwrapped", "/event/rumor_event_ref", Value::Null),
        ("unwrap_rejected", "/event/reason", json!("unwrap_failed")),
        ("unwrap_failed", "/event/reason", json!("invalid_signature")),
        (
            "unwrap_failed",
            "/event/rumor_event_ref",
            json!("f".repeat(64)),
        ),
        (
            "unwrap_failed",
            "/event/reason",
            json!("missing_key_package"),
        ),
        ("joined", "/event/engine_commit", json!("unknown")),
        ("joined", "/group_ref", Value::Null),
        ("joined", "/event/epoch", Value::Null),
        ("join_rejected", "/event/engine_commit", json!("committed")),
        ("join_rejected", "/event/reason", json!("duplicate")),
        ("app_pending", "/event/compute", json!("failed")),
        ("app_failed", "/event/invite_state", json!("accepted")),
        (
            "app_confirmed",
            "/event/invite_state",
            json!("pending_confirmation"),
        ),
        ("baseline", "/event/epoch", Value::Null),
        ("baseline", "/event/members/0/admin", Value::Null),
        ("baseline_partial", "/event/limitations", json!([])),
        ("baseline_partial", "/event/members_complete", json!(true)),
        ("baseline_failed", "/event/epoch", json!("0")),
    ] {
        let mut body = fixture(name);
        *body.pointer_mut(path).unwrap() = value;
        assert!(!schema.is_valid(&body), "schema accepted {name} {path}");
        assert!(decode(&body).is_err(), "Rust accepted {name} {path}");
    }
}

#[test]
fn unwrap_result_reason_sets_are_closed_in_rust_and_schema() {
    let schema = validator();
    for (fixture_name, reasons) in [
        (
            "unwrap_rejected",
            ["wrong_recipient", "invalid_signature", "invalid_encoding"].as_slice(),
        ),
        (
            "unwrap_failed",
            ["unwrap_failed", "internal_failed", "unclassified"].as_slice(),
        ),
    ] {
        for reason in reasons {
            let mut body = fixture(fixture_name);
            body["event"]["reason"] = json!(reason);
            assert!(
                schema.is_valid(&body),
                "schema rejected {fixture_name}/{reason}"
            );
            assert!(
                decode(&body).is_ok(),
                "Rust rejected {fixture_name}/{reason}"
            );
        }
    }
}

#[test]
fn semantic_count_and_identity_rules_supplement_json_schema() {
    for (name, path, value) in [
        ("publish_started", "/event/target_count", json!(2)),
        (
            "publish_finished",
            "/event/accepted_this_attempt_count",
            json!(2),
        ),
        ("publish_finished", "/event/accepted_total_count", json!(0)),
        ("publish_finished", "/event/required_acks", json!(2)),
        ("publish_rejected", "/event/accepted_total_count", json!(1)),
        ("baseline", "/event/member_count", json!(2)),
        ("baseline_partial", "/event/member_count", json!(0)),
    ] {
        let mut body = fixture(name);
        // Partial empty subset with total zero is not inherently inconsistent; supply one member.
        if name == "baseline_partial" {
            body["event"]["members"] = fixture("baseline")["event"]["members"].clone();
        }
        *body.pointer_mut(path).unwrap() = value;
        assert!(decode(&body).is_err(), "accepted {name} {path}");
    }
    let mut body = fixture("publish_finished");
    let mut result = body["event"]["results"][0].clone();
    result["status"] = json!("failed");
    result["failure_kind"] = json!("possibly_exposed");
    body["event"]["results"]
        .as_array_mut()
        .unwrap()
        .push(result);
    assert!(
        decode(&body).is_err(),
        "same endpoint cannot have two result entries"
    );
}

#[test]
fn canonical_integer_strings_and_strict_json_boundaries() {
    let schema = validator();
    for text in [
        "0",
        "01",
        "+1",
        "-1",
        "1.0",
        "1e3",
        "18446744073709551616",
        "1\n",
    ] {
        let mut v = fixture("observed");
        v["seq"] = json!(text);
        assert!(!schema.is_valid(&v), "schema accepted seq {text:?}");
        assert!(decode(&v).is_err());
    }
    for text in ["18446744073709551615", "9007199254740993"] {
        let mut v = fixture("observed");
        v["seq"] = json!(text);
        assert!(schema.is_valid(&v));
        assert!(decode(&v).is_ok());
    }
    for text in ["-9223372036854775808", "9223372036854775807", "0"] {
        let mut v = fixture("observed");
        v["wall_time_ms"] = json!(text);
        assert!(schema.is_valid(&v));
        assert!(decode(&v).is_ok());
    }
    for text in [
        "-0",
        "9223372036854775808",
        "-9223372036854775809",
        "00",
        "+1",
    ] {
        let mut v = fixture("observed");
        v["wall_time_ms"] = json!(text);
        assert!(!schema.is_valid(&v));
        assert!(decode(&v).is_err());
    }
    let body = serde_json::to_string(&fixture("observed")).unwrap();
    for bad in [
        body.replacen("\"seq\":", "\"seq\":\"1\",\"seq\":", 1),
        body.replace("\"type\":", "\"type\":\"welcome_observed\",\"type\":"),
        body.replace("\"fetch_id\":", "\"fetch_id\":null,\"fetch_id\":"),
        body.replace("\"host_build\":", "\"host_build\":null,\"host_build\":"),
        format!("{body}\n"),
        format!("{body}{{}}"),
        format!("{}{body}", " ".repeat(MAX_BODY_BYTES)),
        body.replace("\"mono_us\":\"0\"", "\"mono_us\":NaN"),
    ] {
        assert!(Record::from_json(bad.as_bytes()).is_err());
    }
    assert!(Record::from_json(&[0xff]).is_err());
    let mut count = serde_json::to_string(&fixture("publish_started")).unwrap();
    count = count.replace("\"required_acks\":1", "\"required_acks\":1.0");
    assert!(
        Record::from_json(count.as_bytes()).is_err(),
        "integer-valued floats are not count syntax"
    );
}

#[test]
fn maximum_shapes_fit_and_overflow_is_not_silently_trimmed() {
    let schema = validator();
    let mut v = fixture("baseline");
    v["seq"] = json!(u64::MAX.to_string());
    v["mono_us"] = v["seq"].clone();
    v["wall_time_ms"] = json!(i64::MIN.to_string());
    v["producer"]["mdk_revision"] = json!("f".repeat(64));
    v["producer"]["host_build"] = json!("X".repeat(64));
    v["event"]["members"] = (0..MAX_MEMBERS)
        .map(|i| json!({"member_ref":format!("{i:064x}"),"admin":false}))
        .collect();
    v["event"]["member_count"] = json!(MAX_MEMBERS);
    assert!(schema.is_valid(&v));
    let record = decode(&v).unwrap();
    assert!(record.to_json().unwrap().len() < MAX_BODY_BYTES);
    let extra = json!({"member_ref":format!("{:064x}", MAX_MEMBERS),"admin":true});
    v["event"]["members"].as_array_mut().unwrap().push(extra);
    v["event"]["member_count"] = json!(MAX_MEMBERS + 1);
    assert!(!schema.is_valid(&v));
    assert!(decode(&v).is_err());
    let mut v = fixture("publish_finished");
    v["event"]["results"] = (0..MAX_ENDPOINTS).map(|i| json!({"endpoint_ref":format!("{i:064x}"),"status":"failed","failure_kind":"retryable_unavailable","rejection_category":"auth-required"})).collect();
    v["event"]["accepted_this_attempt_count"] = json!(0);
    v["event"]["accepted_total_count"] = json!(u32::MAX);
    assert!(schema.is_valid(&v));
    assert!(decode(&v).unwrap().to_json().unwrap().len() < MAX_BODY_BYTES);
    v["event"]["results"].as_array_mut().unwrap().push(json!({"endpoint_ref":"f".repeat(64),"status":"acknowledged","failure_kind":null,"rejection_category":null}));
    assert!(!schema.is_valid(&v));
    assert!(decode(&v).is_err());
}

#[test]
fn domain_separated_references_match_portable_vectors() {
    let vectors: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/v5/references.json")).unwrap();
    for v in vectors {
        let bytes = hex::decode(v["input_hex"].as_str().unwrap()).unwrap();
        let actual = match v["kind"].as_str().unwrap() {
            "group" => GroupRef::from_group_id(&bytes).unwrap().as_str().to_owned(),
            "member" => MemberRef::from_member_identity(&bytes)
                .unwrap()
                .as_str()
                .to_owned(),
            "nostr_event" => NostrEventRef::from_validated_event_id(&bytes.try_into().unwrap())
                .as_str()
                .to_owned(),
            "engine_message" => EngineMessageRef::from_message_id(&bytes)
                .unwrap()
                .as_str()
                .to_owned(),
            _ => unreachable!(),
        };
        assert_eq!(actual, v["expected"]);
    }
    let endpoints: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/v5/endpoints.json")).unwrap();
    for v in endpoints {
        assert_eq!(
            EndpointRef::from_normalized_url(v["normalized"].as_str().unwrap())
                .unwrap()
                .as_str(),
            v["expected"].as_str().unwrap()
        );
    }
    assert!(GroupRef::from_group_id(&[]).is_err());
    assert_ne!(
        GroupRef::from_group_id(&[1; 32]).unwrap().as_str(),
        MemberRef::from_member_identity(&[1; 32]).unwrap().as_str()
    );
}

#[test]
fn diagnostics_never_echo_rejected_input_and_v4_remains_current() {
    let mut v = fixture("observed");
    v["producer"]["host_build"] = json!("PRIVATE_SECRET /arbitrary/path");
    let error = decode(&v).unwrap_err();
    assert!(!error.to_string().contains("PRIVATE_SECRET"));
    assert!(!format!("{error:?}").contains("PRIVATE_SECRET"));
    assert_eq!(
        marmot_forensics::AUDIT_LOG_SCHEMA_VERSION,
        "marmot-forensics-audit/v4"
    );
    assert_ne!(SCHEMA_VERSION, marmot_forensics::AUDIT_LOG_SCHEMA_VERSION);
    assert!(serde_json::from_value::<marmot_forensics::AuditEvent>(fixture("observed")).is_err());
}

#[test]
fn scalar_encodings_and_count_ranges_agree_with_schema() {
    let schema = validator();
    for (path, value) in [
        ("/source_ref", json!("A".repeat(32))),
        ("/session_id", json!("0".repeat(31))),
        ("/event/receive_id", json!("g".repeat(32))),
        ("/event/outer_event_ref", json!("0".repeat(63))),
        ("/producer/mdk_revision", json!("f".repeat(41))),
        ("/producer/host_build", json!("x".repeat(65))),
        ("/producer/host_build", json!("")),
        ("/producer/host_build", json!("build/secret")),
        ("/seq", json!(1)),
        ("/mono_us", json!("-1")),
        ("/wall_time_ms", json!("1.1")),
        ("/schema_version", json!("marmot-forensics-audit/v4")),
        ("/event/acquisition", json!("guessed")),
    ] {
        let mut body = fixture("observed");
        *body.pointer_mut(path).unwrap() = value;
        assert!(
            !schema.is_valid(&body),
            "schema accepted invalid scalar at {path}"
        );
        assert!(
            decode(&body).is_err(),
            "Rust accepted invalid scalar at {path}"
        );
    }
    for value in [json!(-1), json!(4294967296_u64), json!(1.5), json!("1")] {
        let mut body = fixture("publish_started");
        body["event"]["accepted_before_count"] = value;
        assert!(!schema.is_valid(&body));
        assert!(decode(&body).is_err());
    }
    let mut body = fixture("publish_started");
    body["event"]["accepted_before_count"] = json!(u32::MAX);
    assert!(schema.is_valid(&body));
    assert!(decode(&body).is_ok());
}

#[test]
fn publication_endpoint_classifications_match_nostr_owner_contract() {
    let schema = validator();
    let kinds = [
        None,
        Some("not_exposed"),
        Some("possibly_exposed"),
        Some("retryable_unavailable"),
        Some("terminal_rejected"),
    ];
    let categories = [
        None,
        Some("duplicate"),
        Some("pow"),
        Some("blocked"),
        Some("rate-limited"),
        Some("invalid"),
        Some("error"),
        Some("unsupported"),
        Some("auth-required"),
        Some("restricted"),
    ];
    for status in ["acknowledged", "failed"] {
        for kind in kinds {
            for category in categories {
                // The source owner accepts duplicate replies before classifying failures.
                // Enumerate every status/kind/category combination, including forbidden pairs.
                let expected = matches!(
                    (status, kind, category),
                    ("acknowledged", None, None | Some("duplicate"))
                        | ("failed", Some("not_exposed"), None)
                        | ("failed", Some("possibly_exposed"), None | Some("error"))
                        | (
                            "failed",
                            Some("retryable_unavailable"),
                            None | Some("rate-limited" | "auth-required"),
                        )
                        | (
                            "failed",
                            Some("terminal_rejected"),
                            Some("pow" | "blocked" | "invalid" | "unsupported" | "restricted"),
                        )
                );
                let mut body = fixture(if status == "acknowledged" {
                    "publish_finished"
                } else {
                    "publish_rejected"
                });
                body["event"]["results"][0]["status"] = json!(status);
                body["event"]["results"][0]["failure_kind"] = json!(kind);
                body["event"]["results"][0]["rejection_category"] = json!(category);
                assert_eq!(
                    schema.is_valid(&body),
                    expected,
                    "schema: {status}/{kind:?}/{category:?}"
                );
                assert_eq!(
                    decode(&body).is_ok(),
                    expected,
                    "Rust: {status}/{kind:?}/{category:?}"
                );
            }
        }
    }
}
