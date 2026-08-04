//! Long-lived coverage for the versioned convergence-node protocol.

use std::collections::BTreeMap;

use cgka_conformance_simulator::node_protocol::{
    MAX_NODE_JSONL_BYTES, NODE_OBSERVATION_SCHEMA_VERSION, NodeCommandV1, NodeRequestV1,
    NodeResponseBodyV1, NodeResponseV1, NodeServer, run_node_jsonl,
};
use nostr_relay_builder::MockRelay;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn request(server: &mut NodeServer, id: &str, command: NodeCommandV1) -> NodeResponseBodyV1 {
    server.handle(NodeRequestV1::new(id, command)).await.body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_wraps_one_runtime_and_defines_observable_quiescence() {
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let root = tempfile::tempdir().unwrap();
    let mut server = NodeServer::new();

    let account_id = match request(
        &mut server,
        "initialize",
        NodeCommandV1::Initialize {
            participant: "alice".into(),
            root: root.path().to_path_buf(),
            relay_urls: vec![relay_url],
        },
    )
    .await
    {
        NodeResponseBodyV1::Initialized { account_id } => account_id,
        other => panic!("unexpected initialize response: {other:?}"),
    };
    assert!(matches!(
        request(
            &mut server,
            "peers",
            NodeCommandV1::ConfigurePeers {
                accounts_by_participant: BTreeMap::from([("alice".into(), account_id.clone())]),
            },
        )
        .await,
        NodeResponseBodyV1::Ack { .. }
    ));
    assert!(matches!(
        request(
            &mut server,
            "catch-up-before-group",
            NodeCommandV1::CatchUp {
                action_id: "step-0:tick".into(),
                full_history: false,
            },
        )
        .await,
        NodeResponseBodyV1::Ack { .. }
    ));
    assert!(matches!(
        request(
            &mut server,
            "create",
            NodeCommandV1::CreateGroup {
                action_id: "step-0:create_group@main".into(),
                group: "main".into(),
                name: "node group".into(),
                member_accounts: Vec::new(),
                initial_admin_accounts: vec![account_id],
            },
        )
        .await,
        NodeResponseBodyV1::Ack {
            group_id_hex: Some(_),
            ..
        }
    ));
    assert!(matches!(
        request(
            &mut server,
            "catch-up",
            NodeCommandV1::CatchUp {
                action_id: "step-1:tick".into(),
                full_history: false,
            },
        )
        .await,
        NodeResponseBodyV1::Ack { .. }
    ));

    let first = match request(
        &mut server,
        "observe-1",
        NodeCommandV1::Observe {
            action_id: "step-2:observe".into(),
        },
    )
    .await
    {
        NodeResponseBodyV1::Observation { observation, .. } => observation,
        other => panic!("unexpected observation response: {other:?}"),
    };
    let second = match request(
        &mut server,
        "observe-2",
        NodeCommandV1::Observe {
            action_id: "step-2:observe".into(),
        },
    )
    .await
    {
        NodeResponseBodyV1::Observation { observation, .. } => observation,
        other => panic!("unexpected observation response: {other:?}"),
    };
    assert_eq!(first.schema_version, NODE_OBSERVATION_SCHEMA_VERSION);
    assert_eq!(
        first.protocol.state_commitment_sha256,
        second.protocol.state_commitment_sha256
    );
    assert_eq!(second.progress.stable_checkpoint_observations, 2);
    assert!(second.progress.observably_quiescent());
    assert_eq!(second.protocol.member_identities, vec!["alice"]);

    server.shutdown().await;
}

#[tokio::test]
async fn node_errors_do_not_echo_controlled_identifiers() {
    let mut server = NodeServer::new();
    let marker = "sensitive-controlled-value";
    let response = server
        .handle(NodeRequestV1::new(
            "before-init",
            NodeCommandV1::SelectGroup {
                group: marker.into(),
                group_id_hex: marker.into(),
            },
        ))
        .await;
    let encoded = serde_json::to_string(&response).unwrap();
    assert!(!encoded.contains(marker));
}

#[tokio::test]
async fn oversized_jsonl_frame_is_discarded_as_one_request() {
    let (client, server) = tokio::io::duplex(4096);
    let (server_read, server_write) = tokio::io::split(server);
    let server_task = tokio::spawn(async move {
        run_node_jsonl(BufReader::new(server_read), server_write)
            .await
            .unwrap();
    });
    let (client_read, mut client_write) = tokio::io::split(client);
    let writer = tokio::spawn(async move {
        client_write
            .write_all(&vec![b'x'; MAX_NODE_JSONL_BYTES + 32])
            .await
            .unwrap();
        client_write.write_all(b"\n").await.unwrap();
        let shutdown = NodeRequestV1::new("shutdown", NodeCommandV1::Shutdown);
        client_write
            .write_all(&serde_json::to_vec(&shutdown).unwrap())
            .await
            .unwrap();
        client_write.write_all(b"\n").await.unwrap();
        client_write.shutdown().await.unwrap();
    });

    let mut responses = BufReader::new(client_read).lines();
    let oversized: NodeResponseV1 =
        serde_json::from_str(&responses.next_line().await.unwrap().unwrap()).unwrap();
    assert!(matches!(
        oversized.body,
        NodeResponseBodyV1::Error(ref error) if error.code == "frame_too_large"
    ));
    let shutdown: NodeResponseV1 =
        serde_json::from_str(&responses.next_line().await.unwrap().unwrap()).unwrap();
    assert!(matches!(shutdown.body, NodeResponseBodyV1::Shutdown));
    assert!(responses.next_line().await.unwrap().is_none());
    writer.await.unwrap();
    server_task.await.unwrap();
}
