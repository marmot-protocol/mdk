#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use agent_control::{
    AgentControlEnvelope, AgentControlRequest, AgentControlResponse, read_envelope, write_frame,
};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

#[tokio::test]
async fn group_profile_cli_uses_explicit_route_and_json_stdin() {
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let request = read_envelope::<_, AgentControlRequest>(&mut reader)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.auth_token.as_deref(), Some("test-token"));
        let AgentControlRequest::GroupProfileUpdate {
            account_id_hex,
            group_id_hex,
            name,
            description,
        } = request.payload
        else {
            panic!("wrong request")
        };
        assert_eq!(account_id_hex, "11".repeat(32));
        assert_eq!(group_id_hex, "22".repeat(16));
        assert_eq!(name.as_deref(), Some("New"));
        assert_eq!(description, None);
        write_frame(
            reader.get_mut(),
            &AgentControlEnvelope::new(
                request.id,
                AgentControlResponse::GroupProfileUpdated {
                    group_id_hex,
                    message_ids_hex: vec!["33".repeat(32)],
                },
            ),
        )
        .await
        .unwrap();
    });
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_wn-agent"))
        .arg("group-profile")
        .env("MARMOT_HOME", root.path())
        .env("MARMOT_AGENT_SOCKET", socket)
        .env("MARMOT_ACCOUNT_ID_HEX", "11".repeat(32))
        .env("MARMOT_GROUP_ID_HEX", "22".repeat(16))
        .env("MARMOT_AGENT_AUTH_TOKEN", "test-token")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"name":"New"}"#)
        .await
        .unwrap();
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["ok"],
        true
    );
    assert!(output.stderr.is_empty());
}
