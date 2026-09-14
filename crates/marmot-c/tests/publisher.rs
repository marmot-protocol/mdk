//! Exercise the public C surface against private relay and QUIC fixtures.

use std::ffi::{CStr, CString};
use std::ptr;

use marmot_c::commands::{marmot_create_group, marmot_create_identity, marmot_messages};
use marmot_c::publisher::*;
use marmot_c::subscriptions::*;
use marmot_c::types::account::{marmot_account_summary_free, marmot_send_summary_free};
use marmot_c::types::agent_stream::{MarmotAgentStreamUpdate, marmot_agent_stream_update_free};
use marmot_c::types::message::marmot_app_message_record_list_free;
use marmot_c::*;
use transport_quic_broker::{QuicBrokerConfig, QuicBrokerServer};

fn check(status: MarmotStatus) {
    if status == MarmotStatus::Ok {
        return;
    }
    let detail = marmot_last_error_message();
    let message = unsafe { CStr::from_ptr(detail) }
        .to_string_lossy()
        .into_owned();
    unsafe { marmot_string_free(detail) };
    panic!("{status:?}: {message}");
}

#[test]
fn publisher_preflights_outputs() {
    unsafe {
        let mut out = ptr::dangling_mut::<MarmotAgentPublisher>();
        assert_eq!(
            marmot_agent_publisher_new(
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                &mut out
            ),
            MarmotStatus::NullPointer
        );
        assert!(out.is_null());
        assert_eq!(
            marmot_agent_publisher_finish(ptr::null(), ptr::null_mut()),
            MarmotStatus::NullPointer
        );
        assert_eq!(
            marmot_agent_publisher_append(ptr::null(), u32::MAX, ptr::null(), ptr::null_mut()),
            MarmotStatus::NullPointer
        );
        marmot_agent_publisher_free(ptr::null_mut());
        let mut client = ptr::dangling_mut::<MarmotClient>();
        assert_eq!(
            marmot_client_new_with_options(
                ptr::null(),
                ptr::null(),
                0,
                u32::MAX,
                ptr::null(),
                &mut client
            ),
            MarmotStatus::InvalidArgument
        );
        assert!(client.is_null());
    }
}

#[test]
fn publisher_finishes_and_cancels() {
    keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let relay = runtime
        .block_on(nostr_relay_builder::MockRelay::run())
        .unwrap();
    let relay_url = CString::new(runtime.block_on(relay.url()).to_string()).unwrap();
    let relays = [relay_url.as_ptr()];
    let broker = {
        let _enter = runtime.enter();
        QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        })
        .unwrap()
    };
    let candidate = CString::new(format!(
        "quic://127.0.0.1:{}",
        broker.local_addr().unwrap().port()
    ))
    .unwrap();
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let broker_task = runtime.spawn(broker.run_until(async {
        let _ = stopped.await;
    }));
    let home = tempfile::tempdir().unwrap();
    let home_c = CString::new(home.path().to_str().unwrap()).unwrap();
    unsafe {
        let mut client = ptr::null_mut();
        check(marmot_client_new_with_options(
            home_c.as_ptr(),
            relays.as_ptr(),
            1,
            MarmotRelayPolicy::AllowLoopback as u32,
            ptr::null(),
            &mut client,
        ));
        check(marmot_client_start(client));
        let mut account = ptr::null_mut();
        check(marmot_create_identity(
            client,
            relays.as_ptr(),
            1,
            relays.as_ptr(),
            1,
            &mut account,
        ));
        let mut group = ptr::null_mut();
        check(marmot_create_group(
            client,
            (*account).account_id_hex,
            c"publisher test".as_ptr(),
            ptr::null(),
            0,
            ptr::null(),
            &mut group,
        ));
        let mut options = MarmotPublisherOptions {
            candidate: candidate.as_ptr(),
            server_cert_der: ptr::null(),
            server_cert_der_len: 0,
            trust: MarmotPublisherTrust::PublicOnly as u32,
        };
        let mut publisher = ptr::null_mut();
        // Loopback broker access is independent from relay opt-in.
        assert_ne!(
            marmot_agent_publisher_new(
                client,
                (*account).account_id_hex,
                group,
                &options,
                &mut publisher
            ),
            MarmotStatus::Ok
        );
        assert!(publisher.is_null());
        options.trust = MarmotPublisherTrust::AllowLoopback as u32;
        check(marmot_agent_publisher_new(
            client,
            (*account).account_id_hex,
            group,
            &options,
            &mut publisher,
        ));
        let mut info = ptr::null_mut();
        check(marmot_agent_publisher_info(publisher, &mut info));
        assert_eq!(CStr::from_ptr((*info).stream_id_hex).to_bytes().len(), 64);
        assert_eq!(
            CStr::from_ptr((*info).start_message_id_hex)
                .to_bytes()
                .len(),
            64
        );
        let mut watch = ptr::null_mut();
        check(marmot_watch_agent_text_stream(
            client,
            (*account).account_id_hex,
            group,
            (*info).stream_id_hex,
            ptr::null(),
            0,
            1,
            &mut watch,
        ));
        marmot_publisher_info_free(info);
        assert_eq!(
            marmot_agent_publisher_append(publisher, 0, c"discard".as_ptr(), ptr::null_mut()),
            MarmotStatus::NullPointer
        );
        assert_eq!(
            marmot_agent_publisher_finish(publisher, ptr::null_mut()),
            MarmotStatus::NullPointer
        );
        let mut ack = ptr::null_mut();
        assert_eq!(
            marmot_agent_publisher_append(publisher, u32::MAX, c"ignored".as_ptr(), &mut ack),
            MarmotStatus::InvalidArgument
        );
        assert!(ack.is_null());
        check(marmot_agent_publisher_append(
            publisher,
            MarmotPublisherRecord::Text as u32,
            c"hello".as_ptr(),
            &mut ack,
        ));
        assert_eq!((*ack).chunk_count, 1);
        marmot_publisher_ack_free(ack);
        check(marmot_agent_publisher_append(
            publisher,
            MarmotPublisherRecord::Status as u32,
            c"working".as_ptr(),
            &mut ack,
        ));
        assert_eq!((*ack).chunk_count, 2);
        marmot_publisher_ack_free(ack);
        check(marmot_agent_publisher_append(
            publisher,
            MarmotPublisherRecord::Text as u32,
            c" world".as_ptr(),
            &mut ack,
        ));
        marmot_publisher_ack_free(ack);
        for expected in ["hello", "working", " world"] {
            let mut update = ptr::null_mut();
            check(marmot_agent_stream_subscription_next(
                watch,
                10000,
                &mut update,
            ));
            let text = match &*update {
                MarmotAgentStreamUpdate::Chunk { text, .. } => *text,
                MarmotAgentStreamUpdate::Status { status, .. } => *status,
                _ => panic!("unexpected live record"),
            };
            assert_eq!(CStr::from_ptr(text).to_str().unwrap(), expected);
            marmot_agent_stream_update_free(update);
        }
        let mut summary = ptr::null_mut();
        check(marmot_agent_publisher_finish(publisher, &mut summary));
        assert_eq!((*summary).message_ids_len, 1);
        let final_id = CStr::from_ptr(*(*summary).message_ids).to_owned();
        marmot_send_summary_free(summary);
        let mut update = ptr::null_mut();
        check(marmot_agent_stream_subscription_next(
            watch,
            10000,
            &mut update,
        ));
        match &*update {
            MarmotAgentStreamUpdate::Finished {
                text, chunk_count, ..
            } => {
                assert_eq!(CStr::from_ptr(*text).to_str().unwrap(), "hello world");
                assert_eq!(*chunk_count, 3);
            }
            _ => panic!("expected verified stream completion"),
        }
        marmot_agent_stream_update_free(update);
        marmot_agent_stream_subscription_free(watch);
        let mut messages = ptr::null_mut();
        check(marmot_messages(
            client,
            (*account).account_id_hex,
            group,
            0,
            0,
            ptr::null(),
            0,
            &mut messages,
        ));
        let records = std::slice::from_raw_parts((*messages).items, (*messages).len);
        let final_message = records
            .iter()
            .find(|record| CStr::from_ptr(record.message_id_hex) == final_id.as_c_str())
            .unwrap();
        assert_eq!(
            CStr::from_ptr(final_message.plaintext).to_str().unwrap(),
            "hello world"
        );
        marmot_app_message_record_list_free(messages);
        check(marmot_agent_publisher_finish(publisher, &mut summary));
        assert_eq!(CStr::from_ptr(*(*summary).message_ids), final_id.as_c_str());
        marmot_send_summary_free(summary);
        assert_ne!(
            marmot_agent_publisher_append(publisher, 0, c"late".as_ptr(), &mut ack),
            MarmotStatus::Ok
        );
        marmot_agent_publisher_free(publisher);
        check(marmot_agent_publisher_new(
            client,
            (*account).account_id_hex,
            group,
            &options,
            &mut publisher,
        ));
        check(marmot_agent_publisher_cancel(publisher));
        assert_ne!(
            marmot_agent_publisher_finish(publisher, &mut summary),
            MarmotStatus::Ok
        );
        assert!(summary.is_null());
        marmot_agent_publisher_free(publisher);
        // A missing preview broker must not prevent the durable final.
        shutdown.send(()).unwrap();
        runtime.block_on(broker_task).unwrap().unwrap();
        check(marmot_agent_publisher_new(
            client,
            (*account).account_id_hex,
            group,
            &options,
            &mut publisher,
        ));
        check(marmot_agent_publisher_append(
            publisher,
            0,
            c"offline preview".as_ptr(),
            &mut ack,
        ));
        marmot_publisher_ack_free(ack);
        check(marmot_agent_publisher_finish(publisher, &mut summary));
        assert_eq!((*summary).message_ids_len, 1);
        marmot_send_summary_free(summary);
        marmot_agent_publisher_free(publisher);
        marmot_string_free(group);
        marmot_account_summary_free(account);
        check(marmot_client_shutdown(client));
        marmot_client_free(client);
    }
}
