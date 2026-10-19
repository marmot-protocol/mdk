//! Disk-space outcomes (mdk#2239): a body the device cannot publish parks as
//! `StorageBlocked` with its checkpoint instead of refetching on a timer, and
//! readmits once free space covers its recorded target or the user retries.
//!
//! Free space is pinned per account directory through the test seam in
//! `attachment_resume`, which models a volume: the pinned figure is free space
//! in the worker's frame, and an attempt's own staging files and checkpoint
//! growth consume it as the attempt writes them. The window tests place it
//! exactly where the first implementation looped: above the admission reserve
//! and the bare `4 x body` publication check, but below what the attempt's own
//! staging and checkpoints add on top. The row must park once and stay parked
//! across scheduler ticks until space frees. The scheduler's clock can be
//! pinned, so readmission backoffs are crossed without sleeping.
use super::*;
use crate::media::attachment_resume::test_free_space;
use crate::runtime::account_worker::attachments::test_clock;
use std::sync::atomic::{AtomicUsize, Ordering};
use storage_sqlite::{AttachmentTransferState, STORAGE_READMIT_MARGIN_BYTES};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MIB: u64 = 1024 * 1024;
const PLENTY: u64 = 1 << 40;

struct Fixture {
    _dir: tempfile::TempDir,
    client: AppClient,
    storage: SqliteAccountStorage,
    policy: storage_sqlite::AttachmentDownloadPolicy,
    shared: RuntimeSharedServices,
    http: MediaHttpContext,
    completions: mpsc::UnboundedReceiver<MediaHttpDone>,
    admission: Admission,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        test_free_space::clear(self._dir.path());
        test_clock::clear(self._dir.path());
    }
}

/// An account whose single job fetches `reference` from the loopback fixture,
/// with a durable policy the test can tighten and relax and pinned free space.
async fn fixture(
    reference: &crate::MediaAttachmentReference,
    transfer_limit: u64,
    explicit: bool,
) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    test_free_space::set(dir.path(), PLENTY);
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        MarmotAppConfig {
            attachment_acquisition: Some(crate::AttachmentAcquisitionPolicy::default()),
            allow_loopback_blob_endpoints: true,
            ..MarmotAppConfig::white_noise()
        },
    )
    .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let storage = app.account_storage("alice").unwrap();
    seed(&storage, reference, false);
    client.state.groups.push(projection(reference));
    storage
        .app_storage()
        .remember_encrypted_media_epoch_secret(
            GROUP,
            crate::GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
            3,
            &[7; 32],
        )
        .unwrap();
    let now = crate::unix_now_seconds();
    admit_demands(&storage.app_storage(), now, true).unwrap();
    let asset = storage
        .app_storage()
        .due_attachment_acquisitions(now, 1)
        .unwrap()
        .remove(0);
    if explicit {
        assert!(
            storage
                .app_storage()
                .explicitly_retry_attachment(&asset, now)
                .unwrap()
        );
    }
    let mut policy = crate::runtime::attachment_controls::default_policy(&client.app.config);
    policy.automatic = !explicit;
    policy.transfer_limit = transfer_limit;
    policy.disk_reserve = 0;
    storage
        .app_storage()
        .set_attachment_download_policy(&policy, now)
        .unwrap();
    let (http, completions) = context();
    Fixture {
        _dir: dir,
        client,
        storage,
        policy,
        shared: RuntimeSharedServices::default(),
        http,
        completions,
        admission: Admission::default(),
    }
}

async fn explicit_fixture(
    reference: &crate::MediaAttachmentReference,
    transfer_limit: u64,
) -> Fixture {
    fixture(reference, transfer_limit, true).await
}

impl Fixture {
    /// One scheduler turn plus the global-permit wait it may queue.
    async fn tick(&mut self) {
        schedule(&self.client, &self.shared, &self.http, &mut self.admission).unwrap();
        self.admission.ready().await;
        schedule(&self.client, &self.shared, &self.http, &mut self.admission).unwrap();
    }
    fn media(&self) -> crate::AccountMediaStore {
        self.client
            .app
            .account_media_store(&self.client.state.label, &self.storage)
            .unwrap()
    }
    async fn completion(&mut self) -> MediaHttpDone {
        tokio::time::timeout(Duration::from_secs(180), self.completions.recv())
            .await
            .expect("attachment completion")
            .unwrap()
    }
    fn status(&self) -> storage_sqlite::AttachmentTransferStatus {
        self.storage
            .app_storage()
            .attachment_transfer_status(
                GROUP,
                &"11".repeat(32),
                &"22".repeat(32),
                0,
                crate::unix_now_seconds(),
                self.policy.automatic,
            )
            .unwrap()
            .unwrap()
    }
    fn state(&self) -> AttachmentTransferState {
        self.status().state
    }
    /// Pin free space in the worker's frame; the attempt's own staging and
    /// checkpoint growth are charged against it as they happen.
    fn set_free(&self, free: u64) {
        test_free_space::set_modeled(
            self._dir.path(),
            free,
            &crate::media::file_transfer::media_staging_directory(
                &self.client.app,
                &self.client.state.label,
            ),
            &self.storage,
        );
    }
    /// The parked row's readmission due time, in the scheduler's clock.
    fn due(&self) -> Option<u64> {
        self.storage
            .app_storage()
            .attachment_acquisition_status(&self.status().reference.unwrap())
            .unwrap()
            .unwrap()
            .due
    }
    /// Take the parked completion, then prove the row stays parked and silent
    /// across scheduler ticks. Returns the recorded headroom.
    async fn park_and_hold(&mut self, requests: &AtomicUsize) -> u64 {
        let done = self.completion().await;
        let headroom = parked_headroom(&done);
        complete_media_http(&mut self.client, done, &self.shared, &self.http).await;
        assert_eq!(self.state(), AttachmentTransferState::StorageBlocked);
        let parked_requests = requests.load(Ordering::SeqCst);
        for _ in 0..3 {
            self.tick().await;
            assert!(self.completions.try_recv().is_err());
        }
        assert_eq!(
            requests.load(Ordering::SeqCst),
            parked_requests,
            "a parked job must not refetch in the background"
        );
        assert_eq!(self.state(), AttachmentTransferState::StorageBlocked);
        assert_eq!(self.shared.attachment_transfer.available_permits(), 1);
        headroom
    }
    /// Drive a file-sink completion through retention to `Ready`.
    async fn publish_file(&mut self, plain: &[u8]) {
        let done = self.completion().await;
        assert!(
            matches!(
                &done.completion,
                MediaHttpCompletion::Attachment {
                    result: Ok(crate::client::AcquiredMediaBody::File(_)),
                    ..
                }
            ),
            "explicit bodies above the transfer limit stream through the file sink"
        );
        complete_media_http(&mut self.client, done, &self.shared, &self.http).await;
        let retained = self.completion().await;
        assert!(matches!(
            retained.completion,
            MediaHttpCompletion::AttachmentRetained { result: Ok(()), .. }
        ));
        complete_media_http(&mut self.client, retained, &self.shared, &self.http).await;
        self.assert_ready(plain);
    }
    /// Drive an in-memory completion to `Ready` and return its buffer capacity.
    async fn publish_memory(&mut self, plain: &[u8]) -> usize {
        let done = self.completion().await;
        let MediaHttpCompletion::Attachment { result, .. } = &done.completion else {
            panic!("attachment completion");
        };
        let Ok(crate::client::AcquiredMediaBody::Memory(body)) = result else {
            panic!(
                "bodies within the transfer limit publish through the in-memory sink: {:?}",
                result.as_ref().err()
            );
        };
        assert_eq!(body.plaintext.len(), plain.len());
        let capacity = body.plaintext.capacity();
        complete_and_settle(
            &mut self.client,
            done,
            &self.shared,
            &self.http,
            &mut self.completions,
        )
        .await;
        self.assert_ready(plain);
        capacity
    }
    fn assert_ready(&self, plain: &[u8]) {
        assert_eq!(self.state(), AttachmentTransferState::Ready);
        let reference = self.status().reference.unwrap();
        // Retained as a media file: counted in its row, not the database's
        // retained-byte usage.
        assert_eq!(
            self.storage
                .app_storage()
                .attachment_acquisition_status(&reference)
                .unwrap()
                .unwrap()
                .byte_count,
            plain.len() as u64
        );
        assert_eq!(
            &*read_retained(
                &self.storage,
                &self.client.app,
                &self.client.state.label,
                &reference,
                crate::unix_now_seconds(),
                0,
                64
            )
            .unwrap()
            .unwrap(),
            &plain[..64]
        );
    }
}

fn parked_headroom(done: &MediaHttpDone) -> u64 {
    let MediaHttpCompletion::Attachment { result, .. } = &done.completion else {
        panic!("attachment completion");
    };
    match result {
        Err(AttachmentDownloadFailure::StorageBlocked { headroom, .. }) => *headroom,
        Err(other) => panic!("a body the device cannot publish parks: {other:?}"),
        Ok(_) => panic!("a body the device cannot publish must not publish"),
    }
}

async fn request_headers(socket: &mut tokio::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    loop {
        bytes.push(socket.read_u8().await.unwrap());
        assert!(bytes.len() < 16384);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(bytes).unwrap().to_ascii_lowercase()
}

fn loopback_reference(
    listener: &tokio::net::TcpListener,
    plain: &[u8],
) -> (crate::MediaAttachmentReference, Vec<u8>) {
    let (mut reference, cipher) = crate::media::tests::attachment_worker_fixture(plain);
    reference.locators = vec![crate::MediaLocator {
        kind: "blossom-v1".into(),
        value: format!(
            "http://{}/{}",
            listener.local_addr().unwrap(),
            reference.ciphertext_sha256
        ),
    }];
    (reference, cipher)
}

#[derive(Clone, Copy)]
struct Framing {
    etag: bool,
    chunked: bool,
}

/// Serve `cipher` for every request until `stop`, counting requests. Writes are
/// tolerant: a parked client drops the response early. A `Range` request gets
/// the matching suffix as a validated 206.
fn serve(
    listener: tokio::net::TcpListener,
    cipher: Vec<u8>,
    framing: Framing,
    requests: Arc<AtomicUsize>,
    mut stop: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = tokio::select! {
                biased;
                _ = &mut stop => return,
                accepted = listener.accept() => accepted.unwrap(),
            };
            requests.fetch_add(1, Ordering::SeqCst);
            let request = request_headers(&mut socket).await;
            let etag = if framing.etag { "ETag: \"v1\"\r\n" } else { "" };
            let range = request
                .lines()
                .find_map(|line| line.strip_prefix("range: bytes="))
                .and_then(|value| value.trim_end_matches('-').parse::<usize>().ok());
            if let Some(start) = range {
                assert!(framing.etag && !framing.chunked, "{request}");
                let _ = socket
                    .write_all(
                        format!(
                            "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{}/{}\r\n{etag}Connection: close\r\n\r\n",
                            cipher.len() - start,
                            cipher.len() - 1,
                            cipher.len()
                        )
                        .as_bytes(),
                    )
                    .await;
                let _ = socket.write_all(&cipher[start..]).await;
                continue;
            }
            let length = if framing.chunked {
                "Transfer-Encoding: chunked\r\n".to_owned()
            } else {
                format!("Content-Length: {}\r\n", cipher.len())
            };
            let _ = socket
                .write_all(
                    format!("HTTP/1.1 200 OK\r\n{length}{etag}Connection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await;
            if framing.chunked {
                for chunk in cipher.chunks(64 * 1024) {
                    if socket
                        .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                        .await
                        .is_err()
                        || socket.write_all(chunk).await.is_err()
                        || socket.write_all(b"\r\n").await.is_err()
                    {
                        break;
                    }
                }
                let _ = socket.write_all(b"0\r\n\r\n").await;
            } else {
                let _ = socket.write_all(&cipher).await;
            }
        }
    })
}

/// File sink, no validator, free space that admits the job (two transfer
/// limits) but not the body (its staging plus its store file): the first
/// implementation downloaded until its own staging tripped the reserve,
/// parked with the bytes received, and was readmitted the same tick. Now the
/// declared size parks the job before any body byte, the target is the
/// staging and store file a retry needs, and the row stays parked until space
/// frees.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_sink_without_validator_parks_once_inside_the_loop_window() {
    let plain = vec![0x5a; 32 * MIB as usize];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (reference, cipher) = loopback_reference(&listener, &plain);
    let total = cipher.len() as u64;
    let requests = Arc::new(AtomicUsize::new(0));
    let (stop, stopped) = oneshot::channel();
    let server = serve(
        listener,
        cipher,
        Framing {
            etag: false,
            chunked: false,
        },
        Arc::clone(&requests),
        stopped,
    );
    let mut fixture = explicit_fixture(&reference, MIB).await;
    // 1.5 bodies: enough for the store file, not for the staging beside it.
    fixture.set_free(total * 3 / 2);
    fixture.tick().await;
    let headroom = fixture.park_and_hold(&requests).await;
    assert_eq!(
        headroom,
        2 * total,
        "the target is the staged body plus its store file"
    );
    // The in-memory sink spends one header-only request before handing the
    // transfer to the file sink, which refuses on the declared length.
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    fixture.set_free(2 * total + STORAGE_READMIT_MARGIN_BYTES);
    fixture.tick().await;
    fixture.publish_file(&plain).await;
    assert_eq!(
        requests.load(Ordering::SeqCst),
        4,
        "the readmitted attempt probes once more, then publishes through the file sink"
    );
    fixture.tick().await;
    assert!(fixture.completions.try_recv().is_err());
    stop.send(()).unwrap();
    server.await.unwrap();
}

/// In-memory sink with a validator under the 2x rule (mdk#2314): twice the
/// body free covers its wire checkpoint and its store file. Checkpoints charge
/// the volume as they are written, and the checks count them once, so the job
/// downloads and publishes in one request without parking.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn memory_sink_with_validator_publishes_with_twice_the_body_free() {
    let plain = vec![0x6b; (3 * MIB + 5) as usize];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (reference, cipher) = loopback_reference(&listener, &plain);
    let total = cipher.len() as u64;
    let requests = Arc::new(AtomicUsize::new(0));
    let (stop, stopped) = oneshot::channel();
    let server = serve(
        listener,
        cipher,
        Framing {
            etag: true,
            chunked: false,
        },
        Arc::clone(&requests),
        stopped,
    );
    let mut fixture = explicit_fixture(&reference, total).await;
    fixture.set_free(2 * total);
    fixture.tick().await;
    fixture.publish_memory(&plain).await;
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    stop.send(()).unwrap();
    server.await.unwrap();
}

/// An interrupted in-memory download keeps its checkpoint on disk, so its
/// retry is admitted with twice the body less what is saved: free space
/// already excludes those bytes. Charging two whole bodies again would defer
/// the retry every 15 seconds until more space freed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_download_retries_with_its_checkpoint_credited() {
    let plain = vec![0x2d; (3 * MIB + 5) as usize];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (reference, cipher) = loopback_reference(&listener, &plain);
    let total = cipher.len() as u64;
    let requests = Arc::new(AtomicUsize::new(0));
    let interrupted = (2 * MIB + 100) as usize;
    let server = {
        let requests = Arc::clone(&requests);
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                requests.fetch_add(1, Ordering::SeqCst);
                let request = request_headers(&mut socket).await;
                // Only the declared locator serves the body; the extension
                // fallback must not replace its checkpoint.
                if request
                    .lines()
                    .next()
                    .is_some_and(|line| line.contains(".bin "))
                {
                    let _ = socket
                        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .await;
                    continue;
                }
                let range = request
                    .lines()
                    .find_map(|line| line.strip_prefix("range: bytes="))
                    .and_then(|value| value.trim_end_matches('-').parse::<usize>().ok());
                if let Some(start) = range {
                    let _ = socket
                        .write_all(
                            format!(
                                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{}/{}\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                                cipher.len() - start,
                                cipher.len() - 1,
                                cipher.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                    let _ = socket.write_all(&cipher[start..]).await;
                    continue;
                }
                let _ = socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                            cipher.len()
                        )
                        .as_bytes(),
                    )
                    .await;
                // The connection drops partway through the body.
                let _ = socket.write_all(&cipher[..interrupted]).await;
            }
        })
    };
    let mut fixture = explicit_fixture(&reference, total).await;
    fixture.set_free(PLENTY);
    fixture.tick().await;
    let done = fixture.completion().await;
    assert!(matches!(
        &done.completion,
        MediaHttpCompletion::Attachment {
            result: Err(AttachmentDownloadFailure::Retry(_)),
            ..
        }
    ));
    complete_media_http(&mut fixture.client, done, &fixture.shared, &fixture.http).await;
    let saved = fixture
        .storage
        .app_storage()
        .attachment_partial_bytes_for_test()
        .unwrap();
    assert_eq!(saved, interrupted as u64, "the interrupted prefix is kept");
    assert!(
        fixture
            .storage
            .app_storage()
            .retry_attachment_acquisition(
                &fixture.status().reference.unwrap(),
                crate::unix_now_seconds()
            )
            .unwrap()
    );
    // Exactly the rest of the checkpoint plus the store file.
    fixture.set_free(2 * total - saved);
    fixture.tick().await;
    fixture.publish_memory(&plain).await;
    assert_eq!(
        requests.load(Ordering::SeqCst),
        3,
        "the interrupted request, its failed fallback, and one Range request"
    );
    server.abort();
}

/// File sink, chunked body with neither length nor validator, on a disk that
/// frees exactly what each park asks for. Every attempt starts the body over
/// and parks a little later, recording the need it proved, which never exceeds
/// what the body really needs, so the job publishes as soon as that much is
/// free. Refetches are bounded in time: each readmission waits out the park
/// streak, which the test crosses by pinning the scheduler's clock at each due
/// time instead of sleeping.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_length_parks_record_the_proven_need_and_back_off() {
    let plain = vec![0x7c; 16 * MIB as usize];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (reference, cipher) = loopback_reference(&listener, &plain);
    let total = cipher.len() as u64;
    let requests = Arc::new(AtomicUsize::new(0));
    let (stop, stopped) = oneshot::channel();
    let server = serve(
        listener,
        cipher,
        Framing {
            etag: false,
            chunked: true,
        },
        Arc::clone(&requests),
        stopped,
    );
    let mut fixture = explicit_fixture(&reference, MIB).await;
    // Admission (two transfer limits) passes; the staged body trips the
    // check a few MiB in.
    fixture.set_free(4 * MIB);
    fixture.tick().await;
    let mut target = fixture.park_and_hold(&requests).await;
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    let mut parks = 1;
    // Pin the scheduler's clock, so each readmission delay compares exactly
    // and the early tick below runs strictly before the due time.
    let mut clock = crate::unix_now_seconds();
    test_clock::set_now(fixture._dir.path(), clock);
    let mut delays = vec![];
    loop {
        // The body needs two of itself (its staging and its store file); no
        // recorded target may ask for more.
        assert!(
            target <= 2 * total,
            "target {target} exceeds the body's need"
        );
        // One byte short of the recorded target keeps the row parked, which
        // pins the target storage recorded: the attempt's own projection.
        fixture.set_free(target + STORAGE_READMIT_MARGIN_BYTES - 1);
        let before = requests.load(Ordering::SeqCst);
        fixture.tick().await;
        assert!(fixture.completions.try_recv().is_err());
        assert_eq!(fixture.state(), AttachmentTransferState::StorageBlocked);
        assert_eq!(requests.load(Ordering::SeqCst), before);
        // Free exactly what the last park asked for, as a slowly emptying disk would.
        fixture.set_free(target + STORAGE_READMIT_MARGIN_BYTES);
        schedule(
            &fixture.client,
            &fixture.shared,
            &fixture.http,
            &mut fixture.admission,
        )
        .unwrap();
        assert_eq!(fixture.state(), AttachmentTransferState::Queued);
        let due = fixture.due().unwrap();
        delays.push(due - clock);
        if due > clock {
            // Not a moment earlier: a tick one second before the due time
            // leaves the row queued and fetches nothing.
            test_clock::set_now(fixture._dir.path(), due - 1);
            fixture.tick().await;
            assert!(fixture.completions.try_recv().is_err());
            assert_eq!(fixture.state(), AttachmentTransferState::Queued);
            assert_eq!(requests.load(Ordering::SeqCst), before);
        }
        clock = due;
        test_clock::set_now(fixture._dir.path(), clock);
        fixture.tick().await;
        let done = fixture.completion().await;
        match &done.completion {
            MediaHttpCompletion::Attachment {
                result: Err(AttachmentDownloadFailure::StorageBlocked { headroom }),
                ..
            } => {
                assert!(*headroom > target, "{headroom} after {target}");
                target = *headroom;
                parks += 1;
                complete_media_http(&mut fixture.client, done, &fixture.shared, &fixture.http)
                    .await;
                assert_eq!(fixture.state(), AttachmentTransferState::StorageBlocked);
            }
            MediaHttpCompletion::Attachment {
                result: Ok(crate::client::AcquiredMediaBody::File(_)),
                ..
            } => {
                complete_media_http(&mut fixture.client, done, &fixture.shared, &fixture.http)
                    .await;
                let retained = fixture.completion().await;
                complete_media_http(
                    &mut fixture.client,
                    retained,
                    &fixture.shared,
                    &fixture.http,
                )
                .await;
                fixture.assert_ready(&plain);
                break;
            }
            _ => panic!("unexpected completion"),
        }
        assert!(parks <= 16, "each restart must get further than the last");
    }
    // Readmissions are spaced by the park streak: the first at once, then
    // 15 s doubling, so a trickling disk cannot drive refetches faster.
    let streak: Vec<u64> = (1..=parks as u32)
        .map(|count| {
            if count <= 1 {
                0
            } else {
                (15u64 << (count - 2).min(8)).min(3600)
            }
        })
        .collect();
    assert_eq!(delays, streak);
    assert!(
        parks >= 3,
        "the trickle must exercise the streak: {parks} parks"
    );
    assert_eq!(
        requests.load(Ordering::SeqCst),
        2 * (parks + 1),
        "each parking attempt and the publishing one: an in-memory probe, then the file sink"
    );
    stop.send(()).unwrap();
    server.await.unwrap();
}

/// A validated file-sink job parked mid-transfer by free space dropping while
/// its body streams: what the end-to-end mid-transfer tests start from.
struct MidTransferPark {
    fixture: Fixture,
    plain: Vec<u8>,
    total: u64,
    requests: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
    headroom: u64,
    saved: u64,
}

/// Stream a 16 MiB validated body through the file sink, drop free space once
/// six checkpoints are saved, and complete the park the next mid-transfer
/// check records. The server pauses only the first full response.
async fn park_mid_transfer() -> MidTransferPark {
    let plain = vec![0x5a; 16 * MIB as usize];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (reference, cipher) = loopback_reference(&listener, &plain);
    let total = cipher.len() as u64;
    let requests = Arc::new(AtomicUsize::new(0));
    let (proceed, gate) = watch::channel(false);
    let first = 6 * MIB as usize;
    let server = {
        let requests = Arc::clone(&requests);
        let cipher = cipher.clone();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                requests.fetch_add(1, Ordering::SeqCst);
                let cipher = cipher.clone();
                let mut gate = gate.clone();
                tokio::spawn(async move {
                    let request = request_headers(&mut socket).await;
                    let range = request
                        .lines()
                        .find_map(|line| line.strip_prefix("range: bytes="))
                        .and_then(|value| value.trim_end_matches('-').parse::<usize>().ok());
                    if let Some(start) = range {
                        let _ = socket
                            .write_all(
                                format!(
                                    "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{}/{}\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                                    cipher.len() - start,
                                    cipher.len() - 1,
                                    cipher.len()
                                )
                                .as_bytes(),
                            )
                            .await;
                        let _ = socket.write_all(&cipher[start..]).await;
                        return;
                    }
                    let _ = socket
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                                cipher.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                    if socket.write_all(&cipher[..first]).await.is_err() {
                        return;
                    }
                    // A little past the last whole checkpoint, then hold the
                    // rest until released.
                    if socket
                        .write_all(&cipher[first..first + 4096])
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let _ = gate.wait_for(|released| *released).await;
                    let _ = socket.write_all(&cipher[first + 4096..]).await;
                });
            }
        })
    };
    let mut fixture = explicit_fixture(&reference, MIB).await;
    fixture.tick().await;
    // Wait on the saved checkpoints, which track processed bytes exactly,
    // rather than on throttled progress reports.
    let started = tokio::time::Instant::now();
    while fixture
        .storage
        .app_storage()
        .attachment_partial_bytes_for_test()
        .unwrap()
        < first as u64
    {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "{:?}",
            fixture.status()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    // Something else fills the disk: enough left for checkpoint writes, not
    // for the rest of the body and its store file.
    fixture.set_free(16 * MIB);
    proceed.send(true).unwrap();
    let done = fixture.completion().await;
    let headroom = parked_headroom(&done);
    let saved = fixture
        .storage
        .app_storage()
        .attachment_partial_bytes_for_test()
        .unwrap();
    assert!(saved >= 6 * MIB && saved < total, "saved {saved}");
    complete_media_http(&mut fixture.client, done, &fixture.shared, &fixture.http).await;
    assert_eq!(fixture.state(), AttachmentTransferState::StorageBlocked);
    MidTransferPark {
        fixture,
        plain,
        total,
        requests,
        server,
        headroom,
        saved,
    }
}

/// File sink with a strong validator, end to end: free space drops while the
/// body is mid-transfer, so the mid-transfer check parks with `2T - S` in the
/// worker's frame (the rest of the checkpoint and the store file; the saved
/// prefix stays on disk and nothing is staged). Readmitted at exactly that
/// target plus the margin, the attempt restores the saved prefix, finishes
/// with one Range request and publishes without parking again. A target that
/// dropped the remaining checkpoint growth would re-park here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mid_transfer_park_readmits_at_its_target_and_resumes() {
    let MidTransferPark {
        mut fixture,
        plain,
        total,
        requests,
        server,
        headroom,
        saved,
    } = park_mid_transfer().await;
    assert_eq!(
        headroom,
        2 * total - saved,
        "the rest of the checkpoint and the store file; the saved prefix stays on disk"
    );
    let before = requests.load(Ordering::SeqCst);
    // Exactly the recorded target plus the margin, in the worker's frame.
    fixture.set_free(headroom + STORAGE_READMIT_MARGIN_BYTES);
    fixture.tick().await;
    fixture.publish_file(&plain).await;
    assert_eq!(
        requests.load(Ordering::SeqCst),
        before + 1,
        "the remembered file sink restores the prefix and one Range request finishes the body"
    );
    server.abort();
}

/// Space shrinks mid-transfer below what the next checkpoint write needs:
/// the write is refused and the job parks for what its next attempt still
/// writes (the rest of the body and its store file), instead of retrying on
/// a timer that worker admission would keep refusing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_checkpoint_write_parks_instead_of_retrying() {
    let plain = vec![0x34; (3 * MIB + 7) as usize];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (reference, cipher) = loopback_reference(&listener, &plain);
    let (go, proceed) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        request_headers(&mut socket).await;
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                    cipher.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let first = (MIB + 4096) as usize;
        socket.write_all(&cipher[..first]).await.unwrap();
        proceed.await.unwrap();
        let _ = socket.write_all(&cipher[first..]).await;
    });
    let mut fixture = explicit_fixture(&reference, 64 * MIB).await;
    fixture.tick().await;
    let started = tokio::time::Instant::now();
    while fixture
        .storage
        .app_storage()
        .attachment_partial_bytes_for_test()
        .unwrap()
        < MIB
    {
        assert!(started.elapsed() < Duration::from_secs(10));
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    // Less than one checkpoint unit left.
    fixture.set_free(MIB / 2);
    go.send(()).unwrap();
    let done = fixture.completion().await;
    assert_eq!(
        parked_headroom(&done),
        2 * plain.len() as u64 - MIB,
        "the rest of the body beyond the saved prefix, and its store file"
    );
    complete_media_http(&mut fixture.client, done, &fixture.shared, &fixture.http).await;
    assert_eq!(fixture.state(), AttachmentTransferState::StorageBlocked);
    assert_eq!(fixture.status().retry_at, None, "no retry timer runs");
    server.abort();
}

/// Space shrinks after the whole body has arrived: the in-memory sink
/// checkpoints the complete ciphertext, the job parks, and the readmitted
/// attempt verifies and publishes locally without a second request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pressure_after_the_body_arrives_parks_with_a_complete_checkpoint_and_readmits_offline() {
    let plain = vec![0x33; (2 * MIB + 71) as usize];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (reference, cipher) = loopback_reference(&listener, &plain);
    let (go, proceed) = oneshot::channel::<()>();
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        request_headers(&mut socket).await;
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                    cipher.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let first = MIB as usize;
        socket.write_all(&cipher[..first]).await.unwrap();
        // Let the progress interval elapse so the next chunk reports the
        // received count the test waits for before tightening the reserve.
        tokio::time::sleep(Duration::from_millis(400)).await;
        socket
            .write_all(&cipher[first..first + 4096])
            .await
            .unwrap();
        proceed.await.unwrap();
        socket.write_all(&cipher[first + 4096..]).await.unwrap();
        drop(socket);
        tokio::select! {
            biased;
            connection = listener.accept() => panic!("a checkpointed body was requested again: {connection:?}"),
            _ = stopped => {}
        }
    });
    let mut fixture = explicit_fixture(&reference, 64 * MIB).await;
    fixture.tick().await;
    let started = tokio::time::Instant::now();
    while fixture.status().received < MIB {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            fixture.status()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    // Enough for the tail checkpoint, not for the store file on top of the
    // body's remaining checkpoint.
    fixture.set_free(5 * MIB / 2);
    go.send(()).unwrap();
    let done = fixture.completion().await;
    assert_eq!(
        parked_headroom(&done),
        2 * plain.len() as u64 - 2 * MIB,
        "pressure after the body arrived parks with what is not yet on disk"
    );
    complete_media_http(&mut fixture.client, done, &fixture.shared, &fixture.http).await;
    assert_eq!(fixture.state(), AttachmentTransferState::StorageBlocked);
    fixture.tick().await;
    assert!(fixture.completions.try_recv().is_err());
    assert_eq!(fixture.state(), AttachmentTransferState::StorageBlocked);

    fixture.set_free(PLENTY);
    fixture.tick().await;
    let capacity = fixture.publish_memory(&plain).await;
    assert!(
        capacity <= plain.len() + 16,
        "the body buffer is reserved once at the ciphertext length, capacity {capacity}"
    );
    stop.send(()).unwrap();
    server.await.unwrap();
}

/// The disk running out of room while the media store writes an in-memory
/// body parks the job like a failed free-space check, instead of a retry timer
/// or an opted-in body with no retention. The recorded target never sits below
/// the free space seen at the refusal plus the body, so free space that merely
/// looked sufficient does not refetch onto the same full disk; once the volume
/// gains room the readmitted attempt publishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn memory_publication_onto_a_full_disk_parks_until_room_returns() {
    let plain = vec![0x44; (2 * MIB + 9) as usize];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (reference, cipher) = loopback_reference(&listener, &plain);
    let requests = Arc::new(AtomicUsize::new(0));
    let (stop, stopped) = oneshot::channel();
    let server = serve(
        listener,
        cipher,
        Framing {
            etag: false,
            chunked: false,
        },
        Arc::clone(&requests),
        stopped,
    );
    let mut fixture = explicit_fixture(&reference, 4 * MIB).await;
    let free = 64 * MIB;
    fixture.set_free(free);
    fixture.tick().await;
    let done = fixture.completion().await;
    assert!(matches!(
        &done.completion,
        MediaHttpCompletion::Attachment {
            result: Ok(crate::client::AcquiredMediaBody::Memory(_)),
            ..
        }
    ));
    // The volume reports room, but writing the body hits a full disk.
    fixture.media().simulate_full_disk_for_test(true);
    complete_and_settle(
        &mut fixture.client,
        done,
        &fixture.shared,
        &fixture.http,
        &mut fixture.completions,
    )
    .await;
    assert_eq!(fixture.state(), AttachmentTransferState::StorageBlocked);
    assert_eq!(
        fixture
            .storage
            .app_storage()
            .retained_attachment_byte_count()
            .unwrap(),
        0
    );
    assert_eq!(fixture.status().retry_at, None, "no retry timer runs");
    let target = free + plain.len() as u64;
    fixture.set_free(target + STORAGE_READMIT_MARGIN_BYTES - 1);
    fixture.tick().await;
    assert!(
        fixture.completions.try_recv().is_err(),
        "free space short of the refusal plus a body readmits nothing"
    );
    assert_eq!(fixture.state(), AttachmentTransferState::StorageBlocked);
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    fixture.media().simulate_full_disk_for_test(false);
    fixture.set_free(target + STORAGE_READMIT_MARGIN_BYTES);
    fixture.tick().await;
    fixture.publish_memory(&plain).await;
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    stop.send(()).unwrap();
    server.await.unwrap();
}

/// A full disk while publishing an in-memory body whose checkpoint is on disk
/// parks for what a retry still writes (the store file and the unsaved tail),
/// bounded below by the refusal's own free space plus a body, never four
/// bodies: with little room left the job readmits as soon as that space is
/// back, and resumes from its checkpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn memory_publication_onto_a_full_disk_with_a_checkpoint_parks_for_the_store_file() {
    let plain = vec![0x46; (3 * MIB + 5) as usize];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (reference, cipher) = loopback_reference(&listener, &plain);
    let total = cipher.len() as u64;
    let requests = Arc::new(AtomicUsize::new(0));
    let (stop, stopped) = oneshot::channel();
    let server = serve(
        listener,
        cipher,
        Framing {
            etag: true,
            chunked: false,
        },
        Arc::clone(&requests),
        stopped,
    );
    let mut fixture = explicit_fixture(&reference, total).await;
    let free = 2 * total + MIB;
    fixture.set_free(free);
    fixture.tick().await;
    let done = fixture.completion().await;
    assert!(matches!(
        &done.completion,
        MediaHttpCompletion::Attachment {
            result: Ok(crate::client::AcquiredMediaBody::Memory(_)),
            ..
        }
    ));
    let saved = fixture
        .storage
        .app_storage()
        .attachment_partial_bytes_for_test()
        .unwrap();
    assert_eq!(saved, 3 * MIB, "every whole checkpoint unit is on disk");
    fixture.media().simulate_full_disk_for_test(true);
    complete_and_settle(
        &mut fixture.client,
        done,
        &fixture.shared,
        &fixture.http,
        &mut fixture.completions,
    )
    .await;
    assert_eq!(fixture.state(), AttachmentTransferState::StorageBlocked);
    // The refusal measured the pinned space less the checkpoint.
    let target = free - saved + plain.len() as u64;
    assert!(
        target < 4 * plain.len() as u64,
        "the 4x-era target would wait for four bodies"
    );
    fixture.set_free(target + STORAGE_READMIT_MARGIN_BYTES - 1);
    fixture.tick().await;
    assert!(fixture.completions.try_recv().is_err());
    assert_eq!(fixture.state(), AttachmentTransferState::StorageBlocked);
    fixture.media().simulate_full_disk_for_test(false);
    fixture.set_free(target + STORAGE_READMIT_MARGIN_BYTES);
    fixture.tick().await;
    fixture.publish_memory(&plain).await;
    assert_eq!(
        requests.load(Ordering::SeqCst),
        2,
        "the readmitted attempt resumes its checkpoint with one Range request"
    );
    stop.send(()).unwrap();
    server.await.unwrap();
}

/// A full disk during file-sink publication parks as well. This body has no
/// validator, so its ciphertext was staged rather than checkpointed: the
/// staging this attempt held is counted into the target, the readmitted
/// attempt probes through the in-memory sink and stages the body again, and
/// the retried attempt publishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_publication_onto_a_full_disk_parks_until_room_returns() {
    let plain = vec![0x45; (3 * MIB + 5) as usize];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (reference, cipher) = loopback_reference(&listener, &plain);
    let requests = Arc::new(AtomicUsize::new(0));
    let (stop, stopped) = oneshot::channel();
    let server = serve(
        listener,
        cipher,
        Framing {
            etag: false,
            chunked: false,
        },
        Arc::clone(&requests),
        stopped,
    );
    let mut fixture = explicit_fixture(&reference, MIB).await;
    let free = 64 * MIB;
    fixture.set_free(free);
    fixture.tick().await;
    let done = fixture.completion().await;
    assert!(matches!(
        &done.completion,
        MediaHttpCompletion::Attachment {
            result: Ok(crate::client::AcquiredMediaBody::File(_)),
            ..
        }
    ));
    fixture.media().simulate_full_disk_for_test(true);
    complete_media_http(&mut fixture.client, done, &fixture.shared, &fixture.http).await;
    let retained = fixture.completion().await;
    complete_media_http(
        &mut fixture.client,
        retained,
        &fixture.shared,
        &fixture.http,
    )
    .await;
    assert_eq!(fixture.state(), AttachmentTransferState::StorageBlocked);
    assert_eq!(
        fixture
            .storage
            .app_storage()
            .retained_attachment_byte_count()
            .unwrap(),
        0
    );
    // The refusal saw the pinned space less the staged ciphertext it held
    // (no validator, so no wire checkpoint); the worker's frame gets that file
    // back, so the target is the refusal's own free space plus one more body.
    let target = free + plain.len() as u64;
    fixture.set_free(target + STORAGE_READMIT_MARGIN_BYTES - 1);
    fixture.tick().await;
    assert!(fixture.completions.try_recv().is_err());
    assert_eq!(fixture.state(), AttachmentTransferState::StorageBlocked);
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    fixture.media().simulate_full_disk_for_test(false);
    fixture.set_free(target + STORAGE_READMIT_MARGIN_BYTES);
    fixture.tick().await;
    fixture.publish_file(&plain).await;
    // Without a checkpoint the readmitted attempt probes the in-memory sink first.
    assert_eq!(requests.load(Ordering::SeqCst), 4);
    stop.send(()).unwrap();
    server.await.unwrap();
}

/// Parking and readmission both reach a transfer subscription. A parked row
/// sits outside the one-second refresh set, so a subscriber whose rows are all
/// parked otherwise polls only every 30 seconds: readmission must wake it
/// through the shared update signal, well inside that interval. The park
/// itself always follows an active state and is signalled as well.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transfer_subscribers_see_park_and_readmission_without_the_active_refresh() {
    let plain = vec![0x6c; 2 * MIB as usize];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (reference, cipher) = loopback_reference(&listener, &plain);
    let total = cipher.len() as u64;
    let requests = Arc::new(AtomicUsize::new(0));
    let (stop, stopped) = oneshot::channel();
    let server = serve(
        listener,
        cipher,
        Framing {
            etag: true,
            chunked: false,
        },
        Arc::clone(&requests),
        stopped,
    );
    // A transfer limit below the body sends it through the file sink. Its
    // admission (two limits) passes in 1.5 bodies of free space, and its
    // declared-size check (two bodies) parks it.
    let mut fixture = explicit_fixture(&reference, MIB).await;
    let runtime = fixture.client.app.runtime();
    fixture.shared = runtime.shared.clone();
    let stream = runtime
        .subscribe_attachment_transfers(
            "alice",
            &GroupId::new(hex::decode(GROUP).unwrap()),
            vec![crate::AttachmentLocalTarget {
                message_id_hex: "11".repeat(32),
                source_message_id_hex: "22".repeat(32),
                attachment_index: 0,
            }],
        )
        .await
        .unwrap();
    let state = |rows: Vec<Option<storage_sqlite::AttachmentTransferStatus>>| {
        rows.into_iter().next().flatten().unwrap().state
    };
    assert_eq!(
        state(stream.next().await.unwrap().unwrap()),
        AttachmentTransferState::Queued
    );
    fixture.set_free(total * 3 / 2);
    fixture.tick().await;
    let done = fixture.completion().await;
    parked_headroom(&done);
    complete_media_http(&mut fixture.client, done, &fixture.shared, &fixture.http).await;
    let started = tokio::time::Instant::now();
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(10), stream.next())
            .await
            .expect("the park reaches the subscriber")
            .unwrap()
            .unwrap();
        if state(frame) == AttachmentTransferState::StorageBlocked {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(10));
    }
    fixture.set_free(PLENTY);
    schedule(
        &fixture.client,
        &fixture.shared,
        &fixture.http,
        &mut fixture.admission,
    )
    .unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(10), stream.next())
        .await
        .expect("readmission must wake a subscriber of a parked row")
        .unwrap()
        .unwrap();
    assert_eq!(state(frame), AttachmentTransferState::Queued);
    stream.close();
    drop(fixture);
    runtime.shutdown_and_close().await.unwrap();
    stop.send(()).unwrap();
    server.await.unwrap();
}

/// The growth rule itself, chunk by chunk: an undeclared length doubles up to
/// half the limit, then takes exactly one step to the limit. Plain doubling
/// would end `.., 2 MiB, 4 MiB, 4.125 MiB` and hold 4 + 4.125 MiB at once.
#[test]
fn undeclared_length_growth_doubles_to_half_the_limit_then_steps_once() {
    let limit = (4 * MIB + 128 * 1024) as usize;
    let body = (4 * MIB + 32 * 1024) as usize;
    let chunk = 64 * 1024;
    let (mut capacity, mut len, mut trajectory) = (0, 0, vec![]);
    while len < body {
        let needed = (len + chunk).min(body);
        if capacity < needed {
            capacity = crate::media::attachment_resume::next_body_capacity(capacity, needed, limit);
            trajectory.push(capacity);
        }
        len = needed;
    }
    let half = limit.div_ceil(2);
    let kib = 1024;
    assert_eq!(
        trajectory,
        [
            64 * kib,
            128 * kib,
            256 * kib,
            512 * kib,
            1024 * kib,
            2048 * kib,
            half,
            limit
        ]
    );
    // Every growth copy holds the old and new buffers at most 1.5 limits.
    assert!(
        trajectory
            .windows(2)
            .all(|step| step[0] + step[1] <= limit + limit / 2 + 1)
    );
}

/// An automatic body with no declared length, measured: the buffer never
/// exceeds the transfer limit, and the copy while it grows past half the limit
/// holds at most 1.5 times it. Plain doubling would hold a 16 MiB buffer and its
/// 16.5 MiB successor at once here, about twice the limit.
#[test]
fn automatic_unknown_length_body_stays_within_its_growth_bound() {
    crate::tests::alloc_audit::measure(async {
        use crate::tests::alloc_audit;
        let plain = vec![0x55; (16 * MIB + 128 * 1024) as usize];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (reference, cipher) = loopback_reference(&listener, &plain);
        let requests = Arc::new(AtomicUsize::new(0));
        let (stop, stopped) = oneshot::channel();
        let server = serve(
            listener,
            cipher,
            Framing {
                etag: false,
                chunked: true,
            },
            Arc::clone(&requests),
            stopped,
        );
        let limit = 16 * MIB + 512 * 1024;
        let mut fixture = fixture(&reference, limit, false).await;
        let baseline = alloc_audit::live();
        alloc_audit::reset_peak();
        fixture.tick().await;
        let capacity = fixture.publish_memory(&plain).await;
        let peak = alloc_audit::peak().saturating_sub(baseline).max(0) as u64;
        eprintln!(
            "MDK_BENCH attachment_unknown_length_growth limit={limit} rust_peak_bytes={peak}"
        );
        assert!(
            capacity as u64 <= limit,
            "capacity {capacity} exceeds the transfer limit {limit}"
        );
        // 1.5 times the limit for the growth copy, plus 3 MiB for the HTTP
        // client's own buffers; plain doubling needs about 33 MiB here.
        assert!(
            peak <= limit * 3 / 2 + 3 * MIB,
            "growth held {peak} bytes against a {limit} byte limit"
        );
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        stop.send(()).unwrap();
        server.await.unwrap();
    });
}

/// mdk#2241: an automatic download at the transfer limit (32 MiB here) holds
/// one body plus a bounded allowance in the in-memory sink: the buffer is
/// reserved once, decrypted in place and published through bounded BLOB
/// writes. SQLite's own peak is measured by the storage-sqlite binary.
#[test]
fn automatic_receive_at_the_transfer_limit_holds_about_one_body() {
    crate::tests::alloc_audit::measure(receive_peak(32 * MIB - 16, 32 * MIB, false, Sink::Memory));
}

/// mdk#2241: an explicit download above the transfer limit streams through the
/// file sink and holds no body-sized buffer: staging, checkpoints, decryption
/// and publication all run in bounded chunks.
#[test]
fn explicit_file_sink_receive_holds_no_body_sized_buffer() {
    crate::tests::alloc_audit::measure(receive_peak(32 * MIB, 16 * MIB, true, Sink::File));
}

/// mdk#2241 acceptance size: an explicit 100 MiB body through the in-memory
/// sink (transfer limit raised to 128 MiB). Ignored by default for its run
/// time; the 32 MiB measurement covers the same path in the regular suite.
#[test]
#[ignore = "receives a 100 MiB body; run explicitly to measure"]
fn explicit_in_memory_receive_of_one_hundred_mib_holds_about_one_body() {
    crate::tests::alloc_audit::measure(receive_peak(100 * MIB, 128 * MIB, true, Sink::Memory));
}

/// mdk#2241 acceptance size: an automatic download at the default 64 MiB
/// transfer limit. Ignored by default for its run time.
#[test]
#[ignore = "receives a 64 MiB body; run explicitly to measure"]
fn automatic_receive_at_the_default_transfer_limit_holds_about_one_body() {
    crate::tests::alloc_audit::measure(receive_peak(64 * MIB - 16, 64 * MIB, false, Sink::Memory));
}

/// mdk#2241 acceptance size: with the default 64 MiB transfer limit, an
/// explicit 100 MiB body streams through the file sink. Ignored by default for
/// its run time and disk use.
#[test]
#[ignore = "receives a 100 MiB body; run explicitly to measure"]
fn explicit_file_sink_receive_of_one_hundred_mib_holds_no_body_sized_buffer() {
    crate::tests::alloc_audit::measure(receive_peak(100 * MIB, 64 * MIB, true, Sink::File));
}

/// mdk#2241: a body just under the 512 MiB explicit limit (the largest a
/// White Noise sender produces) takes the same file sink as the 100 MiB
/// measurement and stays within the same bound. Ignored by default for its
/// size, about 2.5 GiB of temporary disk and two fixture buffers of the body;
/// run with `--ignored` to measure.
#[test]
#[ignore = "receives a 512 MiB ciphertext; run explicitly to measure"]
fn explicit_file_sink_receive_just_under_512_mib_holds_no_body_sized_buffer() {
    crate::tests::alloc_audit::measure(receive_peak(512 * MIB - 16, 64 * MIB, true, Sink::File));
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sink {
    Memory,
    File,
}

async fn receive_peak(plain_len: u64, transfer_limit: u64, explicit: bool, sink: Sink) {
    use crate::tests::alloc_audit;
    let plain = vec![0x5a; plain_len as usize];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (reference, cipher) = loopback_reference(&listener, &plain);
    let total = cipher.len() as u64;
    let requests = Arc::new(AtomicUsize::new(0));
    let (stop, stopped) = oneshot::channel();
    let server = serve(
        listener,
        cipher,
        Framing {
            etag: true,
            chunked: false,
        },
        Arc::clone(&requests),
        stopped,
    );
    let mut fixture = fixture(&reference, transfer_limit, explicit).await;
    let baseline = alloc_audit::live();
    alloc_audit::reset_peak();
    fixture.tick().await;
    let capacity = match sink {
        Sink::Memory => Some(fixture.publish_memory(&plain).await),
        Sink::File => {
            fixture.publish_file(&plain).await;
            None
        }
    };
    let peak = alloc_audit::peak().saturating_sub(baseline).max(0) as u64;
    eprintln!(
        "MDK_BENCH attachment_receive explicit={explicit} file_sink={} ciphertext_bytes={total} rust_peak_bytes={peak}",
        sink == Sink::File
    );
    match sink {
        Sink::Memory => {
            // One ciphertext buffer, decrypted in place, plus bounded
            // checkpoint copies; the body itself must be visible.
            assert!(peak >= total, "the audit must see the body buffer: {peak}");
            assert!(
                peak <= total + 16 * MIB,
                "receive held {peak} bytes for a {total} byte body"
            );
            assert_eq!(capacity, Some(total as usize), "one exact reservation");
            assert_eq!(requests.load(Ordering::SeqCst), 1);
        }
        Sink::File => {
            assert!(
                peak <= 16 * MIB,
                "the file sink held {peak} bytes for a {total} byte body"
            );
            // The in-memory sink's header probe, then the file sink.
            assert_eq!(requests.load(Ordering::SeqCst), 2);
        }
    }
    stop.send(()).unwrap();
    server.await.unwrap();
}
