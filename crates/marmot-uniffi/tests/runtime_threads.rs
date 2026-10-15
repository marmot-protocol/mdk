//! Which OS threads run MDK work when a host drives `Marmot` through UniFFI.
//!
//! UniFFI hosts (Swift, Kotlin) poll exported futures from their own threads,
//! with no Tokio runtime entered. This test reproduces that: every async export
//! is called through the `__ffi_` wrapper the generated scaffolding calls,
//! from a plain `host-caller` thread through `futures::executor`. Two `Marmot`
//! roots exchange a group and a burst of messages over a loopback relay, so
//! account workers, the relay plane and subscription forwarders all run.
//!
//! The test records the threads that emitted tracing events per subsystem and
//! the CPU time each named thread used, and asserts that MDK work ran on
//! MarmotKit's runtime threads rather than `async_compat`'s single fallback
//! thread. Run it with `--nocapture` to print the distribution. It lives in
//! its own test binary so no other test's threads or tracing events mix in.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use marmot_uniffi::conversions::MarmotEventFfi;
use marmot_uniffi::{Marmot, MarmotKitError, MarmotOptions, RelayPolicyFfi, SecretStore};
use nostr_relay_builder::MockRelay;
use tracing_subscriber::layer::SubscriberExt;

const MESSAGES: usize = 40;
const SCENARIO_DEADLINE: Duration = Duration::from_secs(120);
const MARMOTKIT_THREAD: &str = "marmotkit-rt";
/// Prefix of `async-compat/tokio-1`; Linux truncates thread names to 15 bytes.
const ASYNC_COMPAT_THREAD: &str = "async-compat";

#[derive(Default)]
struct MemorySecretStore {
    secrets: Mutex<BTreeMap<String, String>>,
}

impl SecretStore for MemorySecretStore {
    fn has_secret_for_label(&self, _label: String) -> Result<bool, MarmotKitError> {
        Ok(false)
    }

    fn has_secret_for_account_id(&self, account_id_hex: String) -> Result<bool, MarmotKitError> {
        Ok(self.secrets.lock().unwrap().contains_key(&account_id_hex))
    }

    fn write_secret(
        &self,
        _label: String,
        account_id_hex: String,
        secret_key_hex: String,
    ) -> Result<(), MarmotKitError> {
        self.secrets
            .lock()
            .unwrap()
            .insert(account_id_hex, secret_key_hex);
        Ok(())
    }

    fn load_secret(
        &self,
        _label: String,
        account_id_hex: String,
    ) -> Result<String, MarmotKitError> {
        self.secrets
            .lock()
            .unwrap()
            .get(&account_id_hex)
            .cloned()
            .ok_or(MarmotKitError::SecretNotFound {
                details: account_id_hex,
            })
    }

    fn remove_secret(&self, _label: String, account_id_hex: String) -> Result<(), MarmotKitError> {
        self.secrets.lock().unwrap().remove(&account_id_hex);
        Ok(())
    }
}

/// Thread names that emitted tracing events, per subsystem.
#[derive(Clone, Default)]
struct ThreadTrace {
    events: Arc<Mutex<BTreeMap<(String, String), usize>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for ThreadTrace {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let target = event.metadata().target();
        let subsystem = target.split("::").take(2).collect::<Vec<_>>().join("::");
        let thread = thread_class(std::thread::current().name().unwrap_or("<unnamed>"));
        *self
            .events
            .lock()
            .unwrap()
            .entry((subsystem, thread))
            .or_default() += 1;
    }
}

/// Collapse numbered worker names so the table groups by pool.
fn thread_class(name: &str) -> String {
    name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '-')
        .to_owned()
}

/// CPU time used so far by each named thread of this process.
#[cfg(target_os = "macos")]
fn thread_cpu_times() -> BTreeMap<String, Duration> {
    use std::ffi::CStr;
    use std::mem::{size_of, zeroed};

    // `PROC_PIDLISTTHREADS` from <sys/proc_info.h>; libc does not export it.
    const PROC_PIDLISTTHREADS: i32 = 6;
    let pid = std::process::id() as i32;
    let mut ids = vec![0u64; 4096];
    let bytes = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDLISTTHREADS,
            0,
            ids.as_mut_ptr().cast(),
            (ids.len() * size_of::<u64>()) as i32,
        )
    };
    let mut result = BTreeMap::new();
    for id in &ids[..bytes.max(0) as usize / size_of::<u64>()] {
        let mut info: libc::proc_threadinfo = unsafe { zeroed() };
        let read = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTHREADINFO,
                *id,
                (&mut info as *mut libc::proc_threadinfo).cast(),
                size_of::<libc::proc_threadinfo>() as i32,
            )
        };
        if read <= 0 {
            continue;
        }
        let name = unsafe { CStr::from_ptr(info.pth_name.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let name = if name.is_empty() {
            "<unnamed>".to_owned()
        } else {
            thread_class(&name)
        };
        *result.entry(name).or_default() +=
            Duration::from_nanos(info.pth_user_time + info.pth_system_time);
    }
    result
}

/// CPU time used so far by each named thread of this process.
#[cfg(target_os = "linux")]
fn thread_cpu_times() -> BTreeMap<String, Duration> {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
    let mut result = BTreeMap::new();
    for task in std::fs::read_dir("/proc/self/task")
        .into_iter()
        .flatten()
        .flatten()
    {
        let path = task.path();
        let (Ok(comm), Ok(stat)) = (
            std::fs::read_to_string(path.join("comm")),
            std::fs::read_to_string(path.join("stat")),
        ) else {
            continue;
        };
        // Fields after the parenthesised command: state is field 3, utime 14, stime 15.
        let Some(after_comm) = stat.rsplit_once(')').map(|(_, rest)| rest) else {
            continue;
        };
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        let (Some(utime), Some(stime)) = (fields.get(11), fields.get(12)) else {
            continue;
        };
        let jiffies = utime.parse::<u64>().unwrap_or(0) + stime.parse::<u64>().unwrap_or(0);
        *result.entry(thread_class(comm.trim())).or_default() +=
            Duration::from_millis(jiffies * 1000 / ticks);
    }
    result
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn thread_cpu_times() -> BTreeMap<String, Duration> {
    BTreeMap::new()
}

/// Paths of the files this process has open.
#[cfg(target_os = "macos")]
fn open_files() -> Vec<PathBuf> {
    use std::ffi::CStr;

    let mut paths = Vec::new();
    for fd in 0..4096 {
        let mut path = [0 as libc::c_char; libc::PATH_MAX as usize];
        if unsafe { libc::fcntl(fd, libc::F_GETPATH, path.as_mut_ptr()) } == 0 {
            let path = unsafe { CStr::from_ptr(path.as_ptr()) };
            paths.push(PathBuf::from(path.to_string_lossy().into_owned()));
        }
    }
    paths
}

/// Paths of the files this process has open.
#[cfg(target_os = "linux")]
fn open_files() -> Vec<PathBuf> {
    std::fs::read_dir("/proc/self/fd")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|fd| std::fs::read_link(fd.path()).ok())
        .collect()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn open_files() -> Vec<PathBuf> {
    Vec::new()
}

fn open(root: &Path, relay_url: &str) -> Arc<Marmot> {
    Marmot::new_with_configuration(
        root.to_string_lossy().into_owned(),
        vec![relay_url.to_owned()],
        MarmotOptions {
            relay_policy: Some(RelayPolicyFfi::AllowLoopback),
            secret_store: Some(Arc::new(MemorySecretStore::default())),
            ..Default::default()
        },
    )
    .expect("open marmot")
}

/// Retry a host call that can race key-package publication or worker startup.
fn retry<T>(what: &str, mut call: impl FnMut() -> Result<T, MarmotKitError>) -> T {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match call() {
            Ok(value) => return value,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Err(error) => panic!("{what}: {error:?}"),
        }
    }
}

struct HostOutcome {
    /// Files still open under any root after `shutdown_and_close`.
    open_after_close: Vec<PathBuf>,
    /// Per-thread CPU time at the end, taken while this thread still exists.
    cpu: BTreeMap<String, Duration>,
    /// Latency of each worker-routed read Carol made during the burst.
    read_latencies: Vec<Duration>,
}

/// The host side of the scenario. Runs on a plain thread with no runtime.
fn host_scenario(relay_url: String) -> HostOutcome {
    use futures::executor::block_on;

    let alice_root = tempfile::tempdir().unwrap();
    let bob_root = tempfile::tempdir().unwrap();
    let alice = open(alice_root.path(), &relay_url);
    let bob = open(bob_root.path(), &relay_url);

    let relays = || vec![relay_url.clone()];
    let alice_id = block_on(alice.__ffi_create_identity(relays(), relays(), Vec::new()))
        .expect("create alice")
        .account_id_hex;
    let bob_id = block_on(bob.__ffi_create_identity(relays(), relays(), Vec::new()))
        .expect("create bob")
        .account_id_hex;
    let bob_events = bob.subscribe_events();
    block_on(alice.__ffi_start()).expect("start alice");
    block_on(bob.__ffi_start()).expect("start bob");

    let group = retry("create group", || {
        block_on(alice.__ffi_create_group(
            alice_id.clone(),
            "threads".into(),
            vec![bob_id.clone()],
            None,
        ))
    });
    loop {
        match block_on(bob_events.__ffi_next()).expect("bob events open") {
            MarmotEventFfi::GroupJoined { group_id_hex, .. } if group_id_hex == group => break,
            _ => {}
        }
    }
    retry("accept invite", || {
        block_on(bob.__ffi_accept_group_invite(bob_id.clone(), group.clone()))
    });

    // Carol is an idle third root with a group of her own. Time her
    // worker-routed reads from this host thread while Alice sends the burst
    // and Bob ingests it, each from its own host thread.
    let carol_root = tempfile::tempdir().unwrap();
    let carol = open(carol_root.path(), &relay_url);
    let carol_id = block_on(carol.__ffi_create_identity(relays(), relays(), Vec::new()))
        .expect("create carol")
        .account_id_hex;
    block_on(carol.__ffi_start()).expect("start carol");
    let carol_group =
        block_on(carol.__ffi_create_group(carol_id.clone(), "notes".into(), Vec::new(), None))
            .expect("carol group");
    let bob_received = std::thread::Builder::new()
        .name("host-events".into())
        .spawn(move || {
            let mut received = 0;
            while received < MESSAGES {
                if let MarmotEventFfi::MessageReceived { received: message } =
                    block_on(bob_events.__ffi_next()).expect("bob events open")
                    && message.account_id_hex == bob_id
                {
                    received += 1;
                }
            }
        })
        .unwrap();
    let alice_sent = {
        let alice = alice.clone();
        let (alice_id, group) = (alice_id.clone(), group.clone());
        std::thread::Builder::new()
            .name("host-sender".into())
            .spawn(move || {
                for index in 0..MESSAGES {
                    block_on(alice.__ffi_send_text(
                        alice_id.clone(),
                        group.clone(),
                        format!("message {index}"),
                    ))
                    .expect("send");
                }
            })
            .unwrap()
    };
    let mut read_latencies = Vec::new();
    while !bob_received.is_finished() {
        let started = Instant::now();
        block_on(carol.__ffi_group_conversation_snapshot(carol_id.clone(), carol_group.clone()))
            .expect("carol snapshot");
        read_latencies.push(started.elapsed());
    }
    alice_sent.join().expect("alice sends the burst");
    bob_received.join().expect("bob receives the burst");

    block_on(alice.__ffi_shutdown_and_close()).expect("close alice");
    block_on(bob.__ffi_shutdown_and_close()).expect("close bob");
    block_on(carol.__ffi_shutdown_and_close()).expect("close carol");
    let roots = [alice_root.path(), bob_root.path(), carol_root.path()]
        .map(|root| root.canonicalize().unwrap());
    HostOutcome {
        open_after_close: open_files()
            .into_iter()
            .filter(|path| roots.iter().any(|root| path.starts_with(root)))
            .collect(),
        cpu: thread_cpu_times(),
        read_latencies,
    }
}

/// Print count and percentiles of the probe's read latencies.
fn print_read_latencies(mut latencies: Vec<Duration>) {
    latencies.sort();
    let at = |q: f64| {
        latencies
            .get(((latencies.len() as f64 - 1.0) * q).round() as usize)
            .map_or(0.0, |latency| latency.as_secs_f64() * 1000.0)
    };
    println!(
        "\nCarol's reads during the burst: {} reads, p50 {:.1} ms, p95 {:.1} ms, max {:.1} ms",
        latencies.len(),
        at(0.5),
        at(0.95),
        at(1.0)
    );
}

#[test]
fn uniffi_exports_run_mdk_work_on_marmotkit_runtime_threads() {
    let trace = ThreadTrace::default();
    let filter = tracing_subscriber::EnvFilter::new(
        "marmot_app=debug,marmot_account=debug,cgka_engine=debug,transport_nostr_adapter=debug,\
         nostr_relay_pool=debug,nostr_sdk=debug",
    );
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(filter)
            .with(trace.clone()),
    )
    .expect("install tracing layer");

    // The relay is test infrastructure; keep it on its own named runtime.
    let relay_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("test-relay")
        .enable_all()
        .build()
        .unwrap();
    let relay = relay_runtime
        .block_on(MockRelay::run())
        .expect("start relay");
    let relay_url = relay_runtime.block_on(relay.url()).to_string();

    let before = thread_cpu_times();
    let started = Instant::now();
    let host = std::thread::Builder::new()
        .name("host-caller".into())
        .spawn(move || host_scenario(relay_url))
        .unwrap();
    while !host.is_finished() {
        assert!(
            started.elapsed() < SCENARIO_DEADLINE,
            "host scenario exceeded {SCENARIO_DEADLINE:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let HostOutcome {
        open_after_close,
        cpu: after,
        read_latencies,
    } = host.join().expect("host scenario");
    let elapsed = started.elapsed();
    let events = trace.events.lock().unwrap().clone();

    println!("scenario wall time: {elapsed:?}");
    println!("\nCPU time by thread (excluding test-relay):");
    let mut total = Duration::ZERO;
    for (thread, cpu) in &after {
        if thread.starts_with("test-relay") {
            continue;
        }
        let spent = cpu.saturating_sub(before.get(thread).copied().unwrap_or_default());
        total += spent;
        if !spent.is_zero() {
            println!("  {thread:<28} {:>8.1} ms", spent.as_secs_f64() * 1000.0);
        }
    }
    println!("  {:<28} {:>8.1} ms", "total", total.as_secs_f64() * 1000.0);
    print_read_latencies(read_latencies);
    println!("\ntracing events by subsystem and thread:");
    for ((subsystem, thread), count) in &events {
        if !thread.starts_with("test-relay") {
            println!("  {subsystem:<44} {thread:<28} {count:>6}");
        }
    }
    println!("\nfiles open under the roots after shutdown_and_close: {open_after_close:#?}");

    assert!(
        !after
            .keys()
            .any(|thread| thread.starts_with(ASYNC_COMPAT_THREAD)),
        "async_compat's fallback runtime thread started"
    );
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        assert!(
            after.contains_key(MARMOTKIT_THREAD),
            "no MarmotKit runtime threads: {:?}",
            after.keys()
        );
    }
    for subsystem in ["marmot_app::", "transport_nostr_adapter::", "nostr_sdk::"] {
        assert!(
            events.keys().any(|(target, thread)| target.starts_with(subsystem)
                && thread == MARMOTKIT_THREAD),
            "no {subsystem} events on MarmotKit runtime threads"
        );
    }
    assert!(
        open_after_close.is_empty(),
        "files still open after shutdown_and_close: {open_after_close:#?}"
    );
    drop(relay);
}
