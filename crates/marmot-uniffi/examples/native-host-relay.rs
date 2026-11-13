#[cfg(unix)]
use std::env;
use std::error::Error;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};
#[cfg(unix)]
use std::process::Command;
use std::process::ExitCode;
#[cfg(unix)]
use std::sync::atomic::{AtomicI32, Ordering};

#[cfg(unix)]
use nostr_relay_builder::MockRelay;

#[cfg(unix)]
static CHILD_GROUP: AtomicI32 = AtomicI32::new(0);
#[cfg(unix)]
static INTERRUPTED: AtomicI32 = AtomicI32::new(0);

#[cfg(unix)]
extern "C" fn interrupt(signal: libc::c_int) {
    INTERRUPTED.store(signal, Ordering::SeqCst);
    stop_child();
}

#[cfg(unix)]
fn stop_child() {
    let group = CHILD_GROUP.load(Ordering::SeqCst);
    if group > 0 {
        unsafe { libc::kill(-group, libc::SIGKILL) };
    }
}

#[cfg(unix)]
fn run() -> Result<u8, Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let command = args
        .next()
        .ok_or("usage: native-host-relay <command> [args...]")?;
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        if unsafe { libc::signal(signal, interrupt as *const () as libc::sighandler_t) }
            == libc::SIG_ERR
        {
            return Err(io::Error::last_os_error().into());
        }
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let relay = runtime.block_on(MockRelay::run())?;
    let url = runtime.block_on(relay.url());
    let result = (|| -> Result<u8, Box<dyn Error>> {
        let signal = INTERRUPTED.load(Ordering::SeqCst);
        if signal != 0 {
            return Ok((128 + signal) as u8);
        }
        let mut child = Command::new(command)
            .args(args)
            .env("MDK_SMOKE_RELAY_URL", url.as_str())
            .process_group(0)
            .spawn()?;
        CHILD_GROUP.store(child.id() as i32, Ordering::SeqCst);
        if INTERRUPTED.load(Ordering::SeqCst) != 0 {
            stop_child();
        }
        let status = child.wait();
        stop_child();
        CHILD_GROUP.store(0, Ordering::SeqCst);
        if status.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let status = status?;
        let signal = INTERRUPTED.load(Ordering::SeqCst);
        Ok(if signal != 0 {
            (128 + signal) as u8
        } else {
            status.code().unwrap_or(128 + status.signal().unwrap_or(1)) as u8
        })
    })();
    relay.shutdown();
    result
}

#[cfg(not(unix))]
fn run() -> Result<u8, Box<dyn Error>> {
    Err("native-host smoke supports macOS and Linux only".into())
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("native-host-relay: {error}");
            ExitCode::FAILURE
        }
    }
}
