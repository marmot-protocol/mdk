#![cfg(unix)]

use std::fs::File;
use std::io::{self, Read};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const PROMPT: &str = "Existing Nostr identity (nsec or raw hex): ";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(10);

struct Pty {
    master: File,
    slave: File,
}

impl Pty {
    fn open() -> Self {
        let mut master = -1;
        let mut slave = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0,
            "openpty failed: {}",
            io::Error::last_os_error()
        );

        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags, -1, "F_GETFL failed: {}", io::Error::last_os_error());
        assert_ne!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            -1,
            "F_SETFL failed: {}",
            io::Error::last_os_error()
        );

        Self { master, slave }
    }

    fn echo_enabled(&self) -> bool {
        let mut settings = MaybeUninit::<libc::termios>::uninit();
        assert_eq!(
            unsafe { libc::tcgetattr(self.slave.as_raw_fd(), settings.as_mut_ptr()) },
            0,
            "tcgetattr failed: {}",
            io::Error::last_os_error()
        );
        unsafe { settings.assume_init() }.c_lflag & libc::ECHO != 0
    }
}

struct KillOnDrop(Option<Child>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn duplicate(file: &File) -> File {
    let fd = unsafe { libc::dup(file.as_raw_fd()) };
    assert_ne!(fd, -1, "dup failed: {}", io::Error::last_os_error());
    unsafe { File::from_raw_fd(fd) }
}

fn read_until_prompt(master: &mut File, child: &mut Child) {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let mut output = Vec::new();
    let mut buffer = [0u8; 256];
    while Instant::now() < deadline {
        match master.read(&mut buffer) {
            Ok(0) => {}
            Ok(read) => {
                output.extend_from_slice(&buffer[..read]);
                if output
                    .windows(PROMPT.len())
                    .any(|window| window == PROMPT.as_bytes())
                {
                    return;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("failed to read PTY output: {error}"),
        }
        if let Some(status) = child.try_wait().expect("query prompt process") {
            panic!(
                "prompt process exited before displaying its prompt ({status}): {}",
                String::from_utf8_lossy(&output)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "prompt did not appear: {}",
        String::from_utf8_lossy(&output)
    );
}

fn wait_for_exit(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("query prompt process") {
            return status;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("prompt process did not exit after signal");
}

#[test]
fn masked_prompt_restores_tty_and_handler_before_reraising_sigint() {
    let home = tempfile::tempdir().unwrap();
    let mut pty = Pty::open();
    assert!(pty.echo_enabled());

    let slave_fd = pty.slave.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_wn-agent"));
    command
        .args([
            "import-identity",
            "--home",
            home.path().to_str().unwrap(),
            "--label",
            "agent",
            "--prompt",
            "--json",
        ])
        .stdin(Stdio::from(duplicate(&pty.slave)))
        .stdout(Stdio::from(duplicate(&pty.slave)))
        .stderr(Stdio::from(duplicate(&pty.slave)));
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = KillOnDrop(Some(command.spawn().expect("spawn prompt process")));
    let process = child.0.as_mut().unwrap();
    read_until_prompt(&mut pty.master, process);
    assert!(!pty.echo_enabled(), "prompt must disable terminal echo");

    assert_eq!(
        unsafe { libc::kill(process.id() as libc::pid_t, libc::SIGINT) },
        0
    );
    let status = wait_for_exit(process);
    child.0.take();

    assert_eq!(status.signal(), Some(libc::SIGINT));
    assert!(
        pty.echo_enabled(),
        "prompt must restore terminal echo before re-raising SIGINT"
    );
}
