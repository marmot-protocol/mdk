use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStderr, ChildStdin};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout_at};

use crate::{HarnessError, Result};

const STDERR_CAPTURE_BYTES: usize = 4096;

/// Reads one stdout line before the current idle deadline.
pub async fn next_stdout_line(
    lines: &mut tokio::io::Lines<impl tokio::io::AsyncBufRead + Unpin>,
    idle_deadline: Instant,
) -> Result<Option<String>> {
    match timeout_at(idle_deadline, lines.next_line()).await {
        Err(_) => Err(HarnessError::BackendIdle),
        Ok(Err(_)) => Err(HarnessError::BackendStream),
        Ok(Ok(line)) => Ok(line),
    }
}

/// Writes and closes backend stdin concurrently with stdout consumption.
pub fn write_stdin(stdin: ChildStdin, prompt: String) -> JoinHandle<std::io::Result<()>> {
    tokio::spawn(async move {
        let mut stdin = stdin;
        stdin.write_all(prompt.as_bytes()).await?;
        stdin.shutdown().await
    })
}

/// Captures a bounded prefix of backend stderr.
pub async fn capture_stderr(stderr: ChildStderr) -> String {
    capture_bounded(stderr).await
}

async fn capture_bounded(mut reader: impl AsyncRead + Unpin) -> String {
    let mut buf = [0_u8; 1024];
    let mut captured = String::new();
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(read) if captured.len() < STDERR_CAPTURE_BYTES => {
                captured.push_str(&String::from_utf8_lossy(&buf[..read]));
                truncate_to_char_boundary(&mut captured, STDERR_CAPTURE_BYTES);
            }
            Ok(_) => {}
        }
    }
    captured
}

/// Aborts auxiliary tasks, terminates the child, and reaps it after failure.
pub async fn cleanup_failed_run(
    child: &mut Child,
    stderr_task: &mut JoinHandle<String>,
    writer_task: Option<&mut JoinHandle<std::io::Result<()>>>,
) {
    if let Some(task) = writer_task {
        task.abort();
    }
    stderr_task.abort();
    kill_and_reap(child).await;
    if !stderr_task.is_finished() {
        let _ = stderr_task.await;
    }
}

/// Best-effort terminates and reaps a backend child.
pub async fn kill_and_reap(child: &mut Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

/// Removes ANSI CSI control sequences from bounded stderr.
pub fn strip_ansi(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn truncate_to_char_boundary(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi_stripping_and_utf8_truncation_are_safe() {
        assert_eq!(strip_ansi("\u{1b}[31merror\u{1b}[0m"), "error");
        let mut value = "ééé".to_owned();
        truncate_to_char_boundary(&mut value, 5);
        assert_eq!(value, "éé");
    }

    #[tokio::test]
    async fn stderr_capture_bounds_one_long_line_while_draining_it() {
        let input = std::io::Cursor::new(vec![b'x'; STDERR_CAPTURE_BYTES * 100]);
        let captured = capture_bounded(input).await;
        assert_eq!(captured.len(), STDERR_CAPTURE_BYTES);
        assert!(captured.bytes().all(|byte| byte == b'x'));
    }
}
