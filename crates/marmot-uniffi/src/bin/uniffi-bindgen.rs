//! UniFFI's binding generator, plus Swift Task cancellation for async calls.
//!
//! UniFFI's generated Swift (0.29.4, and upstream through 0.32) awaits a native
//! future without ever calling `rust_future_cancel`, so cancelling a Swift `Task`
//! leaves the Rust call and its native references running (mdk#3670). After a
//! Swift generation this rewrites `uniffiRustCallAsync` to forward cancellation,
//! and gives every throwing call site its cancel function. Non-throwing sites
//! cannot report `CancellationError`, so they keep waiting for the native result;
//! `swift-support/CancellableSubscriptions.swift` adds throwing receives for them.
//! Exports whose work must finish keep waiting too (`swift_awaits_completion.rs`).

use std::path::{Path, PathBuf};

#[path = "../swift_awaits_completion.rs"]
mod swift_awaits_completion;
use swift_awaits_completion::SWIFT_AWAITS_COMPLETION;

/// UniFFI 0.29.4's helper as generated for this crate. Generation fails if it
/// changes, so a UniFFI upgrade cannot silently drop cancellation.
const UPSTREAM_RUST_CALL_ASYNC: &str = r#"fileprivate func uniffiRustCallAsync<F, T>(
    rustFutureFunc: () -> UInt64,
    pollFunc: (UInt64, @escaping UniffiRustFutureContinuationCallback, UInt64) -> (),
    completeFunc: (UInt64, UnsafeMutablePointer<RustCallStatus>) -> F,
    freeFunc: (UInt64) -> (),
    liftFunc: (F) throws -> T,
    errorHandler: ((RustBuffer) throws -> Swift.Error)?
) async throws -> T {
    // Make sure to call the ensure init function since future creation doesn't have a
    // RustCallStatus param, so doesn't use makeRustCall()
    uniffiEnsureMarmotUniffiInitialized()
    let rustFuture = rustFutureFunc()
    defer {
        freeFunc(rustFuture)
    }
    var pollResult: Int8;
    repeat {
        pollResult = await withUnsafeContinuation {
            pollFunc(
                rustFuture,
                uniffiFutureContinuationCallback,
                uniffiContinuationHandleMap.insert(obj: $0)
            )
        }
    } while pollResult != UNIFFI_RUST_FUTURE_POLL_READY

    return try liftFunc(makeRustCall(
        { completeFunc(rustFuture, $0) },
        errorHandler: errorHandler
    ))
}
"#;

const CANCELLABLE_RUST_CALL_ASYNC: &str = r#"// MarmotKit: with `cancelFunc`, cancelling the awaiting Task cancels the native
// future and the call throws CancellationError. A result that completed first is
// returned instead, so nothing it owns is dropped. The future is freed either
// way, which releases the native references it holds.
fileprivate func uniffiRustCallAsync<F, T>(
    rustFutureFunc: () -> UInt64,
    pollFunc: (UInt64, @escaping UniffiRustFutureContinuationCallback, UInt64) -> (),
    completeFunc: (UInt64, UnsafeMutablePointer<RustCallStatus>) -> F,
    freeFunc: (UInt64) -> (),
    cancelFunc: ((UInt64) -> ())? = nil,
    liftFunc: (F) throws -> T,
    errorHandler: ((RustBuffer) throws -> Swift.Error)?
) async throws -> T {
    // Make sure to call the ensure init function since future creation doesn't have a
    // RustCallStatus param, so doesn't use makeRustCall()
    uniffiEnsureMarmotUniffiInitialized()
    let rustFuture = rustFutureFunc()
    let cancellation = UniffiRustFutureCancellation(rustFuture, cancelFunc)
    defer {
        cancellation.retire()
        freeFunc(rustFuture)
    }
    await withTaskCancellationHandler {
        var pollResult: Int8
        repeat {
            pollResult = await withUnsafeContinuation {
                pollFunc(
                    rustFuture,
                    uniffiFutureContinuationCallback,
                    uniffiContinuationHandleMap.insert(obj: $0)
                )
            }
        } while pollResult != UNIFFI_RUST_FUTURE_POLL_READY
    } onCancel: {
        cancellation.cancel()
    }

    var callStatus = RustCallStatus.init()
    let returnedVal = completeFunc(rustFuture, &callStatus)
    if callStatus.code == CALL_CANCELLED {
        throw CancellationError()
    }
    try uniffiCheckCallStatus(callStatus: callStatus, errorHandler: errorHandler)
    return try liftFunc(returnedVal)
}

// The lock keeps a late cancellation from using the handle after it is freed.
fileprivate final class UniffiRustFutureCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var rustFuture: UInt64?
    private let cancelFunc: ((UInt64) -> ())?

    init(_ rustFuture: UInt64, _ cancelFunc: ((UInt64) -> ())?) {
        self.rustFuture = rustFuture
        self.cancelFunc = cancelFunc
    }

    func cancel() {
        lock.lock()
        defer { lock.unlock() }
        if let rustFuture, let cancelFunc {
            cancelFunc(rustFuture)
        }
    }

    func retire() {
        lock.lock()
        defer { lock.unlock() }
        rustFuture = nil
    }
}
"#;

const FREE_FUNC: &str = "freeFunc: ffi_marmot_uniffi_rust_future_free_";

fn main() {
    uniffi::uniffi_bindgen_main();
    if let Some(out_dir) = swift_out_dir(std::env::args().skip(1)) {
        let path = out_dir.join("marmot_uniffi.swift");
        if let Err(error) = forward_cancellation_in(&path) {
            eprintln!("error: {}: {error}", path.display());
            std::process::exit(1);
        }
    }
}

/// The output directory of a `generate` run that produced Swift (an explicit
/// `--language swift`, or no language, which generates every language).
fn swift_out_dir(args: impl Iterator<Item = String>) -> Option<PathBuf> {
    let args: Vec<String> = args.collect();
    if args.first().map(String::as_str) != Some("generate") {
        return None;
    }
    let (mut out_dir, mut languages) = (None, Vec::new());
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) => (flag, Some(value.to_owned())),
            // Short flags also take an attached value: `-lswift`, `-o/tmp/out`.
            None if arg.len() > 2 && (arg.starts_with("-l") || arg.starts_with("-o")) => {
                (&arg[..2], Some(arg[2..].to_owned()))
            }
            None => (arg.as_str(), None),
        };
        let mut value = || inline.clone().or_else(|| iter.next().cloned());
        match flag {
            "--out-dir" | "-o" => out_dir = value().map(PathBuf::from),
            "--language" | "-l" => languages.extend(value()),
            _ => {}
        }
    }
    let swift = languages.is_empty() || languages.iter().any(|language| language == "swift");
    out_dir.filter(|_| swift)
}

fn forward_cancellation_in(path: &Path) -> Result<(), String> {
    let source = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    std::fs::write(path, forward_cancellation(&source)?).map_err(|error| error.to_string())
}

fn forward_cancellation(source: &str) -> Result<String, String> {
    if source.matches(UPSTREAM_RUST_CALL_ASYNC).count() != 1 {
        return Err(
            "UniFFI's uniffiRustCallAsync changed; update src/bin/uniffi-bindgen.rs".to_owned(),
        );
    }
    let source = source.replace(UPSTREAM_RUST_CALL_ASYNC, CANCELLABLE_RUST_CALL_ASYNC);

    // `forward` is set inside a call site: whether it gets a cancel function.
    let (mut output, mut forward, mut call_sites, mut cancellable) =
        (String::with_capacity(source.len()), None, 0, 0);
    let mut awaited = Vec::new();
    for line in source.split_inclusive('\n') {
        output.push_str(line);
        let code = line.trim_start();
        if code.contains("await uniffiRustCallAsync(") {
            if forward.replace(!code.starts_with("try!")).is_some() {
                return Err(format!("async call site {call_sites} has no freeFunc"));
            }
            call_sites += 1;
        } else if let Some(symbol) = SWIFT_AWAITS_COMPLETION
            .iter()
            .find(|symbol| {
                code.strip_prefix(**symbol)
                    .is_some_and(|rest| rest.starts_with('('))
            })
            .filter(|_| forward.is_some())
        {
            forward = Some(false);
            awaited.push(*symbol);
        } else if let Some(suffix) = code.strip_prefix(FREE_FUNC) {
            match forward.take() {
                Some(true) => {
                    let indent = &line[..line.len() - code.len()];
                    output.push_str(&format!(
                        "{indent}cancelFunc: ffi_marmot_uniffi_rust_future_cancel_{suffix}"
                    ));
                    cancellable += 1;
                }
                Some(false) => {}
                None => return Err(format!("unexpected `{}`", code.trim_end())),
            }
        }
    }
    awaited.sort_unstable();
    if awaited != sorted(SWIFT_AWAITS_COMPLETION) {
        return Err(format!(
            "expected one async call site for each of {SWIFT_AWAITS_COMPLETION:?}"
        ));
    }
    if call_sites == 0 || forward.is_some() {
        return Err(format!(
            "expected a freeFunc in each of {call_sites} async call sites"
        ));
    }
    eprintln!(
        "Swift cancellation: {cancellable} of {call_sites} async calls forward Task cancellation"
    );
    Ok(output)
}

fn sorted(symbols: &[&'static str]) -> Vec<&'static str> {
    let mut symbols = symbols.to_vec();
    symbols.sort_unstable();
    symbols
}
