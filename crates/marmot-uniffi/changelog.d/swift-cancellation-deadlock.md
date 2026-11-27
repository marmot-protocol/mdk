### Fixed

- Swift `uniffiRustCallAsync` no longer ABBA-deadlocks when `Task.cancel()` races with `RustFuture::wake` (mdk#3821): cancellation is dispatched off Swift's `onCancel` handler so `rust_future_cancel` never acquires `RustFuture`'s mutex while `libswift_Concurrency` holds `AsyncTask`'s `StatusRecordLock`, and the poll loop checks `Task.isCancelled` before each native poll.
