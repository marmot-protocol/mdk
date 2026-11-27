### Fixed

- Swift bindings no longer deadlock when cancelling an async MarmotKit `Task` concurrently with a native `RustFuture::wake` (mdk#3821): `uniffiRustCallAsync` now dispatches native future cancellation off Swift's `onCancel` handler (avoiding lock-order inversion between `AsyncTask`'s `StatusRecordLock` and `uniffi_core::RustFuture`'s scheduler mutex) and checks `Task.isCancelled` before polling so a pre-cancelled or woken-after-cancel task does not issue another native poll.
