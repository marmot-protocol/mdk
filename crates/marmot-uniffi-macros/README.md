# marmot-uniffi-macros

Proc macros for [`marmot-uniffi`](../marmot-uniffi/README.md) (MarmotKit). Nothing else should depend on this crate.

## `on_tokio_runtime`

Swift and Kotlin poll MarmotKit's async methods from their own threads, with no Tokio runtime entered. UniFFI's
built-in `async_runtime = "tokio"` handles that by falling back to a single current-thread runtime on one
`async-compat/tokio-1` thread, so every task MDK spawns shares one thread, and part of each call runs on whichever host
thread polls it. `on_tokio_runtime` replaces that attribute:

```rust
#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Bring the runtime to local readiness.
    pub async fn start(&self) -> Result<(), MarmotKitError> {
        self.runtime.start().await?;
        Ok(())
    }
}
```

For each `async fn` in the block, the macro keeps the method as written for Rust callers and exports a hidden
`__ffi_start(self: &Arc<Self>)` wrapper in its place, under the FFI name `start`. The wrapper spawns `start` on
MarmotKit's runtime (`marmot-uniffi`'s `tokio_runtime` module) and awaits the join handle, so the host thread only
polls the handle. Dropping the wrapper's future aborts the task.

The generated Swift and Kotlin are unchanged: UniFFI names the export, its scaffolding symbol and its checksum after the
FFI name, and does not record the receiver type. Synchronous methods and constructors are exported as written.

The [MarmotKit threading model](../marmot-uniffi/README.md#threading-model) describes the runtime itself.
