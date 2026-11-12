import Foundation
import marmot_uniffiFFI

// UniFFI 0.29.4 does not forward Swift Task cancellation to native futures.
extension PresentedChatListSubscription {
  public func nextCancellable() async throws -> PresentedChatListUpdateFfi? {
    try Task.checkCancellation()
    return try await cancellableProjectionNext(
      uniffi_marmot_uniffi_fn_method_presentedchatlistsubscription_next(uniffiClonePointer()),
      read: FfiConverterTypePresentedChatListUpdateFfi.read
    )
  }
}

extension ChatListWindowSubscription {
  public func nextCancellable() async throws -> ChatListWindowSnapshotFfi? {
    try Task.checkCancellation()
    return try await cancellableProjectionNext(
      uniffi_marmot_uniffi_fn_method_chatlistwindowsubscription_next(uniffiClonePointer()),
      read: FfiConverterTypeChatListWindowSnapshotFfi.read
    )
  }
}

extension AccountAttentionSubscription {
  public func nextCancellable() async throws -> AccountAttentionSnapshotFfi? {
    try Task.checkCancellation()
    return try await cancellableProjectionNext(
      uniffi_marmot_uniffi_fn_method_accountattentionsubscription_next(uniffiClonePointer()),
      read: FfiConverterTypeAccountAttentionSnapshotFfi.read
    )
  }
}

extension ConversationWindowSubscription {
  public func nextCancellable() async throws -> ConversationWindowSnapshotFfi? {
    try Task.checkCancellation()
    return try await cancellableProjectionNext(
      uniffi_marmot_uniffi_fn_method_conversationwindowsubscription_next(uniffiClonePointer()),
      read: FfiConverterTypeConversationWindowSnapshotFfi.read
    )
  }
}

extension BlockListSubscription {
  public func nextCancellable() async throws -> BlockListSnapshotFfi? {
    try Task.checkCancellation()
    return try await cancellableProjectionNext(
      uniffi_marmot_uniffi_fn_method_blocklistsubscription_next(uniffiClonePointer()),
      read: FfiConverterTypeBlockListSnapshotFfi.read
    )
  }
}

private func cancellableProjectionNext<Value>(
  _ handle: UInt64,
  read: (inout (data: Data, offset: Data.Index)) throws -> Value
) async throws -> Value? {
  let future = CancellableSubscriptionNativeFuture(handle)
  defer { future.free() }
  // The handle is already owned here. Even a pre-cancelled task must cancel and free it.
  return try await withTaskCancellationHandler {
    var ready: Int8 = 1
    repeat {
      ready = await withCheckedContinuation { continuation in
        let box = Unmanaged.passRetained(CancellableSubscriptionPoll(continuation))
        ffi_marmot_uniffi_rust_future_poll_rust_buffer(
          future.handle,
          { raw, result in
            let box = Unmanaged<CancellableSubscriptionPoll>.fromOpaque(
              UnsafeRawPointer(bitPattern: UInt(raw))!)
            box.takeRetainedValue().continuation.resume(returning: result)
          },
          UInt64(UInt(bitPattern: box.toOpaque()))
        )
      }
    } while ready != 0
    var status = RustCallStatus(code: 0, errorBuf: .init(capacity: 0, len: 0, data: nil))
    let buffer = ffi_marmot_uniffi_rust_future_complete_rust_buffer(future.handle, &status)
    defer {
      freeSubscriptionBuffer(buffer)
      freeSubscriptionBuffer(status.errorBuf)
    }
    switch status.code {
    case 0:
      var reader = try cancellableSubscriptionReader(buffer)
      let value: Value?
      switch try readInt(&reader) as UInt8 {
      case 0: value = nil
      case 1: value = try read(&reader)
      default: throw UniffiInternalError.unexpectedOptionalTag
      }
      guard !hasRemaining(reader) else { throw UniffiInternalError.incompleteData }
      try Task.checkCancellation()
      return value
    case 1:
      // Read rather than lift: the defer owns this buffer even when decoding throws.
      var reader = try cancellableSubscriptionReader(status.errorBuf)
      let error = try FfiConverterTypeMarmotKitError.read(from: &reader)
      guard !hasRemaining(reader) else { throw UniffiInternalError.incompleteData }
      try Task.checkCancellation()
      throw error
    case 2:
      let message: String
      if let bytes = status.errorBuf.data, status.errorBuf.len > 0 {
        message = String(
          decoding: UnsafeBufferPointer(start: bytes, count: Int(status.errorBuf.len)),
          as: UTF8.self)
      } else {
        message = "Rust panic"
      }
      throw UniffiInternalError.rustPanic(message)
    case 3:
      throw CancellationError()
    default:
      throw UniffiInternalError.unexpectedRustCallStatusCode
    }
  } onCancel: {
    future.cancel()
  }
}

private func cancellableSubscriptionReader(_ buffer: RustBuffer) throws -> (
  data: Data, offset: Data.Index
) {
  guard let bytes = buffer.data, buffer.len > 0 else { throw UniffiInternalError.bufferOverflow }
  return (Data(bytesNoCopy: bytes, count: Int(buffer.len), deallocator: .none), 0)
}

private final class CancellableSubscriptionPoll {
  let continuation: CheckedContinuation<Int8, Never>
  init(_ continuation: CheckedContinuation<Int8, Never>) { self.continuation = continuation }
}

// The lock prevents cancellation from using a handle after free, including late cancellation.
private final class CancellableSubscriptionNativeFuture: @unchecked Sendable {
  let handle: UInt64
  private let lock = NSLock()
  private var freed = false
  init(_ handle: UInt64) { self.handle = handle }

  func cancel() {
    lock.lock()
    defer { lock.unlock() }
    if !freed { ffi_marmot_uniffi_rust_future_cancel_rust_buffer(handle) }
  }

  func free() {
    lock.lock()
    defer { lock.unlock() }
    guard !freed else { return }
    freed = true
    ffi_marmot_uniffi_rust_future_free_rust_buffer(handle)
  }
}

private func freeSubscriptionBuffer(_ buffer: RustBuffer) {
  guard buffer.capacity > 0 || buffer.data != nil else { return }
  buffer.deallocate()
}
