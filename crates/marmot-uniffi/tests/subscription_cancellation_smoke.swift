import Foundation

private final class CancellationSmokeStore: SecretStore, @unchecked Sendable {
  private let lock = NSLock()
  private var secrets: [String: String] = [:]

  func hasSecretForLabel(label: String) throws -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return secrets[label] != nil
  }

  func hasSecretForAccountId(accountIdHex: String) throws -> Bool { false }

  func writeSecret(label: String, accountIdHex: String, secretKeyHex: String) throws {
    lock.lock()
    defer { lock.unlock() }
    secrets[label] = secretKeyHex
  }

  func loadSecret(label: String, accountIdHex: String) throws -> String {
    lock.lock()
    defer { lock.unlock() }
    guard let secret = secrets[label] else {
      throw MarmotKitError.SecretNotFound(details: "smoke credential missing")
    }
    return secret
  }

  func removeSecret(label: String, accountIdHex: String) throws {
    lock.lock()
    defer { lock.unlock() }
    secrets.removeValue(forKey: label)
  }
}

private final class NativePollProbe: @unchecked Sendable {
  private let lock = NSLock()
  private var observed: Int8?

  var result: Int8? {
    lock.lock()
    defer { lock.unlock() }
    return observed
  }

  func record(_ result: Int8) {
    lock.lock()
    defer { lock.unlock() }
    precondition(observed == nil, "UniFFI called one poll callback twice")
    observed = result
  }
}

private func pollNative(_ handle: UInt64) -> NativePollProbe {
  let probe = NativePollProbe()
  let retained = Unmanaged.passRetained(probe)
  ffi_marmot_uniffi_rust_future_poll_rust_buffer(
    handle,
    { raw, result in
      Unmanaged<NativePollProbe>.fromOpaque(UnsafeRawPointer(bitPattern: UInt(raw))!)
        .takeRetainedValue().record(result)
    },
    UInt64(UInt(bitPattern: retained.toOpaque()))
  )
  return probe
}

private func expectPrecancelled(_ next: @escaping @Sendable () async throws -> Void) async throws {
  try await Task.detached {
    withUnsafeCurrentTask { $0!.cancel() }
    do {
      try await next()
      preconditionFailure("pre-cancelled public call returned normally")
    } catch is CancellationError {
    }
  }.value
}

private final class NativeReadyPoll {
  let continuation: CheckedContinuation<Int8, Never>
  init(_ continuation: CheckedContinuation<Int8, Never>) { self.continuation = continuation }
}

private func awaitNativeReady(_ handle: UInt64) async {
  while true {
    let result: Int8 = await withCheckedContinuation { continuation in
      let retained = Unmanaged.passRetained(NativeReadyPoll(continuation))
      ffi_marmot_uniffi_rust_future_poll_rust_buffer(
        handle,
        { raw, result in
          Unmanaged<NativeReadyPoll>.fromOpaque(UnsafeRawPointer(bitPattern: UInt(raw))!)
            .takeRetainedValue().continuation.resume(returning: result)
        },
        UInt64(UInt(bitPattern: retained.toOpaque()))
      )
    }
    if result == 0 { return }
    precondition(result == 1, "invalid native poll result")
  }
}

private enum NativeCancelCallback {
  case cancelled
  case cancelledOrWoken
}

// UniFFI 0.29.4 RustFuture::poll polls the receive body synchronously. Ready calls
// back with 0; Pending stores the callback (or returns a wake notification, 1).
// Drain completed updates through the real adapter, then require a poll to return
// with no callback. No task scheduling, elapsed time, or handle allocation stands
// in for this observation. The private helper owns the already-polled handle.
private func cancelNativePending<Value>(
  _ name: String,
  makeHandle: @escaping @Sendable () -> UInt64,
  lift: @escaping @Sendable (RustBuffer) throws -> Value?,
  callback: NativeCancelCallback = .cancelledOrWoken
) async throws {
  try await Task.detached {
    while true {
      let handle = makeHandle()
      while true {
        let probe = pollNative(handle)
        if let result = probe.result {
          if result == 1 { continue }
          precondition(result == 0, "invalid native poll result")
          let value = try await generatedReceive(handle, lift: lift)
          precondition(value != nil, "subscription closed before cancellation proof")
          break
        }
        // The native receive has returned Pending and cannot consume an update
        // until another poll. Cancel before the helper can perform that poll.
        withUnsafeCurrentTask { $0!.cancel() }
        do {
          let _: Value? = try await generatedReceive(
            handle,
            lift: { _ in
              preconditionFailure("cancelled pending native receive decoded a value")
            })
          preconditionFailure("cancelled native receive returned normally")
        } catch is CancellationError {
        }
        // A producer can wake an actor-backed stream after the Pending
        // observation. That delivers 1 rather than cancellation's 0.
        precondition(probe.result == 0 || probe.result == 1, "native callback was not released")
        if callback == .cancelled {
          precondition(probe.result == 0, "quiet native wait was not cancelled")
        }
        print("Native Pending -> cancellation -> cleanup: \(name)")
        return
      }
    }
  }.value
}

// The generated cancellable path every throwing async call takes, applied to a
// future this smoke already polled itself.
private func generatedReceive<Value>(
  _ handle: UInt64,
  lift: (RustBuffer) throws -> Value?
) async throws -> Value? {
  try await uniffiRustCallAsync(
    rustFutureFunc: { handle },
    pollFunc: ffi_marmot_uniffi_rust_future_poll_rust_buffer,
    completeFunc: ffi_marmot_uniffi_rust_future_complete_rust_buffer,
    freeFunc: ffi_marmot_uniffi_rust_future_free_rust_buffer,
    cancelFunc: ffi_marmot_uniffi_rust_future_cancel_rust_buffer,
    liftFunc: lift,
    errorHandler: FfiConverterTypeMarmotKitError_lift
  )
}

// Cancels a quiet receive from outside its task once the generated helper has
// issued its native poll, so the helper's cancellation handler must end the
// wait; a check made only on entry would leave it waiting forever.
private func cancelWhileWaiting(_ makeHandle: @escaping @Sendable () -> UInt64) async throws {
  let (polled, signal) = AsyncStream<Void>.makeStream()
  let waiting = Task.detached {
    try await uniffiRustCallAsync(
      rustFutureFunc: makeHandle,
      pollFunc: { handle, callback, data in
        ffi_marmot_uniffi_rust_future_poll_rust_buffer(handle, callback, data)
        signal.yield()
      },
      completeFunc: ffi_marmot_uniffi_rust_future_complete_rust_buffer,
      freeFunc: ffi_marmot_uniffi_rust_future_free_rust_buffer,
      cancelFunc: ffi_marmot_uniffi_rust_future_cancel_rust_buffer,
      liftFunc: { (_: RustBuffer) -> Void in preconditionFailure("quiet receive returned a value") },
      errorHandler: FfiConverterTypeMarmotKitError_lift
    )
  }
  var polls = polled.makeAsyncIterator()
  _ = await polls.next()
  waiting.cancel()
  do {
    try await waiting.value
    preconditionFailure("receive cancelled while waiting returned normally")
  } catch is CancellationError {
  }
}

// Models uniffi_core::RustFuture::scheduler holding its Mutex while invoking
// uniffiFutureContinuationCallback (which resumes the Swift continuation and
// acquires AsyncTask's StatusRecordLock), racing with Task.cancel() (which
// holds StatusRecordLock while invoking withTaskCancellationHandler's onCancel).
// Calling cancelFunc synchronously inside onCancel deadlocks here
// deterministically (mdk#3821). Also verifies that a MaybeReady wake after
// cancel does not re-poll the future, and that freeFunc never runs ahead of an
// in-flight cancelFunc.
private final class WakeCancelRaceHarness: @unchecked Sendable {
  private let schedulerLock = NSLock()
  private let polled = DispatchSemaphore(value: 0)
  private let cancelEntered = DispatchSemaphore(value: 0)

  private let stateLock = NSLock()
  private var callback: UniffiRustFutureContinuationCallback?
  private var callbackData: UInt64 = 0
  private var polls = 0
  private var freed = false

  var pollCount: Int {
    stateLock.lock()
    defer { stateLock.unlock() }
    return polls
  }

  var wasFreed: Bool {
    stateLock.lock()
    defer { stateLock.unlock() }
    return freed
  }

  func poll(_ callback: @escaping UniffiRustFutureContinuationCallback, _ data: UInt64) {
    stateLock.lock()
    polls += 1
    self.callback = callback
    self.callbackData = data
    stateLock.unlock()
    polled.signal()
  }

  func wakeWhileHoldingSchedulerLock(_ onLockAcquired: () -> Void) {
    polled.wait()
    schedulerLock.lock()
    onLockAcquired()
    cancelEntered.wait()
    stateLock.lock()
    let cb = callback
    let data = callbackData
    callback = nil
    stateLock.unlock()
    if let cb {
      cb(data, 1)
    }
    schedulerLock.unlock()
  }

  func cancel() {
    cancelEntered.signal()
    schedulerLock.lock()
    defer { schedulerLock.unlock() }
    stateLock.lock()
    precondition(!freed, "cancelFunc ran after freeFunc")
    let cb = callback
    let data = callbackData
    callback = nil
    stateLock.unlock()
    if let cb {
      cb(data, 0)
    }
  }

  func free() {
    stateLock.lock()
    freed = true
    stateLock.unlock()
  }
}

private func cancelRacingWithWake() async throws {
  for _ in 0..<20 {
    let harness = WakeCancelRaceHarness()
    let (wakerReady, signalWakerReady) = AsyncStream<Void>.makeStream()
    let (wakerDone, signalWakerDone) = AsyncStream<Void>.makeStream()
    let waiting = Task.detached {
      let _: Void = try await uniffiRustCallAsync(
        rustFutureFunc: { 1 },
        pollFunc: { _, callback, data in
          harness.poll(callback, data)
        },
        completeFunc: { _, callStatus -> Void in
          callStatus.pointee.code = CALL_CANCELLED
        },
        freeFunc: { _ in
          harness.free()
        },
        cancelFunc: { _ in
          harness.cancel()
        },
        liftFunc: { (_: Void) -> Void in
          preconditionFailure("cancelled wake-race future lifted a value")
        },
        errorHandler: nil
      )
    }
    DispatchQueue.global().async {
      harness.wakeWhileHoldingSchedulerLock {
        signalWakerReady.yield()
        signalWakerReady.finish()
      }
      signalWakerDone.yield()
      signalWakerDone.finish()
    }
    var readyIter = wakerReady.makeAsyncIterator()
    _ = await readyIter.next()
    waiting.cancel()
    do {
      try await waiting.value
      preconditionFailure("wake-race cancelled future returned normally")
    } catch is CancellationError {
    }
    var doneIter = wakerDone.makeAsyncIterator()
    _ = await doneIter.next()
    precondition(harness.pollCount == 1, "cancelled future re-polled after MaybeReady wake")
    precondition(harness.wasFreed, "cancelled future was not freed")
  }
  print("Swift cancel-vs-wake lock-order race passed")
}

private func receiveMatching<Value>(
  _ next: () async throws -> Value?,
  matching predicate: (Value) -> Bool
) async throws -> Value {
  while let value = try await next() {
    if predicate(value) { return value }
  }
  preconditionFailure("subscription closed before the expected local update")
}

@main
private struct SubscriptionCancellationSmoke {
  static func main() async throws {
    let watchdog = DispatchWorkItem {
      fputs("Swift subscription cancellation smoke exceeded its 90-second deadline\n", stderr)
      exit(1)
    }
    DispatchQueue.global().asyncAfter(deadline: .now() + 90, execute: watchdog)
    defer { watchdog.cancel() }
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let relay = "ws://127.0.0.1:1"
    let kit = try Marmot.newWithConfiguration(
      rootPath: root.path,
      relayUrls: [relay],
      options: MarmotOptions(
        relayPolicy: .allowLoopbackRelaysAndBlobs,
        secretStore: CancellationSmokeStore(),
        deployment: marmotDeploymentNeutral()
      )
    )
    do {
      try await exercise(kit, relay: relay)
    } catch {
      try? await kit.shutdownAndClose()
      throw error
    }
  }

  private static func exercise(_ kit: Marmot, relay: String) async throws {
    try await kit.start()
    let account = try await kit.createIdentityWithProfile(
      defaultRelays: [relay], bootstrapRelays: [relay]
    ).account
    let creation = try await kit.createGroup(
      accountRef: account.label, name: "Cancellation smoke", memberRefs: [], description: nil)
    guard let group = creation.groupIdHex else {
      preconditionFailure("creator-only group was not created")
    }
    let presented = try await kit.openPresentedChatList(
      accountRef: account.label, includeArchived: false)
    let list = try await kit.openChatListWindow(
      accountRef: account.label, view: .chats, initialRows: 1)
    let attention = try await kit.subscribeAccountAttention()
    let conversation = try await kit.openConversationWindow(
      accountRef: account.label, groupIdHex: group, mode: .latest,
      messageIdHex: nil, initialRows: 1, timeoutMs: 0
    )
    let blocks = try kit.subscribeBlockedUsers(accountRef: account.label)
    let presentedInitial = presented.snapshot()!
    let listInitial = list.snapshot()!
    let attentionInitial = attention.snapshot()!
    let conversationInitial = conversation.snapshot()!
    precondition(blocks.snapshot()!.users.isEmpty)
    precondition(presentedInitial.snapshot.rows.contains { $0.row.groupIdHex == group })
    precondition(listInitial.rows.contains { $0.row.groupIdHex == group })
    precondition(attentionInitial.accounts.contains { $0.accountIdHex == account.accountIdHex })
    precondition(conversationInitial.draft.draft == nil)

    // Public pre-cancellation. Native-pending cancellation is checked
    // separately below; pre-cancellation alone cannot prove it.
    let events = kit.subscribeEvents()
    let notifications = try await kit.subscribeNotifications()
    let search = try await kit.searchUsers(
      accountIdHex: account.accountIdHex, query: "cancellation smoke", radiusStart: 1, radiusEnd: 1)
    try await expectPrecancelled { _ = try await presented.nextCancellable() }
    try await expectPrecancelled { _ = try await list.nextCancellable() }
    try await expectPrecancelled { _ = try await attention.nextCancellable() }
    try await expectPrecancelled { _ = try await conversation.nextCancellable() }
    try await expectPrecancelled { _ = try await blocks.nextCancellable() }
    try await expectPrecancelled { _ = try await events.nextCancellable() }
    try await expectPrecancelled { _ = try await notifications.nextCancellable() }
    try await expectPrecancelled { _ = try await search.nextUpdateCancellable() }
    // Generated throwing commands forward cancellation too, not only receives,
    // and a command cancelled before it starts does nothing.
    let chatCount = try kit.chatList(accountRef: account.label, includeArchived: true).count
    try await expectPrecancelled {
      _ = try await kit.createGroup(
        accountRef: account.label, name: "Cancelled before start", memberRefs: [], description: nil)
    }
    let chatCountAfter = try kit.chatList(accountRef: account.label, includeArchived: true).count
    precondition(chatCountAfter == chatCount, "pre-cancelled createGroup created a chat")


    try await cancelNativePending(
      "PresentedChatListSubscription",
      makeHandle: {
        uniffi_marmot_uniffi_fn_method_presentedchatlistsubscription_next(
          presented.uniffiClonePointer())
      }, lift: { try FfiConverterOptionTypePresentedChatListUpdateFfi.lift($0) })
    try await cancelNativePending(
      "ChatListWindowSubscription",
      makeHandle: {
        uniffi_marmot_uniffi_fn_method_chatlistwindowsubscription_next(list.uniffiClonePointer())
      }, lift: { try FfiConverterOptionTypeChatListWindowSnapshotFfi.lift($0) })
    try await cancelNativePending(
      "AccountAttentionSubscription",
      makeHandle: {
        uniffi_marmot_uniffi_fn_method_accountattentionsubscription_next(
          attention.uniffiClonePointer())
      }, lift: { try FfiConverterOptionTypeAccountAttentionSnapshotFfi.lift($0) })
    try await cancelNativePending(
      "ConversationWindowSubscription",
      makeHandle: {
        uniffi_marmot_uniffi_fn_method_conversationwindowsubscription_next(
          conversation.uniffiClonePointer())
      }, lift: { try FfiConverterOptionTypeConversationWindowSnapshotFfi.lift($0) })
    try await cancelNativePending(
      "BlockListSubscription",
      makeHandle: {
        uniffi_marmot_uniffi_fn_method_blocklistsubscription_next(blocks.uniffiClonePointer())
      }, lift: { try FfiConverterOptionTypeBlockListSnapshotFfi.lift($0) }, callback: .cancelled)
    try await cancelWhileWaiting {
      uniffi_marmot_uniffi_fn_method_blocklistsubscription_next(blocks.uniffiClonePointer())
    }
    try await cancelRacingWithWake()
    // A receive generated without `throws`, through the helper its adapter uses.
    try await cancelNativePending(
      "EventsSubscription",
      makeHandle: {
        uniffi_marmot_uniffi_fn_method_eventssubscription_next(events.uniffiClonePointer())
      }, lift: { try FfiConverterOptionTypeMarmotEventFfi.lift($0) })

    _ = try kit.setChatManuallyUnread(
      accountRef: account.label, groupIdHex: group, manuallyUnread: true)
    let presentedValue = try await receiveMatching {
      try await presented.nextCancellable()
    } matching: {
      $0.snapshot.rows.contains { $0.row.groupIdHex == group && $0.row.manuallyMarkedUnread }
    }
    precondition(presentedValue.subscriptionGeneration == presentedInitial.subscriptionGeneration)
    precondition(presentedValue.sequence > presentedInitial.sequence)
    let listValue = try await receiveMatching {
      try await list.nextCancellable()
    } matching: {
      $0.rows.contains { $0.row.groupIdHex == group && $0.row.manuallyMarkedUnread }
    }
    precondition(listValue.subscriptionGeneration == listInitial.subscriptionGeneration)
    precondition(listValue.sequence > listInitial.sequence)
    let attentionValue = try await receiveMatching {
      try await attention.nextCancellable()
    } matching: {
      value in
      value.accounts.contains { entry in
        if entry.accountIdHex == account.accountIdHex, case .ready(let total) = entry.state {
          return total.attentionOnlyConversations == 1
        }
        return false
      }
    }
    precondition(attentionValue.subscriptionGeneration == attentionInitial.subscriptionGeneration)
    precondition(attentionValue.sequence > attentionInitial.sequence)

    // Queue a local replacement while the native receive is Pending, without
    // polling that future again. Cancellation must leave the draft available
    // to the next public receive, and must release the receiver mutex.
    let queuedHandle = uniffi_marmot_uniffi_fn_method_conversationwindowsubscription_next(
      conversation.uniffiClonePointer())
    let queuedProbe = pollNative(queuedHandle)
    // Conversation authority may have changed while testing other streams.
    // Drain that actual update before staging the queued-draft interleaving.
    var pendingHandle = queuedHandle
    var pendingProbe = queuedProbe
    while let result = pendingProbe.result {
      if result == 0 {
        let value = try await generatedReceive(
          pendingHandle, lift: { try FfiConverterOptionTypeConversationWindowSnapshotFfi.lift($0) })
        precondition(value != nil)
        pendingHandle = uniffi_marmot_uniffi_fn_method_conversationwindowsubscription_next(
          conversation.uniffiClonePointer())
      } else {
        precondition(result == 1)
      }
      pendingProbe = pollNative(pendingHandle)
    }
    let selected = try kit.selectedMessageDraft(accountRef: account.label, groupIdHex: group)
    let saved = try kit.saveMessageDraftIfRevision(
      accountRef: account.label, revision: selected.revision,
      content: "queued after native Pending",
      replyToMessageIdHex: nil, mediaAttachments: []
    )
    precondition(saved.draft?.content == "queued after native Pending")
    let handleToCancel = pendingHandle
    try await Task.detached {
      withUnsafeCurrentTask { $0!.cancel() }
      do {
        let _: ConversationWindowSnapshotFfi? = try await generatedReceive(
          handleToCancel,
          lift: { _ in
            preconditionFailure("cancelled native future consumed the queued draft")
          })
        preconditionFailure("cancelled queued receive returned normally")
      } catch is CancellationError {
      }
    }.value
    precondition(pendingProbe.result == 0 || pendingProbe.result == 1)
    let conversationValue = try await receiveMatching {
      try await conversation.nextCancellable()
    } matching: {
      $0.draft.draft?.content == "queued after native Pending"
    }
    precondition(conversationValue.revision.generation == conversationInitial.revision.generation)
    precondition(conversationValue.revision.sequence > conversationInitial.revision.sequence)

    // A real native command supplies the shared completion path's typed error.
    // Its successful payload is deliberately never decoded as an optional update.
    let invalidRevision = ConversationWindowRevisionFfi(generation: "wrong-generation", sequence: 0)
    let errorHandle = uniffi_marmot_uniffi_fn_method_conversationwindowsubscription_page(
      conversation.uniffiClonePointer(),
      FfiConverterTypeConversationWindowRevisionFfi_lower(invalidRevision),
      FfiConverterTypeConversationPageDirectionFfi_lower(.older), 1, 0
    )
    do {
      let _: ConversationWindowSnapshotFfi? = try await generatedReceive(
        errorHandle,
        lift: { _ in
          preconditionFailure("wrong generation returned a successful native payload")
        })
      preconditionFailure("wrong generation did not propagate a typed native error")
    } catch MarmotKitError.ConversationWindowWrongGeneration {
    }

    try await Task.detached {
      let readyError = uniffi_marmot_uniffi_fn_method_conversationwindowsubscription_page(
        conversation.uniffiClonePointer(),
        FfiConverterTypeConversationWindowRevisionFfi_lower(invalidRevision),
        FfiConverterTypeConversationPageDirectionFfi_lower(.older), 1, 0
      )
      await awaitNativeReady(readyError)
      // A call that completed before its task was cancelled reports what it
      // returned, so nothing a completed result owns is dropped.
      withUnsafeCurrentTask { $0!.cancel() }
      do {
        let _: ConversationWindowSnapshotFfi? = try await generatedReceive(
          readyError,
          lift: { _ in
            preconditionFailure("cancelled ready error decoded a successful payload")
          })
        preconditionFailure("cancelled ready error returned normally")
      } catch MarmotKitError.ConversationWindowWrongGeneration {
      }
    }.value

    await conversation.cancel()
    let closedConversation = try await conversation.nextCancellable()
    precondition(closedConversation == nil)
    // Work that must finish ignores cancellation: even a pre-cancelled caller
    // returns only once storage is closed.
    try await Task.detached {
      withUnsafeCurrentTask { $0!.cancel() }
      try await kit.shutdownAndClose()
    }.value
    precondition(kit.storageIsClosed())
    let closedPresented = try await presented.nextCancellable()
    let closedList = try await list.nextCancellable()
    let closedAttention = try await attention.nextCancellable()
    let closedBlocks = try await blocks.nextCancellable()
    precondition(
      closedPresented == nil && closedList == nil && closedAttention == nil && closedBlocks == nil)
    print(
      "Swift public pre-cancellation, local values, typed native error, queued-update preservation and terminal nil passed"
    )
  }
}
