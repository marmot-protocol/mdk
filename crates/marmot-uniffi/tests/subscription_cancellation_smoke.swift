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
      preconditionFailure("pre-cancelled public nextCancellable returned normally")
    } catch is CancellationError {
    }
  }.value
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
  read: @escaping @Sendable (inout (data: Data, offset: Data.Index)) throws -> Value,
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
          let value = try await cancellableProjectionNext(handle, read: read)
          precondition(value != nil, "subscription closed before cancellation proof")
          break
        }
        // The native receive has returned Pending and cannot consume an update
        // until another poll. Cancel before the helper can perform that poll.
        withUnsafeCurrentTask { $0!.cancel() }
        do {
          let _: Value? = try await cancellableProjectionNext(
            handle,
            read: { _ in
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
    let group = try await kit.createGroup(
      accountRef: account.label, name: "Cancellation smoke", memberRefs: [], description: nil)
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

    // These check the five public prechecks. Native-pending cancellation is
    // checked separately below; pre-cancellation alone cannot prove it.
    try await expectPrecancelled { _ = try await presented.nextCancellable() }
    try await expectPrecancelled { _ = try await list.nextCancellable() }
    try await expectPrecancelled { _ = try await attention.nextCancellable() }
    try await expectPrecancelled { _ = try await conversation.nextCancellable() }
    try await expectPrecancelled { _ = try await blocks.nextCancellable() }

    try await cancelNativePending(
      "PresentedChatListSubscription",
      makeHandle: {
        uniffi_marmot_uniffi_fn_method_presentedchatlistsubscription_next(
          presented.uniffiClonePointer())
      }, read: { try FfiConverterTypePresentedChatListUpdateFfi.read(from: &$0) })
    try await cancelNativePending(
      "ChatListWindowSubscription",
      makeHandle: {
        uniffi_marmot_uniffi_fn_method_chatlistwindowsubscription_next(list.uniffiClonePointer())
      }, read: { try FfiConverterTypeChatListWindowSnapshotFfi.read(from: &$0) })
    try await cancelNativePending(
      "AccountAttentionSubscription",
      makeHandle: {
        uniffi_marmot_uniffi_fn_method_accountattentionsubscription_next(
          attention.uniffiClonePointer())
      }, read: { try FfiConverterTypeAccountAttentionSnapshotFfi.read(from: &$0) })
    try await cancelNativePending(
      "ConversationWindowSubscription",
      makeHandle: {
        uniffi_marmot_uniffi_fn_method_conversationwindowsubscription_next(
          conversation.uniffiClonePointer())
      }, read: { try FfiConverterTypeConversationWindowSnapshotFfi.read(from: &$0) })
    try await cancelNativePending(
      "BlockListSubscription",
      makeHandle: {
        uniffi_marmot_uniffi_fn_method_blocklistsubscription_next(blocks.uniffiClonePointer())
      }, read: { try FfiConverterTypeBlockListSnapshotFfi.read(from: &$0) }, callback: .cancelled)

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
        let value = try await cancellableProjectionNext(
          pendingHandle, read: FfiConverterTypeConversationWindowSnapshotFfi.read)
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
        let _: ConversationWindowSnapshotFfi? = try await cancellableProjectionNext(
          handleToCancel,
          read: { _ in
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
      let _: ConversationWindowSnapshotFfi? = try await cancellableProjectionNext(
        errorHandle,
        read: { _ in
          preconditionFailure("wrong generation returned a successful native payload")
        })
      preconditionFailure("wrong generation did not propagate a typed native error")
    } catch MarmotKitError.ConversationWindowWrongGeneration {
    }

    await conversation.cancel()
    let closedConversation = try await conversation.nextCancellable()
    precondition(closedConversation == nil)
    try await kit.shutdownAndClose()
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
