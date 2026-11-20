import Foundation
import MarmotKit
import XCTest
import marmot_uniffiFFI



private enum SmokeError: Error {
  case setup(String)
  case timedOut(String)
}

final class NativeHostSmoke: XCTestCase {
  func testDeliveryAndRootReuse() async throws {
    guard let relay = ProcessInfo.processInfo.environment["MDK_SMOKE_RELAY_URL"] else {
      throw SmokeError.setup(
        "Run bash crates/marmot-uniffi/native-host-smoke.sh to start the local relay")
    }
    // A hard stop also bounds a stuck native call; ordinary waits throw and run teardown.
    let watchdog = DispatchWorkItem {
      fputs(
        "Native host smoke exceeded its 180-second deadline; inspect the last stage below\n", stderr
      )
      exit(1)
    }
    DispatchQueue.global().asyncAfter(deadline: .now() + 180, execute: watchdog)
    addTeardownBlock { watchdog.cancel() }

    let files = FileManager.default
    let parent = files.temporaryDirectory.resolvingSymlinksInPath()
    let root = parent.appendingPathComponent("marmot-host-\(UUID().uuidString)", isDirectory: true)
    try files.createDirectory(
      at: root, withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700])
    addTeardownBlock { try files.removeItem(at: root) }

    let aliceStore = MemorySecretStore()
    let bobStore = MemorySecretStore()
    let aliceRoot = root.appendingPathComponent("alice", isDirectory: true)
    let alice = try open(root: aliceRoot, relay: relay, store: aliceStore)
    let bob = try open(
      root: root.appendingPathComponent("bob", isDirectory: true),
      relay: relay, store: bobStore)

    print("Native host smoke: start both runtimes")
    _ = try await alice.start()
    _ = try await bob.start()
    print("Native host smoke: create synthetic accounts")
    let aliceId = try await alice.createIdentityWithProfile(
      defaultRelays: [relay], bootstrapRelays: [relay], inboxRelays: [relay]
    ).account
    let bobId = try await bob.createIdentityWithProfile(
      defaultRelays: [relay], bootstrapRelays: [relay], inboxRelays: [relay]
    ).account
    XCTAssertTrue(try alice.listAccounts().contains { $0.accountIdHex == aliceId.accountIdHex })
    XCTAssertTrue(try bob.listAccounts().contains { $0.accountIdHex == bobId.accountIdHex })

    // RelayHealthFfi.totalRelays is a pool snapshot, not an account-publication barrier.
    try await waitUntil("Alice account publication") {
      try self.networkReady(alice, account: aliceId.label)
    }
    try await waitUntil("Bob account publication") {
      try self.networkReady(bob, account: bobId.label)
    }
    print("Native host smoke: deliver and accept Welcome")
    let creation = try await alice.createGroup(
      accountRef: aliceId.label, name: "Native host smoke", memberRefs: [bobId.accountIdHex],
      description: nil)
    let group = try XCTUnwrap(creation.groupIdHex)
    try await waitUntil("Bob Welcome delivery") {
      try bob.chatList(accountRef: bobId.label, includeArchived: false)
        .contains { $0.groupIdHex == group }
    }
    _ = try await bob.acceptGroupInvite(accountRef: bobId.label, groupIdHex: group)

    print("Native host smoke: deliver message to Bob")
    let text = "Synthetic native-host message"
    _ = try await alice.sendText(accountRef: aliceId.label, groupIdHex: group, text: text)
    try await waitUntil("Bob decrypted message delivery") {
      try bob.messages(accountRef: bobId.label, groupIdHex: group, limit: 20, kinds: [9])
        .contains { $0.plaintext == text && $0.sender == aliceId.accountIdHex }
    }
    let delivered = try bob.messages(
      accountRef: bobId.label, groupIdHex: group, limit: 20, kinds: [9]
    )
    .filter { $0.plaintext == text && $0.sender == aliceId.accountIdHex }
    XCTAssertEqual(delivered.count, 1)

    print("Native host smoke: scoped reaction removal")
    let target = try XCTUnwrap(delivered.first).messageIdHex
    func reactions(_ kit: Marmot) throws -> [TimelineUserReactionFfi] {
      try kit.messageReactions(
        accountRef: aliceId.label, groupIdHex: group, messageIdHex: target)
    }
    func reactionIds(_ values: [TimelineUserReactionFfi]) -> Set<String> {
      Set(values.map(\.reactionMessageIdHex))
    }
    for emoji in ["👍", "❤️"] {
      _ = try await alice.reactToMessage(
        accountRef: aliceId.label, groupIdHex: group, targetMessageId: target, emoji: emoji)
    }
    let initialReactionsSecond = UInt64(Date().timeIntervalSince1970)
    _ = try await bob.reactToMessage(
      accountRef: bobId.label, groupIdHex: group, targetMessageId: target, emoji: "👍")
    try await waitUntil("Alice reaction projection") { try reactions(alice).count == 3 }
    let staleHostReactions = try reactions(alice)
    try await expectReactionNotFound {
      _ = try await alice.unreactFromMessageMatching(
        accountRef: aliceId.label, groupIdHex: group, targetMessageId: target, emoji: "🔥")
    }
    XCTAssertEqual(reactionIds(try reactions(alice)), reactionIds(staleHostReactions))
    let preserved = staleHostReactions.filter {
      !($0.sender == aliceId.accountIdHex && $0.emoji == "👍")
    }
    _ = try await alice.unreactFromMessageMatching(
      accountRef: aliceId.label, groupIdHex: group, targetMessageId: target, emoji: "👍")
    XCTAssertEqual(reactionIds(try reactions(alice)), reactionIds(preserved))
    XCTAssertTrue(
      staleHostReactions.contains {
        $0.sender == aliceId.accountIdHex && $0.emoji == "👍"
      })
    try await expectReactionNotFound {
      _ = try await alice.unreactFromMessageMatching(
        accountRef: aliceId.label, groupIdHex: group, targetMessageId: target, emoji: "👍")
    }

    func makeRemovalHandle() -> UInt64 {
      uniffi_marmot_uniffi_fn_method_marmot_unreact_from_message_matching(
        alice.uniffiClonePointer(), lowerNativeString(aliceId.label),
        lowerNativeString(group), lowerNativeString(target), lowerNativeString("❤️"))
    }
    // No poll means the Tokio wrapper has not admitted any work.
    let unpolled = makeRemovalHandle()
    cancelAndFreeNative(unpolled)
    XCTAssertEqual(reactionIds(try reactions(alice)), reactionIds(preserved))

    // One poll starts the real operation. Observe its effect before cancellation;
    // neither task creation nor an elapsed delay proves native admission.
    let bobOnly = staleHostReactions.filter { $0.sender == bobId.accountIdHex }
    let admitted = makeRemovalHandle()
    do {
      defer { cancelAndFreeNative(admitted) }
      ffi_marmot_uniffi_rust_future_poll_rust_buffer(admitted, { _, _ in }, 0)
      try await waitUntil("Native removal before cancellation") {
        try reactionIds(reactions(alice)) == reactionIds(bobOnly)
      }
    }
    XCTAssertEqual(reactionIds(try reactions(alice)), reactionIds(bobOnly))
    try await expectReactionNotFound {
      _ = try await alice.unreactFromMessageMatching(
        accountRef: aliceId.label, groupIdHex: group, targetMessageId: target, emoji: "❤️")
    }

    // Re-added events need a distinct authored second to avoid deleted IDs.
    try await waitUntil("Next authored second after initial reactions") {
      UInt64(Date().timeIntervalSince1970) > initialReactionsSecond
    }
    for emoji in ["👍", "❤️"] {
      _ = try await alice.reactToMessage(
        accountRef: aliceId.label, groupIdHex: group, targetMessageId: target, emoji: emoji)
    }
    XCTAssertEqual(try reactions(alice).count, 3)
    _ = try await alice.unreactFromMessage(
      accountRef: aliceId.label, groupIdHex: group, targetMessageId: target)
    XCTAssertEqual(reactionIds(try reactions(alice)), reactionIds(bobOnly))

    print("Native host smoke: close and reopen Alice with retained store")
    try await alice.shutdownAndClose()
    XCTAssertTrue(alice.storageIsClosed())
    let reopened = try open(root: aliceRoot, relay: relay, store: aliceStore)
    _ = try await reopened.start()
    XCTAssertEqual(try reopened.listAccounts().map(\.accountIdHex), [aliceId.accountIdHex])
    // The host's retained snapshot still contains the removed reaction.
    try await expectReactionNotFound {
      _ = try await reopened.unreactFromMessageMatching(
        accountRef: aliceId.label, groupIdHex: group, targetMessageId: target, emoji: "👍")
    }
    XCTAssertEqual(reactionIds(try reactions(reopened)), reactionIds(bobOnly))
    // Continued delivery proves retained keys can reopen encrypted account state.
    let reply = "Synthetic message after root reuse"
    _ = try await reopened.sendText(accountRef: aliceId.label, groupIdHex: group, text: reply)
    try await waitUntil("Bob delivery after Alice root reuse") {
      try bob.messages(accountRef: bobId.label, groupIdHex: group, limit: 20, kinds: [9])
        .contains { $0.plaintext == reply && $0.sender == aliceId.accountIdHex }
    }
    try await reopened.shutdownAndClose()
    try await bob.shutdownAndClose()
    print("Native host smoke: delivery and root reuse passed")
  }

  private func expectReactionNotFound(_ operation: () async throws -> Void) async throws {
    do {
      try await operation()
      XCTFail("Missing reaction removal succeeded")
    } catch MarmotKitError.ReactionNotFound {
    }
  }

  private func lowerNativeString(_ value: String) -> RustBuffer {
    Array(value.utf8).withUnsafeBufferPointer { bytes in
      var status = RustCallStatus(code: 0, errorBuf: .init(capacity: 0, len: 0, data: nil))
      let buffer = ffi_marmot_uniffi_rustbuffer_from_bytes(
        ForeignBytes(len: Int32(bytes.count), data: bytes.baseAddress), &status)
      precondition(status.code == 0, "Native argument allocation failed")
      return buffer
    }
  }

  private func cancelAndFreeNative(_ handle: UInt64) {
    ffi_marmot_uniffi_rust_future_cancel_rust_buffer(handle)
    ffi_marmot_uniffi_rust_future_free_rust_buffer(handle)
  }

  private func open(root: URL, relay: String, store: MemorySecretStore) throws -> Marmot {
    let kit = try Marmot.newWithConfiguration(
      rootPath: root.path, relayUrls: [relay],
      options: MarmotOptions(
        relayPolicy: .allowLoopback, secretStore: store,
        deployment: marmotDeploymentNeutral()))
    addTeardownBlock {
      if !kit.storageIsClosed() {
        try await kit.shutdownAndClose()
      }
    }
    return kit
  }

  private func networkReady(_ kit: Marmot, account: String) throws -> Bool {
    let state = try kit.accountSetupReadiness(accountRef: account)
    if state == .recoveryRequired {
      throw SmokeError.setup("Account setup requires recovery; local publication failed")
    }
    return state == .networkReady
  }

  private func waitUntil(_ stage: String, ready: () throws -> Bool) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(30))
    while true {
      if try ready() {
        return
      }
      if clock.now >= deadline {
        throw SmokeError.timedOut(stage)
      }
      // Poll produced state rather than assuming a fixed delay establishes readiness.
      try await Task.sleep(for: .milliseconds(20))
    }
  }
}
