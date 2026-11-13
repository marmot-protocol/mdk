import Foundation
import MarmotKit
import XCTest

// Test-only plaintext storage. Keep the same instance when reopening its root.
private final class MemorySecretStore: SecretStore, @unchecked Sendable {
  private struct Credential {
    let label: String
    let secret: String
  }

  private let lock = NSLock()
  private var credentials: [String: Credential] = [:]

  func hasSecretForLabel(label: String) throws -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return credentials.values.contains { $0.label == label }
  }

  func hasSecretForAccountId(accountIdHex: String) throws -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return credentials[accountIdHex] != nil
  }

  func writeSecret(label: String, accountIdHex: String, secretKeyHex: String) throws {
    lock.lock()
    defer { lock.unlock() }
    credentials[accountIdHex] = Credential(label: label, secret: secretKeyHex)
  }

  func loadSecret(label: String, accountIdHex: String) throws -> String {
    lock.lock()
    defer { lock.unlock() }
    guard let credential = credentials[accountIdHex], credential.label == label else {
      throw MarmotKitError.SecretNotFound(details: "Synthetic test credential missing")
    }
    return credential.secret
  }

  func removeSecret(label: String, accountIdHex: String) throws {
    lock.lock()
    defer { lock.unlock() }
    credentials.removeValue(forKey: accountIdHex)
  }
}

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

    // start().totalRelays is a pool snapshot, not an account-publication barrier.
    try await waitUntil("Alice account publication") {
      try self.networkReady(alice, account: aliceId.label)
    }
    try await waitUntil("Bob account publication") {
      try self.networkReady(bob, account: bobId.label)
    }
    print("Native host smoke: deliver and accept Welcome")
    let group = try await alice.createGroup(
      accountRef: aliceId.label, name: "Native host smoke", memberRefs: [bobId.accountIdHex],
      description: nil)
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

    print("Native host smoke: close and reopen Alice with retained store")
    try await alice.shutdownAndClose()
    XCTAssertTrue(alice.storageIsClosed())
    let reopened = try open(root: aliceRoot, relay: relay, store: aliceStore)
    _ = try await reopened.start()
    XCTAssertEqual(try reopened.listAccounts().map(\.accountIdHex), [aliceId.accountIdHex])
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
