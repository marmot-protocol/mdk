import Foundation
#if canImport(MarmotKit)
import MarmotKit
#endif

// Test-only plaintext memory vault. Retain this instance across root reopening.
final class MemorySecretStore: SecretStore, @unchecked Sendable {
  private struct Receipt {
    let record: SecretCredential
    var secret: String?
    let origin: SecretOrigin
    var release: SecretReleaseMode?
  }

  private let namespace = UUID().uuidString
  private let lock = NSLock()
  private var receipts: [Receipt] = []

  func cleanupNamespace() throws -> String { namespace }

  private func sameSlot(_ a: SecretCredential, _ b: SecretCredential) -> Bool {
    a.kind == b.kind && a.accountIdHex == b.accountIdHex
      && (a.kind == .signing || a.homeId == b.homeId)
  }

  private func conflict() -> MarmotKitError {
    .Runtime(details: "In-memory credential ownership conflict")
  }

  private func missing() -> MarmotKitError {
    .SecretNotFound(details: "In-memory credential missing")
  }

  func hasSecretForLabel(label: String) throws -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return receipts.contains {
      $0.record.kind == .signing && $0.record.label == label && $0.secret != nil
    }
  }

  func hasSecretForAccountId(accountIdHex: String) throws -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return receipts.contains {
      $0.record.kind == .signing && $0.record.accountIdHex == accountIdHex && $0.secret != nil
    }
  }

  func acquireSecret(record: SecretCredential, mode: SecretClaimMode, proposedHex: String?) throws -> AcquiredSecret {
    lock.lock()
    defer { lock.unlock() }
    if let prior = receipts.first(where: { $0.record.ownerId == record.ownerId }) {
      guard prior.record == record, prior.release == nil else { throw conflict() }
      guard let secret = prior.secret else { throw missing() }
      guard proposedHex == nil || proposedHex == secret else { throw conflict() }
      return AcquiredSecret(secretKeyHex: secret, origin: prior.origin)
    }
    let source = receipts.first { sameSlot($0.record, record) && $0.secret != nil }
    if mode == .createOnly && (source != nil || proposedHex == nil) { throw conflict() }
    if (mode == .adoptOnly || mode == .migrateLegacy) && source == nil { throw missing() }
    guard let secret = source?.secret ?? proposedHex else { throw missing() }
    guard proposedHex == nil || proposedHex == secret else { throw conflict() }
    guard secret.utf8.count == 64,
      secret.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) })
    else { throw conflict() }
    let origin: SecretOrigin = source == nil ? .created : .existing
    receipts.append(Receipt(record: record, secret: secret, origin: origin, release: nil))
    for index in receipts.indices {
      if sameSlot(receipts[index].record, record) && receipts[index].release == .preserve {
        receipts[index].secret = nil
      }
    }
    return AcquiredSecret(secretKeyHex: secret, origin: origin)
  }

  func loadSecret(record: SecretCredential) throws -> String {
    lock.lock()
    defer { lock.unlock() }
    guard let secret = receipts.first(where: { $0.record == record && $0.release == nil })?.secret
    else { throw missing() }
    return secret
  }

  func releaseSecret(record: SecretCredential, mode: SecretReleaseMode) throws -> SecretReleaseOutcome {
    lock.lock()
    defer { lock.unlock() }
    if let index = receipts.firstIndex(where: { $0.record.ownerId == record.ownerId }) {
      guard receipts[index].record == record else { throw conflict() }
      if receipts[index].release == nil {
        receipts[index].release = mode
        if mode == .deleteIfUnowned { receipts[index].secret = nil }
      }
    } else {
      receipts.append(Receipt(record: record, secret: nil, origin: .existing, release: mode))
    }
    return .released
  }

  func reconcileCleanup() throws {
    lock.lock()
    defer { lock.unlock() }
    for index in receipts.indices {
      if receipts[index].release == .deleteIfUnowned { receipts[index].secret = nil }
    }
  }
}
