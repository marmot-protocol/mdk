import Foundation

private final class OptionsStore: SecretStore, @unchecked Sendable {
    func hasSecretForLabel(label: String) throws -> Bool { label == "probe" }
    func hasSecretForAccountId(accountIdHex: String) throws -> Bool { false }
    func writeSecret(label: String, accountIdHex: String, secretKeyHex: String) throws {}
    func loadSecret(label: String, accountIdHex: String) throws -> String { "callback-probe" }
    func removeSecret(label: String, accountIdHex: String) throws {}
}

@main
struct OptionsSmoke {
    static func main() throws {
        let defaults = MarmotOptions()
        precondition(defaults.relayPolicy == nil && defaults.cursorPersistence == nil)
        precondition(defaults.clientName == nil && defaults.secretStore == nil)
        let options = MarmotOptions(
            relayPolicy: .allowLoopbackRelaysAndBlobs,
            cursorPersistence: .frozen,
            clientName: "whitenoise"
        )
        var copy = try FfiConverterTypeMarmotOptions.lift(FfiConverterTypeMarmotOptions.lower(options))
        precondition(copy.relayPolicy == .allowLoopbackRelaysAndBlobs)
        precondition(copy.cursorPersistence == .frozen && copy.clientName == "whitenoise")
        // Foreign callback handles must cross into Rust; local lower/lift is
        // only valid here while the callback field is nil.
        copy.secretStore = OptionsStore()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let kit = try Marmot.newWithConfiguration(
            rootPath: root.path, relayUrls: ["ws://127.0.0.1:1"], options: copy
        )
        let accounts = try kit.listAccounts()
        precondition(accounts.isEmpty)
        print("Swift runtime options defaults and host-store construction passed")
    }
}
