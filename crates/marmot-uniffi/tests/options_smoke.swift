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
        let findings = [
            OnboardingFindingFfi(issue: .timedOut, endpoint: "wss://example.com",
                context: .recordDiscovery, purpose: .recordLookup, outcome: .unknown,
                declaredCapability: .none, actions: [.retry], observedRevision: 7),
            OnboardingFindingFfi(issue: .timedOut, endpoint: "wss://example.com",
                context: .declaredRoute, purpose: .directoryQuery, outcome: .unknown,
                declaredCapability: .write, actions: [.retry], observedRevision: 7),
            OnboardingFindingFfi(issue: .inspectionCompleted, endpoint: "wss://read.example.com",
                context: .declaredRoute, purpose: .directoryQuery, outcome: .success,
                declaredCapability: .read, actions: [], observedRevision: 7),
        ]
        for finding in findings {
            let diagnostic = try FfiConverterTypeOnboardingFindingFfi.lift(FfiConverterTypeOnboardingFindingFfi.lower(finding))
            precondition(diagnostic == finding)
        }
        // The deployment is the one required field.
        let defaults = MarmotOptions(deployment: marmotDeploymentNeutral())
        precondition(defaults.relayPolicy == nil && defaults.cursorPersistence == nil)
        precondition(defaults.clientName == nil && defaults.secretStore == nil)
        precondition(defaults.deployment.keychainService == "org.marmot-protocol.mdk")
        let options = MarmotOptions(
            relayPolicy: .allowLoopbackRelaysAndBlobs,
            cursorPersistence: .frozen,
            clientName: "whitenoise",
            deployment: marmotDeploymentWhiteNoise()
        )
        var copy = try FfiConverterTypeMarmotOptions.lift(FfiConverterTypeMarmotOptions.lower(options))
        precondition(copy.relayPolicy == .allowLoopbackRelaysAndBlobs)
        precondition(copy.cursorPersistence == .frozen && copy.clientName == "whitenoise")
        precondition(copy.deployment.keychainService == "com.marmot.whitenoise")
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
        print("Swift onboarding diagnostics, runtime options and host-store construction passed")
    }
}
