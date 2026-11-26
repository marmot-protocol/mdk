import Foundation

private final class OptionsStore: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var secrets: [String: (label: String, key: String)] = [:]

    func hasSecretForLabel(label: String) throws -> Bool {
        lock.withLock { label == "probe" || secrets.values.contains { $0.label == label } }
    }
    func hasSecretForAccountId(accountIdHex: String) throws -> Bool {
        lock.withLock { secrets[accountIdHex] != nil }
    }
    func writeSecret(label: String, accountIdHex: String, secretKeyHex: String) throws {
        lock.withLock { secrets[accountIdHex] = (label, secretKeyHex) }
    }
    func loadSecret(label: String, accountIdHex: String) throws -> String {
        try lock.withLock {
            guard let secret = secrets[accountIdHex], secret.label == label else {
                throw MarmotKitError.SecretNotFound(details: "Missing smoke credential")
            }
            return secret.key
        }
    }
    func removeSecret(label: String, accountIdHex: String) throws {
        lock.withLock { secrets[accountIdHex] = nil }
    }
}

@main
struct OptionsSmoke {
    static func main() async throws {
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
        let session = try kit.nip46New(configJson: "{\"relays\":[\"ws://127.0.0.1:1\"],\"name\":\"Swift permissions\"}")
        precondition(session.status().state == .permissionApproval)
        do {
            _ = try session.uri()
            preconditionFailure("unapproved session exposed a pairing URI")
        } catch Nip46ErrorFfi.PermissionApprovalRequired {
        }
        let reviewed = session.reviewPermissions()
        try await session.approvePermissions(version: reviewed.version, grants: reviewed.grants)
        let pairingUri = try session.uri()
        precondition(pairingUri.hasPrefix("nostrconnect://"))
        do {
            try session.cancelRequest(requestId: "stale")
            preconditionFailure("stale request cancellation succeeded")
        } catch Nip46ErrorFfi.RequestNotFound {
        }
        session.disconnect()
        precondition(session.status().state == .disconnected)
        session.cancel()
        precondition(session.status().state == .cancelled)
        // The kept experimental alias still opens.
        let experimentalRoot = root.appendingPathComponent("experimental")
        let experimental = try Marmot.newWithExperimentalDeviceGroups(
            rootPath: experimentalRoot.path, relayUrls: ["ws://127.0.0.1:1"], options: copy
        )
        let experimentalAccounts = try experimental.listAccounts()
        precondition(experimentalAccounts.isEmpty)

        let relay = "ws://127.0.0.1:1"
        try await kit.start()
        let account = try await kit.createIdentityWithProfile(
            defaultRelays: [relay], bootstrapRelays: [relay]
        ).account
        let groupOptions = CreateGroupOptionsFfi(
            description: nil, initialImage: nil, disappearingMessageSecs: 0)
        let creation = try await kit.createGroupWithOptions(
            accountRef: account.label, name: "Founding admins smoke", memberRefs: [], options: groupOptions)
        guard let group = creation.groupIdHex else {
            preconditionFailure("creator-only group was not created")
        }
        let members = try await kit.groupDetails(accountRef: account.label, groupIdHex: group).members
        precondition(members.count == 1 && members[0].isSelf && members[0].isAdmin)

        var invalidOptions = groupOptions
        invalidOptions.initialAdmins = ["79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"]
        do {
            _ = try await kit.createGroupWithOptions(
                accountRef: account.label, name: "Invalid admin smoke", memberRefs: [], options: invalidOptions)
            preconditionFailure("native group creation accepted a nonmember admin")
        } catch MarmotKitError.Runtime(let details) {
            precondition(details == "initial admins must be founding members")
        }
        try await kit.shutdownAndClose()
        print("Swift onboarding diagnostics, runtime options and host-store construction passed")
    }
}
