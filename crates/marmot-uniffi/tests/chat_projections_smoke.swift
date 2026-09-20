import Foundation

@main
struct ChatProjectionsSmoke {
    static func main() throws {
        for preview in [SelectedChatPreviewFfi.draft(draft: ChatListDraftPreviewFfi(text: "draft 🦀", textTruncated: true, attachmentCount: 2, attachmentKind: .mixed)), .message, .invitation, .empty] {
            let copy = try FfiConverterTypeSelectedChatPreviewFfi.lift(FfiConverterTypeSelectedChatPreviewFfi.lower(preview))
            precondition(copy == preview)
        }
        let rowActions = ChatListRowActionsFfi(canMarkRead: true, canMarkUnread: false, canPin: true, canUnpin: false, canMute: true, canUnmute: false, canArchive: true, canRestore: false, canStartLeave: true, canDeleteLocal: false)
        let rowActionsCopy = try FfiConverterTypeChatListRowActionsFfi.lift(FfiConverterTypeChatListRowActionsFfi.lower(rowActions))
        precondition(rowActionsCopy == rowActions)

        let transfer = AttachmentTransferStatusFfi(reference: "job", state: .verifyingPlaintext, attempt: UInt64.max, received: 17, total: nil, retryAt: 42)
        let transferFrame = AttachmentTransferSnapshotFfi(items: [transfer])
        let transferCopy = try FfiConverterTypeAttachmentTransferSnapshotFfi.lift(FfiConverterTypeAttachmentTransferSnapshotFfi.lower(transferFrame))
        precondition(transferCopy == transferFrame)
        let localTarget = AttachmentLocalTargetFfi(messageIdHex: "message", sourceMessageIdHex: "source", attachmentIndex: UInt32.max)
        let localTargetCopy = try FfiConverterTypeAttachmentLocalTargetFfi.lift(FfiConverterTypeAttachmentLocalTargetFfi.lower(localTarget))
        precondition(localTargetCopy == localTarget)
        for asset in [AttachmentLocalAssetFfi(reference: nil, byteCount: 0), AttachmentLocalAssetFfi(reference: "opaque", byteCount: UInt64.max)] {
            let copy = try FfiConverterTypeAttachmentLocalAssetFfi.lift(FfiConverterTypeAttachmentLocalAssetFfi.lower(asset))
            precondition(copy == asset)
        }
        for chunk in [AttachmentLocalBytesFfi(available: false, bytes: Data()), AttachmentLocalBytesFfi(available: true, bytes: Data()), AttachmentLocalBytesFfi(available: true, bytes: Data([0,255,0,42]))] {
            let copy = try FfiConverterTypeAttachmentLocalBytesFfi.lift(FfiConverterTypeAttachmentLocalBytesFfi.lower(chunk))
            precondition(copy == chunk)
        }
        let timing = RuntimePerformanceSnapshotFfi(operation: "conversation_open", started: 5,
            completed: 4, successes: 1, failures: 1, cancelled: 1, timeouts: 1, notReady: 0,
            inFlight: 1, oldestTrackedInFlightMs: 800, untrackedInFlight: 0,
            durationMs: DurationHistogramSnapshotFfi(buckets: [DurationHistogramBucketFfi(upperBoundMs: 100, count: 4)], overflowCount: 0, sumMs: 400))
        let timingCopy = try FfiConverterTypeRuntimePerformanceSnapshotFfi.lift(FfiConverterTypeRuntimePerformanceSnapshotFfi.lower(timing))
        precondition(timingCopy == timing)
        for outcome in [HostPerformanceOutcomeFfi.success, .failure, .cancelled, .timeout, .unavailable] {
            let outcomeCopy = try FfiConverterTypeHostPerformanceOutcomeFfi.lift(FfiConverterTypeHostPerformanceOutcomeFfi.lower(outcome))
            precondition(outcomeCopy == outcome)
        }
        for state in [AvatarAvailabilityFfi.missing, .ready, .stale, .invalidated] {
            for acquisition in [AvatarAcquisitionStateFfi.idle, .queued, .fetching, .retryScheduled, .blocked] {
                let asset = AvatarAssetFfi(target: "opaque-target", reference: "opaque-reference", availability: state, acquisition: acquisition, contentRevision: 7, byteCount: 4)
                let copy = try FfiConverterTypeAvatarAssetFfi.lift(FfiConverterTypeAvatarAssetFfi.lower(asset))
                precondition(copy == asset)
            }
            let image = AvatarBytesFfi(reference: "opaque-reference", availability: state, contentRevision: 7, byteCount: 4, deferred: false, bytes: Data([1,2,3,4]), mediaType: "image/png", width: 1, height: 1)
            let copy = try FfiConverterTypeAvatarBytesFfi.lift(FfiConverterTypeAvatarBytesFfi.lower(image))
            precondition(copy == image)
        }
        for provenance in [GroupSystemEventProvenanceFfi.authenticatedGroupState, .memberAuthored] {
            let event = GroupSystemEventFfi(provenance: provenance, actorDisplayName: "Actor", subjectDisplayName: "Subject",
                systemType: "member_added", text: "Member added", actorAccountIdHex: "actor", subjectAccountIdHex: "subject",
                name: nil, oldName: nil, oldRetentionSeconds: nil, newRetentionSeconds: nil)
            let preview = ChatListMessagePreviewFfi(groupSystem: event, messageIdHex: "selected", sender: "actor", senderDisplayName: nil,
                plaintext: "raw", contentTokens: MarkdownDocumentFfi(blocks: [], truncated: false, blankLinesBefore: Data()), kind: 1210, timelineAt: 50,
                retentionSeconds: nil, retentionExpiresAt: nil, deleted: false, deletionSource: .unknown,
                attachmentKind: nil, attachmentCount: 0, deliveryState: .notApplicable)
            let copy = try FfiConverterTypeChatListMessagePreviewFfi.lift(FfiConverterTypeChatListMessagePreviewFfi.lower(preview))
            precondition(copy == preview && copy.groupSystem?.provenance == provenance)
            let decisions: [(UInt64?, UInt64?)] = [(nil, nil), (0, nil), (300, 350), (300, nil)]
            for (seconds, expiry) in decisions {
                var timed = preview
                timed.retentionSeconds = seconds
                timed.retentionExpiresAt = expiry
                let timedCopy = try FfiConverterTypeChatListMessagePreviewFfi.lift(FfiConverterTypeChatListMessagePreviewFfi.lower(timed))
                precondition(timedCopy.retentionSeconds == seconds && timedCopy.retentionExpiresAt == expiry)
            }
        }
        for source in [DeletionSourceFfi.author, .admin, .unknown] {
            let preview = TimelineReplyPreviewFfi(messageIdHex: "deleted", sender: "author", plaintext: "",
                contentTokens: MarkdownDocumentFfi(blocks: [], truncated: false, blankLinesBefore: Data()), kind: 9,
                mediaJson: nil, media: [], agentTextStreamJson: nil, deleted: true, deletionSource: source, invalidationStatus: nil)
            let copy = try FfiConverterTypeTimelineReplyPreviewFfi.lift(FfiConverterTypeTimelineReplyPreviewFfi.lower(preview))
            precondition(copy == preview && copy.deletionSource == source)
        }
        let blocks = BlockListSnapshotFfi(revision: UInt64.max, users: [BlockedUserFfi(publicKey: "key", isPrivate: true, createdAtMs: 123)])
        let blockCopy = try FfiConverterTypeBlockListSnapshotFfi.lift(FfiConverterTypeBlockListSnapshotFfi.lower(blocks))
        precondition(blockCopy == blocks)
        let anchors: [ChatListAnchorOutcomeFfi] = [
            .top, .retained(groupIdHex: "aabb", index: 0),
            .recovered(groupIdHex: "ccdd", index: 199), .reset,
        ]
        for view in [ChatListViewFfi.chats, .unread, .archived, .left] {
            for anchor in anchors {
                let value = ChatListWindowSnapshotFfi(subscriptionGeneration: "generation", sequence: UInt64.max,
                    view: view, rows: [], hasMoreBefore: true, hasMoreAfter: false, anchor: anchor)
                let copy = try FfiConverterTypeChatListWindowSnapshotFfi.lift(FfiConverterTypeChatListWindowSnapshotFfi.lower(value))
                precondition(copy == value)
            }
        }
        let total = AccountAttentionTotalFfi(unreadCount: UInt64.max, unreadMentionCount: 7,
            unreadConversations: 4, attentionOnlyConversations: 1)
        let states: [AccountAttentionStateFfi] = [.ready(total: total),
            .unavailable(reason: .preparing), .unavailable(reason: .readFailed), .unavailable(reason: .resetting)]
        let value = AccountAttentionSnapshotFfi(subscriptionGeneration: "summary", sequence: UInt64.max,
            accounts: states.map { AccountAttentionEntryFfi(accountIdHex: "account", state: $0) })
        let copy = try FfiConverterTypeAccountAttentionSnapshotFfi.lift(FfiConverterTypeAccountAttentionSnapshotFfi.lower(value))
        precondition(copy == value)
        let report = ContentReportFfi(reportIdHex: "report", messageIdHex: "message", messageAuthor: "author", reporter: "member",
            reason: .other, explanation: "explanation", reportedAt: 42, dismissed: true)
        let reports = ContentReportPageFfi(reports: [report], nextCursor: nil)
        let reportsCopy = try FfiConverterTypeContentReportPageFfi.lift(FfiConverterTypeContentReportPageFfi.lower(reports))
        precondition(reportsCopy == reports)
        let labels = ReportDismissalPageFfi(labels: [ReportDismissalFfi(eventIdHex: "label", admin: "admin", explanation: "reviewed", createdAt: 43)], nextCursor: "cursor")
        let labelsCopy = try FfiConverterTypeReportDismissalPageFfi.lift(FfiConverterTypeReportDismissalPageFfi.lower(labels))
        precondition(labelsCopy == labels)
        let edit = TimelineEditSummaryFfi(editCount: 3, latestEditMessageIdHex: "edit", editedAt: 17)
        let editCopy = try FfiConverterTypeTimelineEditSummaryFfi.lift(FfiConverterTypeTimelineEditSummaryFfi.lower(edit))
        precondition(editCopy == edit)
        let history = TimelineEditHistoryPageFfi(versions: [TimelineEditVersionFfi(messageIdHex: "edit", editedAt: 17, plaintext: "replacement")], hasMoreBefore: true)
        let historyCopy = try FfiConverterTypeTimelineEditHistoryPageFfi.lift(FfiConverterTypeTimelineEditHistoryPageFfi.lower(history))
        precondition(historyCopy == history)
        try conversationRoundTrips()
        print("Swift C4/C5/C6 projection round trips passed")
    }
}

// Compile the host command surface as well as the records. Runtime/lifetime behavior
// is exercised by the Rust UniFFI/C boundary tests, with a local mock relay.
func compileScreenCommands(_ marmot: Marmot, account: String) async throws {
    let list = try await marmot.openChatListWindow(accountRef: account, view: .chats, initialRows: 50)
    if let initial = list.snapshot() {
        let page = try await list.page(sequence: initial.sequence, direction: .forward, count: 50)
        if let row = page.rows.first {
            let anchored = try await list.setVisibleAnchor(sequence: page.sequence, groupIdHex: row.row.groupIdHex)
            _ = try await list.returnToTop(sequence: anchored.sequence)
        }
    }
    _ = try await list.next()
    let summary = try await marmot.subscribeAccountAttention()
    _ = summary.snapshot()
    _ = try await summary.next()
}

func conversationRoundTrips() throws {
    let revision = ConversationWindowRevisionFfi(generation: "window", sequence: UInt64.max)
    let revisionCopy = try FfiConverterTypeConversationWindowRevisionFfi.lift(FfiConverterTypeConversationWindowRevisionFfi.lower(revision))
    precondition(revisionCopy == revision)
    for kind in [ConversationAnchorKindFfi.empty, .latest, .firstUnread, .message, .retained, .recoveredNext, .recoveredPrevious] {
        let value = ConversationAnchorOutcomeFfi(kind: kind, index: kind == .empty ? nil : 199)
        let copy = try FfiConverterTypeConversationAnchorOutcomeFfi.lift(FfiConverterTypeConversationAnchorOutcomeFfi.lower(value))
        precondition(copy == value)
    }
    for reacted in [false, true] {
        let value = ConversationReactionFfi(emoji: "👍", count: 3, reactors: ["other-a", "other-b"], viewerReacted: reacted)
        let copy = try FfiConverterTypeConversationReactionFfi.lift(FfiConverterTypeConversationReactionFfi.lower(value))
        precondition(copy.viewerReacted == reacted && copy == value)
    }
    let reactions = ConversationReactionsFfi(totalCount: UInt64.max, totalKinds: 10,
        items: [ConversationReactionFfi(emoji: "👍", count: UInt64.max, reactors: ["author"], viewerReacted: true)], omittedKinds: 9)
    let refs = ConversationMessageReferencesFfi(messageIdHex: "message", sender: "author", replyAuthor: nil,
        mentions: ["author"], mentionsTruncated: true, replyMentions: [], replyMentionsTruncated: false,
        system: ConversationSystemReferencesFfi(systemType: "member_removed", actor: "author", subject: nil), reactions: reactions)
    let copy = try FfiConverterTypeConversationMessageReferencesFfi.lift(FfiConverterTypeConversationMessageReferencesFfi.lower(refs))
    precondition(copy == refs)
    let attachment = SelectedMessageDraftAttachmentFfi(id: "a", fileName: "voice.ogg", mediaType: "audio/ogg",
        plaintextSize: UInt64.max, dim: nil, thumbhash: "thumb", durationSeconds: 1.5, waveformSamples: [0.2, 0.5])
    let draft = SelectedMessageDraftContentFfi(groupIdHex: "group", content: "unsent", replyToMessageIdHex: nil,
        mediaAttachments: [attachment], createdAtMs: 1, updatedAtMs: 2)
    let draftCopy = try FfiConverterTypeSelectedMessageDraftContentFfi.lift(FfiConverterTypeSelectedMessageDraftContentFfi.lower(draft))
    precondition(draftCopy == draft)
}
func compileConversationCommands(_ marmot: Marmot, account: String, group: String) async throws {
    let window = try await marmot.openConversationWindow(accountRef: account, groupIdHex: group,
        mode: .automatic, messageIdHex: nil, initialRows: 50, timeoutMs: 0)
    if let initial = window.snapshot() {
        let page = try await window.page(revision: initial.revision, direction: .older, count: 50, timeoutMs: 0)
        if let row = page.messages.first {
            let anchor = try await window.setVisibleAnchor(revision: page.revision, messageIdHex: row.timeline.messageIdHex, timeoutMs: 0)
            let jumped = try await window.jumpToMessage(revision: anchor.revision, messageIdHex: row.timeline.messageIdHex, timeoutMs: 0)
            _ = try await window.returnToLatest(revision: jumped.revision, timeoutMs: 0)
        }
        _ = try marmot.messageDraftAttachmentIfRevision(accountRef: account, revision: initial.draft.revision, attachmentId: "a")
        _ = try marmot.saveMessageDraftIfRevision(accountRef: account, revision: initial.draft.revision, content: "draft", replyToMessageIdHex: nil, mediaAttachments: [])
    }
    _ = try await window.next()
    await window.cancel()
}

func compileBlockCommands(_ marmot: Marmot, account: String, user: String) async throws {
    try await marmot.blockUser(accountRef: account, userAccountIdHex: user)
    try await marmot.unblockUser(accountRef: account, userAccountIdHex: user)
    _ = try marmot.getBlockedUsers(accountRef: account)
    _ = try marmot.isUserBlocked(accountRef: account, userAccountIdHex: user)
    let sub = try marmot.subscribeBlockedUsers(accountRef: account)
    _ = sub.snapshot()
    _ = await sub.next()
}

func compileModerationCommands(_ marmot: Marmot, account: String, group: String) async throws {
    _ = try await marmot.reportMessage(accountRef: account, groupIdHex: group, messageId: "message", reason: .spam, explanation: "")
    _ = try await marmot.dismissReports(accountRef: account, groupIdHex: group, reportIds: ["report"], explanation: "reviewed")
    _ = try marmot.contentReports(accountRef: account, groupIdHex: group, messageId: "message", after: nil, limit: 50)
    _ = try marmot.reportedMessage(accountRef: account, groupIdHex: group, messageId: "message")
    _ = try marmot.reportDismissals(accountRef: account, groupIdHex: group, reportId: "report", after: nil, limit: 50)
}

func compileEditHistory(_ marmot: Marmot, account: String, group: String, target: String) throws {
    let page = try marmot.messageEditHistory(accountRef: account, groupIdHex: group, targetMessageIdHex: target, beforeEditedAt: nil, beforeMessageIdHex: nil, limit: 50)
    if let oldest = page.versions.first {
        _ = try marmot.messageEditHistory(accountRef: account, groupIdHex: group, targetMessageIdHex: target, beforeEditedAt: oldest.editedAt, beforeMessageIdHex: oldest.messageIdHex, limit: 50)
    }
}

func compileAvatarCommands(_ marmot: Marmot, account: String, asset: AvatarAssetFfi) async throws {
    let requested = try await marmot.requestAvatarAssets(accountRef: account, targets: [asset.target])
    _ = try await marmot.readAvatarAssets(accountRef: account, references: requested.compactMap(\.reference), maxBytes: 1024 * 1024)
    try await marmot.clearAvatarCache(accountRef: account)
}

func compileAttachmentCommands(_ marmot: Marmot, account: String, group: String) async throws {
    let result = try await marmot.attachmentHistoryPage(accountRef: account, groupIdHex: group, limit: 50, cursor: nil)
    if case let .page(page) = result {
        let current = try await marmot.attachmentHistoryVersion(accountRef: account, groupIdHex: group)
        _ = current.changeSince(previous: page.version)
        if page.hasMore {
            _ = try await marmot.attachmentHistoryPage(accountRef: account, groupIdHex: group, limit: 50, cursor: page.nextCursor)
        }
    }
}

func compileLocalAttachmentCommands(_ marmot: Marmot, account: String, group: String,
                                    message: String, source: String, index: UInt32) async throws {
    let target = AttachmentLocalTargetFfi(messageIdHex: message, sourceMessageIdHex: source, attachmentIndex: index)
    let assets = try await marmot.attachmentLocalAssets(accountRef: account, groupIdHex: group, targets: [target])
    if let reference = assets.first?.reference {
        let chunk = try await marmot.readAttachmentAsset(accountRef: account, reference: reference, offset: 0, limit: 65536)
        if chunk.available { _ = chunk.bytes }
    }
}

func compileAttachmentControls(_ marmot: Marmot, account: String, group: String, target: AttachmentLocalTargetFfi) async throws {
    var policy = try await marmot.attachmentDownloadPolicy(accountRef: account)
    policy.automatic = false
    try await marmot.setAttachmentDownloadPolicy(accountRef: account, policy: policy)
    let snapshot = try await marmot.attachmentTransferSnapshot(accountRef: account, groupIdHex: group, targets: [target])
    if let reference = snapshot.items.first?.reference {
        _ = try await marmot.controlAttachment(accountRef: account, reference: reference, control: .cancel)
        _ = try await marmot.controlAttachment(accountRef: account, reference: reference, control: .retry)
        _ = try await marmot.controlAttachment(accountRef: account, reference: reference, control: .remove)
    }
    _ = try await marmot.downloadAttachmentAgain(accountRef: account, groupIdHex: group, target: target)
    let stream = try await marmot.subscribeAttachmentTransfers(accountRef: account, groupIdHex: group, targets: [target])
    _ = try await stream.next()
    stream.cancel()
}
