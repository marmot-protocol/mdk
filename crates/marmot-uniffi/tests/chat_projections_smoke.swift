import Foundation

@main
struct ChatProjectionsSmoke {
    static func main() throws {
        for provenance in [GroupSystemEventProvenanceFfi.authenticatedGroupState, .memberAuthored] {
            let event = GroupSystemEventFfi(provenance: provenance, actorDisplayName: "Actor", subjectDisplayName: "Subject",
                systemType: "member_added", text: "Member added", actorAccountIdHex: "actor", subjectAccountIdHex: "subject",
                name: nil, oldName: nil, oldRetentionSeconds: nil, newRetentionSeconds: nil)
            let preview = ChatListMessagePreviewFfi(groupSystem: event, messageIdHex: "selected", sender: "actor", senderDisplayName: nil,
                plaintext: "raw", contentTokens: MarkdownDocumentFfi(blocks: [], truncated: false, blankLinesBefore: Data()), kind: 1210, timelineAt: 50, deleted: false,
                attachmentKind: nil, attachmentCount: 0, deliveryState: .notApplicable)
            let copy = try FfiConverterTypeChatListMessagePreviewFfi.lift(FfiConverterTypeChatListMessagePreviewFfi.lower(preview))
            precondition(copy == preview && copy.groupSystem?.provenance == provenance)
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
