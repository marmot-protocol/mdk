import Foundation

@main
struct ChatProjectionsSmoke {
    static func main() throws {
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
        try conversationRoundTrips()
        print("Swift C4/C5 projection round trips passed")
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
    let reactions = ConversationReactionsFfi(totalCount: UInt64.max, totalKinds: 10,
        items: [ConversationReactionFfi(emoji: "👍", count: UInt64.max, reactors: ["author"])], omittedKinds: 9)
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
