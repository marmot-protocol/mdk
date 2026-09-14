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
        print("Swift C4 window and attention round trips passed")
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
