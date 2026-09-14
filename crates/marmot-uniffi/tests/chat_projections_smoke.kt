package dev.ipf.marmotkit

fun main() {
    val anchors = listOf(ChatListAnchorOutcomeFfi.Top, ChatListAnchorOutcomeFfi.Retained("aabb", 0u),
        ChatListAnchorOutcomeFfi.Recovered("ccdd", 199u), ChatListAnchorOutcomeFfi.Reset)
    for (view in ChatListViewFfi.entries) {
        for (anchor in anchors) {
            val value = ChatListWindowSnapshotFfi("generation", ULong.MAX_VALUE, view, emptyList(), true, false, anchor)
            val copy = FfiConverterTypeChatListWindowSnapshotFfi.lift(FfiConverterTypeChatListWindowSnapshotFfi.lower(value))
            check(copy == value)
        }
    }
    val states = listOf(AccountAttentionStateFfi.Ready(AccountAttentionTotalFfi(ULong.MAX_VALUE, 7u, 4u, 1u)),
        AccountAttentionStateFfi.Unavailable(AccountAttentionUnavailableFfi.PREPARING),
        AccountAttentionStateFfi.Unavailable(AccountAttentionUnavailableFfi.READ_FAILED),
        AccountAttentionStateFfi.Unavailable(AccountAttentionUnavailableFfi.RESETTING))
    val value = AccountAttentionSnapshotFfi("summary", ULong.MAX_VALUE, states.map { AccountAttentionEntryFfi("account", it) })
    val copy = FfiConverterTypeAccountAttentionSnapshotFfi.lift(FfiConverterTypeAccountAttentionSnapshotFfi.lower(value))
    check(copy == value)
    println("Kotlin C4 window and attention round trips passed")
}

suspend fun compileScreenCommands(marmot: Marmot, account: String) {
    marmot.openChatListWindow(account, ChatListViewFfi.CHATS, 50u).use { list ->
        list.snapshot()?.let { initial ->
            val page = list.page(initial.sequence, ChatListPageDirectionFfi.FORWARD, 50u)
            page.rows.firstOrNull()?.let { row ->
                val anchored = list.setVisibleAnchor(page.sequence, row.row.groupIdHex)
                list.returnToTop(anchored.sequence)
            }
        }
        list.next()
    }
    marmot.subscribeAccountAttention().use { summary ->
        summary.snapshot()
        summary.next()
    }
}
