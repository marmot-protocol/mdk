package dev.ipf.marmotkit

fun main() {
    val blocks = BlockListSnapshotFfi(ULong.MAX_VALUE, listOf(BlockedUserFfi("key", true, 123L)))
    check(FfiConverterTypeBlockListSnapshotFfi.lift(FfiConverterTypeBlockListSnapshotFfi.lower(blocks)) == blocks)
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
    conversationRoundTrips()
    println("Kotlin C4/C5 projection round trips passed")
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

fun conversationRoundTrips() {
    val revision = ConversationWindowRevisionFfi("window", ULong.MAX_VALUE)
    check(FfiConverterTypeConversationWindowRevisionFfi.lift(FfiConverterTypeConversationWindowRevisionFfi.lower(revision)) == revision)
    for (kind in ConversationAnchorKindFfi.entries) {
        val value = ConversationAnchorOutcomeFfi(kind, if (kind == ConversationAnchorKindFfi.EMPTY) null else 199u)
        check(FfiConverterTypeConversationAnchorOutcomeFfi.lift(FfiConverterTypeConversationAnchorOutcomeFfi.lower(value)) == value)
    }
    for (reacted in listOf(false, true)) {
        val value = ConversationReactionFfi("👍", 3u, listOf("other-a", "other-b"), reacted)
        val copy = FfiConverterTypeConversationReactionFfi.lift(FfiConverterTypeConversationReactionFfi.lower(value))
        check(copy.viewerReacted == reacted && copy == value)
    }
    val reactions = ConversationReactionsFfi(ULong.MAX_VALUE, 10u,
        listOf(ConversationReactionFfi("👍", ULong.MAX_VALUE, listOf("author"), true)), 9u)
    val refs = ConversationMessageReferencesFfi("message", "author", null, listOf("author"), true,
        emptyList(), false, ConversationSystemReferencesFfi("member_removed", "author", null), reactions)
    check(FfiConverterTypeConversationMessageReferencesFfi.lift(FfiConverterTypeConversationMessageReferencesFfi.lower(refs)) == refs)
    val attachment = SelectedMessageDraftAttachmentFfi("a", "voice.ogg", "audio/ogg", ULong.MAX_VALUE,
        null, "thumb", 1.5, listOf(0.2, 0.5))
    val draft = SelectedMessageDraftContentFfi("group", "unsent", null, listOf(attachment), 1L, 2L)
    check(FfiConverterTypeSelectedMessageDraftContentFfi.lift(FfiConverterTypeSelectedMessageDraftContentFfi.lower(draft)) == draft)
}
suspend fun compileConversationCommands(marmot: Marmot, account: String, group: String) {
    marmot.openConversationWindow(account, group, ConversationOpenModeFfi.AUTOMATIC, null, 50u, 0u).use { window ->
        window.snapshot()?.let { initial ->
            val page = window.page(initial.revision, ConversationPageDirectionFfi.OLDER, 50u, 0u)
            page.messages.firstOrNull()?.let { row ->
                val anchor = window.setVisibleAnchor(page.revision, row.timeline.messageIdHex, 0u)
                val jumped = window.jumpToMessage(anchor.revision, row.timeline.messageIdHex, 0u)
                window.returnToLatest(jumped.revision, 0u)
            }
            marmot.messageDraftAttachmentIfRevision(account, initial.draft.revision, "a")
            marmot.saveMessageDraftIfRevision(account, initial.draft.revision, "draft", null, emptyList())
        }
        window.next()
        window.cancel()
    }
}

suspend fun compileBlockCommands(marmot: Marmot, account: String, user: String) {
    marmot.blockUser(account, user)
    marmot.unblockUser(account, user)
    marmot.getBlockedUsers(account)
    marmot.isUserBlocked(account, user)
    marmot.subscribeBlockedUsers(account).use { sub -> sub.snapshot(); sub.next() }
}
