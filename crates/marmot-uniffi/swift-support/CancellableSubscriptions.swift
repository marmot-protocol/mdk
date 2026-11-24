import Foundation
import marmot_uniffiFFI

// MarmotKit's binding generator makes every throwing async call forward Swift Task
// cancellation to its native future (src/bin/uniffi-bindgen.rs). These receives
// are generated non-throwing, so they cannot report cancellation: each adapter
// below is its throwing, cancellable form.

extension BackupRestoreSubscription {
  public func nextCancellable() async throws -> BackupRestoreStatusFfi? {
    try await cancellableReceive(
      { uniffi_marmot_uniffi_fn_method_backuprestoresubscription_next(self.uniffiClonePointer()) },
      FfiConverterOptionTypeBackupRestoreStatusFfi.lift)
  }
}

extension BlockListSubscription {
  public func nextCancellable() async throws -> BlockListSnapshotFfi? {
    try await cancellableReceive(
      { uniffi_marmot_uniffi_fn_method_blocklistsubscription_next(self.uniffiClonePointer()) },
      FfiConverterOptionTypeBlockListSnapshotFfi.lift)
  }
}

extension ChatListSubscription {
  public func nextCancellable() async throws -> ChatListRowFfi? {
    try await cancellableReceive(
      { uniffi_marmot_uniffi_fn_method_chatlistsubscription_next(self.uniffiClonePointer()) },
      FfiConverterOptionTypeChatListRowFfi.lift)
  }

  public func nextUpdateCancellable() async throws -> ChatListSubscriptionUpdateFfi? {
    try await cancellableReceive(
      {
        uniffi_marmot_uniffi_fn_method_chatlistsubscription_next_update(self.uniffiClonePointer())
      },
      FfiConverterOptionTypeChatListSubscriptionUpdateFfi.lift)
  }
}

extension ChatsSubscription {
  public func nextCancellable() async throws -> AppGroupRecordFfi? {
    try await cancellableReceive(
      { uniffi_marmot_uniffi_fn_method_chatssubscription_next(self.uniffiClonePointer()) },
      FfiConverterOptionTypeAppGroupRecordFfi.lift)
  }
}

extension EventsSubscription {
  public func nextCancellable() async throws -> MarmotEventFfi? {
    try await cancellableReceive(
      { uniffi_marmot_uniffi_fn_method_eventssubscription_next(self.uniffiClonePointer()) },
      FfiConverterOptionTypeMarmotEventFfi.lift)
  }
}

extension GroupStateSubscription {
  public func nextCancellable() async throws -> AppGroupRecordFfi? {
    try await cancellableReceive(
      { uniffi_marmot_uniffi_fn_method_groupstatesubscription_next(self.uniffiClonePointer()) },
      FfiConverterOptionTypeAppGroupRecordFfi.lift)
  }
}

extension MessagesSubscription {
  public func nextCancellable() async throws -> MessageUpdateFfi? {
    try await cancellableReceive(
      { uniffi_marmot_uniffi_fn_method_messagessubscription_next(self.uniffiClonePointer()) },
      FfiConverterOptionTypeMessageUpdateFfi.lift)
  }
}

extension NotificationsSubscription {
  public func nextCancellable() async throws -> NotificationUpdateFfi? {
    try await cancellableReceive(
      { uniffi_marmot_uniffi_fn_method_notificationssubscription_next(self.uniffiClonePointer()) },
      FfiConverterOptionTypeNotificationUpdateFfi.lift)
  }
}

extension OnboardingSubscription {
  public func nextCancellable() async throws -> OnboardingSnapshotFfi? {
    try await cancellableReceive(
      { uniffi_marmot_uniffi_fn_method_onboardingsubscription_next(self.uniffiClonePointer()) },
      FfiConverterOptionTypeOnboardingSnapshotFfi.lift)
  }
}

extension TimelineMessagesSubscription {
  public func nextCancellable() async throws -> TimelinePageFfi? {
    try await cancellableReceive(
      {
        uniffi_marmot_uniffi_fn_method_timelinemessagessubscription_next(self.uniffiClonePointer())
      },
      FfiConverterOptionTypeTimelinePageFfi.lift)
  }

  public func nextUpdateCancellable() async throws -> TimelineSubscriptionUpdateFfi? {
    try await cancellableReceive(
      {
        uniffi_marmot_uniffi_fn_method_timelinemessagessubscription_next_update(
          self.uniffiClonePointer())
      },
      FfiConverterOptionTypeTimelineSubscriptionUpdateFfi.lift)
  }
}

extension UserSearchSubscription {
  public func nextUpdateCancellable() async throws -> UserSearchUpdateFfi? {
    try await cancellableReceive(
      { uniffi_marmot_uniffi_fn_method_usersearchsubscription_next_update(self.uniffiClonePointer()) },
      FfiConverterOptionTypeUserSearchUpdateFfi.lift)
  }
}

// These generated `next()` methods throw, so they already forward cancellation.
// The adapters remain for hosts written against them.

extension PresentedChatListSubscription {
  public func nextCancellable() async throws -> PresentedChatListUpdateFfi? { try await next() }
}

extension ChatListWindowSubscription {
  public func nextCancellable() async throws -> ChatListWindowSnapshotFfi? { try await next() }
}

extension AccountAttentionSubscription {
  public func nextCancellable() async throws -> AccountAttentionSnapshotFfi? { try await next() }
}

extension ConversationWindowSubscription {
  public func nextCancellable() async throws -> ConversationWindowSnapshotFfi? { try await next() }
}

private func cancellableReceive<Value>(
  _ makeFuture: () -> UInt64,
  _ lift: (RustBuffer) throws -> Value
) async throws -> Value {
  try await uniffiRustCallAsync(
    rustFutureFunc: makeFuture,
    pollFunc: ffi_marmot_uniffi_rust_future_poll_rust_buffer,
    completeFunc: ffi_marmot_uniffi_rust_future_complete_rust_buffer,
    freeFunc: ffi_marmot_uniffi_rust_future_free_rust_buffer,
    cancelFunc: ffi_marmot_uniffi_rust_future_cancel_rust_buffer,
    liftFunc: lift,
    errorHandler: nil
  )
}
