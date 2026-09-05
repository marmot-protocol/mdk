#ifndef MARMOT_CHAT_LIST_ROW_PREVIOUS_H
#define MARMOT_CHAT_LIST_ROW_PREVIOUS_H

#include <stdbool.h>
#include <stdint.h>

/* Focused snapshot of MarmotChatListRow and its by-value enums from the
 * checked-in header immediately before direct-peer presentation support. */
enum MarmotGroupLifecycleState {
  MARMOT_GROUP_LIFECYCLE_STATE_STABLE,
  MARMOT_GROUP_LIFECYCLE_STATE_PENDING_PUBLISH,
  MARMOT_GROUP_LIFECYCLE_STATE_MERGING,
  MARMOT_GROUP_LIFECYCLE_STATE_RECOVERING,
  MARMOT_GROUP_LIFECYCLE_STATE_UNRECOVERABLE,
  MARMOT_GROUP_LIFECYCLE_STATE_DISBANDED,
};

enum MarmotSelfMembership {
  MARMOT_SELF_MEMBERSHIP_MEMBER,
  MARMOT_SELF_MEMBERSHIP_LEFT,
  MARMOT_SELF_MEMBERSHIP_REMOVED,
};

enum MarmotChatConversationKind {
  MARMOT_CHAT_CONVERSATION_KIND_UNKNOWN,
  MARMOT_CHAT_CONVERSATION_KIND_DIRECT,
  MARMOT_CHAT_CONVERSATION_KIND_GROUP,
};

struct MarmotDisbandRequest;
struct MarmotChatListAvatar;
struct MarmotChatListMessagePreview;

struct MarmotChatListRow {
  char *group_id_hex;
  bool pinned;
  bool has_pinned_position;
  uint32_t pinned_position;
  bool archived;
  bool pending_confirmation;
  enum MarmotGroupLifecycleState lifecycle_state;
  bool disbanding;
  struct MarmotDisbandRequest *disband_request;
  char *title;
  char *group_name;
  char *avatar_url;
  struct MarmotChatListAvatar *avatar;
  struct MarmotChatListMessagePreview *last_message;
  uint64_t unread_count;
  bool has_unread;
  bool manually_marked_unread;
  uint64_t unread_mention_count;
  bool unread_mention;
  char *first_unread_message_id_hex;
  char *last_read_message_id_hex;
  bool has_last_read_timeline_at;
  uint64_t last_read_timeline_at;
  uint64_t conversation_created_at;
  uint64_t activity_sort_at;
  uint64_t updated_at;
  enum MarmotSelfMembership self_membership;
  enum MarmotChatConversationKind conversation_kind;
  bool muted;
  bool has_muted_until_ms;
  int64_t muted_until_ms;
  bool leave_request_pending;
  bool has_leave_requested_at_ms;
  uint64_t leave_requested_at_ms;
};

#endif
