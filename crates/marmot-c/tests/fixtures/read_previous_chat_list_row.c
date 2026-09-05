#include <stddef.h>

#include "chat_list_row_previous.h"

size_t marmot_previous_header_chat_list_row_size(void) {
  return sizeof(struct MarmotChatListRow);
}

const char *marmot_previous_header_second_group_id(
    const struct MarmotChatListRow *rows) {
  return rows[1].group_id_hex;
}
