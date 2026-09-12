/*
 * Compile-only C consumer for the rich attachment-diagnostic subscription
 * surfaces. Existing smoke.c stays on the legacy mirrors; this file proves
 * the generated header exports the plan-prescribed _v2 callback and
 * full-window timeline next symbols.
 */

#include <stddef.h>
#include <stdint.h>

#include <marmot.h>

static void on_event(const MarmotEventV2 *item, void *user_data) {
    (void)item;
    (void)user_data;
}

static void on_message(const MarmotMessageUpdateV2 *item, void *user_data) {
    (void)item;
    (void)user_data;
}

static void on_timeline(const MarmotTimelinePageV2 *item, void *user_data) {
    (void)item;
    (void)user_data;
}

int main(void) {
    MarmotStatus (*event_cb)(const MarmotEventsSubscription *, MarmotEventCallbackV2, void *) =
        marmot_events_subscription_set_callback_v2;
    MarmotStatus (*message_cb)(const MarmotMessagesSubscription *, MarmotMessageUpdateCallbackV2,
                               void *) = marmot_messages_subscription_set_callback_v2;
    MarmotStatus (*timeline_cb)(const MarmotTimelineSubscription *, MarmotTimelinePageCallbackV2,
                                void *) = marmot_timeline_subscription_set_callback_v2;
    MarmotStatus (*timeline_next)(const MarmotTimelineSubscription *, uint32_t,
                                  MarmotTimelinePageV2 **) = marmot_timeline_subscription_next_v2;
    (void)event_cb;
    (void)message_cb;
    (void)timeline_cb;
    (void)timeline_next;
    (void)on_event;
    (void)on_message;
    (void)on_timeline;
    return 0;
}
