#ifndef CHAT_MANAGER_H
#define CHAT_MANAGER_H

#include <stdbool.h>
#include <time.h>
#include "peer_list.h"
#include "orcashi.h"

typedef struct {
    char peer_id[64];
    bool is_online;
    bool is_secure;
    time_t last_activity;
    PeerList* peer_list;
    ORCASHI* orcashi;
    int pending_count;
    bool running;
} ChatSession;

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

int chat_manager_init(ORCASHI* orcashi, PeerList* peer_list);
void chat_manager_cleanup(void);

/* ============================================================================
 * Chat Session
 * ============================================================================ */

int chat_start(const char* peer_id);
int chat_send_message(const char* peer_id, const char* msg);
int chat_receive_messages(const char* peer_id);
int chat_check_pending(const char* peer_id);

/* ============================================================================
 * Auto-Delivery
 * ============================================================================ */

int chat_deliver_pending(const char* peer_id);
int chat_deliver_all_pending(void);
bool chat_has_pending(const char* peer_id);

/* ============================================================================
 * Status
 * ============================================================================ */

int chat_get_status(const char* peer_id, char* status_out, size_t size);
int chat_get_pending_count(const char* peer_id);

#endif
