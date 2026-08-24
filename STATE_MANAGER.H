#ifndef STATE_MANAGER_H
#define STATE_MANAGER_H

#include <stdbool.h>
#include <time.h>
#include <pthread.h>

/* ============================================================================
 * PEER STATES
 * ============================================================================ */

typedef enum {
    PEER_UNKNOWN = 0,
    PEER_REQUEST_SENT,      /* Sent request, waiting for accept */
    PEER_REQUEST_RECEIVED,  /* Received request, waiting for decision */
    PEER_FRIEND,            /* Accepted friend */
    PEER_ONLINE,            /* Online */
    PEER_OFFLINE,           /* Offline */
    PEER_BUSY,              /* In chat/call */
    PEER_GHOST              /* Ghost room (offline/busy) */
} PeerState;

/* ============================================================================
 * PEER STRUCTURE
 * ============================================================================ */

typedef struct {
    char id[64];
    PeerState state;
    bool online;
    bool busy;
    bool is_secure;
    char ip[INET_ADDRSTRLEN];
    int port;
    time_t last_seen;
    time_t created_at;
    time_t request_sent_at;
    time_t request_received_at;
    time_t friend_since;
    int pending_messages;
    int ghost_count;
    char public_key[4096];
    char name[128];
} Peer;

/* ============================================================================
 * GHOST MESSAGE
 * ============================================================================ */

typedef struct {
    char id[64];               /* Message ID */
    char from_id[64];
    char to_id[64];
    char message[4096];
    time_t timestamp;
    bool delivered;
    time_t delivered_at;
    int retry_count;
} GhostMessage;

/* ============================================================================
 * STATE MANAGER FUNCTIONS
 * ============================================================================ */

/* Initialize state manager */
int state_init(void);

/* Save state to disk */
int state_save(void);

/* Load state from disk */
int state_load(void);

/* ============================================================================
 * PEER OPERATIONS
 * ============================================================================ */

/* Add/update peer */
int state_add_peer(const char* id);
int state_update_peer(const char* id, PeerState state);
int state_remove_peer(const char* id);

/* Get peer info */
Peer* state_get_peer(const char* id);
int state_get_peers(Peer* out, int max);
int state_get_count(void);

/* Query peer state */
bool state_is_online(const char* id);
bool state_is_friend(const char* id);
bool state_is_busy(const char* id);
PeerState state_get_state(const char* id);

/* Update peer fields */
int state_set_online(const char* id, bool online);
int state_set_busy(const char* id, bool busy);
int state_set_secure(const char* id, bool secure);
int state_set_ip(const char* id, const char* ip);
int state_set_port(const char* id, int port);
int state_set_name(const char* id, const char* name);
int state_set_public_key(const char* id, const char* pubkey);
int state_update_last_seen(const char* id);

/* ============================================================================
 * PENDING REQUESTS
 * ============================================================================ */

int state_get_pending(Peer* out, int max);
int state_get_pending_count(void);
bool state_has_pending_request(const char* id);

/* ============================================================================
 * FRIEND LIST
 * ============================================================================ */

int state_get_friends(Peer* out, int max);
int state_get_friend_count(void);
bool state_is_friend(const char* id);

/* ============================================================================
 * GHOST MESSAGES
 * ============================================================================ */

int state_add_ghost_message(const char* to_id, const char* message);
int state_get_ghost_messages(const char* to_id, GhostMessage* out, int max);
int state_deliver_ghost_messages(const char* to_id);
int state_get_ghost_count(const char* to_id);
bool state_has_ghost_messages(const char* to_id);

/* ============================================================================
 * MESSAGES
 * ============================================================================ */

int state_add_message(const char* from_id, const char* message);
int state_get_messages(const char* peer_id, char* out[], int max);
int state_clear_messages(const char* peer_id);

/* ============================================================================
 * UTILITIES
 * ============================================================================ */

const char* state_to_string(PeerState state);
void state_debug_print(void);

#endif /* STATE_MANAGER_H */
