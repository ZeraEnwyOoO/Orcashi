 #ifndef PEER_LIST_H
#define PEER_LIST_H

#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "registry.h"

#define PEER_LIST_MAX_PEERS 1024
#define PEER_LIST_MAX_MSGS 4096
#define PEER_LIST_MAX_ID_LEN 64
#define PEER_LIST_MAX_IP_LEN INET_ADDRSTRLEN
#define PEER_LIST_MAX_PORT_LEN 16
#define PEER_LIST_MAX_STATUS_LEN 16
#define PEER_LIST_MAX_NAME_LEN 128
#define PEER_LIST_MAX_PUBKEY_LEN 4096
#define PEER_LIST_MAX_SIG_LEN 512
#define PEER_LIST_MAX_MSG_LEN 4096
#define PEER_LIST_MAX_MSG_ID_LEN 64

typedef enum {
    MSG_STATUS_PENDING = 0,
    MSG_STATUS_SENT = 1,
    MSG_STATUS_DELIVERED = 2,
    MSG_STATUS_FAILED = 3,
    MSG_STATUS_READ = 4
} MessageStatus;

typedef struct {
    char id[PEER_LIST_MAX_ID_LEN];
    char ip[PEER_LIST_MAX_IP_LEN];
    char port[PEER_LIST_MAX_PORT_LEN];
    bool online;
    char status[PEER_LIST_MAX_STATUS_LEN];
    time_t last_seen;
    RegistryMode mode;
    char name[PEER_LIST_MAX_NAME_LEN];
    char public_key[PEER_LIST_MAX_PUBKEY_LEN];
    char signature[PEER_LIST_MAX_SIG_LEN];
    char salt_hex[33];
    time_t created_at;
    bool verified;
} PeerListEntry;

typedef struct {
    char msg_id[PEER_LIST_MAX_MSG_ID_LEN];
    char from_id[PEER_LIST_MAX_ID_LEN];
    char to_id[PEER_LIST_MAX_ID_LEN];
    char payload[PEER_LIST_MAX_MSG_LEN];
    time_t timestamp;
    MessageStatus status;
    bool encrypted;
    time_t delivered_at;
    int retry_count;
} QueuedMessage;

typedef struct {
    PeerListEntry peers[PEER_LIST_MAX_PEERS];
    int peer_count;
    QueuedMessage messages[PEER_LIST_MAX_MSGS];
    int msg_count;
    char data_dir[512];
    pthread_mutex_t mutex;
    bool dirty;
} PeerList;

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

PeerList* peer_list_create(void);
void peer_list_destroy(PeerList* pl);

/* ============================================================================
 * Peer Operations
 * ============================================================================ */

int peer_list_add_peer(PeerList* pl, const RegistryPeer* peer);
int peer_list_update_peer(PeerList* pl, const char* id, const RegistryPeer* peer);
int peer_list_remove_peer(PeerList* pl, const char* id);
PeerListEntry* peer_list_find_peer(PeerList* pl, const char* id);
int peer_list_get_peers(PeerList* pl, PeerListEntry* out, int max);
int peer_list_get_accepted_peers(PeerList* pl, PeerListEntry* out, int max);
bool peer_list_is_accepted(PeerList* pl, const char* id);

/* ============================================================================
 * Message Queue Operations
 * ============================================================================ */

int peer_list_queue_message(PeerList* pl, const char* to_id, 
                            const char* payload, bool encrypted);
int peer_list_get_pending_messages(PeerList* pl, const char* to_id,
                                   QueuedMessage* out, int max);
int peer_list_get_messages_for_peer(PeerList* pl, const char* peer_id,
                                    QueuedMessage* out, int max);
int peer_list_mark_message_delivered(PeerList* pl, const char* msg_id);
int peer_list_mark_message_failed(PeerList* pl, const char* msg_id);
int peer_list_mark_message_sent(PeerList* pl, const char* msg_id);
int peer_list_get_pending_count(PeerList* pl, const char* to_id);
bool peer_list_has_pending_messages(PeerList* pl, const char* to_id);
int peer_list_get_all_pending_messages(PeerList* pl, QueuedMessage* out, int max);

/* ============================================================================
 * Load / Save - Using sscanf() no buffer bugs!
 * ============================================================================ */

int peer_list_load(PeerList* pl);
int peer_list_save(PeerList* pl);
int peer_list_load_messages(PeerList* pl);
int peer_list_save_messages(PeerList* pl);

/* ============================================================================
 * Sync with Registry
 * ============================================================================ */

int peer_list_sync_to_registry(PeerList* pl, Registry* reg);
int peer_list_sync_from_registry(PeerList* pl, Registry* reg);

/* ============================================================================
 * Utility
 * ============================================================================ */

bool peer_list_normalize_id(const char* input, char* output, size_t output_size);
void peer_list_mark_dirty(PeerList* pl);
bool peer_list_is_dirty(PeerList* pl);
void peer_list_clear(PeerList* pl);

#endif
