 #ifndef PEER_LIST_H
#define PEER_LIST_H

#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "registry.h"

#define PEER_LIST_MAX_PEERS 1024
#define PEER_LIST_MAX_ID_LEN 64
#define PEER_LIST_MAX_IP_LEN INET_ADDRSTRLEN
#define PEER_LIST_MAX_PORT_LEN 16
#define PEER_LIST_MAX_STATUS_LEN 16
#define PEER_LIST_MAX_NAME_LEN 128
#define PEER_LIST_MAX_PUBKEY_LEN 4096
#define PEER_LIST_MAX_SIG_LEN 512

/* ============================================================================
 * Peer List Entry (Persistent Storage)
 * ============================================================================ */

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

/* ============================================================================
 * Peer List (Persistent Storage Manager)
 * ============================================================================ */

typedef struct {
    PeerListEntry peers[PEER_LIST_MAX_PEERS];
    int count;
    char file_path[512];
    bool dirty;
    pthread_mutex_t mutex;
} PeerList;

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

PeerList* peer_list_create(void);
void peer_list_destroy(PeerList* pl);

/* ============================================================================
 * Load / Save
 * ============================================================================ */

int peer_list_load(PeerList* pl);
int peer_list_save(PeerList* pl);

/* ============================================================================
 * Query
 * ============================================================================ */

int peer_list_get_count(PeerList* pl);
PeerListEntry* peer_list_get(PeerList* pl, int index);
PeerListEntry* peer_list_find(PeerList* pl, const char* id);

/* ============================================================================
 * Modify
 * ============================================================================ */

int peer_list_add(PeerList* pl, const RegistryPeer* peer);
int peer_list_add_entry(PeerList* pl, const PeerListEntry* entry);
int peer_list_update(PeerList* pl, const char* id, const RegistryPeer* peer);
int peer_list_remove(PeerList* pl, const char* id);
void peer_list_clear(PeerList* pl);

/* ============================================================================
 * Sync with Registry
 * ============================================================================ */

int peer_list_sync_to_registry(PeerList* pl, Registry* reg);
int peer_list_sync_from_registry(PeerList* pl, Registry* reg);

/* ============================================================================
 * Utility
 * ============================================================================ */

void peer_list_mark_dirty(PeerList* pl);
bool peer_list_is_dirty(PeerList* pl);
bool peer_list_normalize_id(const char* input, char* output, size_t output_size);

#endif /* PEER_LIST_H */
