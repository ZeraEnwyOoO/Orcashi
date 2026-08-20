 #ifndef REGISTRY_H
#define REGISTRY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define REGISTRY_MAX_PEERS 1024
#define REGISTRY_MAX_ID_LEN 64
#define REGISTRY_MAX_IP_LEN INET_ADDRSTRLEN
#define REGISTRY_MAX_PORT_LEN 16
#define REGISTRY_MAX_STATUS_LEN 16
#define REGISTRY_MAX_NAME_LEN 128
#define REGISTRY_MAX_PUBKEY_LEN 4096
#define REGISTRY_MAX_SIG_LEN 512

typedef enum {
    REG_MODE_NORMAL = 0,
    REG_MODE_SECURE = 1
} RegistryMode;

/* ============================================================================
 * Registry Peer Entry
 * ============================================================================ */

typedef struct {
    char id[REGISTRY_MAX_ID_LEN];
    char ip[REGISTRY_MAX_IP_LEN];
    char port[REGISTRY_MAX_PORT_LEN];
    bool online;
    char status[REGISTRY_MAX_STATUS_LEN];
    time_t last_seen;
    RegistryMode mode;
    char name[REGISTRY_MAX_NAME_LEN];
    char public_key[REGISTRY_MAX_PUBKEY_LEN];
    char signature[REGISTRY_MAX_SIG_LEN];
    char salt_hex[33];
    time_t created_at;
    bool verified;
} RegistryPeer;

/* ============================================================================
 * Registry Runtime State
 * ============================================================================ */

typedef struct {
    RegistryPeer peers[REGISTRY_MAX_PEERS];
    int peer_count;
    pthread_mutex_t mutex;
} Registry;

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

Registry* registry_create(void);
void registry_destroy(Registry* reg);

/* ============================================================================
 * Registration Operations
 * ============================================================================ */

bool registry_register_peer(Registry* reg, const char* id, 
                            const char* ip, const char* port);

bool registry_register_secure(Registry* reg, const char* id,
                              const char* ip, const char* port,
                              const char* name, const char* public_key,
                              const char* signature, const char* salt_hex);

/* ============================================================================
 * Status Operations
 * ============================================================================ */

void registry_update_status(Registry* reg, const char* id, const char* status);
const char* registry_get_status(Registry* reg, const char* id);
bool registry_is_accepted(Registry* reg, const char* id);
bool registry_is_pending(Registry* reg, const char* id);

/* ============================================================================
 * Query Operations
 * ============================================================================ */

bool registry_get_peer(Registry* reg, const char* id, RegistryPeer* out_peer);
bool registry_get_peer_by_name(Registry* reg, const char* name, 
                               RegistryPeer* out_peer);
bool registry_peer_exists(Registry* reg, const char* id);

/* ============================================================================
 * List Operations
 * ============================================================================ */

int registry_get_all_peers(Registry* reg, RegistryPeer* peers, int max_peers);
int registry_get_accepted_peers(Registry* reg, RegistryPeer* peers, int max_peers);
int registry_get_pending_peers(Registry* reg, RegistryPeer* peers, int max_peers);
int registry_get_secure_peers(Registry* reg, RegistryPeer* peers, int max_peers);

/* ============================================================================
 * Update Operations
 * ============================================================================ */

void registry_update_peer(Registry* reg, const char* id, 
                          const char* ip, const char* port);
void registry_set_online(Registry* reg, const char* id, bool online);

/* ============================================================================
 * Remove Operations
 * ============================================================================ */

bool registry_remove_peer(Registry* reg, const char* id);

/* ============================================================================
 * Utility
 * ============================================================================ */

bool registry_is_secure(const RegistryPeer* peer);
const char* registry_get_mode_string(const RegistryPeer* peer);
bool registry_normalize_id(const char* input, char* output, size_t output_size);
bool registry_is_same_id(const char* id1, const char* id2);

#endif /* REGISTRY_H */
