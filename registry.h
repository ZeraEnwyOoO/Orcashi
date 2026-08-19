// registry.h - Runtime registry/business logic ONLY
#ifndef REGISTRY_H
#define REGISTRY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define MAX_REGISTRY_PEERS 1024

typedef enum {
    REG_MODE_NORMAL = 0,
    REG_MODE_SECURE = 1
} RegMode;

typedef struct {
    char id[64];
    char ip[INET_ADDRSTRLEN];
    char port[16];
    bool online;
    char status[16];
    time_t last_seen;
    RegMode mode;
    char name[128];
    char public_key[4096];
    char signature[512];
    char salt_hex[33];
    time_t created_at;
    bool verified;
} RegistryPeer;

typedef struct {
    RegistryPeer peers[MAX_REGISTRY_PEERS];
    int peer_count;
    pthread_mutex_t mutex;
} Registry;

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

Registry* registry_create(void);
void registry_destroy(Registry* reg);

/* ============================================================================
 * Registration
 * ============================================================================ */

bool registry_register_peer(Registry* reg, const char* id, const char* ip, const char* port);
bool registry_register_secure(Registry* reg, const char* id, const char* ip, const char* port,
                              const char* name, const char* public_key,
                              const char* signature, const char* salt_hex);

/* ============================================================================
 * Query
 * ============================================================================ */

bool registry_get_peer(Registry* reg, const char* id, RegistryPeer* out_peer);
bool registry_get_peer_by_name(Registry* reg, const char* name, RegistryPeer* out_peer);
bool registry_peer_exists(Registry* reg, const char* id);

/* ============================================================================
 * Update
 * ============================================================================ */

void registry_update_status(Registry* reg, const char* id, const char* status);
void registry_update_peer(Registry* reg, const char* id, const char* ip, const char* port);
void registry_set_online(Registry* reg, const char* id, bool online);

/* ============================================================================
 * List
 * ============================================================================ */

int registry_get_all_peers(Registry* reg, RegistryPeer* peers, int max_peers);
int registry_get_accepted_peers(Registry* reg, RegistryPeer* peers, int max_peers);
int registry_get_pending_peers(Registry* reg, RegistryPeer* peers, int max_peers);
int registry_get_secure_peers(Registry* reg, RegistryPeer* peers, int max_peers);

/* ============================================================================
 * Remove
 * ============================================================================ */

bool registry_remove_peer(Registry* reg, const char* id);

/* ============================================================================
 * Utility
 * ============================================================================ */

bool registry_is_secure(const RegistryPeer* peer);
const char* registry_get_mode_string(const RegistryPeer* peer);

#endif
