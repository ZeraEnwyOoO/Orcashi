 // registry.c - Runtime registry/business logic ONLY
#include "registry.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define DEBUG_REGISTRY 1

#if DEBUG_REGISTRY
#define RLOG(fmt, ...) \
    do { \
        fprintf(stderr, "[REGISTRY DEBUG] " fmt "\n", ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define RLOG(fmt, ...) ((void)0)
#endif

static int ids_match(const char* id1, const char* id2) {
    if (!id1 || !id2) return 0;
    
    /* Strip brackets for comparison */
    char n1[64], n2[64];
    memset(n1, 0, sizeof(n1));
    memset(n2, 0, sizeof(n2));
    
    int j = 0;
    for (int i = 0; id1[i] && j < (int)sizeof(n1) - 1; i++) {
        if (id1[i] != '<' && id1[i] != '>') {
            n1[j++] = id1[i];
        }
    }
    n1[j] = '\0';
    
    j = 0;
    for (int i = 0; id2[i] && j < (int)sizeof(n2) - 1; i++) {
        if (id2[i] != '<' && id2[i] != '>') {
            n2[j++] = id2[i];
        }
    }
    n2[j] = '\0';
    
    return strcmp(n1, n2) == 0;
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

Registry* registry_create(void) {
    Registry* reg = (Registry*)calloc(1, sizeof(Registry));
    if (!reg) {
        RLOG("registry_create: malloc failed");
        return NULL;
    }
    
    reg->peer_count = 0;
    pthread_mutex_init(&reg->mutex, NULL);
    RLOG("registry_create: created");
    return reg;
}

void registry_destroy(Registry* reg) {
    if (!reg) return;
    
    RLOG("registry_destroy: peer_count=%d", reg->peer_count);
    
    /* Do NOT save - persistence is handled by peer_list */
    pthread_mutex_destroy(&reg->mutex);
    free(reg);
}

/* ============================================================================
 * Registration
 * ============================================================================ */

bool registry_register_peer(Registry* reg, const char* id, const char* ip, const char* port) {
    if (!reg || !id || !ip || !port) {
        RLOG("registry_register_peer: NULL parameter");
        return false;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    RLOG("registry_register_peer: id='%s', ip='%s', port='%s'", id, ip, port);
    
    /* Check if peer exists */
    for (int i = 0; i < reg->peer_count; i++) {
        if (ids_match(reg->peers[i].id, id)) {
            RLOG("registry_register_peer: peer %s already exists, updating", id);
            strcpy(reg->peers[i].ip, ip);
            strcpy(reg->peers[i].port, port);
            reg->peers[i].online = true;
            reg->peers[i].last_seen = time(NULL);
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    if (reg->peer_count >= REGISTRY_MAX_PEERS) {
        RLOG("registry_register_peer: registry full");
        pthread_mutex_unlock(&reg->mutex);
        return false;
    }
    
    RegistryPeer* peer = &reg->peers[reg->peer_count++];
    strcpy(peer->id, id);
    strcpy(peer->ip, ip);
    strcpy(peer->port, port);
    strcpy(peer->status, "pending");
    peer->online = true;
    peer->last_seen = time(NULL);
    peer->mode = REG_MODE_NORMAL;
    peer->verified = true;
    peer->created_at = time(NULL);
    memset(peer->public_key, 0, sizeof(peer->public_key));
    memset(peer->signature, 0, sizeof(peer->signature));
    memset(peer->salt_hex, 0, sizeof(peer->salt_hex));
    memset(peer->name, 0, sizeof(peer->name));
    
    RLOG("registry_register_peer: added peer %s (slot %d)", id, reg->peer_count - 1);
    
    pthread_mutex_unlock(&reg->mutex);
    return true;
}

bool registry_register_secure(Registry* reg, const char* id, const char* ip, const char* port,
                              const char* name, const char* public_key,
                              const char* signature, const char* salt_hex) {
    if (!reg || !id || !ip || !port) {
        RLOG("registry_register_secure: NULL parameter");
        return false;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    RLOG("registry_register_secure: id='%s', name='%s', ip='%s', port='%s'", id, name, ip, port);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (ids_match(reg->peers[i].id, id)) {
            RLOG("registry_register_secure: peer %s already exists, updating", id);
            strcpy(reg->peers[i].ip, ip);
            strcpy(reg->peers[i].port, port);
            reg->peers[i].online = true;
            reg->peers[i].last_seen = time(NULL);
            reg->peers[i].mode = REG_MODE_SECURE;
            if (name) strcpy(reg->peers[i].name, name);
            if (public_key) strcpy(reg->peers[i].public_key, public_key);
            if (signature) strcpy(reg->peers[i].signature, signature);
            if (salt_hex) strcpy(reg->peers[i].salt_hex, salt_hex);
            reg->peers[i].verified = true;
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    if (reg->peer_count >= REGISTRY_MAX_PEERS) {
        RLOG("registry_register_secure: registry full");
        pthread_mutex_unlock(&reg->mutex);
        return false;
    }
    
    RegistryPeer* peer = &reg->peers[reg->peer_count++];
    strcpy(peer->id, id);
    strcpy(peer->ip, ip);
    strcpy(peer->port, port);
    strcpy(peer->status, "pending");
    peer->online = true;
    peer->last_seen = time(NULL);
    peer->mode = REG_MODE_SECURE;
    peer->created_at = time(NULL);
    peer->verified = true;
    if (name) strcpy(peer->name, name);
    if (public_key) strcpy(peer->public_key, public_key);
    if (signature) strcpy(peer->signature, signature);
    if (salt_hex) strcpy(peer->salt_hex, salt_hex);
    
    RLOG("registry_register_secure: added secure peer %s (slot %d)", id, reg->peer_count - 1);
    
    pthread_mutex_unlock(&reg->mutex);
    return true;
}

/* ============================================================================
 * Query
 * ============================================================================ */

bool registry_get_peer(Registry* reg, const char* id, RegistryPeer* out_peer) {
    if (!reg || !out_peer || !id) return false;
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (ids_match(reg->peers[i].id, id)) {
            *out_peer = reg->peers[i];
            RLOG("registry_get_peer: found peer %s", id);
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    RLOG("registry_get_peer: peer %s not found", id);
    pthread_mutex_unlock(&reg->mutex);
    return false;
}

bool registry_get_peer_by_name(Registry* reg, const char* name, RegistryPeer* out_peer) {
    if (!reg || !out_peer || !name) return false;
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (reg->peers[i].mode == REG_MODE_SECURE &&
            strcmp(reg->peers[i].name, name) == 0) {
            *out_peer = reg->peers[i];
            RLOG("registry_get_peer_by_name: found peer %s", name);
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    RLOG("registry_get_peer_by_name: peer %s not found", name);
    pthread_mutex_unlock(&reg->mutex);
    return false;
}

bool registry_peer_exists(Registry* reg, const char* id) {
    if (!reg || !id) return false;
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (ids_match(reg->peers[i].id, id)) {
            RLOG("registry_peer_exists: peer %s exists", id);
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    pthread_mutex_unlock(&reg->mutex);
    return false;
}

/* ============================================================================
 * Update
 * ============================================================================ */

void registry_update_status(Registry* reg, const char* id, const char* status) {
    if (!reg || !id || !status) return;
    
    pthread_mutex_lock(&reg->mutex);
    
    RLOG("registry_update_status: id='%s', status='%s'", id, status);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (ids_match(reg->peers[i].id, id)) {
            strcpy(reg->peers[i].status, status);
            RLOG("registry_update_status: updated peer %s to '%s'", id, status);
            pthread_mutex_unlock(&reg->mutex);
            return;
        }
    }
    
    RLOG("registry_update_status: peer %s not found", id);
    pthread_mutex_unlock(&reg->mutex);
}

void registry_update_peer(Registry* reg, const char* id, const char* ip, const char* port) {
    if (!reg || !id || !ip || !port) return;
    
    pthread_mutex_lock(&reg->mutex);
    
    RLOG("registry_update_peer: id='%s', ip='%s', port='%s'", id, ip, port);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (ids_match(reg->peers[i].id, id)) {
            strcpy(reg->peers[i].ip, ip);
            strcpy(reg->peers[i].port, port);
            reg->peers[i].last_seen = time(NULL);
            RLOG("registry_update_peer: updated peer %s", id);
            pthread_mutex_unlock(&reg->mutex);
            return;
        }
    }
    
    RLOG("registry_update_peer: peer %s not found", id);
    pthread_mutex_unlock(&reg->mutex);
}

void registry_set_online(Registry* reg, const char* id, bool online) {
    if (!reg || !id) return;
    
    pthread_mutex_lock(&reg->mutex);
    
    RLOG("registry_set_online: id='%s', online=%d", id, online);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (ids_match(reg->peers[i].id, id)) {
            reg->peers[i].online = online;
            reg->peers[i].last_seen = time(NULL);
            RLOG("registry_set_online: set peer %s online=%d", id, online);
            pthread_mutex_unlock(&reg->mutex);
            return;
        }
    }
    
    RLOG("registry_set_online: peer %s not found", id);
    pthread_mutex_unlock(&reg->mutex);
}

/* ============================================================================
 * List
 * ============================================================================ */

int registry_get_all_peers(Registry* reg, RegistryPeer* peers, int max_peers) {
    if (!reg || !peers) return 0;
    
    pthread_mutex_lock(&reg->mutex);
    
    int count = 0;
    for (int i = 0; i < reg->peer_count && count < max_peers; i++) {
        peers[count++] = reg->peers[i];
    }
    
    RLOG("registry_get_all_peers: returned %d peers", count);
    pthread_mutex_unlock(&reg->mutex);
    return count;
}

int registry_get_accepted_peers(Registry* reg, RegistryPeer* peers, int max_peers) {
    if (!reg || !peers) return 0;
    
    pthread_mutex_lock(&reg->mutex);
    
    int count = 0;
    for (int i = 0; i < reg->peer_count && count < max_peers; i++) {
        if (strcmp(reg->peers[i].status, "accepted") == 0) {
            peers[count++] = reg->peers[i];
        }
    }
    
    RLOG("registry_get_accepted_peers: returned %d peers", count);
    pthread_mutex_unlock(&reg->mutex);
    return count;
}

int registry_get_pending_peers(Registry* reg, RegistryPeer* peers, int max_peers) {
    if (!reg || !peers) return 0;
    
    pthread_mutex_lock(&reg->mutex);
    
    int count = 0;
    for (int i = 0; i < reg->peer_count && count < max_peers; i++) {
        if (strcmp(reg->peers[i].status, "pending") == 0) {
            peers[count++] = reg->peers[i];
        }
    }
    
    RLOG("registry_get_pending_peers: returned %d peers", count);
    pthread_mutex_unlock(&reg->mutex);
    return count;
}

int registry_get_secure_peers(Registry* reg, RegistryPeer* peers, int max_peers) {
    if (!reg || !peers) return 0;
    
    pthread_mutex_lock(&reg->mutex);
    
    int count = 0;
    for (int i = 0; i < reg->peer_count && count < max_peers; i++) {
        if (reg->peers[i].mode == REG_MODE_SECURE) {
            peers[count++] = reg->peers[i];
        }
    }
    
    RLOG("registry_get_secure_peers: returned %d peers", count);
    pthread_mutex_unlock(&reg->mutex);
    return count;
}

/* ============================================================================
 * Remove
 * ============================================================================ */

bool registry_remove_peer(Registry* reg, const char* id) {
    if (!reg || !id) return false;
    
    pthread_mutex_lock(&reg->mutex);
    
    RLOG("registry_remove_peer: id='%s'", id);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (ids_match(reg->peers[i].id, id)) {
            for (int j = i; j < reg->peer_count - 1; j++) {
                reg->peers[j] = reg->peers[j + 1];
            }
            reg->peer_count--;
            RLOG("registry_remove_peer: removed peer %s", id);
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    RLOG("registry_remove_peer: peer %s not found", id);
    pthread_mutex_unlock(&reg->mutex);
    return false;
}

/* ============================================================================
 * Utility
 * ============================================================================ */

bool registry_is_secure(const RegistryPeer* peer) {
    return peer && peer->mode == REG_MODE_SECURE;
}

const char* registry_get_mode_string(const RegistryPeer* peer) {
    if (!peer) return "unknown";
    return peer->mode == REG_MODE_SECURE ? "secure" : "normal";
}
