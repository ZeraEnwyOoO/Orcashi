 #include "registry.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#define REGISTRY_DEBUG 1

#if REGISTRY_DEBUG
#define RLOG(fmt, ...) \
    do { \
        fprintf(stderr, "[REGISTRY] " fmt "\n", ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define RLOG(fmt, ...) ((void)0)
#endif

/* ============================================================================
 * ID Normalization (Single Source of Truth)
 * ============================================================================ */

bool registry_normalize_id(const char* input, char* output, size_t output_size) {
    if (!input || !output || output_size == 0) {
        return false;
    }
    
    size_t i = 0, j = 0;
    size_t len = strlen(input);
    
    /* Strip angle brackets */
    for (i = 0; i < len && j < output_size - 1; i++) {
        if (input[i] != '<' && input[i] != '>') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
    
    /* Validate: must not be empty */
    if (j == 0) {
        return false;
    }
    
    /* Validate: must contain only digits */
    for (i = 0; i < j; i++) {
        if (!isdigit((unsigned char)output[i])) {
            return false;
        }
    }
    
    return true;
}

bool registry_is_same_id(const char* id1, const char* id2) {
    if (!id1 || !id2) return false;
    
    char n1[REGISTRY_MAX_ID_LEN];
    char n2[REGISTRY_MAX_ID_LEN];
    
    if (!registry_normalize_id(id1, n1, sizeof(n1))) return false;
    if (!registry_normalize_id(id2, n2, sizeof(n2))) return false;
    
    return strcmp(n1, n2) == 0;
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

Registry* registry_create(void) {
    Registry* reg = (Registry*)calloc(1, sizeof(Registry));
    if (!reg) {
        RLOG("registry_create: calloc failed");
        return NULL;
    }
    
    reg->peer_count = 0;
    
    if (pthread_mutex_init(&reg->mutex, NULL) != 0) {
        RLOG("registry_create: pthread_mutex_init failed");
        free(reg);
        return NULL;
    }
    
    RLOG("registry_create: created");
    return reg;
}

void registry_destroy(Registry* reg) {
    if (!reg) return;
    
    RLOG("registry_destroy: destroying (peer_count=%d)", reg->peer_count);
    
    pthread_mutex_destroy(&reg->mutex);
    free(reg);
    
    RLOG("registry_destroy: destroyed");
}

/* ============================================================================
 * Registration Operations
 * ============================================================================ */

bool registry_register_peer(Registry* reg, const char* id, 
                            const char* ip, const char* port) {
    if (!reg || !id || !ip || !port) {
        RLOG("registry_register_peer: NULL parameter");
        return false;
    }
    
    char norm_id[REGISTRY_MAX_ID_LEN];
    if (!registry_normalize_id(id, norm_id, sizeof(norm_id))) {
        RLOG("registry_register_peer: invalid id '%s'", id);
        return false;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    /* Check if peer already exists */
    for (int i = 0; i < reg->peer_count; i++) {
        char existing_norm[REGISTRY_MAX_ID_LEN];
        if (!registry_normalize_id(reg->peers[i].id, existing_norm, 
                                   sizeof(existing_norm))) {
            continue;
        }
        
        if (strcmp(existing_norm, norm_id) == 0) {
            /* Peer exists - update fields */
            RLOG("registry_register_peer: peer %s exists, updating", id);
            
            strncpy(reg->peers[i].ip, ip, sizeof(reg->peers[i].ip) - 1);
            reg->peers[i].ip[sizeof(reg->peers[i].ip) - 1] = '\0';
            
            strncpy(reg->peers[i].port, port, sizeof(reg->peers[i].port) - 1);
            reg->peers[i].port[sizeof(reg->peers[i].port) - 1] = '\0';
            
            reg->peers[i].online = true;
            reg->peers[i].last_seen = time(NULL);
            
            /* CRITICAL: DO NOT change status on update */
            /* Status remains whatever it was (accepted/pending/rejected) */
            
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    /* Peer doesn't exist - add new */
    if (reg->peer_count >= REGISTRY_MAX_PEERS) {
        RLOG("registry_register_peer: registry full");
        pthread_mutex_unlock(&reg->mutex);
        return false;
    }
    
    RegistryPeer* peer = &reg->peers[reg->peer_count++];
    
    strncpy(peer->id, id, sizeof(peer->id) - 1);
    peer->id[sizeof(peer->id) - 1] = '\0';
    
    strncpy(peer->ip, ip, sizeof(peer->ip) - 1);
    peer->ip[sizeof(peer->ip) - 1] = '\0';
    
    strncpy(peer->port, port, sizeof(peer->port) - 1);
    peer->port[sizeof(peer->port) - 1] = '\0';
    
    strcpy(peer->status, "pending");  /* Default status */
    peer->online = true;
    peer->last_seen = time(NULL);
    peer->mode = REG_MODE_NORMAL;
    peer->verified = true;
    peer->created_at = time(NULL);
    
    memset(peer->name, 0, sizeof(peer->name));
    memset(peer->public_key, 0, sizeof(peer->public_key));
    memset(peer->signature, 0, sizeof(peer->signature));
    memset(peer->salt_hex, 0, sizeof(peer->salt_hex));
    
    RLOG("registry_register_peer: added peer %s (status=pending, total=%d)", 
         id, reg->peer_count);
    
    pthread_mutex_unlock(&reg->mutex);
    return true;
}

bool registry_register_secure(Registry* reg, const char* id,
                              const char* ip, const char* port,
                              const char* name, const char* public_key,
                              const char* signature, const char* salt_hex) {
    if (!reg || !id || !ip || !port) {
        RLOG("registry_register_secure: NULL parameter");
        return false;
    }
    
    char norm_id[REGISTRY_MAX_ID_LEN];
    if (!registry_normalize_id(id, norm_id, sizeof(norm_id))) {
        RLOG("registry_register_secure: invalid id '%s'", id);
        return false;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    /* Check if peer already exists */
    for (int i = 0; i < reg->peer_count; i++) {
        char existing_norm[REGISTRY_MAX_ID_LEN];
        if (!registry_normalize_id(reg->peers[i].id, existing_norm, 
                                   sizeof(existing_norm))) {
            continue;
        }
        
        if (strcmp(existing_norm, norm_id) == 0) {
            /* Peer exists - update fields */
            RLOG("registry_register_secure: peer %s exists, updating", id);
            
            strncpy(reg->peers[i].ip, ip, sizeof(reg->peers[i].ip) - 1);
            reg->peers[i].ip[sizeof(reg->peers[i].ip) - 1] = '\0';
            
            strncpy(reg->peers[i].port, port, sizeof(reg->peers[i].port) - 1);
            reg->peers[i].port[sizeof(reg->peers[i].port) - 1] = '\0';
            
            reg->peers[i].online = true;
            reg->peers[i].last_seen = time(NULL);
            reg->peers[i].mode = REG_MODE_SECURE;
            
            if (name) {
                strncpy(reg->peers[i].name, name, sizeof(reg->peers[i].name) - 1);
                reg->peers[i].name[sizeof(reg->peers[i].name) - 1] = '\0';
            }
            
            if (public_key) {
                strncpy(reg->peers[i].public_key, public_key, 
                        sizeof(reg->peers[i].public_key) - 1);
                reg->peers[i].public_key[sizeof(reg->peers[i].public_key) - 1] = '\0';
            }
            
            if (signature) {
                strncpy(reg->peers[i].signature, signature, 
                        sizeof(reg->peers[i].signature) - 1);
                reg->peers[i].signature[sizeof(reg->peers[i].signature) - 1] = '\0';
            }
            
            if (salt_hex) {
                strncpy(reg->peers[i].salt_hex, salt_hex, 
                        sizeof(reg->peers[i].salt_hex) - 1);
                reg->peers[i].salt_hex[sizeof(reg->peers[i].salt_hex) - 1] = '\0';
            }
            
            reg->peers[i].verified = true;
            
            /* CRITICAL: DO NOT change status on update */
            /* Status remains whatever it was (accepted/pending/rejected) */
            
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    /* Peer doesn't exist - add new */
    if (reg->peer_count >= REGISTRY_MAX_PEERS) {
        RLOG("registry_register_secure: registry full");
        pthread_mutex_unlock(&reg->mutex);
        return false;
    }
    
    RegistryPeer* peer = &reg->peers[reg->peer_count++];
    
    strncpy(peer->id, id, sizeof(peer->id) - 1);
    peer->id[sizeof(peer->id) - 1] = '\0';
    
    strncpy(peer->ip, ip, sizeof(peer->ip) - 1);
    peer->ip[sizeof(peer->ip) - 1] = '\0';
    
    strncpy(peer->port, port, sizeof(peer->port) - 1);
    peer->port[sizeof(peer->port) - 1] = '\0';
    
    strcpy(peer->status, "pending");  /* Default status */
    peer->online = true;
    peer->last_seen = time(NULL);
    peer->mode = REG_MODE_SECURE;
    peer->created_at = time(NULL);
    peer->verified = true;
    
    if (name) {
        strncpy(peer->name, name, sizeof(peer->name) - 1);
        peer->name[sizeof(peer->name) - 1] = '\0';
    }
    
    if (public_key) {
        strncpy(peer->public_key, public_key, sizeof(peer->public_key) - 1);
        peer->public_key[sizeof(peer->public_key) - 1] = '\0';
    }
    
    if (signature) {
        strncpy(peer->signature, signature, sizeof(peer->signature) - 1);
        peer->signature[sizeof(peer->signature) - 1] = '\0';
    }
    
    if (salt_hex) {
        strncpy(peer->salt_hex, salt_hex, sizeof(peer->salt_hex) - 1);
        peer->salt_hex[sizeof(peer->salt_hex) - 1] = '\0';
    }
    
    RLOG("registry_register_secure: added secure peer %s (status=pending, total=%d)", 
         id, reg->peer_count);
    
    pthread_mutex_unlock(&reg->mutex);
    return true;
}

/* ============================================================================
 * Status Operations
 * ============================================================================ */

void registry_update_status(Registry* reg, const char* id, const char* status) {
    if (!reg || !id || !status) {
        RLOG("registry_update_status: NULL parameter");
        return;
    }
    
    char norm_id[REGISTRY_MAX_ID_LEN];
    if (!registry_normalize_id(id, norm_id, sizeof(norm_id))) {
        RLOG("registry_update_status: invalid id '%s'", id);
        return;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        char existing_norm[REGISTRY_MAX_ID_LEN];
        if (!registry_normalize_id(reg->peers[i].id, existing_norm, 
                                   sizeof(existing_norm))) {
            continue;
        }
        
        if (strcmp(existing_norm, norm_id) == 0) {
            strncpy(reg->peers[i].status, status, 
                    sizeof(reg->peers[i].status) - 1);
            reg->peers[i].status[sizeof(reg->peers[i].status) - 1] = '\0';
            
            RLOG("registry_update_status: peer %s status -> %s", id, status);
            pthread_mutex_unlock(&reg->mutex);
            return;
        }
    }
    
    RLOG("registry_update_status: peer %s not found", id);
    pthread_mutex_unlock(&reg->mutex);
}

const char* registry_get_status(Registry* reg, const char* id) {
    if (!reg || !id) return NULL;
    
    char norm_id[REGISTRY_MAX_ID_LEN];
    if (!registry_normalize_id(id, norm_id, sizeof(norm_id))) {
        return NULL;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        char existing_norm[REGISTRY_MAX_ID_LEN];
        if (!registry_normalize_id(reg->peers[i].id, existing_norm, 
                                   sizeof(existing_norm))) {
            continue;
        }
        
        if (strcmp(existing_norm, norm_id) == 0) {
            pthread_mutex_unlock(&reg->mutex);
            return reg->peers[i].status;
        }
    }
    
    pthread_mutex_unlock(&reg->mutex);
    return NULL;
}

bool registry_is_accepted(Registry* reg, const char* id) {
    const char* status = registry_get_status(reg, id);
    return status && strcmp(status, "accepted") == 0;
}

bool registry_is_pending(Registry* reg, const char* id) {
    const char* status = registry_get_status(reg, id);
    return status && strcmp(status, "pending") == 0;
}

/* ============================================================================
 * Query Operations
 * ============================================================================ */

bool registry_get_peer(Registry* reg, const char* id, RegistryPeer* out_peer) {
    if (!reg || !id || !out_peer) {
        RLOG("registry_get_peer: NULL parameter");
        return false;
    }
    
    char norm_id[REGISTRY_MAX_ID_LEN];
    if (!registry_normalize_id(id, norm_id, sizeof(norm_id))) {
        RLOG("registry_get_peer: invalid id '%s'", id);
        return false;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        char existing_norm[REGISTRY_MAX_ID_LEN];
        if (!registry_normalize_id(reg->peers[i].id, existing_norm, 
                                   sizeof(existing_norm))) {
            continue;
        }
        
        if (strcmp(existing_norm, norm_id) == 0) {
            *out_peer = reg->peers[i];
            pthread_mutex_unlock(&reg->mutex);
            RLOG("registry_get_peer: found peer %s", id);
            return true;
        }
    }
    
    pthread_mutex_unlock(&reg->mutex);
    RLOG("registry_get_peer: peer %s not found", id);
    return false;
}

bool registry_get_peer_by_name(Registry* reg, const char* name, 
                               RegistryPeer* out_peer) {
    if (!reg || !name || !out_peer) {
        RLOG("registry_get_peer_by_name: NULL parameter");
        return false;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (reg->peers[i].mode == REG_MODE_SECURE &&
            strcmp(reg->peers[i].name, name) == 0) {
            *out_peer = reg->peers[i];
            pthread_mutex_unlock(&reg->mutex);
            RLOG("registry_get_peer_by_name: found peer %s", name);
            return true;
        }
    }
    
    pthread_mutex_unlock(&reg->mutex);
    RLOG("registry_get_peer_by_name: peer %s not found", name);
    return false;
}

bool registry_peer_exists(Registry* reg, const char* id) {
    if (!reg || !id) return false;
    
    char norm_id[REGISTRY_MAX_ID_LEN];
    if (!registry_normalize_id(id, norm_id, sizeof(norm_id))) {
        return false;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        char existing_norm[REGISTRY_MAX_ID_LEN];
        if (!registry_normalize_id(reg->peers[i].id, existing_norm, 
                                   sizeof(existing_norm))) {
            continue;
        }
        
        if (strcmp(existing_norm, norm_id) == 0) {
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    pthread_mutex_unlock(&reg->mutex);
    return false;
}

/* ============================================================================
 * List Operations
 * ============================================================================ */

int registry_get_all_peers(Registry* reg, RegistryPeer* peers, int max_peers) {
    if (!reg || !peers || max_peers <= 0) {
        return 0;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    int count = 0;
    for (int i = 0; i < reg->peer_count && count < max_peers; i++) {
        peers[count++] = reg->peers[i];
    }
    
    pthread_mutex_unlock(&reg->mutex);
    RLOG("registry_get_all_peers: returned %d peers", count);
    return count;
}

int registry_get_accepted_peers(Registry* reg, RegistryPeer* peers, int max_peers) {
    if (!reg || !peers || max_peers <= 0) {
        return 0;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    int count = 0;
    for (int i = 0; i < reg->peer_count && count < max_peers; i++) {
        if (strcmp(reg->peers[i].status, "accepted") == 0) {
            peers[count++] = reg->peers[i];
        }
    }
    
    pthread_mutex_unlock(&reg->mutex);
    RLOG("registry_get_accepted_peers: returned %d peers", count);
    return count;
}

int registry_get_pending_peers(Registry* reg, RegistryPeer* peers, int max_peers) {
    if (!reg || !peers || max_peers <= 0) {
        return 0;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    int count = 0;
    for (int i = 0; i < reg->peer_count && count < max_peers; i++) {
        if (strcmp(reg->peers[i].status, "pending") == 0) {
            peers[count++] = reg->peers[i];
        }
    }
    
    pthread_mutex_unlock(&reg->mutex);
    RLOG("registry_get_pending_peers: returned %d peers", count);
    return count;
}

int registry_get_secure_peers(Registry* reg, RegistryPeer* peers, int max_peers) {
    if (!reg || !peers || max_peers <= 0) {
        return 0;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    int count = 0;
    for (int i = 0; i < reg->peer_count && count < max_peers; i++) {
        if (reg->peers[i].mode == REG_MODE_SECURE) {
            peers[count++] = reg->peers[i];
        }
    }
    
    pthread_mutex_unlock(&reg->mutex);
    RLOG("registry_get_secure_peers: returned %d peers", count);
    return count;
}

/* ============================================================================
 * Update Operations
 * ============================================================================ */

void registry_update_peer(Registry* reg, const char* id, 
                          const char* ip, const char* port) {
    if (!reg || !id || !ip || !port) {
        RLOG("registry_update_peer: NULL parameter");
        return;
    }
    
    char norm_id[REGISTRY_MAX_ID_LEN];
    if (!registry_normalize_id(id, norm_id, sizeof(norm_id))) {
        RLOG("registry_update_peer: invalid id '%s'", id);
        return;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        char existing_norm[REGISTRY_MAX_ID_LEN];
        if (!registry_normalize_id(reg->peers[i].id, existing_norm, 
                                   sizeof(existing_norm))) {
            continue;
        }
        
        if (strcmp(existing_norm, norm_id) == 0) {
            strncpy(reg->peers[i].ip, ip, sizeof(reg->peers[i].ip) - 1);
            reg->peers[i].ip[sizeof(reg->peers[i].ip) - 1] = '\0';
            
            strncpy(reg->peers[i].port, port, sizeof(reg->peers[i].port) - 1);
            reg->peers[i].port[sizeof(reg->peers[i].port) - 1] = '\0';
            
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
    if (!reg || !id) {
        RLOG("registry_set_online: NULL parameter");
        return;
    }
    
    char norm_id[REGISTRY_MAX_ID_LEN];
    if (!registry_normalize_id(id, norm_id, sizeof(norm_id))) {
        RLOG("registry_set_online: invalid id '%s'", id);
        return;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        char existing_norm[REGISTRY_MAX_ID_LEN];
        if (!registry_normalize_id(reg->peers[i].id, existing_norm, 
                                   sizeof(existing_norm))) {
            continue;
        }
        
        if (strcmp(existing_norm, norm_id) == 0) {
            reg->peers[i].online = online;
            reg->peers[i].last_seen = time(NULL);
            RLOG("registry_set_online: peer %s online=%d", id, online);
            pthread_mutex_unlock(&reg->mutex);
            return;
        }
    }
    
    RLOG("registry_set_online: peer %s not found", id);
    pthread_mutex_unlock(&reg->mutex);
}

/* ============================================================================
 * Remove Operations
 * ============================================================================ */

bool registry_remove_peer(Registry* reg, const char* id) {
    if (!reg || !id) {
        RLOG("registry_remove_peer: NULL parameter");
        return false;
    }
    
    char norm_id[REGISTRY_MAX_ID_LEN];
    if (!registry_normalize_id(id, norm_id, sizeof(norm_id))) {
        RLOG("registry_remove_peer: invalid id '%s'", id);
        return false;
    }
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        char existing_norm[REGISTRY_MAX_ID_LEN];
        if (!registry_normalize_id(reg->peers[i].id, existing_norm, 
                                   sizeof(existing_norm))) {
            continue;
        }
        
        if (strcmp(existing_norm, norm_id) == 0) {
            /* Shift remaining peers */
            for (int j = i; j < reg->peer_count - 1; j++) {
                reg->peers[j] = reg->peers[j + 1];
            }
            reg->peer_count--;
            
            RLOG("registry_remove_peer: removed peer %s (remaining=%d)", 
                 id, reg->peer_count);
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
