 // registry.c - Add ids_match function and fix thread safety
#include "registry.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define REGISTRY_FILE "/tmp/.orcashi/registry.json"

#define DEBUG_REGISTRY 1

#if DEBUG_REGISTRY
#define RLOG(fmt, ...) printf("[REGISTRY DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define RLOG(fmt, ...) ((void)0)
#endif

// ===== FIXED: ids_match function for consistent ID comparison =====
static int ids_match(const char* id1, const char* id2) {
    if (!id1 || !id2) return 0;
    
    char n1[64], n2[64];
    strip_brackets(id1, n1, sizeof(n1));
    strip_brackets(id2, n2, sizeof(n2));
    
    return strcmp(n1, n2) == 0;
}

Registry* registry_create(void) {
    Registry* reg = (Registry*)calloc(1, sizeof(Registry));
    if (!reg) return NULL;
    
    strcpy(reg->registry_file, REGISTRY_FILE);
    mkdir("/tmp/.orcashi/", 0700);
    
    pthread_mutex_init(&reg->mutex, NULL);
    RLOG("registry_create() called");
    
    registry_load(reg);
    
    return reg;
}

void registry_destroy(Registry* reg) {
    if (reg) {
        RLOG("registry_destroy() called");
        registry_save(reg);
        pthread_mutex_destroy(&reg->mutex);
        free(reg);
    }
}

bool registry_register_peer(Registry* reg, const char* id, const char* ip, const char* port) {
    if (!reg) return false;
    
    RLOG("registry_register_peer: id='%s', ip='%s', port='%s'", id, ip, port);
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (ids_match(reg->peers[i].id, id)) {
            RLOG("  Peer %s already exists, updating", id);
            strcpy(reg->peers[i].ip, ip);
            strcpy(reg->peers[i].port, port);
            strcpy(reg->peers[i].status, "pending");
            reg->peers[i].online = true;
            reg->peers[i].last_seen = time(NULL);
            registry_save(reg);
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    if (reg->peer_count >= MAX_REGISTRY_PEERS) {
        RLOG("  Registry full! Cannot add peer %s", id);
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
    
    RLOG("  Peer %s added to registry (slot %d)", id, reg->peer_count - 1);
    
    registry_save(reg);
    pthread_mutex_unlock(&reg->mutex);
    return true;
}

bool registry_get_peer(Registry* reg, const char* id, RegistryPeer* out_peer) {
    if (!reg || !out_peer) return false;
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (ids_match(reg->peers[i].id, id)) {
            *out_peer = reg->peers[i];
            RLOG("registry_get_peer: Found peer %s at slot %d", id, i);
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    RLOG("registry_get_peer: Peer %s not found", id);
    pthread_mutex_unlock(&reg->mutex);
    return false;
}

void registry_update_status(Registry* reg, const char* id, const char* status) {
    if (!reg) return;
    
    RLOG("registry_update_status: id='%s', status='%s'", id, status);
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (ids_match(reg->peers[i].id, id)) {
            strcpy(reg->peers[i].status, status);
            RLOG("  Status updated for peer %s to '%s'", id, status);
            registry_save(reg);
            pthread_mutex_unlock(&reg->mutex);
            return;
        }
    }
    
    RLOG("  Peer %s not found for status update", id);
    pthread_mutex_unlock(&reg->mutex);
}

void registry_update_peer(Registry* reg, const char* id, const char* ip, const char* port) {
    if (!reg) return;
    
    RLOG("registry_update_peer: id='%s', ip='%s', port='%s'", id, ip, port);
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (ids_match(reg->peers[i].id, id)) {
            strcpy(reg->peers[i].ip, ip);
            strcpy(reg->peers[i].port, port);
            reg->peers[i].last_seen = time(NULL);
            RLOG("  Peer %s updated", id);
            registry_save(reg);
            break;
        }
    }
    
    pthread_mutex_unlock(&reg->mutex);
}

void registry_set_online(Registry* reg, const char* id, bool online) {
    if (!reg) return;
    
    RLOG("registry_set_online: id='%s', online=%d", id, online);
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (ids_match(reg->peers[i].id, id)) {
            reg->peers[i].online = online;
            reg->peers[i].last_seen = time(NULL);
            RLOG("  Peer %s online status set to %d", id, online);
            registry_save(reg);
            break;
        }
    }
    
    pthread_mutex_unlock(&reg->mutex);
}

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

bool registry_remove_peer(Registry* reg, const char* id) {
    if (!reg) return false;
    
    RLOG("registry_remove_peer: id='%s'", id);
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (ids_match(reg->peers[i].id, id)) {
            for (int j = i; j < reg->peer_count - 1; j++) {
                reg->peers[j] = reg->peers[j + 1];
            }
            reg->peer_count--;
            RLOG("  Peer %s removed", id);
            registry_save(reg);
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    RLOG("  Peer %s not found for removal", id);
    pthread_mutex_unlock(&reg->mutex);
    return false;
}

bool registry_peer_exists(Registry* reg, const char* id) {
    if (!reg) return false;
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (ids_match(reg->peers[i].id, id)) {
            RLOG("registry_peer_exists: Peer %s exists", id);
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    pthread_mutex_unlock(&reg->mutex);
    return false;
}

void registry_load(Registry* reg) {
    if (!reg) return;
    
    RLOG("registry_load: Loading from %s", reg->registry_file);
    
    FILE* f = fopen(reg->registry_file, "r");
    if (!f) {
        RLOG("  No registry file found, starting fresh");
        return;
    }
    
    // ===== FIXED: Thread safety - lock mutex =====
    pthread_mutex_lock(&reg->mutex);
    
    char line[2048];
    RegistryPeer peer;
    bool in_peer = false;
    int loaded = 0;
    
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "\"id\":\"") != NULL) {
            char* start = strstr(line, "\"id\":\"") + 6;
            char* end = strchr(start, '"');
            if (end) {
                int len = end - start;
                if (len < (int)sizeof(peer.id)) {
                    strncpy(peer.id, start, len);
                    peer.id[len] = '\0';
                    in_peer = true;
                    RLOG("  Found peer id: %s", peer.id);
                }
            }
        }
        
        if (in_peer && strstr(line, "\"ip\":\"") != NULL) {
            char* start = strstr(line, "\"ip\":\"") + 6;
            char* end = strchr(start, '"');
            if (end) {
                int len = end - start;
                if (len < (int)sizeof(peer.ip)) {
                    strncpy(peer.ip, start, len);
                    peer.ip[len] = '\0';
                }
            }
        }
        
        if (in_peer && strstr(line, "\"port\":\"") != NULL) {
            char* start = strstr(line, "\"port\":\"") + 8;
            char* end = strchr(start, '"');
            if (end) {
                int len = end - start;
                if (len < (int)sizeof(peer.port)) {
                    strncpy(peer.port, start, len);
                    peer.port[len] = '\0';
                }
            }
        }
        
        if (in_peer && strstr(line, "\"online\":") != NULL) {
            char* start = strstr(line, "\"online\":") + 9;
            peer.online = (strstr(start, "true") != NULL);
        }
        
        if (in_peer && strstr(line, "\"status\":\"") != NULL) {
            char* start = strstr(line, "\"status\":\"") + 10;
            char* end = strchr(start, '"');
            if (end) {
                int len = end - start;
                if (len < (int)sizeof(peer.status)) {
                    strncpy(peer.status, start, len);
                    peer.status[len] = '\0';
                    RLOG("  Found status: %s", peer.status);
                }
            }
        }
        
        if (in_peer && strstr(line, "\"last_seen\":") != NULL) {
            char* start = strstr(line, "\"last_seen\":") + 12;
            peer.last_seen = atol(start);
        }
        
        if (in_peer && strchr(line, '}') != NULL) {
            if (strlen(peer.id) > 0 && reg->peer_count < MAX_REGISTRY_PEERS) {
                reg->peers[reg->peer_count++] = peer;
                loaded++;
                RLOG("  Loaded peer %s (slot %d)", peer.id, reg->peer_count - 1);
                memset(&peer, 0, sizeof(peer));
                in_peer = false;
            }
        }
    }
    
    fclose(f);
    RLOG("registry_load: Loaded %d peers, total peer_count=%d", loaded, reg->peer_count);
    
    // ===== FIXED: Thread safety - unlock mutex =====
    pthread_mutex_unlock(&reg->mutex);
}

void registry_save(Registry* reg) {
    if (!reg) return;
    
    RLOG("registry_save: Saving to %s, %d peers", reg->registry_file, reg->peer_count);
    
    // ===== FIXED: Thread safety - lock mutex =====
    pthread_mutex_lock(&reg->mutex);
    
    FILE* f = fopen(reg->registry_file, "w");
    if (!f) {
        RLOG("  Failed to open registry file for writing!");
        pthread_mutex_unlock(&reg->mutex);
        return;
    }
    
    fprintf(f, "{\n  \"peers\": [\n");
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (i > 0) fprintf(f, ",\n");
        RegistryPeer* p = &reg->peers[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": \"%s\",\n", p->id);
        fprintf(f, "      \"ip\": \"%s\",\n", p->ip);
        fprintf(f, "      \"port\": \"%s\",\n", p->port);
        fprintf(f, "      \"online\": %s,\n", p->online ? "true" : "false");
        fprintf(f, "      \"status\": \"%s\",\n", p->status);
        fprintf(f, "      \"last_seen\": %ld\n", (long)p->last_seen);
        fprintf(f, "    }");
    }
    
    fprintf(f, "\n  ]\n}\n");
    fclose(f);
    
    RLOG("registry_save: Saved successfully");
    
    // ===== FIXED: Thread safety - unlock mutex =====
    pthread_mutex_unlock(&reg->mutex);
}
