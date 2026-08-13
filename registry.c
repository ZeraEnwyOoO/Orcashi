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
#define RLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[REGISTRY DEBUG] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define RLOG(fmt, ...) ((void)0)
#endif

Registry* registry_create(void) {
    Registry* reg = (Registry*)calloc(1, sizeof(Registry));
    if (!reg) return NULL;
    
    strcpy(reg->registry_file, REGISTRY_FILE);
    mkdir("/tmp/.orcashi/", 0700);
    pthread_mutex_init(&reg->mutex, NULL);
    RLOG("Registry created");
    registry_load(reg);
    
    return reg;
}

void registry_destroy(Registry* reg) {
    if (reg) {
        RLOG("Registry destroyed");
        registry_save(reg);
        pthread_mutex_destroy(&reg->mutex);
        free(reg);
    }
}

bool registry_register_peer(Registry* reg, const char* id, const char* ip, const char* port) {
    if (!reg) return false;
    
    RLOG("Registering peer: id='%s', ip='%s', port='%s'", id, ip, port);
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (strcmp(reg->peers[i].id, id) == 0) {
            RLOG("Peer %s already exists, updating", id);
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
        RLOG("Registry full! Cannot add peer %s", id);
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
    
    RLOG("Peer %s added to registry (slot %d)", id, reg->peer_count - 1);
    
    registry_save(reg);
    pthread_mutex_unlock(&reg->mutex);
    return true;
}

bool registry_get_peer(Registry* reg, const char* id, RegistryPeer* out_peer) {
    if (!reg || !out_peer) return false;
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (strcmp(reg->peers[i].id, id) == 0) {
            *out_peer = reg->peers[i];
            RLOG("Found peer %s at slot %d", id, i);
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    RLOG("Peer %s not found", id);
    pthread_mutex_unlock(&reg->mutex);
    return false;
}

void registry_update_status(Registry* reg, const char* id, const char* status) {
    if (!reg) return;
    
    RLOG("Updating status: id='%s', status='%s'", id, status);
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (strcmp(reg->peers[i].id, id) == 0) {
            strcpy(reg->peers[i].status, status);
            RLOG("Status updated for peer %s to '%s'", id, status);
            registry_save(reg);
            pthread_mutex_unlock(&reg->mutex);
            return;
        }
    }
    
    RLOG("Peer %s not found for status update", id);
    pthread_mutex_unlock(&reg->mutex);
}

void registry_update_peer(Registry* reg, const char* id, const char* ip, const char* port) {
    if (!reg) return;
    
    RLOG("Updating peer: id='%s', ip='%s', port='%s'", id, ip, port);
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (strcmp(reg->peers[i].id, id) == 0) {
            strcpy(reg->peers[i].ip, ip);
            strcpy(reg->peers[i].port, port);
            reg->peers[i].last_seen = time(NULL);
            RLOG("Peer %s updated", id);
            registry_save(reg);
            break;
        }
    }
    
    pthread_mutex_unlock(&reg->mutex);
}

void registry_set_online(Registry* reg, const char* id, bool online) {
    if (!reg) return;
    
    RLOG("Setting online status: id='%s', online=%d", id, online);
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (strcmp(reg->peers[i].id, id) == 0) {
            reg->peers[i].online = online;
            reg->peers[i].last_seen = time(NULL);
            RLOG("Peer %s online status set to %d", id, online);
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
    
    RLOG("get_all_peers: returned %d peers", count);
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
    
    RLOG("get_accepted_peers: returned %d peers", count);
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
    
    RLOG("get_pending_peers: returned %d peers", count);
    pthread_mutex_unlock(&reg->mutex);
    return count;
}

bool registry_remove_peer(Registry* reg, const char* id) {
    if (!reg) return false;
    
    RLOG("Removing peer: id='%s'", id);
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (strcmp(reg->peers[i].id, id) == 0) {
            for (int j = i; j < reg->peer_count - 1; j++) {
                reg->peers[j] = reg->peers[j + 1];
            }
            reg->peer_count--;
            RLOG("Peer %s removed", id);
            registry_save(reg);
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    RLOG("Peer %s not found for removal", id);
    pthread_mutex_unlock(&reg->mutex);
    return false;
}

bool registry_peer_exists(Registry* reg, const char* id) {
    if (!reg) return false;
    
    pthread_mutex_lock(&reg->mutex);
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (strcmp(reg->peers[i].id, id) == 0) {
            RLOG("Peer %s exists", id);
            pthread_mutex_unlock(&reg->mutex);
            return true;
        }
    }
    
    pthread_mutex_unlock(&reg->mutex);
    return false;
}

void registry_load(Registry* reg) {
    if (!reg) return;
    
    RLOG("Loading registry from %s", reg->registry_file);
    
    FILE* f = fopen(reg->registry_file, "r");
    if (!f) {
        RLOG("No registry file found, starting fresh");
        return;
    }
    
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
                strncpy(peer.id, start, len);
                peer.id[len] = '\0';
                in_peer = true;
            }
        }
        
        if (in_peer && strstr(line, "\"ip\":\"") != NULL) {
            char* start = strstr(line, "\"ip\":\"") + 6;
            char* end = strchr(start, '"');
            if (end) {
                int len = end - start;
                strncpy(peer.ip, start, len);
                peer.ip[len] = '\0';
            }
        }
        
        if (in_peer && strstr(line, "\"port\":\"") != NULL) {
            char* start = strstr(line, "\"port\":\"") + 8;
            char* end = strchr(start, '"');
            if (end) {
                int len = end - start;
                strncpy(peer.port, start, len);
                peer.port[len] = '\0';
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
                strncpy(peer.status, start, len);
                peer.status[len] = '\0';
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
                memset(&peer, 0, sizeof(peer));
                in_peer = false;
            }
        }
    }
    
    fclose(f);
    RLOG("Loaded %d peers from registry", loaded);
    pthread_mutex_unlock(&reg->mutex);
}

void registry_save(Registry* reg) {
    if (!reg) return;
    
    RLOG("Saving registry to %s, %d peers", reg->registry_file, reg->peer_count);
    
    pthread_mutex_lock(&reg->mutex);
    
    FILE* f = fopen(reg->registry_file, "w");
    if (!f) {
        RLOG("Failed to open registry file for writing!");
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
    
    RLOG("Registry saved successfully");
    pthread_mutex_unlock(&reg->mutex);
}
