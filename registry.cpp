 // registry.c - Peer Registry Implementation in C
#include "registry.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define REGISTRY_FILE "/tmp/.orcashi/registry.json"

Registry* registry_create(void) {
    Registry* reg = (Registry*)calloc(1, sizeof(Registry));
    if (!reg) return NULL;
    
    strcpy(reg->registry_file, REGISTRY_FILE);
    
    // Create directory
    mkdir("/tmp/.orcashi/", 0700);
    
    registry_load(reg);
    
    return reg;
}

void registry_destroy(Registry* reg) {
    if (reg) {
        registry_save(reg);
        free(reg);
    }
}

bool registry_register_peer(Registry* reg, const char* id, const char* ip, const char* port) {
    if (!reg) return false;
    
    // Check if already exists
    for (int i = 0; i < reg->peer_count; i++) {
        if (strcmp(reg->peers[i].id, id) == 0) {
            fprintf(stderr, "[ERROR] ID %s already registered!\n", id);
            return false;
        }
    }
    
    if (reg->peer_count >= MAX_REGISTRY_PEERS) return false;
    
    RegistryPeer* peer = &reg->peers[reg->peer_count++];
    strcpy(peer->id, id);
    strcpy(peer->ip, ip);
    strcpy(peer->port, port);
    peer->online = true;
    peer->last_seen = time(NULL);
    
    registry_save(reg);
    return true;
}

bool registry_get_peer(Registry* reg, const char* id, RegistryPeer* out_peer) {
    if (!reg || !out_peer) return false;
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (strcmp(reg->peers[i].id, id) == 0) {
            *out_peer = reg->peers[i];
            return true;
        }
    }
    
    return false;
}

void registry_update_peer(Registry* reg, const char* id, const char* ip, const char* port) {
    if (!reg) return;
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (strcmp(reg->peers[i].id, id) == 0) {
            strcpy(reg->peers[i].ip, ip);
            strcpy(reg->peers[i].port, port);
            reg->peers[i].last_seen = time(NULL);
            registry_save(reg);
            break;
        }
    }
}

void registry_set_online(Registry* reg, const char* id, bool online) {
    if (!reg) return;
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (strcmp(reg->peers[i].id, id) == 0) {
            reg->peers[i].online = online;
            reg->peers[i].last_seen = time(NULL);
            registry_save(reg);
            break;
        }
    }
}

int registry_get_all_peers(Registry* reg, RegistryPeer* peers, int max_peers) {
    if (!reg || !peers) return 0;
    
    int count = 0;
    for (int i = 0; i < reg->peer_count && count < max_peers; i++) {
        peers[count++] = reg->peers[i];
    }
    
    return count;
}

bool registry_remove_peer(Registry* reg, const char* id) {
    if (!reg) return false;
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (strcmp(reg->peers[i].id, id) == 0) {
            for (int j = i; j < reg->peer_count - 1; j++) {
                reg->peers[j] = reg->peers[j + 1];
            }
            reg->peer_count--;
            registry_save(reg);
            return true;
        }
    }
    
    return false;
}

bool registry_peer_exists(Registry* reg, const char* id) {
    if (!reg) return false;
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (strcmp(reg->peers[i].id, id) == 0) {
            return true;
        }
    }
    
    return false;
}

void registry_load(Registry* reg) {
    if (!reg) return;
    
    FILE* f = fopen(reg->registry_file, "r");
    if (!f) return;
    
    char line[1024];
    RegistryPeer peer;
    bool in_peer = false;
    
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
        
        if (in_peer && strchr(line, '}') != NULL) {
            if (strlen(peer.id) > 0 && reg->peer_count < MAX_REGISTRY_PEERS) {
                reg->peers[reg->peer_count++] = peer;
                memset(&peer, 0, sizeof(peer));
                in_peer = false;
            }
        }
    }
    
    fclose(f);
}

void registry_save(Registry* reg) {
    if (!reg) return;
    
    FILE* f = fopen(reg->registry_file, "w");
    if (!f) return;
    
    fprintf(f, "{\n  \"peers\": [\n");
    
    for (int i = 0; i < reg->peer_count; i++) {
        if (i > 0) fprintf(f, ",\n");
        RegistryPeer* p = &reg->peers[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": \"%s\",\n", p->id);
        fprintf(f, "      \"ip\": \"%s\",\n", p->ip);
        fprintf(f, "      \"port\": \"%s\",\n", p->port);
        fprintf(f, "      \"online\": %s,\n", p->online ? "true" : "false");
        fprintf(f, "      \"last_seen\": %ld\n", (long)p->last_seen);
        fprintf(f, "    }");
    }
    
    fprintf(f, "\n  ]\n}\n");
    fclose(f);
}
