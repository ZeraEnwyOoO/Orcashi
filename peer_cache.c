 #include "peer_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

PeerCache* peer_cache_create(void) {
    PeerCache* pc = (PeerCache*)calloc(1, sizeof(PeerCache));
    if (!pc) return NULL;
    
    strcpy(pc->cache_file, CACHE_FILE);
    pc->peer_count = 0;
    pc->dirty = false;
    
    mkdir("/tmp/.orcashi/", 0700);
    pthread_mutex_init(&pc->mutex, NULL);
    
    peer_cache_load(pc);
    
    return pc;
}

void peer_cache_destroy(PeerCache* pc) {
    if (!pc) return;
    
    if (pc->dirty) {
        peer_cache_save(pc);
    }
    
    pthread_mutex_destroy(&pc->mutex);
    free(pc);
}

void peer_cache_save_peer(PeerCache* pc, const CachePeer* peer) {
    if (!pc || !peer) return;
    
    pthread_mutex_lock(&pc->mutex);
    
    int found = -1;
    for (int i = 0; i < pc->peer_count; i++) {
        if (strcmp(pc->peers[i].id, peer->id) == 0) {
            found = i;
            break;
        }
    }
    
    if (found == -1 && pc->peer_count < MAX_CACHE_PEERS) {
        found = pc->peer_count++;
    }
    
    if (found >= 0) {
        pc->peers[found] = *peer;
        pc->dirty = true;
    }
    
    if (pc->dirty) {
        peer_cache_save(pc);
        pc->dirty = false;
    }
    
    pthread_mutex_unlock(&pc->mutex);
}

bool peer_cache_get_peer(PeerCache* pc, const char* id, CachePeer* out_peer) {
    if (!pc || !out_peer) return false;
    
    pthread_mutex_lock(&pc->mutex);
    
    for (int i = 0; i < pc->peer_count; i++) {
        if (strcmp(pc->peers[i].id, id) == 0) {
            *out_peer = pc->peers[i];
            pthread_mutex_unlock(&pc->mutex);
            return true;
        }
    }
    
    pthread_mutex_unlock(&pc->mutex);
    return false;
}

int peer_cache_get_all(PeerCache* pc, CachePeer* peers, int max_peers) {
    if (!pc || !peers) return 0;
    
    pthread_mutex_lock(&pc->mutex);
    
    int count = 0;
    for (int i = 0; i < pc->peer_count && count < max_peers; i++) {
        peers[count++] = pc->peers[i];
    }
    
    pthread_mutex_unlock(&pc->mutex);
    return count;
}

void peer_cache_remove_peer(PeerCache* pc, const char* id) {
    if (!pc) return;
    
    pthread_mutex_lock(&pc->mutex);
    
    for (int i = 0; i < pc->peer_count; i++) {
        if (strcmp(pc->peers[i].id, id) == 0) {
            for (int j = i; j < pc->peer_count - 1; j++) {
                pc->peers[j] = pc->peers[j + 1];
            }
            pc->peer_count--;
            pc->dirty = true;
            break;
        }
    }
    
    if (pc->dirty) {
        peer_cache_save(pc);
        pc->dirty = false;
    }
    
    pthread_mutex_unlock(&pc->mutex);
}

void peer_cache_clear(PeerCache* pc) {
    if (!pc) return;
    
    pthread_mutex_lock(&pc->mutex);
    pc->peer_count = 0;
    pc->dirty = true;
    peer_cache_save(pc);
    pc->dirty = false;
    pthread_mutex_unlock(&pc->mutex);
}

void peer_cache_load(PeerCache* pc) {
    if (!pc) return;
    
    FILE* f = fopen(pc->cache_file, "r");
    if (!f) return;
    
    char line[2048];
    CachePeer peer;
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
        
        if (in_peer && strstr(line, "\"port\":") != NULL) {
            char* start = strstr(line, "\"port\":") + 7;
            peer.port = atoi(start);
        }
        
        if (in_peer && strstr(line, "\"online\":") != NULL) {
            char* start = strstr(line, "\"online\":") + 9;
            peer.online = (strstr(start, "true") != NULL);
        }
        
        if (in_peer && strstr(line, "\"last_seen\":") != NULL) {
            char* start = strstr(line, "\"last_seen\":") + 12;
            peer.last_seen = atol(start);
        }
        
        if (in_peer && strchr(line, '}') != NULL) {
            if (strlen(peer.id) > 0 && pc->peer_count < MAX_CACHE_PEERS) {
                pc->peers[pc->peer_count++] = peer;
                memset(&peer, 0, sizeof(peer));
                in_peer = false;
            }
        }
    }
    
    fclose(f);
}

void peer_cache_save(PeerCache* pc) {
    if (!pc) return;
    
    FILE* f = fopen(pc->cache_file, "w");
    if (!f) return;
    
    fprintf(f, "{\n  \"peers\": [\n");
    
    for (int i = 0; i < pc->peer_count; i++) {
        if (i > 0) fprintf(f, ",\n");
        
        CachePeer* p = &pc->peers[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": \"%s\",\n", p->id);
        fprintf(f, "      \"ip\": \"%s\",\n", p->ip);
        fprintf(f, "      \"port\": %d,\n", p->port);
        fprintf(f, "      \"online\": %s,\n", p->online ? "true" : "false");
        fprintf(f, "      \"last_seen\": %ld\n", (long)p->last_seen);
        fprintf(f, "    }");
    }
    
    fprintf(f, "\n  ]\n}\n");
    fclose(f);
}

void peer_cache_auto_save(PeerCache* pc) {
    if (!pc) return;
    
    pthread_mutex_lock(&pc->mutex);
    if (pc->dirty) {
        peer_cache_save(pc);
        pc->dirty = false;
    }
    pthread_mutex_unlock(&pc->mutex);
}
