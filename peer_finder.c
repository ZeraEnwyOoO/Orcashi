#include "peer_finder.h"
#include "orcashi.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

struct PeerFinder {
    ORCASHI* orcashi;
};

// ===== Create =====
PeerFinder* peer_finder_create(ORCASHI* orcashi) {
    PeerFinder* finder = (PeerFinder*)calloc(1, sizeof(PeerFinder));
    if (!finder) return NULL;
    
    finder->orcashi = orcashi;
    
    return finder;
}

// ===== Destroy =====
void peer_finder_destroy(PeerFinder* finder) {
    if (!finder) return;
    free(finder);
}

// ===== Find Peer =====
char* peer_finder_find(PeerFinder* finder, const char* id) {
    if (!finder || !finder->orcashi) return NULL;
    
    ORCASHI* orcashi = finder->orcashi;
    
    // 1. Check Cache
    CachePeer peer;
    if (peer_cache_get_peer(orcashi->cache, id, &peer) && peer.online) {
        char* result = (char*)malloc(128);
        snprintf(result, 128, "%s:%d", peer.ip, peer.port);
        printf("[PEER] Found in cache: %s\n", result);
        return result;
    }
    
    // 2. Check Registry
    RegistryPeer reg_peer;
    if (registry_get_peer(orcashi->registry, id, &reg_peer)) {
        char* result = (char*)malloc(128);
        snprintf(result, 128, "%s:%s", reg_peer.ip, reg_peer.port);
        printf("[PEER] Found in registry: %s\n", result);
        return result;
    }
    
    // 3. Check DHT
    if (orcashi->dht_wrapper) {
        char* result = dht_wrapper_lookup(orcashi->dht_wrapper, id);
        if (result) {
            // Cache it
            char ip[64];
            int port;
            sscanf(result, "%[^:]:%d", ip, &port);
            
            CachePeer new_peer;
            strcpy(new_peer.id, id);
            strcpy(new_peer.ip, ip);
            new_peer.port = port;
            new_peer.online = true;
            new_peer.last_seen = time(NULL);
            peer_cache_save_peer(orcashi->cache, &new_peer);
            
            return result;
        }
    }
    
    printf("[PEER] Peer %s not found!\n", id);
    return NULL;
}

// ===== Cache =====
void peer_finder_cache_peer(PeerFinder* finder, const char* id, const char* endpoint) {
    if (!finder || !finder->orcashi || !id || !endpoint) return;
    
    ORCASHI* orcashi = finder->orcashi;
    
    char ip[64];
    int port;
    sscanf(endpoint, "%[^:]:%d", ip, &port);
    
    CachePeer peer;
    strcpy(peer.id, id);
    strcpy(peer.ip, ip);
    peer.port = port;
    peer.online = true;
    peer.last_seen = time(NULL);
    peer_cache_save_peer(orcashi->cache, &peer);
}

// ===== Clear =====
void peer_finder_clear(PeerFinder* finder) {
    if (!finder || !finder->orcashi) return;
    peer_cache_clear(finder->orcashi->cache);
}
