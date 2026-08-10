 // peer_cache.h - Peer Cache in C
#ifndef PEER_CACHE_H
#define PEER_CACHE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <arpa/inet.h>

#define MAX_CACHE_PEERS 1024
#define PEER_CACHE_FILE "/tmp/.orcashi/peers.json"

typedef struct {
    char id[64];
    char ip[INET_ADDRSTRLEN];
    int port;
    char endpoint[128];
    bool online;
    time_t last_seen;
} CachePeer;

typedef struct {
    CachePeer peers[MAX_CACHE_PEERS];
    int peer_count;
    char cache_file[512];
    bool modified;
    pthread_mutex_t mutex;
} PeerCache;

// Core functions
PeerCache* peer_cache_create(void);
void peer_cache_destroy(PeerCache* pc);

bool peer_cache_save_peer(PeerCache* pc, const CachePeer* peer);
bool peer_cache_get_peer(PeerCache* pc, const char* id, CachePeer* out_peer);
int peer_cache_get_all(PeerCache* pc, CachePeer* peers, int max_peers);
void peer_cache_clear(PeerCache* pc);

void peer_cache_auto_save(PeerCache* pc);

// Load/Save
void peer_cache_load(PeerCache* pc);
void peer_cache_save(PeerCache* pc);

#endif
