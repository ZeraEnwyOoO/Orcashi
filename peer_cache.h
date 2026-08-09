 // peer_cache.h - Peer Cache in C (REAL)
#ifndef PEER_CACHE_H
#define PEER_CACHE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_CACHE_PEERS 1024
#define CACHE_FILE "/tmp/.orcashi/peers.cache"

typedef struct {
    char id[64];
    char endpoint[128];
    char ip[INET_ADDRSTRLEN];
    int port;
    char name[128];
    time_t last_seen;
    bool online;
    char public_key[512];
} CachePeer;

typedef struct {
    CachePeer peers[MAX_CACHE_PEERS];
    int peer_count;
    char cache_file[512];
    pthread_mutex_t mutex;
    bool dirty;
} PeerCache;

// Functions
PeerCache* peer_cache_create(void);
void peer_cache_destroy(PeerCache* pc);

void peer_cache_save_peer(PeerCache* pc, const CachePeer* peer);
bool peer_cache_get_peer(PeerCache* pc, const char* id, CachePeer* out_peer);
int peer_cache_get_all(PeerCache* pc, CachePeer* peers, int max_peers);
void peer_cache_remove_peer(PeerCache* pc, const char* id);
void peer_cache_clear(PeerCache* pc);

void peer_cache_load(PeerCache* pc);
void peer_cache_save(PeerCache* pc);
void peer_cache_auto_save(PeerCache* pc);

#endif
