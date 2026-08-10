#ifndef PEER_FINDER_H
#define PEER_FINDER_H

#include <stdbool.h>

typedef struct PeerFinder PeerFinder;
typedef struct ORCASHI ORCASHI;

// ===== Create / Destroy =====
PeerFinder* peer_finder_create(ORCASHI* orcashi);
void peer_finder_destroy(PeerFinder* finder);

// ===== Find Peer =====
char* peer_finder_find(PeerFinder* finder, const char* id);

// ===== Cache =====
void peer_finder_cache_peer(PeerFinder* finder, const char* id, const char* endpoint);

// ===== Clear =====
void peer_finder_clear(PeerFinder* finder);

#endif
