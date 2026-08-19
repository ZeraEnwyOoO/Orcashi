// peer_list.h - Persistent accepted-peer list management
#ifndef PEER_LIST_H
#define PEER_LIST_H

#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_PEER_LIST 1024

/* Reuse RegistryPeer from registry.h */
#include "registry.h"

typedef RegistryPeer PeerListEntry;

/* ============================================================================
 * Peer List - Persistent storage for accepted peers
 * ============================================================================ */

typedef struct {
    PeerListEntry peers[MAX_PEER_LIST];
    int count;
    char file_path[512];
    bool dirty;
} PeerList;

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

PeerList* peer_list_create(void);
void peer_list_destroy(PeerList* pl);

/* ============================================================================
 * Load / Save
 * ============================================================================ */

int peer_list_load(PeerList* pl);
int peer_list_save(PeerList* pl);

/* ============================================================================
 * Query
 * ============================================================================ */

int peer_list_get_count(PeerList* pl);
PeerListEntry* peer_list_get(PeerList* pl, int index);
PeerListEntry* peer_list_find(PeerList* pl, const char* id);

/* ============================================================================
 * Modify
 * ============================================================================ */

int peer_list_add(PeerList* pl, const RegistryPeer* peer);
int peer_list_remove(PeerList* pl, const char* id);
void peer_list_clear(PeerList* pl);
void peer_list_mark_dirty(PeerList* pl);
bool peer_list_is_dirty(PeerList* pl);

#endif
