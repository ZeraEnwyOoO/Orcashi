 // registry.h - Peer Registry in C
#ifndef REGISTRY_H
#define REGISTRY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#define MAX_REGISTRY_PEERS 1024

typedef struct {
    char id[64];
    char ip[INET_ADDRSTRLEN];
    char port[16];
    bool online;
    time_t last_seen;
} RegistryPeer;

typedef struct {
    RegistryPeer peers[MAX_REGISTRY_PEERS];
    int peer_count;
    char registry_file[512];
} Registry;

// Functions
Registry* registry_create(void);
void registry_destroy(Registry* reg);

bool registry_register_peer(Registry* reg, const char* id, const char* ip, const char* port);
bool registry_get_peer(Registry* reg, const char* id, RegistryPeer* out_peer);
void registry_update_peer(Registry* reg, const char* id, const char* ip, const char* port);
void registry_set_online(Registry* reg, const char* id, bool online);
int registry_get_all_peers(Registry* reg, RegistryPeer* peers, int max_peers);
bool registry_remove_peer(Registry* reg, const char* id);
bool registry_peer_exists(Registry* reg, const char* id);

void registry_load(Registry* reg);
void registry_save(Registry* reg);

#endif
