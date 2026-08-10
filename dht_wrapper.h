#ifndef DHT_WRAPPER_H
#define DHT_WRAPPER_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

// Forward declarations
typedef struct DHTWrapper DHTWrapper;
typedef struct ORCASHI ORCASHI;

// ===== Create / Destroy =====
DHTWrapper* dht_wrapper_create(ORCASHI* orcashi);
void dht_wrapper_destroy(DHTWrapper* wrapper);

// ===== Core Functions =====
bool dht_wrapper_init(DHTWrapper* wrapper);
void dht_wrapper_loop(DHTWrapper* wrapper);
void dht_wrapper_stop(DHTWrapper* wrapper);

// ===== Announce =====
bool dht_wrapper_announce(DHTWrapper* wrapper, const char* id, const char* endpoint);

// ===== Lookup =====
char* dht_wrapper_lookup(DHTWrapper* wrapper, const char* id);

// ===== Bootstrap =====
void dht_wrapper_bootstrap(DHTWrapper* wrapper);

// ===== Status =====
bool dht_wrapper_is_connected(DHTWrapper* wrapper);
int dht_wrapper_get_nodes(DHTWrapper* wrapper);

#endif
