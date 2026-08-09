// dht_impl.h - DHT Implementation Helper Header
//sorry bro i forget this header haha
#ifndef DHT_IMPL_H
#define DHT_IMPL_H

#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// ===== Debug Functions =====
void dht_set_log_file(const char* filename);
void dht_set_debug(int enabled);

// ===== Initialization =====
int dht_init_helper(int port, const unsigned char* id);
void dht_shutdown_helper(void);
int dht_get_socket(void);
const char* dht_get_node_id(void);
int dht_is_initialized(void);

// ===== DHT Operations =====
int dht_store_peer(const char* id, int port);
int dht_lookup_peer(const char* id, char* result, int result_size);

// ===== Bootstrap =====
int dht_add_bootstrap_node(const char* host, int port);
void dht_auto_bootstrap(void);

// ===== Statistics =====
void dht_print_stats(void);
void dht_dump_table(void);

#ifdef __cplusplus
}
#endif

#endif
