//that shit again i almost die and need new file? damn real feelling when make orcashi 
//it's so hard than i am imagine bro maybe i am new? i just self learn can't lie i am vibe coder
//code just a tool but i try my best to make it as long term project 
 #ifndef DHT_NODE_H
#define DHT_NODE_H

#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DHT_NODE_PORT 33446

typedef struct DHTNode DHTNode;

// ===== Lifecycle =====
DHTNode* dht_node_create(void);
void dht_node_destroy(DHTNode* node);
int dht_node_start(DHTNode* node, int port);
void dht_node_stop(DHTNode* node);

// ===== Announcement =====
int dht_node_announce(DHTNode* node, const char* id, int port);
int dht_node_announce_secure(DHTNode* node, const char* id, int port, 
                             const char* public_key, const char* signature);

// ===== Lookup =====
int dht_node_lookup(DHTNode* node, const char* id, int timeout_sec, 
                    char* ip_out, int* port_out);
int dht_node_lookup_secure(DHTNode* node, const char* id, int timeout_sec,
                           char* ip_out, int* port_out,
                           char* public_key_out, char* signature_out);

// ===== Periodic =====
void dht_node_periodic(DHTNode* node);

// ===== Status =====
bool dht_node_is_running(DHTNode* node);
int dht_node_get_port(DHTNode* node);

#endif
