//that shit again i almost die and need new file? damn real feelling when make orcashi 
//it's so hard than i am imagine bro maybe i am new? i just self learn can't lie i am vibe coder
//code just a tool but i try my best to make it as long term project 
#ifndef DHT_NODE_H
#define DHT_NODE_H

#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct DHTNode DHTNode;

DHTNode* dht_node_create(void);
void dht_node_destroy(DHTNode* node);
int dht_node_start(DHTNode* node, int port);
void dht_node_stop(DHTNode* node);
int dht_node_announce(DHTNode* node, const char* id, int port);
int dht_node_lookup(DHTNode* node, const char* id, int timeout_sec, char* ip_out, int* port_out);
void dht_node_periodic(DHTNode* node);

#endif
