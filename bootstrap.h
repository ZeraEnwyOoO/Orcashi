 // bootstrap.h - Added bootstrap_connect_dht
#ifndef BOOTSTRAP_H
#define BOOTSTRAP_H

#include <arpa/inet.h>

#define BOOTSTRAP_NODES 6

typedef struct {
    char host[64];
    int port;
    char ip[INET_ADDRSTRLEN];
} BootstrapNode;

extern BootstrapNode bootstrap_nodes[BOOTSTRAP_NODES];

void bootstrap_init(void);
int bootstrap_get_node(int index, BootstrapNode* node);
void bootstrap_connect_dht(int dht_socket);

#endif
