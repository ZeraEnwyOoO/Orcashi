#ifndef BOOTSTRAP_H
#define BOOTSTRAP_H

#define BOOTSTRAP_NODES 4

typedef struct {
    char host[64];
    int port;
} BootstrapNode;

extern BootstrapNode bootstrap_nodes[BOOTSTRAP_NODES];

void bootstrap_init(void);

#endif
