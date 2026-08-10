#include "bootstrap.h"
#include <stdio.h>

BootstrapNode bootstrap_nodes[BOOTSTRAP_NODES] = {
    {"router.bittorrent.com", 6881},
    {"dht.transmissionbt.com", 6881},
    {"router.utorrent.com", 6881},
    {"dht.aelitis.com", 6881}
};

void bootstrap_init(void) {
    printf("[BOOTSTRAP] %d bootstrap nodes loaded\n", BOOTSTRAP_NODES);
}
