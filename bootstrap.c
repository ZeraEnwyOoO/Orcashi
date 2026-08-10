 #include "bootstrap.h"
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>

BootstrapNode bootstrap_nodes[BOOTSTRAP_NODES] = {
    {"router.bittorrent.com", 6881, ""},
    {"dht.transmissionbt.com", 6881, ""},
    {"router.utorrent.com", 6881, ""},
    {"dht.aelitis.com", 6881, ""},
    {"bootstrap.jami.net", 6881, ""},
    {"dht.libtorrent.org", 6881, ""}
};

void bootstrap_init(void) {
    printf("[BOOTSTRAP] Loading %d bootstrap nodes...\n", BOOTSTRAP_NODES);
    
    for (int i = 0; i < BOOTSTRAP_NODES; i++) {
        struct hostent* he = gethostbyname(bootstrap_nodes[i].host);
        if (he && he->h_addr_list[0]) {
            struct sockaddr_in addr;
            memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
            inet_ntop(AF_INET, &addr.sin_addr, bootstrap_nodes[i].ip, INET_ADDRSTRLEN);
            printf("[BOOTSTRAP] %s -> %s\n", bootstrap_nodes[i].host, bootstrap_nodes[i].ip);
        } else {
            printf("[BOOTSTRAP] Failed to resolve %s\n", bootstrap_nodes[i].host);
        }
    }
}

int bootstrap_get_node(int index, BootstrapNode* node) {
    if (index < 0 || index >= BOOTSTRAP_NODES) return -1;
    *node = bootstrap_nodes[index];
    return 0;
}
