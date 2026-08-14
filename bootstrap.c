 // bootstrap.c - Fixed with fallback IP addresses
#include "bootstrap.h"
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>

BootstrapNode bootstrap_nodes[BOOTSTRAP_NODES] = {
    {"router.bittorrent.com", 6881, ""},
    {"dht.transmissionbt.com", 6881, ""},
    {"router.utorrent.com", 6881, ""},
    {"dht.aelitis.com", 6881, ""},
    {"bootstrap.jami.net", 6881, ""},
    {"dht.libtorrent.org", 6881, ""}
};

// ===== FALLBACK IPs for when DNS fails =====
static const char* fallback_ips[BOOTSTRAP_NODES] = {
    "83.236.216.176",    // router.bittorrent.com
    "162.159.192.33",    // dht.transmissionbt.com
    "104.244.79.180",    // router.utorrent.com
    "5.45.84.215",       // dht.aelitis.com
    "51.222.100.206",    // bootstrap.jami.net
    "144.217.249.33"     // dht.libtorrent.org
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
            // ===== FIX: Use fallback IP if DNS fails =====
            printf("[BOOTSTRAP] DNS failed for %s, using fallback\n", bootstrap_nodes[i].host);
            strcpy(bootstrap_nodes[i].ip, fallback_ips[i]);
            printf("[BOOTSTRAP] %s -> %s (fallback)\n", bootstrap_nodes[i].host, bootstrap_nodes[i].ip);
        }
    }
}

int bootstrap_get_node(int index, BootstrapNode* node) {
    if (index < 0 || index >= BOOTSTRAP_NODES) return -1;
    *node = bootstrap_nodes[index];
    return 0;
}
