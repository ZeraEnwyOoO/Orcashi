#include "connector.h"
#include "orcashi.h"
#include "nat_punch.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

struct Connector {
    ORCASHI* orcashi;
    PunchState* punch;
    bool connected;
};

// ===== Create =====
Connector* connector_create(ORCASHI* orcashi) {
    Connector* connector = (Connector*)calloc(1, sizeof(Connector));
    if (!connector) return NULL;
    
    connector->orcashi = orcashi;
    connector->punch = orcashi ? orcashi->punch : NULL;
    connector->connected = false;
    
    return connector;
}

// ===== Destroy =====
void connector_destroy(Connector* connector) {
    if (!connector) return;
    free(connector);
}

// ===== Connect by ID =====
bool connector_connect(Connector* connector, const char* id) {
    if (!connector || !connector->orcashi) return false;
    
    ORCASHI* orcashi = connector->orcashi;
    
    printf("[CONN] Looking for peer: %s\n", id);
    
    // Use peer finder
    if (!orcashi->peer_finder) {
        printf("[CONN] Peer finder not initialized!\n");
        return false;
    }
    
    char* endpoint = peer_finder_find(orcashi->peer_finder, id);
    if (!endpoint) {
        printf("[CONN] Peer not found!\n");
        return false;
    }
    
    // Parse endpoint
    char ip[INET_ADDRSTRLEN];
    int port = 9000;
    sscanf(endpoint, "%[^:]:%d", ip, &port);
    free(endpoint);
    
    printf("[CONN] Found peer at %s:%d\n", ip, port);
    
    // Try NAT punch
    if (orcashi->punch) {
        printf("[CONN] Attempting NAT hole punch...\n");
        if (punch_punch(orcashi->punch, ip, PUNCH_PORT) == 0) {
            printf("[CONN] NAT punch successful!\n");
            connector->connected = true;
            return true;
        }
        printf("[CONN] NAT punch failed, trying direct connect...\n");
    }
    
    // Direct connect
    return connector_connect_direct(connector, ip, port);
}

// ===== Direct Connect =====
bool connector_connect_direct(Connector* connector, const char* ip, int port) {
    if (!connector || !connector->orcashi) return false;
    
    ORCASHI* orcashi = connector->orcashi;
    
    printf("[CONN] Direct connecting to %s:%d...\n", ip, port);
    
    // Use plug to connect
    if (orcashi->plug) {
        if (plug_connect_client(orcashi->plug, ip, port)) {
            connector->connected = true;
            orcashi->connected = true;
            orcashi->running = true;
            strcpy(orcashi->peer_ip, ip);
            printf("[CONN] Connected!\n");
            return true;
        }
    }
    
    printf("[CONN] Failed to connect!\n");
    return false;
}

// ===== Status =====
bool connector_is_connected(Connector* connector) {
    if (!connector) return false;
    
    if (connector->orcashi && connector->orcashi->plug) {
        return plug_is_connected(connector->orcashi->plug);
    }
    
    return connector->connected;
}
