 // orcashi.h - ORCASHI Main Header with DHT
#ifndef ORCASHI_H
#define ORCASHI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ctype.h>

#include "plug.h"
#include "discovery.h"
#include "registry.h"
#include "request.h"
#include "peer_cache.h"
#include "endpoint.h"

// DHT Forward declaration (will be added in v2.0)
// #include "dht.h"

#define ORCASHI_VERSION "1.0"
#define ORCASHI_PORT 9000

typedef struct {
    TCPPlug* plug;
    Discovery* discovery;
    Registry* registry;
    RequestManager* requests;
    PeerCache* cache;
    EndpointRegistry* endpoints;
    
    char my_id[64];
    char peer_id[64];
    char local_ip[INET_ADDRSTRLEN];
    char peer_ip[INET_ADDRSTRLEN];
    
    bool connected;
    bool running;
    bool registered;
    
    pthread_t chat_thread;
    pthread_t heartbeat_thread;
    pthread_mutex_t mutex;
} ORCASHI;

// Main functions
ORCASHI* orcashi_create(void);
void orcashi_destroy(ORCASHI* orcashi);

bool orcashi_init(ORCASHI* orcashi);
bool orcashi_create_room(ORCASHI* orcashi, int port);
bool orcashi_join_room(ORCASHI* orcashi, const char* ip, int port);

bool orcashi_send_message(ORCASHI* orcashi, const char* msg);
bool orcashi_receive_message(ORCASHI* orcashi, char* msg, int msg_size, int timeout_ms);
bool orcashi_is_connected(ORCASHI* orcashi);
void orcashi_disconnect(ORCASHI* orcashi);

const char* orcashi_get_my_id(ORCASHI* orcashi);
const char* orcashi_get_peer_id(ORCASHI* orcashi);
const char* orcashi_get_peer_ip(ORCASHI* orcashi);

// Identity
bool orcashi_register_identity(ORCASHI* orcashi);
bool orcashi_connect_peer(ORCASHI* orcashi, const char* id);

// Discovery
void orcashi_broadcast_presence(ORCASHI* orcashi);
void orcashi_search_peer(ORCASHI* orcashi, const char* id);

// Peers
void orcashi_show_peers(ORCASHI* orcashi);
void orcashi_show_requests(ORCASHI* orcashi);
bool orcashi_accept_request(ORCASHI* orcashi, const char* from_id);

// UI
void orcashi_show_banner(ORCASHI* orcashi);
void orcashi_show_help(void);

// Helpers
char* orcashi_generate_id(void);
char* orcashi_get_local_ip(void);

#endif
