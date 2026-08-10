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

#include "plug.h"
#include "discovery.h"
#include "registry.h"
#include "request.h"
#include "peer_cache.h"
#include "endpoint.h"
#include "dht.h"
#include "dht_impl.h"
#include "nat_punch.h"
#include "bootstrap.h"

#define ORCASHI_VERSION "3.1"
#define ORCASHI_PORT 9000
#define DHT_PORT 6881

typedef struct {
    TCPPlug* plug;
    Discovery* discovery;
    Registry* registry;
    RequestManager* requests;
    PeerCache* cache;
    EndpointRegistry* endpoints;
    
    int dht_socket;
    unsigned char dht_id[20];
    char dht_id_hex[41];
    bool dht_initialized;
    pthread_t dht_thread;
    pthread_mutex_t dht_mutex;
    
    PunchState* punch;
    
    char my_id[64];
    char peer_id[64];
    char local_ip[INET_ADDRSTRLEN];
    char peer_ip[INET_ADDRSTRLEN];
    
    bool connected;
    bool running;
    bool registered;
    bool dht_enabled;
    
    pthread_t chat_thread;
    pthread_t heartbeat_thread;
    pthread_mutex_t mutex;
    
    void (*on_peer_found)(const char* id, const char* ip);
    void (*on_message_received)(const char* from, const char* msg);
    void (*on_status_change)(const char* status);
} ORCASHI;

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

// ===== DHT Functions =====
bool orcashi_dht_init(ORCASHI* orcashi);
void orcashi_dht_shutdown(ORCASHI* orcashi);
bool orcashi_dht_register(ORCASHI* orcashi);
char* orcashi_dht_lookup(ORCASHI* orcashi, const char* id);
char* orcashi_dht_search(ORCASHI* orcashi, const char* id);  // Alias for lookup

// ===== Identity =====
bool orcashi_register_identity(ORCASHI* orcashi);
bool orcashi_connect_peer(ORCASHI* orcashi, const char* id);

// ===== Peers =====
void orcashi_show_peers(ORCASHI* orcashi);

// ===== Callbacks =====
void orcashi_set_callbacks(ORCASHI* orcashi,
                          void (*on_peer_found)(const char*, const char*),
                          void (*on_message_received)(const char*, const char*),
                          void (*on_status_change)(const char*));

// ===== Helpers =====
char* orcashi_generate_id(void);
char* orcashi_get_local_ip(void);
char* orcashi_bytes_to_hex(const unsigned char* bytes, int len);

#endif
