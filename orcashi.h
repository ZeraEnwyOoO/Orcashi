 // orcashi.h
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
#include <signal.h>
#include <errno.h>

#include "DHT.h"
#include "onion.h"
#include "onion_client.h"
#include "net_crypto.h"
#include "crypto_core.h"
#include "LAN_discovery.h"
#include "network.h"
#include "mono_time.h"
#include "logger.h"
#include "mem.h"
#include "rng.h"
#include "ping.h"

#define ORCASHI_VERSION "3.2"
#define ORCASHI_PORT 9000
#define DHT_PORT 6881
#define MAX_MSG_LEN 4096
#define DHT_LOOKUP_TIMEOUT 15
#define MAX_PEER_CACHE 256

// Peer structure
typedef struct {
    char id[64];                    // Public key hex
    char ip[INET_ADDRSTRLEN];       // IP address
    int port;                       // Port
    bool online;                    // Online status
    time_t last_seen;              // Last seen timestamp
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];  // Raw public key
} Peer;

// DHT lookup callback data
typedef struct {
    char id[64];
    char endpoint[128];
    int done;
    int success;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} DHTLookup;

// Main ORCASHI structure
typedef struct {
    // DHT Core
    DHT* dht;
    Onion* onion;
    Onion_Client* onion_client;
    Net_Crypto* net_crypto;
    Networking_Core* net;
    Mono_Time* mono_time;
    Memory* mem;
    Random* rng;
    Logger* logger;
    
    // DHT socket
    int dht_socket;
    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];
    char self_id_hex[CRYPTO_PUBLIC_KEY_SIZE * 2 + 1];
    
    // Threads
    pthread_t dht_thread;
    pthread_t lookup_thread;
    bool running;
    bool dht_initialized;
    pthread_mutex_t dht_mutex;
    
    // Peer cache
    Peer peers[MAX_PEER_CACHE];
    int peer_count;
    pthread_mutex_t peer_mutex;
    
    // TCP Plug
    int tcp_socket;
    bool connected;
    char peer_ip[INET_ADDRSTRLEN];
    char peer_id[64];
    pthread_t tcp_receive_thread;
    pthread_t tcp_send_thread;
    pthread_mutex_t tcp_mutex;
    pthread_cond_t tcp_cond;
    char** message_queue;
    char** send_queue;
    int message_count;
    int send_count;
    int queue_capacity;
    
    // Callbacks
    void (*on_peer_found)(const char* id, const char* ip);
    void (*on_message_received)(const char* from, const char* msg);
    void (*on_status_change)(const char* status);
    
    // Bootstrap nodes
    BootstrapNode* bootstrap_nodes;
    int bootstrap_count;
} ORCASHI;

// Functions
ORCASHI* orcashi_create(void);
void orcashi_destroy(ORCASHI* orcashi);

bool orcashi_init(ORCASHI* orcashi);
bool orcashi_dht_init(ORCASHI* orcashi);
void orcashi_dht_shutdown(ORCASHI* orcashi);
void orcashi_dht_loop(ORCASHI* orcashi);

// DHT Operations
bool orcashi_dht_bootstrap(ORCASHI* orcashi, const char* host, int port);
bool orcashi_dht_register(ORCASHI* orcashi);
char* orcashi_dht_lookup(ORCASHI* orcashi, const char* id);
char* orcashi_dht_search(ORCASHI* orcashi, const char* id);

// Peer management
bool orcashi_add_peer(ORCASHI* orcashi, const char* id, const char* ip, int port);
bool orcashi_find_peer(ORCASHI* orcashi, const char* id, Peer* out_peer);
void orcashi_show_peers(ORCASHI* orcashi);

// TCP Chat
bool orcashi_create_room(ORCASHI* orcashi, int port);
bool orcashi_join_room(ORCASHI* orcashi, const char* ip, int port);
bool orcashi_send_message(ORCASHI* orcashi, const char* msg);
bool orcashi_receive_message(ORCASHI* orcashi, char* msg, int msg_size, int timeout_ms);
bool orcashi_is_connected(ORCASHI* orcashi);
void orcashi_disconnect(ORCASHI* orcashi);

// Connection by ID
bool orcashi_connect_peer(ORCASHI* orcashi, const char* id);
bool orcashi_register_identity(ORCASHI* orcashi);

// Getters
const char* orcashi_get_my_id(ORCASHI* orcashi);
const char* orcashi_get_peer_id(ORCASHI* orcashi);
const char* orcashi_get_peer_ip(ORCASHI* orcashi);

// Callbacks
void orcashi_set_callbacks(ORCASHI* orcashi,
                          void (*on_peer_found)(const char*, const char*),
                          void (*on_message_received)(const char*, const char*),
                          void (*on_status_change)(const char*));

// Helpers
char* orcashi_generate_id(void);
char* orcashi_get_local_ip(void);
char* orcashi_bytes_to_hex(const uint8_t* bytes, int len);
int orcashi_hex_to_bytes(const char* hex, uint8_t* bytes, int len);

#endif
