 // orcashi.h - Full version with ORCA Identity and Crypto
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
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "plug.h"
#include "discovery.h"
#include "registry.h"
#include "request.h"
#include "peer_cache.h"
#include "endpoint.h"
#include "nat_punch.h"
#include "bootstrap.h"
#include "dht_node.h"
#include "orca_identity.h"
#include "orca_crypto.h"
#include "ecdh.h"
#include "aes_gcm.h"

#define ORCASHI_VERSION "4.0"
#define ORCASHI_PORT 9000
#define DISCOVERY_PORT 9001
#define PUNCH_PORT 33445
#define DHT_NODE_PORT 33446
#define ORCASHI_HOME "/tmp/.orcashi/"
#define ID_FILE ORCASHI_HOME "id"

typedef struct ORCASHI {
    TCPPlug* plug;
    Discovery* discovery;
    Registry* registry;
    RequestManager* requests;
    PeerCache* cache;
    EndpointRegistry* endpoints;
    PunchState* punch;
    DHTNode* dht;
    
    /* Identity */
    OrcaIdentity identity;
    bool has_identity;
    char my_id[64];
    char peer_id[64];
    char local_ip[INET_ADDRSTRLEN];
    char peer_ip[INET_ADDRSTRLEN];
    
    /* Secure Session */
    OrcaECDSession* session;
    unsigned char shared_secret[ORCA_AES_GCM_KEY_LEN];
    bool session_established;
    char peer_public_key_hex[65];
    
    bool connected;
    bool running;
    bool registered;
    
    pthread_t heartbeat_thread;
    bool heartbeat_thread_created;
    pthread_mutex_t mutex;
    
    void (*on_peer_found)(const char* id, const char* ip);
    void (*on_message_received)(const char* from, const char* msg);
    void (*on_status_change)(const char* status);
    
} ORCASHI;

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

ORCASHI* orcashi_create(void);
void orcashi_destroy(ORCASHI* orcashi);
bool orcashi_init(ORCASHI* orcashi);

/* ============================================================================
 * Room Management
 * ============================================================================ */

bool orcashi_create_room(ORCASHI* orcashi, int port);
bool orcashi_join_room(ORCASHI* orcashi, const char* ip, int port);

/* ============================================================================
 * Messaging
 * ============================================================================ */

bool orcashi_send_message(ORCASHI* orcashi, const char* msg);
bool orcashi_send_secure_message(ORCASHI* orcashi, const char* msg);
bool orcashi_receive_message(ORCASHI* orcashi, char* msg, int msg_size, int timeout_ms);

/* ============================================================================
 * Connection
 * ============================================================================ */

bool orcashi_is_connected(ORCASHI* orcashi);
void orcashi_disconnect(ORCASHI* orcashi);

/* ============================================================================
 * Identity
 * ============================================================================ */

const char* orcashi_get_my_id(ORCASHI* orcashi);
const char* orcashi_get_peer_id(ORCASHI* orcashi);
const char* orcashi_get_peer_ip(ORCASHI* orcashi);
bool orcashi_load_identity(ORCASHI* orcashi, const char* passcode);
bool orcashi_has_identity(ORCASHI* orcashi);

/* ============================================================================
 * Secure Connection
 * ============================================================================ */

bool orcashi_init_secure_session(ORCASHI* orcashi);
bool orcashi_complete_secure_session(ORCASHI* orcashi, const char* peer_public_key_hex);
bool orcashi_session_established(ORCASHI* orcashi);

/* ============================================================================
 * Peer Management
 * ============================================================================ */

bool orcashi_register_identity(ORCASHI* orcashi);
bool orcashi_connect_peer(ORCASHI* orcashi, const char* id);
void orcashi_show_peers(ORCASHI* orcashi);

/* ============================================================================
 * Callbacks
 * ============================================================================ */

void orcashi_set_callbacks(ORCASHI* orcashi,
                          void (*on_peer_found)(const char*, const char*),
                          void (*on_message_received)(const char*, const char*),
                          void (*on_status_change)(const char*));

/* ============================================================================
 * Utility
 * ============================================================================ */

char* orcashi_generate_id(void);
char* orcashi_get_local_ip(void);
char* orcashi_bytes_to_hex(const unsigned char* bytes, int len);
bool orcashi_save_ip(const char* ip);

#endif /* ORCASHI_H */
