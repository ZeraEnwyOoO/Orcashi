 #ifndef DISCOVERY_H
#define DISCOVERY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <time.h>
#include <errno.h>

#include "registry.h"
#include "request.h"
#include "orca_identity.h"
#include "orca_crypto.h"

#define DISCOVERY_PORT 9001
#define DISCOVERY_MAX_PEERS 256
#define DISCOVERY_PEER_TIMEOUT 300
#define DISCOVERY_BUFFER_SIZE 4096
#define DISCOVERY_MAX_PENDING 256
#define DISCOVERY_MAX_ID_LEN 64
#define DISCOVERY_MAX_IP_LEN INET_ADDRSTRLEN
#define DISCOVERY_MAX_ENDPOINT_LEN 128
#define DISCOVERY_MAX_NAME_LEN 128
#define DISCOVERY_MAX_PUBKEY_LEN ORCA_PUBKEY_LEN
#define DISCOVERY_MAX_SIG_LEN ORCA_SIG_LEN

/* ============================================================================
 * Peer Information (Runtime Discovery Cache)
 * ============================================================================ */

typedef struct {
    char id[DISCOVERY_MAX_ID_LEN];
    char endpoint[DISCOVERY_MAX_ENDPOINT_LEN];
    char ip[DISCOVERY_MAX_IP_LEN];
    int port;
    char name[DISCOVERY_MAX_NAME_LEN];
    time_t last_seen;
    bool online;
    char public_key[DISCOVERY_MAX_PUBKEY_LEN];
    char signature[DISCOVERY_MAX_SIG_LEN];
    bool is_secure;
    bool verified;
} DiscoveryPeerInfo;

/* ============================================================================
 * Pending Friend Request
 * ============================================================================ */

typedef struct {
    char from_id[DISCOVERY_MAX_ID_LEN];
    char from_ip[DISCOVERY_MAX_IP_LEN];
    int from_port;
    char from_name[DISCOVERY_MAX_NAME_LEN];
    char public_key[DISCOVERY_MAX_PUBKEY_LEN];
    char signature[DISCOVERY_MAX_SIG_LEN];
    bool is_secure;
    time_t received_at;
} DiscoveryPendingRequest;

/* ============================================================================
 * ACCEPT_CONFIRM State (Thread-Safe)
 * ============================================================================ */

typedef struct {
    char target_id[DISCOVERY_MAX_ID_LEN];
    char from_id[DISCOVERY_MAX_ID_LEN];
    char from_ip[DISCOVERY_MAX_IP_LEN];
    int from_port;
    bool is_secure;
    char public_key[DISCOVERY_MAX_PUBKEY_LEN];
    char signature[DISCOVERY_MAX_SIG_LEN];
    bool received;
    bool processed;
} DiscoveryAcceptState;

/* ============================================================================
 * Discovery Main Structure
 * ============================================================================ */

typedef struct Discovery Discovery;

struct Discovery {
    /* Socket */
    int udp_socket;
    int port;
    bool running;
    
    /* Threads */
    pthread_t listen_thread;
    pthread_t broadcast_thread;
    bool listen_thread_created;
    bool broadcast_thread_created;
    
    /* Synchronization */
    pthread_mutex_t mutex;
    pthread_cond_t accept_cond;
    
    /* Peer Cache */
    DiscoveryPeerInfo peers[DISCOVERY_MAX_PEERS];
    int peer_count;
    
    /* Pending Requests */
    DiscoveryPendingRequest pending_requests[DISCOVERY_MAX_PENDING];
    int pending_count;
    
    /* ACCEPT_CONFIRM State */
    DiscoveryAcceptState accept_state;
    
    /* External References */
    Registry* registry;
    RequestManager* request_manager;
    
    /* Callbacks */
    void (*on_peer_found)(DiscoveryPeerInfo* peer);
    void (*on_peer_offline)(DiscoveryPeerInfo* peer);
    void (*on_accept_confirm)(const char* from_id, const char* from_ip, 
                              int from_port, bool is_secure);
};

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

Discovery* discovery_create(void);
void discovery_destroy(Discovery* disc);
bool discovery_init(Discovery* disc, int port);
void discovery_start(Discovery* disc);
void discovery_stop(Discovery* disc);
bool discovery_is_running(Discovery* disc);

/* ============================================================================
 * Identity Configuration
 * ============================================================================ */

void discovery_set_my_identity(Discovery* disc, const char* id, 
                               const char* ip, int port);
void discovery_set_my_secure_identity(Discovery* disc, 
                                      const OrcaIdentity* identity);

/* ============================================================================
 * External References
 * ============================================================================ */

void discovery_set_registry(Discovery* disc, Registry* reg);
void discovery_set_request_manager(Discovery* disc, RequestManager* rm);

/* ============================================================================
 * Broadcasting
 * ============================================================================ */

void discovery_broadcast_presence(Discovery* disc, const char* id, 
                                  const char* endpoint);
void discovery_broadcast_search(Discovery* disc, const char* id);
void discovery_query_peer(Discovery* disc, const char* id);

/* ============================================================================
 * Friend Request Flow
 * ============================================================================ */

void discovery_send_add_request(Discovery* disc, const char* target_id,
                                const char* my_id, const char* my_ip, 
                                int my_port);
void discovery_send_add_request_secure(Discovery* disc, const char* target_id,
                                       const char* my_id, const char* my_ip,
                                       int my_port, const char* name,
                                       const char* public_key,
                                       const char* signature);

/* ============================================================================
 * ACCEPT_CONFIRM Flow
 * ============================================================================ */

void discovery_send_accept_confirm(Discovery* disc, const char* target_id,
                                   const char* my_id, const char* my_ip,
                                   int my_port);
void discovery_send_accept_confirm_secure(Discovery* disc, const char* target_id,
                                          const char* my_id, const char* my_ip,
                                          int my_port, const char* public_key,
                                          const char* signature);

/* ============================================================================
 * ACCEPT_CONFIRM Waiting (Thread-Safe)
 * ============================================================================ */

bool discovery_wait_for_accept(Discovery* disc, const char* target_id, 
                               int timeout_sec);
void discovery_reset_accept_state(Discovery* disc);

/* ============================================================================
 * Peer Discovery
 * ============================================================================ */

bool discovery_find_peer(Discovery* disc, const char* id, 
                         DiscoveryPeerInfo* out_peer);
int discovery_get_peers(Discovery* disc, DiscoveryPeerInfo* peers, 
                        int max_peers);
void discovery_cleanup_stale(Discovery* disc);

/* ============================================================================
 * Pending Requests
 * ============================================================================ */

void discovery_push_pending(Discovery* disc, const char* from_id,
                            const char* from_ip, int from_port);
bool discovery_pop_pending(Discovery* disc, DiscoveryPendingRequest* out);
int discovery_pending_count(Discovery* disc);
bool discovery_has_pending(Discovery* disc);

/* ============================================================================
 * Callbacks
 * ============================================================================ */

void discovery_set_on_peer_found(Discovery* disc, 
                                 void (*callback)(DiscoveryPeerInfo*));
void discovery_set_on_peer_offline(Discovery* disc, 
                                   void (*callback)(DiscoveryPeerInfo*));
void discovery_set_on_accept_confirm(Discovery* disc,
                                     void (*callback)(const char*, const char*,
                                                      int, bool));

/* ============================================================================
 * ID Normalization (Single Source of Truth)
 * ============================================================================ */

bool discovery_normalize_id(const char* input, char* output, size_t output_size);
bool discovery_is_valid_id(const char* id);
bool discovery_is_same_id(const char* id1, const char* id2);

/* ============================================================================
 * Utility
 * ============================================================================ */

char* discovery_get_local_ip(void);
void strip_brackets(const char* input, char* output, size_t out_size);

#endif /* DISCOVERY_H */
