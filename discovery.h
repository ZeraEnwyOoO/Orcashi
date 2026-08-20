 
 
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

#include "request.h"
#include "registry.h"
#include "orca_identity.h"

#define DISCOVERY_PORT 9001
#define MAX_PEERS 256
#define PEER_TIMEOUT 300
#define MAX_PENDING_REQUESTS 64
#define MAX_PACKET_SIZE 4096
#define MAX_ID_LEN 64
#define MAX_IP_LEN INET_ADDRSTRLEN
#define MAX_PORT_LEN 16
#define MAX_ENDPOINT_LEN 256
#define MAX_PUBKEY_LEN ORCA_PUBKEY_LEN
#define MAX_SIG_LEN ORCA_SIG_LEN
#define MAX_NAME_LEN 128

/* ============================================================================
 * PEER INFO STRUCT
 * ============================================================================ */

typedef struct {
    char id[MAX_ID_LEN];
    char endpoint[MAX_ENDPOINT_LEN];
    char ip[MAX_IP_LEN];
    int port;
    char name[MAX_NAME_LEN];
    time_t last_seen;
    bool online;
    char public_key[MAX_PUBKEY_LEN];
    char signature[MAX_SIG_LEN];
    bool is_secure;
    bool verified;
} PeerInfo;

/* ============================================================================
 * PENDING REQUEST STRUCT
 * ============================================================================ */

typedef struct {
    char from_id[MAX_ID_LEN];
    char from_ip[MAX_IP_LEN];
    int from_port;
    char from_name[MAX_NAME_LEN];
    char public_key[MAX_PUBKEY_LEN];
    char signature[MAX_SIG_LEN];
    bool is_secure;
    time_t received_at;
} PendingRequest;

/* ============================================================================
 * DISCOVERY STRUCT
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
    
    /* Peer cache */
    PeerInfo peers[MAX_PEERS];
    int peer_count;
    
    /* Pending requests queue */
    PendingRequest pending_requests[MAX_PENDING_REQUESTS];
    int pending_count;
    
    /* ACCEPT_CONFIRM waiting state */
    char accept_target[MAX_ID_LEN];
    bool accept_received;
    
    /* Callbacks */
    void (*on_peer_found)(PeerInfo* peer);
    void (*on_peer_offline)(PeerInfo* peer);
    void (*on_accept_confirm)(const char* from_id, const char* from_ip, 
                              int from_port, bool is_secure);
};

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

Discovery* discovery_create(void);
void discovery_destroy(Discovery* disc);
bool discovery_init(Discovery* disc, int port);
void discovery_start(Discovery* disc);
void discovery_stop(Discovery* disc);
bool discovery_is_running(const Discovery* disc);

/* ============================================================================
 * IDENTITY CONFIGURATION
 * ============================================================================ */

void discovery_set_my_identity(Discovery* disc, const char* id, const char* ip, int port);
void discovery_set_my_secure_identity(Discovery* disc, const OrcaIdentity* identity);

/* ============================================================================
 * CALLBACKS
 * ============================================================================ */

void discovery_set_on_peer_found(Discovery* disc, void (*callback)(PeerInfo*));
void discovery_set_on_peer_offline(Discovery* disc, void (*callback)(PeerInfo*));
void discovery_set_on_accept_confirm(Discovery* disc, 
                                     void (*callback)(const char*, const char*, int, bool));

/* ============================================================================
 * DISCOVERY MESSAGES
 * ============================================================================ */

void discovery_query_peer(Discovery* disc, const char* id);
void discovery_broadcast_presence(Discovery* disc, const char* id, const char* endpoint);

void discovery_send_add_request_with_ack(Discovery* disc, const char* target_id,
                                         const char* my_id, const char* my_ip, int my_port);

void discovery_send_accept_confirm(Discovery* disc, const char* target_id,
                                   const char* my_id, const char* my_ip, int my_port);

void discovery_send_accept_confirm_secure(Discovery* disc, const char* target_id,
                                          const char* my_id, const char* my_ip, int my_port,
                                          const char* public_key, const char* signature);

/* ============================================================================
 * ACCEPT_CONFIRM WAITING (THREAD-SAFE)
 * ============================================================================ */

bool discovery_wait_for_accept(Discovery* disc, const char* target_id, int timeout_sec);
void discovery_reset_accept_state(Discovery* disc);
bool discovery_has_accept_confirm(const Discovery* disc, const char* target_id);

/* ============================================================================
 * PEER QUERY
 * ============================================================================ */

bool discovery_find_peer(const Discovery* disc, const char* id, PeerInfo* out_peer);
int discovery_get_peers(const Discovery* disc, PeerInfo* peers, int max_peers);
void discovery_cleanup_stale(Discovery* disc);

/* ============================================================================
 * PENDING REQUESTS
 * ============================================================================ */

void discovery_push_pending(Discovery* disc, const char* from_id, const char* from_ip, 
                            int from_port, bool is_secure);
bool discovery_pop_pending(Discovery* disc, PendingRequest* out);
int discovery_pending_count(const Discovery* disc);
bool discovery_has_pending(const Discovery* disc);

/* ============================================================================
 * EXTERNAL DEPENDENCIES
 * ============================================================================ */

void discovery_set_request_manager(RequestManager* rm);
void discovery_set_registry(Registry* reg);

/* ============================================================================
 * UTILITY
 * ============================================================================ */

char* discovery_get_local_ip(void);
bool normalize_id(const char* input, char* output, size_t output_size);

#endif /* DISCOVERY_H */
