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

typedef struct {
    char id[64];
    char endpoint[128];
    char ip[INET_ADDRSTRLEN];
    int port;
    char name[128];
    time_t last_seen;
    bool online;
    char public_key[ORCA_PUBKEY_LEN];
    char signature[ORCA_SIG_LEN];
    bool is_secure;
    bool verified;
} PeerInfo;

typedef struct {
    char from_id[64];
    char from_ip[INET_ADDRSTRLEN];
    int from_port;
    char from_name[128];
    char public_key[ORCA_PUBKEY_LEN];
    char signature[ORCA_SIG_LEN];
    bool is_secure;
} PendingRequest;

typedef struct {
    int udp_socket;
    int port;
    bool running;
    pthread_t listen_thread;
    pthread_t broadcast_thread;
    pthread_mutex_t mutex;
    PeerInfo peers[MAX_PEERS];
    int peer_count;
    PendingRequest pending_requests[MAX_PEERS];
    int pending_count;
    void (*on_peer_found)(PeerInfo* peer);
    void (*on_peer_offline)(PeerInfo* peer);
    void (*on_accept_confirm)(const char* from_id, const char* from_ip, int from_port, bool is_secure);
} Discovery;

Discovery* discovery_create(void);
void discovery_destroy(Discovery* disc);
bool discovery_init(Discovery* disc, int port);
void discovery_start(Discovery* disc);
void discovery_stop(Discovery* disc);

// ===== Broadcasting =====
void discovery_broadcast_presence(Discovery* disc, const char* id, const char* endpoint);
void discovery_broadcast_search(Discovery* disc, const char* id);
void discovery_query_peer(Discovery* disc, const char* id);

// ===== Secure Messages =====
void discovery_send_add_request_with_ack(Discovery* disc, const char* target_id, 
                                         const char* my_id, const char* my_ip, int my_port);
void discovery_send_add_request_ack(Discovery* disc, const char* target_id, const char* from_id);

// ===== ACCEPT_CONFIRM =====
void discovery_send_accept_confirm(Discovery* disc, const char* target_id, 
                                   const char* my_id, const char* my_ip, int my_port);
void discovery_send_accept_confirm_secure(Discovery* disc, const char* target_id,
                                         const char* my_id, const char* my_ip, int my_port,
                                         const char* public_key, const char* signature);

// ===== Peer Discovery =====
bool discovery_find_peer(Discovery* disc, const char* id, PeerInfo* out_peer);
int discovery_get_peers(Discovery* disc, PeerInfo* peers, int max_peers);
void discovery_cleanup_stale(Discovery* disc);

// ===== Identity =====
void discovery_set_my_identity(Discovery* disc, const char* id, const char* ip, int port);
void discovery_set_my_secure_identity(Discovery* disc, const OrcaIdentity* identity);

// ===== Callbacks =====
void discovery_set_request_manager(RequestManager* rm);
void discovery_set_registry(Registry* reg);
void discovery_set_on_peer_found(Discovery* disc, void (*callback)(PeerInfo*));
void discovery_set_on_peer_offline(Discovery* disc, void (*callback)(PeerInfo*));
void discovery_set_on_accept_confirm(Discovery* disc, void (*callback)(const char*, const char*, int, bool));

// ===== Pending Requests =====
void discovery_push_pending(Discovery* disc, const char* from_id, const char* from_ip, int from_port);
bool discovery_pop_pending(Discovery* disc, PendingRequest* out);
int discovery_pending_count(Discovery* disc);
bool discovery_has_pending(Discovery* disc);

// ===== Utility =====
char* discovery_get_local_ip(void);

#endif
