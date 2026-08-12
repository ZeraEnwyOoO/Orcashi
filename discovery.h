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

#define DISCOVERY_PORT 9001
#define MAX_PEERS 256
#define PEER_TIMEOUT 60

typedef struct {
    char id[64];
    char endpoint[128];
    char ip[INET_ADDRSTRLEN];
    int port;
    char name[128];
    time_t last_seen;
    bool online;
    char public_key[256];
} PeerInfo;

typedef struct {
    int udp_socket;
    int port;
    bool running;
    pthread_t listen_thread;
    pthread_t broadcast_thread;
    pthread_mutex_t mutex;
    PeerInfo peers[MAX_PEERS];
    int peer_count;
    void (*on_peer_found)(PeerInfo* peer);
    void (*on_peer_offline)(PeerInfo* peer);
} Discovery;

// ===== Create / Destroy =====
Discovery* discovery_create(void);
void discovery_destroy(Discovery* disc);

// ===== Init / Start / Stop =====
bool discovery_init(Discovery* disc, int port);
void discovery_start(Discovery* disc);
void discovery_stop(Discovery* disc);

// ===== Broadcast =====
void discovery_broadcast_presence(Discovery* disc, const char* id, const char* endpoint);
void discovery_broadcast_search(Discovery* disc, const char* id);

// ===== Active Query =====
void discovery_query_peer(Discovery* disc, const char* id);

// ===== Friend Request =====
void discovery_send_add_request(Discovery* disc, const char* target_id, const char* my_id, const char* my_ip, int my_port);

// ===== Peer Management =====
bool discovery_find_peer(Discovery* disc, const char* id, PeerInfo* out_peer);
int discovery_get_peers(Discovery* disc, PeerInfo* peers, int max_peers);
void discovery_cleanup_stale(Discovery* disc);

// ===== Identity =====
void discovery_set_my_identity(Discovery* disc, const char* id, const char* ip, int port);
char* discovery_get_local_ip(void);

// ===== Callbacks =====
void discovery_set_on_peer_found(Discovery* disc, void (*callback)(PeerInfo*));
void discovery_set_on_peer_offline(Discovery* disc, void (*callback)(PeerInfo*));

#endif
