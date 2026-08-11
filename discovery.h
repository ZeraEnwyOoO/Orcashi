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

Discovery* discovery_create(void);
void discovery_destroy(Discovery* disc);
bool discovery_init(Discovery* disc, int port);
void discovery_start(Discovery* disc);
void discovery_stop(Discovery* disc);
void discovery_broadcast_presence(Discovery* disc, const char* id, const char* endpoint);
void discovery_broadcast_search(Discovery* disc, const char* id);
bool discovery_find_peer(Discovery* disc, const char* id, PeerInfo* out_peer);
int discovery_get_peers(Discovery* disc, PeerInfo* peers, int max_peers);
void discovery_cleanup_stale(Discovery* disc);
char* discovery_get_local_ip(void);
void discovery_set_on_peer_found(Discovery* disc, void (*callback)(PeerInfo*));
void discovery_set_on_peer_offline(Discovery* disc, void (*callback)(PeerInfo*));
void discovery_set_my_identity(Discovery* disc, const char* id, const char* ip, int port);

#endif
