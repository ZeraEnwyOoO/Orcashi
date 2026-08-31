 #ifndef P2P_MANAGER_H
#define P2P_MANAGER_H

#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>

#include "nat_classifier.h"

#define P2P_PORT 9000
#define P2P_BUFFER_SIZE 4096
#define P2P_MAX_PEERS 256
#define P2P_CONNECTION_TIMEOUT 5
#define P2P_MAX_RETRY 3

typedef enum {
    P2P_STATE_DISCONNECTED = 0,
    P2P_STATE_CONNECTING,
    P2P_STATE_HANDSHAKE,
    P2P_STATE_SECURE,
    P2P_STATE_ESTABLISHED
} P2PState;

typedef struct {
    char id[64];
    char ip[INET_ADDRSTRLEN];
    int port;
    bool has_ipv6;
    char ipv6[INET6_ADDRSTRLEN];
    NATType nat_type;
    bool has_upnp;
    bool has_relay;
    bool is_relay;
    time_t last_seen;
} PeerCapability;

typedef struct {
    char id[64];
    char ip[INET_ADDRSTRLEN];
    int port;
    P2PState state;
    int udp_socket;
    struct sockaddr_in addr;
    unsigned char shared_secret[32];
    unsigned char aes_key[32];
    uint64_t send_nonce;
    uint64_t recv_nonce;
    time_t last_activity;
    time_t created_at;
    bool is_secure;
    bool is_initiator;
    int retry_count;
    NATType nat_type;
    bool has_ipv6;
    char ipv6[INET6_ADDRSTRLEN];
    char public_key[4096];
} P2PPeer;

int p2p_init(void);
void p2p_cleanup(void);

int p2p_connect(const char* peer_id);
int p2p_accept(const char* peer_id);
int p2p_disconnect(const char* peer_id);

int p2p_send(const char* peer_id, const char* message);
int p2p_send_secure(const char* peer_id, const unsigned char* data, size_t len);
int p2p_recv(const char* peer_id, char* message, int max_len);

int p2p_hole_punch(const char* ip, int port, NATType peer_nat);
int p2p_punch_listen(char* ip_out, int* port_out);

NATType p2p_detect_nat_type(void);
bool p2p_has_ipv6(void);
bool p2p_has_upnp(void);

int p2p_get_peer_capability(const char* peer_id, PeerCapability* cap);
int p2p_exchange_capabilities(const char* peer_id, PeerCapability* remote);

bool p2p_is_connected(const char* peer_id);
bool p2p_is_secure(const char* peer_id);
P2PState p2p_get_state(const char* peer_id);
NATType p2p_get_nat_type(void);

void p2p_debug_print(void);

#endif
