#ifndef P2P_MANAGER_H
#define P2P_MANAGER_H

#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define P2P_PORT 9000
#define P2P_BUFFER_SIZE 4096
#define P2P_MAX_PEERS 256

/* ============================================================================
 * P2P CONNECTION STATE
 * ============================================================================ */

typedef enum {
    P2P_STATE_DISCONNECTED = 0,
    P2P_STATE_CONNECTING,
    P2P_STATE_HANDSHAKE,
    P2P_STATE_SECURE,
    P2P_STATE_ESTABLISHED
} P2PState;

/* ============================================================================
 * P2P PEER
 * ============================================================================ */

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
    bool is_secure;
    bool is_initiator;
} P2PPeer;

/* ============================================================================
 * P2P MANAGER FUNCTIONS
 * ============================================================================ */

/* Initialize P2P manager */
int p2p_init(void);

/* Cleanup P2P manager */
void p2p_cleanup(void);

/* ============================================================================
 * P2P CONNECTION
 * ============================================================================ */

/* Connect to peer via DHT + UDP hole punch */
int p2p_connect(const char* peer_id);

/* Accept incoming connection */
int p2p_accept(const char* peer_id);

/* Disconnect from peer */
int p2p_disconnect(const char* peer_id);

/* ============================================================================
 * P2P MESSAGING
 * ============================================================================ */

/* Send message to peer */
int p2p_send(const char* peer_id, const char* message);

/* Receive message from peer (non-blocking) */
int p2p_recv(const char* peer_id, char* message, int max_len);

/* ============================================================================
 * P2P HOLE PUNCHING
 * ============================================================================ */

/* UDP hole punch to peer */
int p2p_hole_punch(const char* ip, int port);

/* Listen for incoming punches */
int p2p_punch_listen(char* ip_out, int* port_out);

/* ============================================================================
 * P2P STATUS
 * ============================================================================ */

bool p2p_is_connected(const char* peer_id);
bool p2p_is_secure(const char* peer_id);
P2PState p2p_get_state(const char* peer_id);

/* ============================================================================
 * P2P DEBUG
 * ============================================================================ */

void p2p_debug_print(void);

#endif /* P2P_MANAGER_H */
