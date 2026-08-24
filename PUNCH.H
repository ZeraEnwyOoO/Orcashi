#ifndef PUNCH_H
#define PUNCH_H

#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PUNCH_PORT 33445
#define PUNCH_MAX_RETRY 10
#define PUNCH_TIMEOUT 2

/* ============================================================================
 * PUNCH STATE
 * ============================================================================ */

typedef struct {
    int udp_socket;
    int local_port;
    char peer_ip[INET_ADDRSTRLEN];
    int peer_port;
    bool punched;
    struct sockaddr_in peer_addr;
} PunchState;

/* ============================================================================
 * PUNCH FUNCTIONS
 * ============================================================================ */

/* Initialize punch (create UDP socket) */
int punch_init(PunchState* p, int port);

/* Cleanup punch (close socket) */
void punch_close(PunchState* p);

/* ============================================================================
 * PUNCH OPERATIONS
 * ============================================================================ */

/* Send punch packet to peer */
int punch_send(PunchState* p, const char* target_ip, int target_port);

/* Listen for punch packet from peer */
int punch_listen(PunchState* p, char* peer_ip_out, int* peer_port_out);

/* Full punch sequence (send + listen) */
int punch_punch(PunchState* p, const char* target_ip, int target_port);

/* Try to connect via punch (with retries) */
int punch_try_connect(PunchState* p, const char* target_ip, int target_port);

/* ============================================================================
 * PUNCH UTILITIES
 * ============================================================================ */

/* Check if punch is successful */
bool punch_is_successful(PunchState* p);

/* Get peer info after successful punch */
int punch_get_peer(PunchState* p, char* ip_out, int* port_out);

/* Reset punch state */
void punch_reset(PunchState* p);

#endif /* PUNCH_H */
