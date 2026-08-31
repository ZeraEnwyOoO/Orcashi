 #ifndef PUNCH_H
#define PUNCH_H

#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PUNCH_PORT 33445
#define PUNCH_MAX_RETRY 10
#define PUNCH_TIMEOUT 2
#define PUNCH_MAX_TTL 10

/* ============================================================================
 * PUNCH TECHNIQUES
 * ============================================================================ */

typedef enum {
    PUNCH_TECH_UDP = 0,
    PUNCH_TECH_TTL,
    PUNCH_TECH_SIMULTANEOUS,
    PUNCH_TECH_PORT_PREDICTION,
    PUNCH_TECH_TCP
} PunchTechnique;

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
    PunchTechnique last_technique;
    int retry_count;
    bool ttl_used;
    bool simultaneous_used;
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

/* Send punch with TTL manipulation */
int punch_send_ttl(PunchState* p, const char* target_ip, int target_port, int ttl);

/* Listen for punch packet from peer */
int punch_listen(PunchState* p, char* peer_ip_out, int* peer_port_out);

/* Full punch sequence (send + listen) */
int punch_punch(PunchState* p, const char* target_ip, int target_port);

/* Try to connect via punch (with retries) */
int punch_try_connect(PunchState* p, const char* target_ip, int target_port);

/* ============================================================================
 * MULTI-STRATEGY PUNCH
 * ============================================================================ */

/* Try all punch techniques in parallel */
int punch_multi_strategy(const char* target_ip, int target_port, 
                         int local_nat_type, int peer_nat_type);

/* Try UDP punch only */
int punch_try_udp(PunchState* p, const char* target_ip, int target_port);

/* Try TTL punch only */
int punch_try_ttl(PunchState* p, const char* target_ip, int target_port);

/* Try simultaneous open only */
int punch_try_simultaneous(PunchState* p, const char* target_ip, int target_port);

/* Try port prediction only */
int punch_try_port_prediction(PunchState* p, const char* target_ip, int target_port);

/* Try TCP punch only */
int punch_try_tcp(PunchState* p, const char* target_ip, int target_port);

/* ============================================================================
 * PUNCH UTILITIES
 * ============================================================================ */

/* Check if punch is successful */
bool punch_is_successful(PunchState* p);

/* Get peer info after successful punch */
int punch_get_peer(PunchState* p, char* ip_out, int* port_out);

/* Reset punch state */
void punch_reset(PunchState* p);

/* Get technique name */
const char* punch_technique_name(PunchTechnique tech);

#endif /* PUNCH_H */
