 #include "punch.h"
#include "ttl_punch.h"
#include "simultaneous_open.h"
#include "port_prediction.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>

#define PUNCH_DEBUG 1

#if PUNCH_DEBUG
#define DLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[PUNCH] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define DLOG(fmt, ...) ((void)0)
#endif

/* ============================================================================
 * TECHNIQUE NAMES
 * ============================================================================ */

const char* punch_technique_name(PunchTechnique tech) {
    switch (tech) {
        case PUNCH_TECH_UDP: return "UDP_HOLE_PUNCH";
        case PUNCH_TECH_TTL: return "TTL_MANIPULATION";
        case PUNCH_TECH_SIMULTANEOUS: return "SIMULTANEOUS_OPEN";
        case PUNCH_TECH_PORT_PREDICTION: return "PORT_PREDICTION";
        case PUNCH_TECH_TCP: return "TCP_PUNCH";
        default: return "UNKNOWN";
    }
}

/* ============================================================================
 * INIT / CLEANUP
 * ============================================================================ */

int punch_init(PunchState* p, int port) {
    if (!p) return -1;
    
    DLOG("Initializing punch on port %d", port);
    
    p->udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (p->udp_socket < 0) {
        DLOG("Failed to create UDP socket: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    setsockopt(p->udp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(p->udp_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        DLOG("Failed to bind UDP socket: %s", strerror(errno));
        close(p->udp_socket);
        p->udp_socket = -1;
        return -1;
    }
    
    p->local_port = port;
    p->punched = false;
    p->retry_count = 0;
    p->ttl_used = false;
    p->simultaneous_used = false;
    p->last_technique = PUNCH_TECH_UDP;
    memset(&p->peer_addr, 0, sizeof(p->peer_addr));
    
    DLOG("Punch initialized on port %d", port);
    return 0;
}

void punch_close(PunchState* p) {
    if (!p) return;
    
    if (p->udp_socket >= 0) {
        close(p->udp_socket);
        p->udp_socket = -1;
    }
    
    p->punched = false;
    DLOG("Punch closed");
}

/* ============================================================================
 * PUNCH OPERATIONS
 * ============================================================================ */

int punch_send(PunchState* p, const char* target_ip, int target_port) {
    if (!p || !target_ip) return -1;
    if (p->udp_socket < 0) return -1;
    
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &target.sin_addr);
    
    const char* msg = "ORCA_PUNCH";
    ssize_t sent = sendto(p->udp_socket, msg, strlen(msg), 0,
                          (struct sockaddr*)&target, sizeof(target));
    
    if (sent < 0) {
        DLOG("Failed to send punch to %s:%d: %s", target_ip, target_port, strerror(errno));
        return -1;
    }
    
    DLOG("Sent punch to %s:%d", target_ip, target_port);
    return 0;
}

int punch_send_ttl(PunchState* p, const char* target_ip, int target_port, int ttl) {
    if (!p || !target_ip) return -1;
    if (p->udp_socket < 0) return -1;
    
    /* Create new socket for TTL */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    
    /* Set TTL */
    if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        close(sock);
        return -1;
    }
    
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &target.sin_addr);
    
    const char* msg = "ORCA_PUNCH_TTL";
    ssize_t sent = sendto(sock, msg, strlen(msg), 0,
                          (struct sockaddr*)&target, sizeof(target));
    
    close(sock);
    
    if (sent < 0) {
        DLOG("Failed to send TTL punch to %s:%d: %s", target_ip, target_port, strerror(errno));
        return -1;
    }
    
    DLOG("Sent TTL punch (TTL=%d) to %s:%d", ttl, target_ip, target_port);
    return 0;
}

int punch_listen(PunchState* p, char* peer_ip_out, int* peer_port_out) {
    if (!p || !peer_ip_out || !peer_port_out) return -1;
    if (p->udp_socket < 0) return -1;
    
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    char buffer[256];
    
    /* Set timeout */
    struct timeval tv;
    tv.tv_sec = PUNCH_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(p->udp_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    int n = recvfrom(p->udp_socket, buffer, sizeof(buffer) - 1, 0,
                     (struct sockaddr*)&from, &from_len);
    
    /* Reset timeout */
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(p->udp_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            DLOG("recvfrom error: %s", strerror(errno));
        }
        return -1;
    }
    
    buffer[n] = '\0';
    
    if (strcmp(buffer, "ORCA_PUNCH") == 0 ||
        strcmp(buffer, "ORCA_PUNCH_RESPONSE") == 0 ||
        strcmp(buffer, "ORCA_PUNCH_TTL") == 0 ||
        strcmp(buffer, "ORCA_PUNCH_SIM") == 0) {
        inet_ntop(AF_INET, &from.sin_addr, peer_ip_out, INET_ADDRSTRLEN);
        *peer_port_out = ntohs(from.sin_port);
        DLOG("Received punch from %s:%d", peer_ip_out, *peer_port_out);
        return 0;
    }
    
    return -1;
}

int punch_punch(PunchState* p, const char* target_ip, int target_port) {
    if (!p || !target_ip) return -1;
    
    DLOG("Starting punch sequence to %s:%d", target_ip, target_port);
    
    /* Send multiple punch packets */
    for (int i = 0; i < PUNCH_MAX_RETRY; i++) {
        punch_send(p, target_ip, target_port);
        usleep(50000); /* 50ms */
    }
    
    /* Listen for response */
    char peer_ip[INET_ADDRSTRLEN];
    int peer_port;
    
    for (int i = 0; i < PUNCH_MAX_RETRY; i++) {
        if (punch_listen(p, peer_ip, &peer_port) == 0) {
            strcpy(p->peer_ip, peer_ip);
            p->peer_port = peer_port;
            p->punched = true;
            p->last_technique = PUNCH_TECH_UDP;
            
            memcpy(&p->peer_addr, &(struct sockaddr_in){
                .sin_family = AF_INET,
                .sin_port = htons(peer_port),
                .sin_addr = { .s_addr = inet_addr(peer_ip) }
            }, sizeof(struct sockaddr_in));
            
            DLOG("Punch successful! Peer at %s:%d", peer_ip, peer_port);
            return 0;
        }
        usleep(100000); /* 100ms */
    }
    
    DLOG("Punch failed to %s:%d", target_ip, target_port);
    return -1;
}

int punch_try_connect(PunchState* p, const char* target_ip, int target_port) {
    if (!p || !target_ip) return -1;
    
    DLOG("Trying to connect to %s:%d via punch", target_ip, target_port);
    
    /* Send initial punches */
    for (int i = 0; i < 5; i++) {
        punch_send(p, target_ip, target_port);
        usleep(50000);
    }
    
    /* Listen for response with retries */
    char peer_ip[INET_ADDRSTRLEN];
    int peer_port;
    
    for (int i = 0; i < PUNCH_MAX_RETRY; i++) {
        if (punch_listen(p, peer_ip, &peer_port) == 0) {
            strcpy(p->peer_ip, peer_ip);
            p->peer_port = peer_port;
            p->punched = true;
            p->last_technique = PUNCH_TECH_UDP;
            DLOG("Connected to %s:%d", peer_ip, peer_port);
            return 0;
        }
        
        /* Send punch every few retries */
        if (i % 3 == 0) {
            punch_send(p, target_ip, target_port);
        }
        
        usleep(100000);
    }
    
    DLOG("Failed to connect to %s:%d", target_ip, target_port);
    return -1;
}

/* ============================================================================
 * MULTI-STRATEGY PUNCH
 * ============================================================================ */

int punch_multi_strategy(const char* target_ip, int target_port, 
                         int local_nat_type, int peer_nat_type) {
    if (!target_ip) return -1;
    
    DLOG("Multi-strategy punch to %s:%d", target_ip, target_port);
    DLOG("Local NAT: %d, Peer NAT: %d", local_nat_type, peer_nat_type);
    
    /* Result tracking */
    typedef struct {
        PunchTechnique tech;
        int result;
        char ip[INET_ADDRSTRLEN];
        int port;
    } PunchResult;
    
    PunchResult results[4] = {0};
    int strategy_count = 0;
    pthread_t threads[4];
    
    /* Determine which strategies to try based on NAT types */
    bool try_udp = true;
    bool try_ttl = true;
    bool try_sim = true;
    bool try_pred = false;
    
    /* If both are symmetric, port prediction might help */
    if (local_nat_type == 4 && peer_nat_type == 4) { /* SYMMETRIC */
        try_pred = true;
        try_udp = false; /* UDP punch rarely works with symmetric */
    }
    
    /* If one is symmetric, still try UDP but with prediction */
    if (local_nat_type == 4 || peer_nat_type == 4) {
        try_pred = true;
    }
    
    DLOG("Strategies: UDP=%d, TTL=%d, SIM=%d, PRED=%d", 
         try_udp, try_ttl, try_sim, try_pred);
    
    /* Try UDP punch */
    if (try_udp) {
        PunchState p;
        if (punch_init(&p, PUNCH_PORT) == 0) {
            results[strategy_count].tech = PUNCH_TECH_UDP;
            results[strategy_count].result = punch_try_connect(&p, target_ip, target_port);
            if (results[strategy_count].result == 0) {
                punch_get_peer(&p, results[strategy_count].ip, &results[strategy_count].port);
            }
            punch_close(&p);
            strategy_count++;
        }
    }
    
    /* Try TTL punch */
    if (try_ttl) {
        PunchState p;
        if (punch_init(&p, PUNCH_PORT + 1) == 0) {
            results[strategy_count].tech = PUNCH_TECH_TTL;
            results[strategy_count].result = punch_try_ttl(&p, target_ip, target_port);
            if (results[strategy_count].result == 0) {
                punch_get_peer(&p, results[strategy_count].ip, &results[strategy_count].port);
            }
            punch_close(&p);
            strategy_count++;
        }
    }
    
    /* Try simultaneous open */
    if (try_sim) {
        PunchState p;
        if (punch_init(&p, PUNCH_PORT + 2) == 0) {
            results[strategy_count].tech = PUNCH_TECH_SIMULTANEOUS;
            results[strategy_count].result = punch_try_simultaneous(&p, target_ip, target_port);
            if (results[strategy_count].result == 0) {
                punch_get_peer(&p, results[strategy_count].ip, &results[strategy_count].port);
            }
            punch_close(&p);
            strategy_count++;
        }
    }
    
    /* Try port prediction (only if needed) */
    if (try_pred) {
        PunchState p;
        if (punch_init(&p, PUNCH_PORT + 3) == 0) {
            results[strategy_count].tech = PUNCH_TECH_PORT_PREDICTION;
            results[strategy_count].result = punch_try_port_prediction(&p, target_ip, target_port);
            if (results[strategy_count].result == 0) {
                punch_get_peer(&p, results[strategy_count].ip, &results[strategy_count].port);
            }
            punch_close(&p);
            strategy_count++;
        }
    }
    
    /* Return first successful result */
    for (int i = 0; i < strategy_count; i++) {
        if (results[i].result == 0) {
            DLOG("✅ Success with technique: %s", punch_technique_name(results[i].tech));
            return 0;
        }
    }
    
    DLOG("❌ All punch techniques failed");
    return -1;
}

/* ============================================================================
 * TECHNIQUE-SPECIFIC PUNCH
 * ============================================================================ */

int punch_try_udp(PunchState* p, const char* target_ip, int target_port) {
    if (!p || !target_ip) return -1;
    p->last_technique = PUNCH_TECH_UDP;
    return punch_try_connect(p, target_ip, target_port);
}

int punch_try_ttl(PunchState* p, const char* target_ip, int target_port) {
    if (!p || !target_ip) return -1;
    p->last_technique = PUNCH_TECH_TTL;
    p->ttl_used = true;
    
    DLOG("Trying TTL punch to %s:%d", target_ip, target_port);
    
    /* Try different TTL values */
    for (int ttl = 1; ttl <= PUNCH_MAX_TTL; ttl++) {
        punch_send_ttl(p, target_ip, target_port, ttl);
        usleep(50000);
        
        char peer_ip[INET_ADDRSTRLEN];
        int peer_port;
        if (punch_listen(p, peer_ip, &peer_port) == 0) {
            strcpy(p->peer_ip, peer_ip);
            p->peer_port = peer_port;
            p->punched = true;
            DLOG("TTL punch successful with TTL=%d", ttl);
            return 0;
        }
    }
    
    return -1;
}

int punch_try_simultaneous(PunchState* p, const char* target_ip, int target_port) {
    if (!p || !target_ip) return -1;
    p->last_technique = PUNCH_TECH_SIMULTANEOUS;
    p->simultaneous_used = true;
    
    DLOG("Trying simultaneous open to %s:%d", target_ip, target_port);
    
    /* Use simultaneous_open module */
    return simultaneous_open_punch(p, target_ip, target_port);
}

/* ============================================================================
 * PUNCH_TRY_PORT_PREDICTION - FIXED: Use port_predictor_punch
 * ============================================================================ */

int punch_try_port_prediction(PunchState* p, const char* target_ip, int target_port) {
    if (!p || !target_ip) return -1;
    p->last_technique = PUNCH_TECH_PORT_PREDICTION;
    
    DLOG("Trying port prediction to %s:%d", target_ip, target_port);
    
    /* Use port_predictor_punch from port_prediction.c */
    return port_predictor_punch(p, target_ip, target_port);
}

int punch_try_tcp(PunchState* p, const char* target_ip, int target_port) {
    if (!p || !target_ip) return -1;
    p->last_technique = PUNCH_TECH_TCP;
    
    DLOG("Trying TCP punch to %s:%d (not implemented yet)", target_ip, target_port);
    
    /* TODO: Implement TCP punch */
    return -1;
}

/* ============================================================================
 * PUNCH UTILITIES
 * ============================================================================ */

bool punch_is_successful(PunchState* p) {
    return p && p->punched;
}

int punch_get_peer(PunchState* p, char* ip_out, int* port_out) {
    if (!p || !ip_out || !port_out) return -1;
    if (!p->punched) return -1;
    
    strcpy(ip_out, p->peer_ip);
    *port_out = p->peer_port;
    return 0;
}

void punch_reset(PunchState* p) {
    if (!p) return;
    p->punched = false;
    p->retry_count = 0;
    p->ttl_used = false;
    p->simultaneous_used = false;
    memset(p->peer_ip, 0, sizeof(p->peer_ip));
    p->peer_port = 0;
    memset(&p->peer_addr, 0, sizeof(p->peer_addr));
    DLOG("Punch state reset");
}

/* ============================================================================
 * PUNCH BACKGROUND LISTENER
 * ============================================================================ */

static void* punch_listener_thread(void* arg) {
    PunchState* p = (PunchState*)arg;
    if (!p) return NULL;
    
    DLOG("Punch listener thread started");
    
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    char buffer[256];
    fd_set fds;
    struct timeval tv;
    
    while (p->udp_socket >= 0) {
        FD_ZERO(&fds);
        FD_SET(p->udp_socket, &fds);
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(p->udp_socket + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            DLOG("select error: %s", strerror(errno));
            break;
        }
        
        if (ret == 0) continue;
        
        int n = recvfrom(p->udp_socket, buffer, sizeof(buffer) - 1, 0,
                         (struct sockaddr*)&from, &from_len);
        
        if (n <= 0) continue;
        buffer[n] = '\0';
        
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
        int port = ntohs(from.sin_port);
        
        if (strcmp(buffer, "ORCA_PUNCH") == 0 ||
            strcmp(buffer, "ORCA_PUNCH_TTL") == 0 ||
            strcmp(buffer, "ORCA_PUNCH_SIM") == 0) {
            DLOG("Received punch from %s:%d", ip, port);
            /* Respond to punch */
            sendto(p->udp_socket, "ORCA_PUNCH_RESPONSE", 18, 0,
                   (struct sockaddr*)&from, from_len);
        }
    }
    
    DLOG("Punch listener thread stopped");
    return NULL;
}
