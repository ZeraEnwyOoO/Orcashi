#include "punch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

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
    
    if (strcmp(buffer, "ORCA_PUNCH") == 0) {
        inet_ntop(AF_INET, &from.sin_addr, peer_ip_out, INET_ADDRSTRLEN);
        *peer_port_out = ntohs(from.sin_port);
        DLOG("Received punch from %s:%d", peer_ip_out, *peer_port_out);
        return 0;
    }
    
    if (strcmp(buffer, "ORCA_PUNCH_RESPONSE") == 0) {
        inet_ntop(AF_INET, &from.sin_addr, peer_ip_out, INET_ADDRSTRLEN);
        *peer_port_out = ntohs(from.sin_port);
        DLOG("Received punch response from %s:%d", peer_ip_out, *peer_port_out);
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
        
        if (strcmp(buffer, "ORCA_PUNCH") == 0) {
            DLOG("Received punch from %s:%d", ip, port);
            /* Respond to punch */
            sendto(p->udp_socket, "ORCA_PUNCH_RESPONSE", 18, 0,
                   (struct sockaddr*)&from, from_len);
        }
    }
    
    DLOG("Punch listener thread stopped");
    return NULL;
}
