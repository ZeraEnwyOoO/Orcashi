 // nat_punch.c - Fixed with actual punch usage
#include "nat_punch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>

int punch_init(PunchState* p, int port) {
    p->udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (p->udp_socket < 0) {
        fprintf(stderr, "[NAT] Failed to create UDP socket: %s\n", strerror(errno));
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
        fprintf(stderr, "[NAT] Failed to bind UDP socket: %s\n", strerror(errno));
        close(p->udp_socket);
        return -1;
    }
    
    p->local_port = port;
    p->punched = false;
    printf("[NAT] UDP socket bound to port %d\n", port);
    return 0;
}

int punch_send(PunchState* p, const char* target_ip, int target_port) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &target.sin_addr);
    
    char msg[] = "ORCA_PUNCH";
    int sent = sendto(p->udp_socket, msg, strlen(msg), 0,
                      (struct sockaddr*)&target, sizeof(target));
    
    if (sent < 0) {
        fprintf(stderr, "[NAT] Failed to send punch: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int punch_listen(PunchState* p, char* peer_ip, int* peer_port) {
    char buffer[256];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(p->udp_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    int n = recvfrom(p->udp_socket, buffer, sizeof(buffer), 0,
                     (struct sockaddr*)&from, &from_len);
    
    if (n < 0) {
        return -1;
    }
    
    buffer[n] = '\0';
    if (strcmp(buffer, "ORCA_PUNCH") == 0) {
        inet_ntop(AF_INET, &from.sin_addr, peer_ip, INET_ADDRSTRLEN);
        *peer_port = ntohs(from.sin_port);
        return 0;
    }
    return -1;
}

int punch_punch(PunchState* p, const char* target_ip, int target_port) {
    printf("[NAT] Sending punch packets to %s:%d...\n", target_ip, target_port);
    
    for (int i = 0; i < 10; i++) {
        punch_send(p, target_ip, target_port + i);
        usleep(10000);
    }
    
    char peer_ip[INET_ADDRSTRLEN];
    int peer_port;
    
    for (int i = 0; i < MAX_RETRY; i++) {
        if (punch_listen(p, peer_ip, &peer_port) == 0) {
            printf("[NAT] Punch successful! Peer at %s:%d\n", peer_ip, peer_port);
            p->punched = true;
            strcpy(p->peer_ip, peer_ip);
            p->peer_port = peer_port;
            return 0;
        }
        usleep(100000);
    }
    
    printf("[NAT] Punch failed!\n");
    return -1;
}

// ===== FIXED: Try to punch through NAT when connecting =====
int punch_try_connect(PunchState* p, const char* target_ip, int target_port) {
    printf("[NAT] Attempting NAT punch to %s:%d...\n", target_ip, target_port);
    
    // Send initial punch packets
    for (int i = 0; i < 5; i++) {
        punch_send(p, target_ip, target_port);
        usleep(50000);
    }
    
    // Listen for response
    char peer_ip[INET_ADDRSTRLEN];
    int peer_port;
    
    for (int i = 0; i < MAX_RETRY; i++) {
        if (punch_listen(p, peer_ip, &peer_port) == 0) {
            printf("[NAT] Punch successful! Connected to %s:%d\n", peer_ip, peer_port);
            p->punched = true;
            strcpy(p->peer_ip, peer_ip);
            p->peer_port = peer_port;
            return 0;
        }
        
        // Keep sending punches while waiting
        if (i % 3 == 0) {
            punch_send(p, target_ip, target_port);
        }
        usleep(100000);
    }
    
    printf("[NAT] Punch failed, falling back to direct connection\n");
    return -1;
}

void punch_close(PunchState* p) {
    if (p->udp_socket >= 0) {
        close(p->udp_socket);
        p->udp_socket = -1;
    }
}
