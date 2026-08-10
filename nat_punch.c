#include "nat_punch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

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

void punch_close(PunchState* p) {
    if (p->udp_socket >= 0) {
        close(p->udp_socket);
        p->udp_socket = -1;
    }
}
