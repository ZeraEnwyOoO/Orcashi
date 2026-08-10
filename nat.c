#include "nat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

int nat_init(NATState* nat, int port) {
    nat->udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (nat->udp_socket < 0) return -1;
    
    int opt = 1;
    setsockopt(nat->udp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(nat->udp_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(nat->udp_socket);
        return -1;
    }
    
    nat->local_port = port;
    nat->punched = false;
    return 0;
}

int nat_punch(NATState* nat, const char* target_ip, int target_port) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &target.sin_addr);
    
    char msg[] = "ORCA_PUNCH";
    int sent = sendto(nat->udp_socket, msg, strlen(msg), 0,
                      (struct sockaddr*)&target, sizeof(target));
    
    return sent > 0 ? 0 : -1;
}

int nat_listen(NATState* nat, char* peer_ip, int* peer_port) {
    char buffer[256];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    
    int n = recvfrom(nat->udp_socket, buffer, sizeof(buffer), 0,
                     (struct sockaddr*)&from, &from_len);
    
    if (n > 0 && strcmp(buffer, "ORCA_PUNCH") == 0) {
        inet_ntop(AF_INET, &from.sin_addr, peer_ip, INET_ADDRSTRLEN);
        *peer_port = ntohs(from.sin_port);
        return 0;
    }
    return -1;
}

void nat_close(NATState* nat) {
    if (nat->udp_socket >= 0) {
        close(nat->udp_socket);
        nat->udp_socket = -1;
    }
}
