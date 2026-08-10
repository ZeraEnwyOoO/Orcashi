#ifndef NAT_H
#define NAT_H

#include <stdbool.h>
#include <netinet/in.h>

typedef struct {
    int udp_socket;
    int local_port;
    char peer_ip[INET_ADDRSTRLEN];
    int peer_port;
    bool punched;
} NATState;

int nat_init(NATState* nat, int port);
int nat_punch(NATState* nat, const char* target_ip, int target_port);
int nat_listen(NATState* nat, char* peer_ip, int* peer_port);
void nat_close(NATState* nat);

#endif
