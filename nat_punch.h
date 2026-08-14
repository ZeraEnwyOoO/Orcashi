 // nat_punch.h - Added punch_try_connect
#ifndef NAT_PUNCH_H
#define NAT_PUNCH_H

#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PUNCH_PORT 33445
#define MAX_RETRY 10

typedef struct {
    int udp_socket;
    int local_port;
    char peer_ip[INET_ADDRSTRLEN];
    int peer_port;
    bool punched;
} PunchState;

int punch_init(PunchState* p, int port);
int punch_send(PunchState* p, const char* target_ip, int target_port);
int punch_listen(PunchState* p, char* peer_ip, int* peer_port);
int punch_punch(PunchState* p, const char* target_ip, int target_port);
int punch_try_connect(PunchState* p, const char* target_ip, int target_port);
void punch_close(PunchState* p);

#endif
