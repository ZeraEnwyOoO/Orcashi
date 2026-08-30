 #ifndef SIMULTANEOUS_OPEN_H
#define SIMULTANEOUS_OPEN_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define SIM_OPEN_MAX_RETRY 5
#define SIM_OPEN_TIMEOUT_MS 3000
#define SIM_OPEN_PORT_RANGE 10
#define SIM_OPEN_SYNC_DELAY_MS 50

typedef enum {
    SIM_OPEN_STATE_IDLE = 0,
    SIM_OPEN_STATE_CONNECTING,
    SIM_OPEN_STATE_SYNCING,
    SIM_OPEN_STATE_ESTABLISHED,
    SIM_OPEN_STATE_FAILED
} SimOpenState;

typedef struct {
    char target_ip[INET_ADDRSTRLEN];
    int target_port;
    int local_port;
    int socket_fd;
    SimOpenState state;
    uint32_t sync_token;
    time_t start_time;
    time_t last_activity;
    int retry_count;
    bool is_initiator;
    struct sockaddr_in peer_addr;
    char peer_ip[INET_ADDRSTRLEN];
    int peer_port;
} SimOpenSession;

int simultaneous_open_init(SimOpenSession* session, const char* target_ip, int target_port);
void simultaneous_open_cleanup(SimOpenSession* session);

int simultaneous_open_punch(void* punch_state, const char* target_ip, int target_port);
int simultaneous_open_connect(SimOpenSession* session);
int simultaneous_open_accept(SimOpenSession* session);
int simultaneous_open_send(SimOpenSession* session, const uint8_t* data, size_t len);
int simultaneous_open_recv(SimOpenSession* session, uint8_t* buffer, size_t max_len);
int simultaneous_open_close(SimOpenSession* session);

bool simultaneous_open_is_connected(SimOpenSession* session);
SimOpenState simultaneous_open_get_state(SimOpenSession* session);
int simultaneous_open_get_peer(SimOpenSession* session, char* ip_out, int* port_out);

void simultaneous_open_debug_print(SimOpenSession* session);

#endif
