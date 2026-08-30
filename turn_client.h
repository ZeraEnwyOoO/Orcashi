#ifndef TURN_CLIENT_H
#define TURN_CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define TURN_SERVER_MAX 8
#define TURN_BUFFER_SIZE 4096
#define TURN_DEFAULT_PORT 3478
#define TURN_TIMEOUT_MS 5000
#define TURN_KEEPALIVE_INTERVAL 30

typedef enum {
    TURN_STATE_IDLE = 0,
    TURN_STATE_CONNECTING,
    TURN_STATE_ALLOCATING,
    TURN_STATE_ESTABLISHED,
    TURN_STATE_CLOSED,
    TURN_STATE_ERROR
} TURNState;

typedef struct {
    char server_host[128];
    char server_ip[INET_ADDRSTRLEN];
    int port;
    char username[64];
    char password[64];
    char realm[128];
    char nonce[256];
    bool use_auth;
} TURNServerConfig;

typedef struct {
    char peer_id[64];
    char relay_ip[INET_ADDRSTRLEN];
    int relay_port;
    char external_ip[INET_ADDRSTRLEN];
    int external_port;
    uint32_t allocation_id;
    uint32_t session_id;
    TURNState state;
    int socket_fd;
    time_t last_activity;
    time_t created_at;
    time_t allocation_expires;
    bool is_initiator;
    int retry_count;
    uint8_t shared_secret[32];
    TURNServerConfig server;
} TURNSession;

typedef struct {
    TURNSession sessions[TURN_SERVER_MAX];
    int count;
    pthread_mutex_t mutex;
    bool initialized;
    TURNServerConfig servers[TURN_SERVER_MAX];
    int server_count;
} TURNManager;

/* TURN manager functions */
int turn_manager_init(TURNManager* mgr);
void turn_manager_cleanup(TURNManager* mgr);
int turn_manager_add_server(TURNManager* mgr, const char* host, int port,
                             const char* username, const char* password);

/* TURN session functions */
int turn_connect(TURNManager* mgr, const char* peer_id, const char* server_host);
int turn_allocate(TURNManager* mgr, const char* peer_id);
int turn_send(TURNManager* mgr, const char* peer_id, const uint8_t* data, size_t len);
int turn_recv(TURNManager* mgr, const char* peer_id, uint8_t* buffer, size_t max_len);
int turn_disconnect(TURNManager* mgr, const char* peer_id);
int turn_refresh_allocation(TURNManager* mgr, const char* peer_id);

/* TURN status functions */
bool turn_is_connected(TURNManager* mgr, const char* peer_id);
TURNState turn_get_state(TURNManager* mgr, const char* peer_id);
int turn_get_external_address(TURNManager* mgr, const char* peer_id,
                               char* ip_out, int* port_out);

/* TURN debug */
void turn_debug_print(TURNManager* mgr);

#endif
