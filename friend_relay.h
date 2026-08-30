 #ifndef FRIEND_RELAY_H
#define FRIEND_RELAY_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define RELAY_MAX_PEERS 32
#define RELAY_BUFFER_SIZE 4096
#define RELAY_TIMEOUT_MS 5000
#define RELAY_KEEPALIVE_INTERVAL 30
#define RELAY_MAX_HOPS 5
#define RELAY_MAX_PATH 8

typedef enum {
    RELAY_STATE_IDLE = 0,
    RELAY_STATE_CONNECTING,
    RELAY_STATE_ESTABLISHED,
    RELAY_STATE_CLOSED
} RelayState;

typedef struct {
    char peer_id[64];
    char relay_id[64];
    char ip[INET_ADDRSTRLEN];
    int port;
    RelayState state;
    int socket_fd;
    uint32_t session_id;
    time_t last_activity;
    time_t created_at;
    bool is_initiator;
    int retry_count;
    int hop_count;
    char path[RELAY_MAX_PATH][64];
    uint8_t shared_secret[32];
    bool is_secure;
} RelaySession;

typedef struct {
    RelaySession sessions[RELAY_MAX_PEERS];
    int count;
    pthread_mutex_t mutex;
    bool initialized;
    bool is_relay_node;
    char my_id[64];
    int relay_port;
    int relay_socket;
} RelayManager;

int relay_manager_init(RelayManager* mgr, const char* my_id, int port);
void relay_manager_cleanup(RelayManager* mgr);
int relay_manager_enable_relay(RelayManager* mgr, bool enable);

int relay_connect(RelayManager* mgr, const char* peer_id, const char* relay_id,
                  const char* relay_ip, int relay_port);
int relay_accept(RelayManager* mgr, const char* peer_id, const char* relay_id);
int relay_send(RelayManager* mgr, const char* peer_id, const uint8_t* data, size_t len);
int relay_recv(RelayManager* mgr, const char* peer_id, uint8_t* buffer, size_t max_len);
int relay_disconnect(RelayManager* mgr, const char* peer_id);

int relay_discover_peers(RelayManager* mgr, char relay_ids[][64], int max);
int relay_announce(RelayManager* mgr, int port);

bool relay_is_connected(RelayManager* mgr, const char* peer_id);
RelayState relay_get_state(RelayManager* mgr, const char* peer_id);
int relay_get_peer_count(RelayManager* mgr);
int relay_get_relay_path(RelayManager* mgr, const char* peer_id, char path[][64], int* count);

void relay_debug_print(RelayManager* mgr);

#endif
