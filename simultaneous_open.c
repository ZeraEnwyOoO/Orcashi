 #include "simultaneous_open.h"
#include "orca_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>

#define SIM_DEBUG 1

#if SIM_DEBUG
#define SLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[SIMOPEN] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define SLOG(fmt, ...) ((void)0)
#endif

#define SIM_MAGIC 0x53494D4F
#define SIM_PROTOCOL_VERSION 1
#define SIM_SYNC_PORT_START 33450
#define SIM_SYNC_PORT_END 33460

typedef struct {
    uint32_t magic;
    uint8_t version;
    uint8_t type;
    uint32_t sync_token;
    uint32_t timestamp;
    uint16_t payload_len;
    uint8_t payload[];
} __attribute__((packed)) SimPacket;

typedef enum {
    SIM_PKT_SYNC = 1,
    SIM_PKT_SYNC_ACK = 2,
    SIM_PKT_SYNC_CONFIRM = 3,
    SIM_PKT_DATA = 4,
    SIM_PKT_KEEPALIVE = 5,
    SIM_PKT_CLOSE = 6
} SimPacketType;

static int simultaneous_open_create_socket(int port);
static int simultaneous_open_send_packet(SimOpenSession* session, uint8_t type,
                                          const uint8_t* payload, size_t payload_len);
static int simultaneous_open_process_packet(SimOpenSession* session,
                                             const SimPacket* packet, size_t len);
static uint32_t simultaneous_open_generate_sync_token(void);
static int simultaneous_open_wait_for_sync(SimOpenSession* session, int timeout_ms);
static int simultaneous_open_handshake(SimOpenSession* session);

int simultaneous_open_init(SimOpenSession* session, const char* target_ip, int target_port) {
    if (!session || !target_ip || target_port <= 0) {
        return -1;
    }
    
    memset(session, 0, sizeof(SimOpenSession));
    strcpy(session->target_ip, target_ip);
    session->target_port = target_port;
    session->state = SIM_OPEN_STATE_IDLE;
    session->socket_fd = -1;
    session->sync_token = 0;
    session->retry_count = 0;
    session->is_initiator = 0;
    
    SLOG("Simultaneous open initialized for %s:%d", target_ip, target_port);
    return 0;
}

void simultaneous_open_cleanup(SimOpenSession* session) {
    if (!session) return;
    
    if (session->socket_fd >= 0) {
        close(session->socket_fd);
        session->socket_fd = -1;
    }
    
    session->state = SIM_OPEN_STATE_IDLE;
    SLOG("Simultaneous open cleaned up");
}

int simultaneous_open_create_socket(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        SLOG("Failed to create TCP socket: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        SLOG("Failed to bind TCP socket on port %d: %s", port, strerror(errno));
        close(sock);
        return -1;
    }
    
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    SLOG("Created TCP socket on port %d", port);
    return sock;
}

uint32_t simultaneous_open_generate_sync_token(void) {
    uint32_t token;
    orca_random_bytes((unsigned char*)&token, sizeof(token));
    return token ^ (uint32_t)time(NULL) ^ (uint32_t)getpid();
}

int simultaneous_open_send_packet(SimOpenSession* session, uint8_t type,
                                   const uint8_t* payload, size_t payload_len) {
    if (!session || session->socket_fd < 0) {
        return -1;
    }
    
    size_t packet_size = sizeof(SimPacket) + payload_len;
    uint8_t* buffer = (uint8_t*)malloc(packet_size);
    if (!buffer) {
        return -1;
    }
    
    SimPacket* packet = (SimPacket*)buffer;
    packet->magic = SIM_MAGIC;
    packet->version = SIM_PROTOCOL_VERSION;
    packet->type = type;
    packet->sync_token = session->sync_token;
    packet->timestamp = (uint32_t)time(NULL);
    packet->payload_len = (uint16_t)payload_len;
    
    if (payload && payload_len > 0) {
        memcpy(packet->payload, payload, payload_len);
    }
    
    ssize_t sent = send(session->socket_fd, buffer, packet_size, 0);
    free(buffer);
    
    if (sent < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            SLOG("Failed to send packet: %s", strerror(errno));
        }
        return -1;
    }
    
    session->last_activity = time(NULL);
    return 0;
}

int simultaneous_open_process_packet(SimOpenSession* session,
                                      const SimPacket* packet, size_t len) {
    if (!session || !packet || len < sizeof(SimPacket)) {
        return -1;
    }
    
    if (packet->magic != SIM_MAGIC) {
        SLOG("Invalid packet magic: 0x%x", packet->magic);
        return -1;
    }
    
    if (packet->version != SIM_PROTOCOL_VERSION) {
        SLOG("Unsupported protocol version: %d", packet->version);
        return -1;
    }
    
    session->last_activity = time(NULL);
    
    switch (packet->type) {
        case SIM_PKT_SYNC:
            SLOG("SYNC received (token: %u)", packet->sync_token);
            session->sync_token = packet->sync_token;
            simultaneous_open_send_packet(session, SIM_PKT_SYNC_ACK, NULL, 0);
            if (session->state == SIM_OPEN_STATE_SYNCING) {
                session->state = SIM_OPEN_STATE_ESTABLISHED;
                SLOG("Simultaneous open established via SYNC");
            }
            break;
            
        case SIM_PKT_SYNC_ACK:
            SLOG("SYNC_ACK received (token: %u)", packet->sync_token);
            if (session->sync_token == packet->sync_token) {
                simultaneous_open_send_packet(session, SIM_PKT_SYNC_CONFIRM, NULL, 0);
                session->state = SIM_OPEN_STATE_ESTABLISHED;
                SLOG("Simultaneous open established via SYNC_ACK");
            }
            break;
            
        case SIM_PKT_SYNC_CONFIRM:
            SLOG("SYNC_CONFIRM received");
            if (session->state == SIM_OPEN_STATE_SYNCING) {
                session->state = SIM_OPEN_STATE_ESTABLISHED;
                SLOG("Simultaneous open established via SYNC_CONFIRM");
            }
            break;
            
        case SIM_PKT_DATA:
            SLOG("Data received (%d bytes)", packet->payload_len);
            break;
            
        case SIM_PKT_KEEPALIVE:
            SLOG("Keepalive received");
            break;
            
        case SIM_PKT_CLOSE:
            SLOG("Close received");
            session->state = SIM_OPEN_STATE_IDLE;
            break;
            
        default:
            SLOG("Unknown packet type: %d", packet->type);
            break;
    }
    
    return 0;
}

int simultaneous_open_wait_for_sync(SimOpenSession* session, int timeout_ms) {
    if (!session || session->socket_fd < 0) {
        return -1;
    }
    
    fd_set fds;
    struct timeval tv;
    uint8_t buffer[512];
    
    FD_ZERO(&fds);
    FD_SET(session->socket_fd, &fds);
    
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    int ret = select(session->socket_fd + 1, &fds, NULL, NULL, &tv);
    if (ret < 0) {
        SLOG("select error: %s", strerror(errno));
        return -1;
    }
    
    if (ret == 0) {
        SLOG("Sync timeout after %d ms", timeout_ms);
        return -1;
    }
    
    int n = recv(session->socket_fd, buffer, sizeof(buffer), 0);
    if (n <= 0) {
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            SLOG("recv error: %s", strerror(errno));
        }
        return -1;
    }
    
    if (n >= (int)sizeof(SimPacket)) {
        SimPacket* packet = (SimPacket*)buffer;
        return simultaneous_open_process_packet(session, packet, n);
    }
    
    return -1;
}

int simultaneous_open_connect(SimOpenSession* session) {
    if (!session) {
        return -1;
    }
    
    SLOG("Simultaneous open connect to %s:%d", session->target_ip, session->target_port);
    
    session->local_port = SIM_SYNC_PORT_START + (rand() % (SIM_SYNC_PORT_END - SIM_SYNC_PORT_START));
    session->socket_fd = simultaneous_open_create_socket(session->local_port);
    if (session->socket_fd < 0) {
        return -1;
    }
    
    session->sync_token = simultaneous_open_generate_sync_token();
    session->is_initiator = 1;
    session->state = SIM_OPEN_STATE_CONNECTING;
    session->start_time = time(NULL);
    
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(session->target_port);
    inet_pton(AF_INET, session->target_ip, &target.sin_addr);
    
    int ret = connect(session->socket_fd, (struct sockaddr*)&target, sizeof(target));
    if (ret < 0 && errno != EINPROGRESS) {
        SLOG("connect failed: %s", strerror(errno));
        simultaneous_open_cleanup(session);
        return -1;
    }
    
    session->state = SIM_OPEN_STATE_SYNCING;
    
    simultaneous_open_send_packet(session, SIM_PKT_SYNC, NULL, 0);
    
    for (int i = 0; i < SIM_OPEN_MAX_RETRY; i++) {
        if (simultaneous_open_wait_for_sync(session, SIM_OPEN_TIMEOUT_MS / SIM_OPEN_MAX_RETRY) == 0) {
            if (session->state == SIM_OPEN_STATE_ESTABLISHED) {
                SLOG("Simultaneous open connect successful");
                return 0;
            }
        }
        
        if (i < SIM_OPEN_MAX_RETRY - 1) {
            simultaneous_open_send_packet(session, SIM_PKT_SYNC, NULL, 0);
            usleep(SIM_OPEN_SYNC_DELAY_MS * 1000);
        }
    }
    
    SLOG("Simultaneous open connect failed after %d retries", SIM_OPEN_MAX_RETRY);
    simultaneous_open_cleanup(session);
    return -1;
}

int simultaneous_open_accept(SimOpenSession* session) {
    if (!session) {
        return -1;
    }
    
    SLOG("Simultaneous open accept on %s:%d", session->target_ip, session->target_port);
    
    session->local_port = SIM_SYNC_PORT_START + (rand() % (SIM_SYNC_PORT_END - SIM_SYNC_PORT_START));
    session->socket_fd = simultaneous_open_create_socket(session->local_port);
    if (session->socket_fd < 0) {
        return -1;
    }
    
    session->sync_token = simultaneous_open_generate_sync_token();
    session->is_initiator = 0;
    session->state = SIM_OPEN_STATE_CONNECTING;
    session->start_time = time(NULL);
    
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(session->target_port);
    inet_pton(AF_INET, session->target_ip, &target.sin_addr);
    
    int ret = connect(session->socket_fd, (struct sockaddr*)&target, sizeof(target));
    if (ret < 0 && errno != EINPROGRESS) {
        SLOG("connect failed: %s", strerror(errno));
        simultaneous_open_cleanup(session);
        return -1;
    }
    
    session->state = SIM_OPEN_STATE_SYNCING;
    
    for (int i = 0; i < SIM_OPEN_MAX_RETRY; i++) {
        if (simultaneous_open_wait_for_sync(session, SIM_OPEN_TIMEOUT_MS / SIM_OPEN_MAX_RETRY) == 0) {
            if (session->state == SIM_OPEN_STATE_ESTABLISHED) {
                SLOG("Simultaneous open accept successful");
                return 0;
            }
        }
        
        if (i < SIM_OPEN_MAX_RETRY - 1) {
            usleep(SIM_OPEN_SYNC_DELAY_MS * 1000);
        }
    }
    
    SLOG("Simultaneous open accept failed after %d retries", SIM_OPEN_MAX_RETRY);
    simultaneous_open_cleanup(session);
    return -1;
}

int simultaneous_open_punch(void* punch_state, const char* target_ip, int target_port) {
    if (!target_ip || target_port <= 0) {
        return -1;
    }
    
    SLOG("Simultaneous open punch to %s:%d", target_ip, target_port);
    
    SimOpenSession session;
    if (simultaneous_open_init(&session, target_ip, target_port) < 0) {
        return -1;
    }
    
    int result = simultaneous_open_connect(&session);
    if (result == 0) {
        if (punch_state) {
            PunchState* p = (PunchState*)punch_state;
            p->udp_socket = session.socket_fd;
            strcpy(p->peer_ip, session.peer_ip);
            p->peer_port = session.peer_port;
            p->punched = 1;
        }
        
        SLOG("Simultaneous open punch successful");
        return 0;
    }
    
    SLOG("Simultaneous open punch failed");
    return -1;
}

int simultaneous_open_send(SimOpenSession* session, const uint8_t* data, size_t len) {
    if (!session || !data || len == 0) {
        return -1;
    }
    
    if (session->state != SIM_OPEN_STATE_ESTABLISHED) {
        SLOG("Not connected, cannot send");
        return -1;
    }
    
    return simultaneous_open_send_packet(session, SIM_PKT_DATA, data, len);
}

int simultaneous_open_recv(SimOpenSession* session, uint8_t* buffer, size_t max_len) {
    if (!session || !buffer || max_len == 0) {
        return -1;
    }
    
    if (session->state != SIM_OPEN_STATE_ESTABLISHED) {
        return -1;
    }
    
    uint8_t recv_buffer[512];
    int n = recv(session->socket_fd, recv_buffer, sizeof(recv_buffer), MSG_DONTWAIT);
    
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        SLOG("recv error: %s", strerror(errno));
        return -1;
    }
    
    if (n == 0) {
        session->state = SIM_OPEN_STATE_IDLE;
        return 0;
    }
    
    if (n >= (int)sizeof(SimPacket)) {
        SimPacket* packet = (SimPacket*)recv_buffer;
        if (packet->magic == SIM_MAGIC) {
            if (packet->type == SIM_PKT_DATA) {
                size_t copy_len = packet->payload_len;
                if (copy_len > max_len) copy_len = max_len;
                memcpy(buffer, packet->payload, copy_len);
                session->last_activity = time(NULL);
                return (int)copy_len;
            }
            simultaneous_open_process_packet(session, packet, n);
        }
    }
    
    return 0;
}

int simultaneous_open_close(SimOpenSession* session) {
    if (!session) return -1;
    
    if (session->socket_fd >= 0) {
        simultaneous_open_send_packet(session, SIM_PKT_CLOSE, NULL, 0);
        close(session->socket_fd);
        session->socket_fd = -1;
    }
    
    session->state = SIM_OPEN_STATE_IDLE;
    SLOG("Simultaneous open closed");
    return 0;
}

bool simultaneous_open_is_connected(SimOpenSession* session) {
    return session && session->state == SIM_OPEN_STATE_ESTABLISHED;
}

SimOpenState simultaneous_open_get_state(SimOpenSession* session) {
    return session ? session->state : SIM_OPEN_STATE_IDLE;
}

int simultaneous_open_get_peer(SimOpenSession* session, char* ip_out, int* port_out) {
    if (!session || !ip_out || !port_out) {
        return -1;
    }
    
    if (session->state != SIM_OPEN_STATE_ESTABLISHED) {
        return -1;
    }
    
    strcpy(ip_out, session->peer_ip);
    *port_out = session->peer_port;
    return 0;
}

void simultaneous_open_debug_print(SimOpenSession* session) {
    if (!session) {
        printf("SimOpenSession is NULL\n");
        return;
    }
    
    printf("\n=== SIMULTANEOUS OPEN DEBUG ===\n");
    printf("Target: %s:%d\n", session->target_ip, session->target_port);
    printf("Local Port: %d\n", session->local_port);
    printf("Socket FD: %d\n", session->socket_fd);
    printf("State: %d\n", session->state);
    printf("Sync Token: %u\n", session->sync_token);
    printf("Is Initiator: %s\n", session->is_initiator ? "YES" : "NO");
    printf("Retry Count: %d\n", session->retry_count);
    printf("Peer: %s:%d\n", session->peer_ip, session->peer_port);
    printf("Last Activity: %s", ctime(&session->last_activity));
    printf("==============================\n");
}
