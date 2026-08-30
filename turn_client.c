#include "turn_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>

#define TURN_DEBUG 1

#if TURN_DEBUG
#define TLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[TURN] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define TLOG(fmt, ...) ((void)0)
#endif

#define TURN_MAGIC 0x5455524E
#define TURN_PROTOCOL_VERSION 1

typedef struct {
    uint32_t magic;
    uint8_t version;
    uint8_t type;
    uint32_t allocation_id;
    uint32_t session_id;
    uint32_t sequence;
    uint16_t payload_len;
    uint8_t payload[];
} TURNPacket;

#define TURN_TYPE_ALLOCATE_REQUEST 1
#define TURN_TYPE_ALLOCATE_RESPONSE 2
#define TURN_TYPE_DATA 3
#define TURN_TYPE_KEEPALIVE 4
#define TURN_TYPE_CLOSE 5
#define TURN_TYPE_AUTH_REQUEST 6
#define TURN_TYPE_AUTH_RESPONSE 7

static TURNManager* g_turn_mgr = NULL;
static pthread_t g_turn_thread = 0;
static bool g_turn_running = 0;

static int turn_resolve_host(const char* host, char* ip_out, size_t ip_size);
static int turn_send_packet(TURNSession* session, uint8_t type,
                             const uint8_t* payload, size_t payload_len);
static void* turn_listener_thread(void* arg);
static int turn_process_packet(TURNSession* session, const TURNPacket* packet,
                                size_t packet_len);
static int turn_create_auth_challenge(TURNSession* session, uint8_t* buffer, size_t* len);
static int turn_verify_auth(TURNSession* session, const uint8_t* data, size_t len);

int turn_manager_init(TURNManager* mgr) {
    if (!mgr) {
        return -1;
    }
    
    memset(mgr, 0, sizeof(TURNManager));
    mgr->count = 0;
    mgr->server_count = 0;
    mgr->initialized = 1;
    
    if (pthread_mutex_init(&mgr->mutex, NULL) != 0) {
        TLOG("Failed to initialize TURN mutex");
        return -1;
    }
    
    TLOG("TURN manager initialized");
    return 0;
}

void turn_manager_cleanup(TURNManager* mgr) {
    if (!mgr || !mgr->initialized) {
        return;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    for (int i = 0; i < mgr->count; i++) {
        if (mgr->sessions[i].socket_fd > 0) {
            turn_send_packet(&mgr->sessions[i], TURN_TYPE_CLOSE, NULL, 0);
            close(mgr->sessions[i].socket_fd);
        }
    }
    
    mgr->count = 0;
    mgr->initialized = 0;
    
    pthread_mutex_unlock(&mgr->mutex);
    pthread_mutex_destroy(&mgr->mutex);
    
    TLOG("TURN manager cleaned up");
}

int turn_manager_add_server(TURNManager* mgr, const char* host, int port,
                             const char* username, const char* password) {
    if (!mgr || !host || mgr->server_count >= TURN_SERVER_MAX) {
        return -1;
    }
    
    TURNServerConfig* server = &mgr->servers[mgr->server_count++];
    strncpy(server->server_host, host, sizeof(server->server_host) - 1);
    server->port = port > 0 ? port : TURN_DEFAULT_PORT;
    
    if (username) {
        strncpy(server->username, username, sizeof(server->username) - 1);
        server->use_auth = 1;
    }
    if (password) {
        strncpy(server->password, password, sizeof(server->password) - 1);
        server->use_auth = 1;
    }
    
    if (turn_resolve_host(host, server->server_ip, sizeof(server->server_ip)) < 0) {
        TLOG("Failed to resolve TURN server: %s", host);
        return -1;
    }
    
    TLOG("Added TURN server: %s (%s:%d)", host, server->server_ip, server->port);
    return 0;
}

static int turn_resolve_host(const char* host, char* ip_out, size_t ip_size) {
    struct addrinfo hints, *res, *rp;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(host, NULL, &hints, &res) != 0) {
        return -1;
    }
    
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        struct sockaddr_in* addr = (struct sockaddr_in*)rp->ai_addr;
        void* sin_addr = &addr->sin_addr;
        if (inet_ntop(AF_INET, sin_addr, ip_out, ip_size) != NULL) {
            freeaddrinfo(res);
            return 0;
        }
    }
    
    freeaddrinfo(res);
    return -1;
}

static TURNSession* turn_find_session(TURNManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) {
        return NULL;
    }
    
    for (int i = 0; i < mgr->count; i++) {
        if (strcmp(mgr->sessions[i].peer_id, peer_id) == 0) {
            return &mgr->sessions[i];
        }
    }
    
    return NULL;
}

static TURNSession* turn_add_session(TURNManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) {
        return NULL;
    }
    
    if (mgr->count >= TURN_SERVER_MAX) {
        TLOG("TURN session limit reached");
        return NULL;
    }
    
    TURNSession* session = &mgr->sessions[mgr->count++];
    memset(session, 0, sizeof(TURNSession));
    strcpy(session->peer_id, peer_id);
    session->state = TURN_STATE_IDLE;
    session->socket_fd = -1;
    session->created_at = time(NULL);
    session->last_activity = time(NULL);
    session->session_id = (uint32_t)(time(NULL) ^ getpid() ^ rand());
    session->allocation_id = (uint32_t)(time(NULL) ^ getpid() ^ rand() ^ 0xDEADBEEF);
    
    TLOG("Added TURN session for %s (ID: %u, ALLOC: %u)", 
         peer_id, session->session_id, session->allocation_id);
    return session;
}

static int turn_create_connection(const char* server_ip, int server_port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        TLOG("Failed to create TURN socket: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        TLOG("Failed to connect to TURN server %s:%d: %s", 
             server_ip, server_port, strerror(errno));
        close(sock);
        return -1;
    }
    
    TLOG("Connected to TURN server %s:%d", server_ip, server_port);
    return sock;
}

int turn_connect(TURNManager* mgr, const char* peer_id, const char* server_host) {
    if (!mgr || !peer_id || !server_host) {
        return -1;
    }
    
    TLOG("TURN connect for %s via %s", peer_id, server_host);
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    if (!session) {
        session = turn_add_session(mgr, peer_id);
        if (!session) {
            pthread_mutex_unlock(&mgr->mutex);
            return -1;
        }
    }
    
    if (session->state == TURN_STATE_ESTABLISHED) {
        TLOG("Already connected to %s via TURN", peer_id);
        pthread_mutex_unlock(&mgr->mutex);
        return 0;
    }
    
    /* Find server */
    TURNServerConfig* server = NULL;
    for (int i = 0; i < mgr->server_count; i++) {
        if (strcmp(mgr->servers[i].server_host, server_host) == 0) {
            server = &mgr->servers[i];
            break;
        }
    }
    
    if (!server) {
        TLOG("TURN server not found: %s", server_host);
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    session->server = *server;
    session->state = TURN_STATE_CONNECTING;
    
    pthread_mutex_unlock(&mgr->mutex);
    
    int sock = turn_create_connection(server->server_ip, server->port);
    if (sock < 0) {
        pthread_mutex_lock(&mgr->mutex);
        session->state = TURN_STATE_ERROR;
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    session->socket_fd = sock;
    session->is_initiator = 1;
    session->state = TURN_STATE_ALLOCATING;
    pthread_mutex_unlock(&mgr->mutex);
    
    /* Send allocation request */
    if (turn_allocate(mgr, peer_id) < 0) {
        pthread_mutex_lock(&mgr->mutex);
        session->state = TURN_STATE_ERROR;
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    session->state = TURN_STATE_ESTABLISHED;
    session->last_activity = time(NULL);
    pthread_mutex_unlock(&mgr->mutex);
    
    TLOG("TURN connection established for %s", peer_id);
    return 0;
}

int turn_allocate(TURNManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) {
        return -1;
    }
    
    TLOG("Allocating TURN relay for %s", peer_id);
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    if (!session || session->socket_fd < 0) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    uint8_t allocate_msg[256];
    size_t msg_len = 0;
    
    if (session->server.use_auth) {
        turn_create_auth_challenge(session, allocate_msg, &msg_len);
    } else {
        /* Simple allocation request */
        struct {
            uint32_t type;
            uint32_t lifetime;
            uint32_t port;
        } __attribute__((packed)) req;
        
        req.type = TURN_TYPE_ALLOCATE_REQUEST;
        req.lifetime = 3600;
        req.port = htons(0);
        
        memcpy(allocate_msg, &req, sizeof(req));
        msg_len = sizeof(req);
    }
    
    int result = turn_send_packet(session, TURN_TYPE_ALLOCATE_REQUEST, 
                                   allocate_msg, msg_len);
    
    pthread_mutex_unlock(&mgr->mutex);
    
    if (result < 0) {
        TLOG("Allocation request failed");
        return -1;
    }
    
    TLOG("Allocation request sent for %s", peer_id);
    return 0;
}

static int turn_create_auth_challenge(TURNSession* session, uint8_t* buffer, size_t* len) {
    if (!session || !buffer || !len) {
        return -1;
    }
    
    struct {
        uint32_t type;
        uint32_t username_len;
        uint32_t password_len;
        char username[64];
        char password[64];
    } __attribute__((packed)) auth;
    
    auth.type = TURN_TYPE_AUTH_REQUEST;
    auth.username_len = strlen(session->server.username);
    auth.password_len = strlen(session->server.password);
    strcpy(auth.username, session->server.username);
    strcpy(auth.password, session->server.password);
    
    *len = sizeof(auth);
    memcpy(buffer, &auth, *len);
    
    return 0;
}

static int turn_send_packet(TURNSession* session, uint8_t type,
                             const uint8_t* payload, size_t payload_len) {
    if (!session || session->socket_fd < 0) {
        return -1;
    }
    
    size_t packet_size = sizeof(TURNPacket) + payload_len;
    uint8_t* buffer = (uint8_t*)malloc(packet_size);
    if (!buffer) {
        return -1;
    }
    
    TURNPacket* packet = (TURNPacket*)buffer;
    packet->magic = TURN_MAGIC;
    packet->version = TURN_PROTOCOL_VERSION;
    packet->type = type;
    packet->allocation_id = session->allocation_id;
    packet->session_id = session->session_id;
    packet->sequence = session->last_activity;
    packet->payload_len = (uint16_t)payload_len;
    
    if (payload && payload_len > 0) {
        memcpy(packet->payload, payload, payload_len);
    }
    
    ssize_t sent = send(session->socket_fd, buffer, packet_size, 0);
    free(buffer);
    
    if (sent < 0) {
        TLOG("Failed to send TURN packet: %s", strerror(errno));
        return -1;
    }
    
    session->last_activity = time(NULL);
    return 0;
}

int turn_send(TURNManager* mgr, const char* peer_id, const uint8_t* data, size_t len) {
    if (!mgr || !peer_id || !data || len == 0) {
        return -1;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    if (!session || session->state != TURN_STATE_ESTABLISHED) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    if (session->socket_fd < 0) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    int result = turn_send_packet(session, TURN_TYPE_DATA, data, len);
    
    pthread_mutex_unlock(&mgr->mutex);
    return result;
}

int turn_recv(TURNManager* mgr, const char* peer_id, uint8_t* buffer, size_t max_len) {
    if (!mgr || !peer_id || !buffer || max_len == 0) {
        return -1;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    if (!session || session->state != TURN_STATE_ESTABLISHED) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    if (session->socket_fd < 0) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    int n = recv(session->socket_fd, buffer, max_len, MSG_DONTWAIT);
    
    pthread_mutex_unlock(&mgr->mutex);
    
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    
    if (n > 0) {
        session->last_activity = time(NULL);
    }
    
    return n;
}

int turn_disconnect(TURNManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) {
        return -1;
    }
    
    TLOG("Disconnecting TURN for %s", peer_id);
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    if (session) {
        if (session->socket_fd > 0) {
            turn_send_packet(session, TURN_TYPE_CLOSE, NULL, 0);
            close(session->socket_fd);
            session->socket_fd = -1;
        }
        session->state = TURN_STATE_CLOSED;
        
        for (int i = 0; i < mgr->count - 1; i++) {
            if (strcmp(mgr->sessions[i].peer_id, peer_id) == 0) {
                memcpy(&mgr->sessions[i], &mgr->sessions[i + 1], sizeof(TURNSession));
                break;
            }
        }
        mgr->count--;
    }
    
    pthread_mutex_unlock(&mgr->mutex);
    return 0;
}

int turn_refresh_allocation(TURNManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) {
        return -1;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    if (!session || session->state != TURN_STATE_ESTABLISHED) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    /* Send keepalive to refresh allocation */
    int result = turn_send_packet(session, TURN_TYPE_KEEPALIVE, NULL, 0);
    
    pthread_mutex_unlock(&mgr->mutex);
    
    if (result == 0) {
        TLOG("Allocation refreshed for %s", peer_id);
    }
    
    return result;
}

bool turn_is_connected(TURNManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) {
        return 0;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    bool connected = session && session->state == TURN_STATE_ESTABLISHED;
    
    pthread_mutex_unlock(&mgr->mutex);
    return connected;
}

TURNState turn_get_state(TURNManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) {
        return TURN_STATE_IDLE;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    TURNState state = session ? session->state : TURN_STATE_IDLE;
    
    pthread_mutex_unlock(&mgr->mutex);
    return state;
}

int turn_get_external_address(TURNManager* mgr, const char* peer_id,
                               char* ip_out, int* port_out) {
    if (!mgr || !peer_id || !ip_out || !port_out) {
        return -1;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    if (!session || session->state != TURN_STATE_ESTABLISHED) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    strcpy(ip_out, session->external_ip);
    *port_out = session->external_port;
    
    pthread_mutex_unlock(&mgr->mutex);
    return 0;
}

static void* turn_listener_thread(void* arg) {
    TURNManager* mgr = (TURNManager*)arg;
    if (!mgr) {
        return NULL;
    }
    
    TLOG("TURN listener thread started");
    
    fd_set fds;
    int max_fd = 0;
    struct timeval tv;
    
    while (g_turn_running) {
        FD_ZERO(&fds);
        max_fd = 0;
        
        pthread_mutex_lock(&mgr->mutex);
        
        for (int i = 0; i < mgr->count; i++) {
            if (mgr->sessions[i].socket_fd > 0) {
                FD_SET(mgr->sessions[i].socket_fd, &fds);
                if (mgr->sessions[i].socket_fd > max_fd) {
                    max_fd = mgr->sessions[i].socket_fd;
                }
            }
        }
        
        pthread_mutex_unlock(&mgr->mutex);
        
        if (max_fd == 0) {
            sleep(1);
            continue;
        }
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(max_fd + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            TLOG("select error: %s", strerror(errno));
            break;
        }
        
        if (ret == 0) {
            continue;
        }
        
        pthread_mutex_lock(&mgr->mutex);
        
        for (int i = 0; i < mgr->count; i++) {
            TURNSession* session = &mgr->sessions[i];
            if (session->socket_fd > 0 && FD_ISSET(session->socket_fd, &fds)) {
                uint8_t buffer[TURN_BUFFER_SIZE];
                int n = recv(session->socket_fd, buffer, sizeof(buffer), 0);
                
                if (n <= 0) {
                    if (n < 0) {
                        TLOG("recv error for %s: %s", session->peer_id, strerror(errno));
                    } else {
                        TLOG("Connection closed for %s", session->peer_id);
                    }
                    close(session->socket_fd);
                    session->socket_fd = -1;
                    session->state = TURN_STATE_CLOSED;
                    continue;
                }
                
                if (n >= (int)sizeof(TURNPacket)) {
                    turn_process_packet(session, (const TURNPacket*)buffer, n);
                }
            }
        }
        
        pthread_mutex_unlock(&mgr->mutex);
    }
    
    TLOG("TURN listener thread stopped");
    return NULL;
}

static int turn_process_packet(TURNSession* session, const TURNPacket* packet,
                                size_t packet_len) {
    if (!session || !packet || packet_len < sizeof(TURNPacket)) {
        return -1;
    }
    
    if (packet->magic != TURN_MAGIC) {
        TLOG("Invalid packet magic: 0x%x", packet->magic);
        return -1;
    }
    
    if (packet->version != TURN_PROTOCOL_VERSION) {
        TLOG("Unsupported protocol version: %d", packet->version);
        return -1;
    }
    
    session->last_activity = time(NULL);
    
    switch (packet->type) {
        case TURN_TYPE_ALLOCATE_RESPONSE:
            TLOG("Allocation response received for %s", session->peer_id);
            session->state = TURN_STATE_ESTABLISHED;
            if (packet->payload_len >= 16) {
                memcpy(session->external_ip, packet->payload, 16);
                session->external_port = ntohs(*(uint16_t*)(packet->payload + 16));
                TLOG("External address: %s:%d", session->external_ip, session->external_port);
            }
            break;
            
        case TURN_TYPE_DATA:
            TLOG("Data received for %s (%d bytes)", session->peer_id, packet->payload_len);
            break;
            
        case TURN_TYPE_KEEPALIVE:
            TLOG("Keepalive from TURN server");
            break;
            
        case TURN_TYPE_AUTH_RESPONSE:
            TLOG("Authentication successful");
            session->state = TURN_STATE_ESTABLISHED;
            break;
            
        case TURN_TYPE_CLOSE:
            TLOG("Close from TURN server");
            session->state = TURN_STATE_CLOSED;
            break;
            
        default:
            TLOG("Unknown packet type: %d", packet->type);
            break;
    }
    
    return 0;
}

void turn_debug_print(TURNManager* mgr) {
    if (!mgr) {
        printf("TURN manager is NULL\n");
        return;
    }
    
    printf("\n=== TURN MANAGER DEBUG ===\n");
    printf("Initialized: %s\n", mgr->initialized ? "YES" : "NO");
    printf("Sessions: %d\n", mgr->count);
    printf("Servers: %d\n", mgr->server_count);
    
    for (int i = 0; i < mgr->server_count; i++) {
        TURNServerConfig* s = &mgr->servers[i];
        printf("  Server[%d]: %s (%s:%d) auth=%s\n",
               i, s->server_host, s->server_ip, s->port,
               s->use_auth ? "YES" : "NO");
    }
    
    for (int i = 0; i < mgr->count; i++) {
        TURNSession* s = &mgr->sessions[i];
        printf("  Session[%d]: %s -> state=%d fd=%d alloc=%u\n",
               i, s->peer_id, s->state, s->socket_fd, s->allocation_id);
    }
    printf("===========================\n");
}
