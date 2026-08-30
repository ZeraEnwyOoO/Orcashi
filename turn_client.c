 #include "turn_client.h"
#include "orca_crypto.h"
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

#define TURN_MAGIC_COOKIE 0x2112A442
#define TURN_STUN_HEADER_SIZE 20

typedef enum {
    TURN_MSG_ALLOCATE_REQUEST = 0x0003,
    TURN_MSG_ALLOCATE_RESPONSE = 0x0103,
    TURN_MSG_ALLOCATE_ERROR = 0x0113,
    TURN_MSG_REFRESH_REQUEST = 0x0004,
    TURN_MSG_REFRESH_RESPONSE = 0x0104,
    TURN_MSG_SEND_INDICATION = 0x0016,
    TURN_MSG_DATA_INDICATION = 0x0017,
    TURN_MSG_CHANNEL_BIND_REQUEST = 0x0009,
    TURN_MSG_CHANNEL_BIND_RESPONSE = 0x0109,
    TURN_MSG_CHANNEL_BIND_ERROR = 0x0119
} TURNMessageType;

typedef enum {
    TURN_ATTR_MAPPED_ADDRESS = 0x0001,
    TURN_ATTR_USERNAME = 0x0006,
    TURN_ATTR_MESSAGE_INTEGRITY = 0x0008,
    TURN_ATTR_ERROR_CODE = 0x0009,
    TURN_ATTR_UNKNOWN_ATTRIBUTES = 0x000A,
    TURN_ATTR_REALM = 0x0014,
    TURN_ATTR_NONCE = 0x0015,
    TURN_ATTR_XOR_MAPPED_ADDRESS = 0x0020,
    TURN_ATTR_LIFETIME = 0x000D,
    TURN_ATTR_XOR_RELAYED_ADDRESS = 0x0016,
    TURN_ATTR_DATA = 0x0013,
    TURN_ATTR_REQUESTED_TRANSPORT = 0x0019,
    TURN_ATTR_CHANNEL_NUMBER = 0x000C,
    TURN_ATTR_XOR_PEER_ADDRESS = 0x0012,
    TURN_ATTR_EVEN_PORT = 0x0018,
    TURN_ATTR_RESERVATION_TOKEN = 0x0022
} TURNAttributeType;

typedef struct {
    uint16_t type;
    uint16_t length;
    uint8_t value[];
} __attribute__((packed)) TURNAttribute;

typedef struct {
    uint16_t type;
    uint16_t length;
    uint32_t cookie;
    uint8_t transaction_id[12];
    uint8_t attributes[];
} __attribute__((packed)) TURNMessage;

static TURNManager* g_turn_mgr = NULL;
static pthread_t g_turn_thread = 0;
static bool g_turn_running = false;

static int turn_resolve_host(const char* host, char* ip_out, size_t ip_size);
static int turn_send_message(TURNSession* session, uint16_t msg_type,
                              TURNAttribute* attrs, int attr_count,
                              const uint8_t* data, size_t data_len);
static void* turn_listener_thread(void* arg);
static int turn_process_message(TURNSession* session, const uint8_t* buffer, size_t len);
static int turn_parse_attributes(const uint8_t* data, size_t len, TURNAttribute** attrs, int* count);
static int turn_create_message_integrity(TURNSession* session, uint8_t* buffer, size_t len);
static int turn_verify_message_integrity(TURNSession* session, const uint8_t* buffer, size_t len);
static uint32_t turn_xor_ip(const uint8_t* ip, uint32_t cookie, uint32_t transaction_id);
static int turn_build_allocate_request(TURNSession* session, uint8_t* buffer, size_t* len);
static int turn_build_refresh_request(TURNSession* session, uint8_t* buffer, size_t* len);
static int turn_build_send_indication(TURNSession* session, const char* peer_ip, int peer_port,
                                       const uint8_t* data, size_t data_len,
                                       uint8_t* buffer, size_t* len);
static int turn_parse_allocate_response(TURNSession* session, const uint8_t* buffer, size_t len);

int turn_manager_init(TURNManager* mgr) {
    if (!mgr) return -1;
    
    memset(mgr, 0, sizeof(TURNManager));
    mgr->count = 0;
    mgr->server_count = 0;
    mgr->initialized = true;
    mgr->udp_socket = -1;
    
    if (pthread_mutex_init(&mgr->mutex, NULL) != 0) {
        TLOG("Failed to initialize TURN mutex");
        return -1;
    }
    
    mgr->udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (mgr->udp_socket < 0) {
        TLOG("Failed to create TURN UDP socket: %s", strerror(errno));
        pthread_mutex_destroy(&mgr->mutex);
        return -1;
    }
    
    int opt = 1;
    setsockopt(mgr->udp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = 0;
    
    if (bind(mgr->udp_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        TLOG("Failed to bind TURN socket: %s", strerror(errno));
        close(mgr->udp_socket);
        mgr->udp_socket = -1;
        pthread_mutex_destroy(&mgr->mutex);
        return -1;
    }
    
    TLOG("TURN manager initialized");
    return 0;
}

void turn_manager_cleanup(TURNManager* mgr) {
    if (!mgr || !mgr->initialized) return;
    
    g_turn_running = false;
    if (g_turn_thread) {
        pthread_join(g_turn_thread, NULL);
        g_turn_thread = 0;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    for (int i = 0; i < mgr->count; i++) {
        if (mgr->sessions[i].socket_fd > 0) {
            close(mgr->sessions[i].socket_fd);
            mgr->sessions[i].socket_fd = -1;
        }
    }
    mgr->count = 0;
    
    if (mgr->udp_socket >= 0) {
        close(mgr->udp_socket);
        mgr->udp_socket = -1;
    }
    
    mgr->initialized = false;
    
    pthread_mutex_unlock(&mgr->mutex);
    pthread_mutex_destroy(&mgr->mutex);
    
    TLOG("TURN manager cleaned up");
}

int turn_manager_add_server(TURNManager* mgr, const char* host, int port,
                             const char* username, const char* password) {
    if (!mgr || !host || mgr->server_count >= TURN_SERVER_MAX) return -1;
    
    TURNServerConfig* server = &mgr->servers[mgr->server_count++];
    strncpy(server->server_host, host, sizeof(server->server_host) - 1);
    server->server_host[sizeof(server->server_host) - 1] = '\0';
    server->port = port > 0 ? port : TURN_DEFAULT_PORT;
    server->lifetime = 3600;
    
    if (username) {
        strncpy(server->username, username, sizeof(server->username) - 1);
        server->username[sizeof(server->username) - 1] = '\0';
        server->use_auth = true;
    }
    if (password) {
        strncpy(server->password, password, sizeof(server->password) - 1);
        server->password[sizeof(server->password) - 1] = '\0';
        server->use_auth = true;
    }
    
    if (turn_resolve_host(host, server->server_ip, sizeof(server->server_ip)) < 0) {
        TLOG("Failed to resolve TURN server: %s", host);
        mgr->server_count--;
        return -1;
    }
    
    TLOG("Added TURN server: %s (%s:%d)", host, server->server_ip, server->port);
    return 0;
}

int turn_manager_set_server_lifetime(TURNManager* mgr, const char* host, uint32_t lifetime) {
    if (!mgr || !host) return -1;
    
    for (int i = 0; i < mgr->server_count; i++) {
        if (strcmp(mgr->servers[i].server_host, host) == 0) {
            mgr->servers[i].lifetime = lifetime;
            TLOG("Set lifetime for %s to %u seconds", host, lifetime);
            return 0;
        }
    }
    
    return -1;
}

int turn_resolve_host(const char* host, char* ip_out, size_t ip_size) {
    struct addrinfo hints, *res, *rp;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
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

TURNSession* turn_find_session(TURNManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) return NULL;
    
    for (int i = 0; i < mgr->count; i++) {
        if (strcmp(mgr->sessions[i].peer_id, peer_id) == 0) {
            return &mgr->sessions[i];
        }
    }
    return NULL;
}

TURNSession* turn_add_session(TURNManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) return NULL;
    
    if (mgr->count >= TURN_MAX_SESSIONS) {
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
    session->allocation_id = (uint32_t)(time(NULL) ^ getpid() ^ rand());
    session->transaction_id = (uint32_t)(time(NULL) ^ getpid() ^ rand() ^ 0xDEADBEEF);
    
    TLOG("Added TURN session for %s", peer_id);
    return session;
}

int turn_connect(TURNManager* mgr, const char* peer_id, const char* server_host) {
    if (!mgr || !peer_id || !server_host) return -1;
    
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

int turn_build_allocate_request(TURNSession* session, uint8_t* buffer, size_t* len) {
    if (!session || !buffer || !len) return -1;
    
    TURNMessage* msg = (TURNMessage*)buffer;
    msg->type = htons(TURN_MSG_ALLOCATE_REQUEST);
    msg->length = 0;
    msg->cookie = htonl(TURN_MAGIC_COOKIE);
    
    orca_random_bytes(msg->transaction_id, 12);
    
    uint8_t* pos = (uint8_t*)msg->attributes;
    size_t pos_offset = 0;
    
    TURNAttribute* req_trans = (TURNAttribute*)pos;
    req_trans->type = htons(TURN_ATTR_REQUESTED_TRANSPORT);
    req_trans->length = htons(4);
    uint8_t* transport = req_trans->value;
    transport[0] = 17;
    transport[1] = 0;
    transport[2] = 0;
    transport[3] = 0;
    pos_offset += sizeof(TURNAttribute) + 4;
    pos = (uint8_t*)msg + pos_offset;
    
    TURNAttribute* lifetime = (TURNAttribute*)pos;
    lifetime->type = htons(TURN_ATTR_LIFETIME);
    lifetime->length = htons(4);
    uint32_t lifetime_val = htonl(session->server.lifetime);
    memcpy(lifetime->value, &lifetime_val, 4);
    pos_offset += sizeof(TURNAttribute) + 4;
    pos = (uint8_t*)msg + pos_offset;
    
    if (session->server.use_auth && strlen(session->server.username) > 0) {
        TURNAttribute* username_attr = (TURNAttribute*)pos;
        username_attr->type = htons(TURN_ATTR_USERNAME);
        uint16_t username_len = strlen(session->server.username);
        username_attr->length = htons(username_len);
        memcpy(username_attr->value, session->server.username, username_len);
        pos_offset += sizeof(TURNAttribute) + username_len;
        pos = (uint8_t*)msg + pos_offset;
    }
    
    size_t msg_len = sizeof(TURNMessage) + pos_offset - sizeof(TURNMessage);
    msg->length = htons(msg_len);
    
    size_t total_len = sizeof(TURNMessage) + msg_len;
    *len = total_len;
    
    return 0;
}

int turn_allocate(TURNManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) return -1;
    
    TLOG("Allocating TURN relay for %s", peer_id);
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    if (!session) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    uint8_t request[512];
    size_t request_len = 0;
    
    if (turn_build_allocate_request(session, request, &request_len) < 0) {
        pthread_mutex_unlock(&mgr->mutex);
        TLOG("Failed to build allocate request");
        return -1;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(session->server.port);
    inet_pton(AF_INET, session->server.server_ip, &server_addr.sin_addr);
    
    ssize_t sent = sendto(mgr->udp_socket, request, request_len, 0,
                          (struct sockaddr*)&server_addr, sizeof(server_addr));
    
    pthread_mutex_unlock(&mgr->mutex);
    
    if (sent < 0) {
        TLOG("Failed to send allocate request: %s", strerror(errno));
        return -1;
    }
    
    TLOG("Allocation request sent for %s (%zu bytes)", peer_id, request_len);
    
    uint8_t response[512];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(mgr->udp_socket, &fds);
    
    if (select(mgr->udp_socket + 1, &fds, NULL, NULL, &tv) > 0) {
        int n = recvfrom(mgr->udp_socket, response, sizeof(response), 0,
                         (struct sockaddr*)&from, &from_len);
        if (n > 0) {
            return turn_parse_allocate_response(session, response, n);
        }
    }
    
    TLOG("Allocation timeout for %s", peer_id);
    return -1;
}

int turn_parse_allocate_response(TURNSession* session, const uint8_t* buffer, size_t len) {
    if (!session || !buffer || len < TURN_STUN_HEADER_SIZE) {
        return -1;
    }
    
    TURNMessage* msg = (TURNMessage*)buffer;
    uint16_t msg_type = ntohs(msg->type);
    uint16_t msg_len = ntohs(msg->length);
    uint32_t cookie = ntohl(msg->cookie);
    
    if (cookie != TURN_MAGIC_COOKIE) {
        TLOG("Invalid TURN magic cookie");
        return -1;
    }
    
    if (msg_type == TURN_MSG_ALLOCATE_RESPONSE) {
        TLOG("Allocation success response received");
        
        size_t attr_offset = TURN_STUN_HEADER_SIZE;
        const uint8_t* attr_data = buffer + attr_offset;
        size_t attr_len = msg_len;
        
        while (attr_len >= 4) {
            TURNAttribute* attr = (TURNAttribute*)attr_data;
            uint16_t attr_type = ntohs(attr->type);
            uint16_t attr_length = ntohs(attr->length);
            
            if (attr_type == TURN_ATTR_XOR_RELAYED_ADDRESS && attr_length >= 8) {
                const uint8_t* addr_data = attr->value;
                uint8_t family = addr_data[1];
                
                if (family == 0x01) {
                    uint16_t port = ntohs(*(uint16_t*)(addr_data + 2));
                    uint32_t ip = *(uint32_t*)(addr_data + 4);
                    uint32_t xor_ip = ip ^ ntohl(msg->cookie);
                    
                    struct in_addr addr;
                    addr.s_addr = xor_ip;
                    inet_ntop(AF_INET, &addr, session->relay_ip, sizeof(session->relay_ip));
                    session->relay_port = port;
                    
                    TLOG("Relay address: %s:%d", session->relay_ip, session->relay_port);
                }
            }
            
            if (attr_type == TURN_ATTR_LIFETIME && attr_length >= 4) {
                uint32_t lifetime = ntohl(*(uint32_t*)attr->value);
                session->allocation_expires = time(NULL) + lifetime;
                TLOG("Allocation lifetime: %u seconds", lifetime);
            }
            
            size_t attr_size = sizeof(TURNAttribute) + attr_length;
            attr_data += attr_size;
            attr_len -= attr_size;
        }
        
        if (strlen(session->relay_ip) > 0 && session->relay_port > 0) {
            session->state = TURN_STATE_ESTABLISHED;
            session->last_activity = time(NULL);
            return 0;
        }
        
        return -1;
    }
    
    if (msg_type == TURN_MSG_ALLOCATE_ERROR) {
        TLOG("Allocation error response");
        
        size_t attr_offset = TURN_STUN_HEADER_SIZE;
        const uint8_t* attr_data = buffer + attr_offset;
        size_t attr_len = msg_len;
        
        while (attr_len >= 4) {
            TURNAttribute* attr = (TURNAttribute*)attr_data;
            uint16_t attr_type = ntohs(attr->type);
            uint16_t attr_length = ntohs(attr->length);
            
            if (attr_type == TURN_ATTR_ERROR_CODE && attr_length >= 4) {
                const uint8_t* err_data = attr->value;
                uint16_t error_code = (err_data[2] << 8) | err_data[3];
                TLOG("Error code: %d", error_code);
                
                if (attr_length > 4) {
                    const char* reason = (const char*)err_data + 4;
                    TLOG("Error reason: %s", reason);
                }
                
                if (error_code == 401 || error_code == 438) {
                    TLOG("Authentication required - need to handle nonce/realm");
                }
            }
            
            size_t attr_size = sizeof(TURNAttribute) + attr_length;
            attr_data += attr_size;
            attr_len -= attr_size;
        }
        
        return -1;
    }
    
    TLOG("Unknown TURN response type: 0x%04x", msg_type);
    return -1;
}

int turn_refresh_allocation(TURNManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) return -1;
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    if (!session || session->state != TURN_STATE_ESTABLISHED) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    uint8_t request[128];
    TURNMessage* msg = (TURNMessage*)request;
    msg->type = htons(TURN_MSG_REFRESH_REQUEST);
    msg->length = 0;
    msg->cookie = htonl(TURN_MAGIC_COOKIE);
    orca_random_bytes(msg->transaction_id, 12);
    
    uint8_t* pos = (uint8_t*)msg->attributes;
    size_t pos_offset = 0;
    
    TURNAttribute* lifetime = (TURNAttribute*)pos;
    lifetime->type = htons(TURN_ATTR_LIFETIME);
    lifetime->length = htons(4);
    uint32_t lifetime_val = htonl(session->server.lifetime);
    memcpy(lifetime->value, &lifetime_val, 4);
    pos_offset += sizeof(TURNAttribute) + 4;
    
    size_t msg_len = sizeof(TURNMessage) + pos_offset - sizeof(TURNMessage);
    msg->length = htons(msg_len);
    size_t total_len = sizeof(TURNMessage) + msg_len;
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(session->server.port);
    inet_pton(AF_INET, session->server.server_ip, &server_addr.sin_addr);
    
    ssize_t sent = sendto(mgr->udp_socket, request, total_len, 0,
                          (struct sockaddr*)&server_addr, sizeof(server_addr));
    
    pthread_mutex_unlock(&mgr->mutex);
    
    if (sent < 0) {
        TLOG("Failed to send refresh request: %s", strerror(errno));
        return -1;
    }
    
    TLOG("Allocation refreshed for %s", peer_id);
    return 0;
}

int turn_send(TURNManager* mgr, const char* peer_id, const uint8_t* data, size_t len) {
    if (!mgr || !peer_id || !data || len == 0) return -1;
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    if (!session || session->state != TURN_STATE_ESTABLISHED) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    if (strlen(session->relay_ip) == 0 || session->relay_port == 0) {
        pthread_mutex_unlock(&mgr->mutex);
        TLOG("No relay address for %s", peer_id);
        return -1;
    }
    
    uint8_t buffer[2048];
    size_t buffer_len = 0;
    
    TURNMessage* msg = (TURNMessage*)buffer;
    msg->type = htons(TURN_MSG_SEND_INDICATION);
    msg->length = 0;
    msg->cookie = htonl(TURN_MAGIC_COOKIE);
    orca_random_bytes(msg->transaction_id, 12);
    
    uint8_t* pos = (uint8_t*)msg->attributes;
    size_t pos_offset = 0;
    
    TURNAttribute* peer_addr = (TURNAttribute*)pos;
    peer_addr->type = htons(TURN_ATTR_XOR_PEER_ADDRESS);
    uint16_t peer_addr_len = 8;
    peer_addr->length = htons(peer_addr_len);
    uint8_t* peer_data = peer_addr->value;
    peer_data[0] = 0;
    peer_data[1] = 0x01;
    
    uint16_t xor_port = htons(session->port) ^ (ntohl(msg->cookie) >> 16);
    memcpy(peer_data + 2, &xor_port, 2);
    
    uint32_t ip_addr;
    inet_pton(AF_INET, session->ip, &ip_addr);
    uint32_t xor_ip = ip_addr ^ ntohl(msg->cookie);
    memcpy(peer_data + 4, &xor_ip, 4);
    
    pos_offset += sizeof(TURNAttribute) + peer_addr_len;
    pos = (uint8_t*)msg + pos_offset;
    
    TURNAttribute* data_attr = (TURNAttribute*)pos;
    data_attr->type = htons(TURN_ATTR_DATA);
    data_attr->length = htons(len);
    memcpy(data_attr->value, data, len);
    pos_offset += sizeof(TURNAttribute) + len;
    
    size_t msg_len = sizeof(TURNMessage) + pos_offset - sizeof(TURNMessage);
    msg->length = htons(msg_len);
    size_t total_len = sizeof(TURNMessage) + msg_len;
    
    struct sockaddr_in relay_addr;
    memset(&relay_addr, 0, sizeof(relay_addr));
    relay_addr.sin_family = AF_INET;
    relay_addr.sin_port = htons(session->relay_port);
    inet_pton(AF_INET, session->relay_ip, &relay_addr.sin_addr);
    
    ssize_t sent = sendto(mgr->udp_socket, buffer, total_len, 0,
                          (struct sockaddr*)&relay_addr, sizeof(relay_addr));
    
    pthread_mutex_unlock(&mgr->mutex);
    
    if (sent < 0) {
        TLOG("Failed to send via TURN to %s: %s", peer_id, strerror(errno));
        return -1;
    }
    
    session->last_activity = time(NULL);
    return 0;
}

int turn_recv(TURNManager* mgr, const char* peer_id, uint8_t* buffer, size_t max_len) {
    if (!mgr || !peer_id || !buffer || max_len == 0) return -1;
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    if (!session || session->state != TURN_STATE_ESTABLISHED) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    uint8_t recv_buffer[4096];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    
    int n = recvfrom(mgr->udp_socket, recv_buffer, sizeof(recv_buffer), MSG_DONTWAIT,
                     (struct sockaddr*)&from, &from_len);
    
    pthread_mutex_unlock(&mgr->mutex);
    
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    
    if (n < TURN_STUN_HEADER_SIZE) {
        return -1;
    }
    
    TURNMessage* msg = (TURNMessage*)recv_buffer;
    uint16_t msg_type = ntohs(msg->type);
    
    if (msg_type == TURN_MSG_DATA_INDICATION) {
        size_t attr_offset = TURN_STUN_HEADER_SIZE;
        const uint8_t* attr_data = recv_buffer + attr_offset;
        size_t attr_len = ntohs(msg->length);
        
        while (attr_len >= 4) {
            TURNAttribute* attr = (TURNAttribute*)attr_data;
            uint16_t attr_type = ntohs(attr->type);
            uint16_t attr_length = ntohs(attr->length);
            
            if (attr_type == TURN_ATTR_DATA) {
                size_t copy_len = attr_length;
                if (copy_len > max_len) copy_len = max_len;
                memcpy(buffer, attr->value, copy_len);
                session->last_activity = time(NULL);
                return (int)copy_len;
            }
            
            size_t attr_size = sizeof(TURNAttribute) + attr_length;
            attr_data += attr_size;
            attr_len -= attr_size;
        }
    }
    
    return 0;
}

int turn_disconnect(TURNManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) return -1;
    
    TLOG("Disconnecting TURN for %s", peer_id);
    
    pthread_mutex_lock(&mgr->mutex);
    
    for (int i = 0; i < mgr->count; i++) {
        if (strcmp(mgr->sessions[i].peer_id, peer_id) == 0) {
            mgr->sessions[i].state = TURN_STATE_CLOSED;
            for (int j = i; j < mgr->count - 1; j++) {
                mgr->sessions[j] = mgr->sessions[j + 1];
            }
            mgr->count--;
            break;
        }
    }
    
    pthread_mutex_unlock(&mgr->mutex);
    return 0;
}

void* turn_listener_thread(void* arg) {
    TURNManager* mgr = (TURNManager*)arg;
    if (!mgr) return NULL;
    
    TLOG("TURN listener thread started");
    
    uint8_t buffer[TURN_BUFFER_SIZE];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    fd_set fds;
    struct timeval tv;
    
    while (g_turn_running) {
        FD_ZERO(&fds);
        FD_SET(mgr->udp_socket, &fds);
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(mgr->udp_socket + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (g_turn_running) {
                TLOG("select error: %s", strerror(errno));
            }
            break;
        }
        
        if (ret == 0) continue;
        
        int n = recvfrom(mgr->udp_socket, buffer, sizeof(buffer), 0,
                         (struct sockaddr*)&from, &from_len);
        
        if (n <= 0) continue;
        
        if (n >= TURN_STUN_HEADER_SIZE) {
            TURNMessage* msg = (TURNMessage*)buffer;
            uint32_t cookie = ntohl(msg->cookie);
            
            if (cookie == TURN_MAGIC_COOKIE) {
                pthread_mutex_lock(&mgr->mutex);
                
                for (int i = 0; i < mgr->count; i++) {
                    TURNSession* session = &mgr->sessions[i];
                    if (session->state == TURN_STATE_ESTABLISHED) {
                        turn_process_message(session, buffer, n);
                    }
                }
                
                pthread_mutex_unlock(&mgr->mutex);
            }
        }
    }
    
    TLOG("TURN listener thread stopped");
    return NULL;
}

int turn_process_message(TURNSession* session, const uint8_t* buffer, size_t len) {
    if (!session || !buffer || len < TURN_STUN_HEADER_SIZE) {
        return -1;
    }
    
    TURNMessage* msg = (TURNMessage*)buffer;
    uint16_t msg_type = ntohs(msg->type);
    
    if (msg_type == TURN_MSG_DATA_INDICATION) {
        size_t attr_offset = TURN_STUN_HEADER_SIZE;
        const uint8_t* attr_data = buffer + attr_offset;
        size_t attr_len = ntohs(msg->length);
        
        while (attr_len >= 4) {
            TURNAttribute* attr = (TURNAttribute*)attr_data;
            uint16_t attr_type = ntohs(attr->type);
            uint16_t attr_length = ntohs(attr->length);
            
            if (attr_type == TURN_ATTR_DATA) {
                TLOG("TURN data received for %s (%d bytes)", session->peer_id, attr_length);
                session->last_activity = time(NULL);
                return 0;
            }
            
            size_t attr_size = sizeof(TURNAttribute) + attr_length;
            attr_data += attr_size;
            attr_len -= attr_size;
        }
    }
    
    return 0;
}

bool turn_is_connected(TURNManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) return false;
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    bool connected = session && session->state == TURN_STATE_ESTABLISHED;
    
    pthread_mutex_unlock(&mgr->mutex);
    return connected;
}

TURNState turn_get_state(TURNManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) return TURN_STATE_IDLE;
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    TURNState state = session ? session->state : TURN_STATE_IDLE;
    
    pthread_mutex_unlock(&mgr->mutex);
    return state;
}

int turn_get_external_address(TURNManager* mgr, const char* peer_id,
                               char* ip_out, int* port_out) {
    if (!mgr || !peer_id || !ip_out || !port_out) return -1;
    
    pthread_mutex_lock(&mgr->mutex);
    
    TURNSession* session = turn_find_session(mgr, peer_id);
    if (!session || session->state != TURN_STATE_ESTABLISHED) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    strcpy(ip_out, session->relay_ip);
    *port_out = session->relay_port;
    
    pthread_mutex_unlock(&mgr->mutex);
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
    printf("UDP Socket: %d\n", mgr->udp_socket);
    
    for (int i = 0; i < mgr->server_count; i++) {
        TURNServerConfig* s = &mgr->servers[i];
        printf("  Server[%d]: %s (%s:%d) auth=%s lifetime=%u\n",
               i, s->server_host, s->server_ip, s->port,
               s->use_auth ? "YES" : "NO", s->lifetime);
    }
    
    for (int i = 0; i < mgr->count; i++) {
        TURNSession* s = &mgr->sessions[i];
        printf("  Session[%d]: %s state=%d relay=%s:%d\n",
               i, s->peer_id, s->state, s->relay_ip, s->relay_port);
    }
    printf("===========================\n");
}
