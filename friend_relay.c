
#include "friend_relay.h"
#include "dht_node.h"
#include "dht.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

#define RELAY_DEBUG 1

#if RELAY_DEBUG
#define RLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[RELAY] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define RLOG(fmt, ...) ((void)0)
#endif

#define RELAY_MAGIC 0x52454C59
#define RELAY_PROTOCOL_VERSION 1

typedef struct {
    uint32_t magic;
    uint8_t version;
    uint8_t type;
    uint32_t session_id;
    uint32_t sequence;
    uint32_t flags;
    uint16_t payload_len;
    uint8_t payload[];
} RelayPacket;

#define RELAY_TYPE_HANDSHAKE 1
#define RELAY_TYPE_DATA 2
#define RELAY_TYPE_KEEPALIVE 3
#define RELAY_TYPE_CLOSE 4
#define RELAY_TYPE_HANDSHAKE_RESPONSE 5

static RelayManager* g_relay_mgr = NULL;
static pthread_t g_relay_thread = 0;
static bool g_relay_running = 0;

static int relay_send_packet(RelaySession* session, uint8_t type, 
                              const uint8_t* payload, size_t payload_len);
static void* relay_listener_thread(void* arg);
static int relay_process_packet(RelaySession* session, const RelayPacket* packet, 
                                 size_t packet_len);

int relay_manager_init(RelayManager* mgr) {
    if (!mgr) {
        return -1;
    }
    
    memset(mgr, 0, sizeof(RelayManager));
    mgr->count = 0;
    mgr->initialized = 1;
    
    if (pthread_mutex_init(&mgr->mutex, NULL) != 0) {
        RLOG("Failed to initialize relay mutex");
        return -1;
    }
    
    RLOG("Relay manager initialized");
    return 0;
}

void relay_manager_cleanup(RelayManager* mgr) {
    if (!mgr || !mgr->initialized) {
        return;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    for (int i = 0; i < mgr->count; i++) {
        if (mgr->sessions[i].socket_fd > 0) {
            close(mgr->sessions[i].socket_fd);
        }
    }
    
    mgr->count = 0;
    mgr->initialized = 0;
    
    pthread_mutex_unlock(&mgr->mutex);
    pthread_mutex_destroy(&mgr->mutex);
    
    RLOG("Relay manager cleaned up");
}

static RelaySession* relay_find_session(RelayManager* mgr, const char* peer_id) {
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

static RelaySession* relay_add_session(RelayManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) {
        return NULL;
    }
    
    if (mgr->count >= RELAY_MAX_PEERS) {
        RLOG("Relay session limit reached");
        return NULL;
    }
    
    RelaySession* session = &mgr->sessions[mgr->count++];
    memset(session, 0, sizeof(RelaySession));
    strcpy(session->peer_id, peer_id);
    session->state = RELAY_STATE_IDLE;
    session->socket_fd = -1;
    session->created_at = time(NULL);
    session->last_activity = time(NULL);
    session->session_id = (uint32_t)(time(NULL) ^ getpid() ^ rand());
    
    RLOG("Added relay session for %s (ID: %u)", peer_id, session->session_id);
    return session;
}

static int relay_create_connection(const char* relay_ip, int relay_port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        RLOG("Failed to create relay socket: %s", strerror(errno));
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
    addr.sin_port = htons(relay_port);
    inet_pton(AF_INET, relay_ip, &addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        RLOG("Failed to connect to relay %s:%d: %s", relay_ip, relay_port, strerror(errno));
        close(sock);
        return -1;
    }
    
    RLOG("Connected to relay %s:%d", relay_ip, relay_port);
    return sock;
}

int relay_connect(RelayManager* mgr, const char* peer_id, const char* relay_id,
                  const char* relay_ip, int relay_port) {
    if (!mgr || !peer_id || !relay_ip || relay_port <= 0) {
        return -1;
    }
    
    RLOG("Relay connect to %s via %s:%d", peer_id, relay_ip, relay_port);
    
    pthread_mutex_lock(&mgr->mutex);
    
    RelaySession* session = relay_find_session(mgr, peer_id);
    if (!session) {
        session = relay_add_session(mgr, peer_id);
        if (!session) {
            pthread_mutex_unlock(&mgr->mutex);
            return -1;
        }
    }
    
    if (session->state == RELAY_STATE_ESTABLISHED) {
        RLOG("Already connected to %s via relay", peer_id);
        pthread_mutex_unlock(&mgr->mutex);
        return 0;
    }
    
    session->state = RELAY_STATE_CONNECTING;
    if (relay_id) {
        strcpy(session->relay_id, relay_id);
    }
    
    pthread_mutex_unlock(&mgr->mutex);
    
    int sock = relay_create_connection(relay_ip, relay_port);
    if (sock < 0) {
        pthread_mutex_lock(&mgr->mutex);
        session->state = RELAY_STATE_IDLE;
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    session->socket_fd = sock;
    session->is_initiator = 1;
    
    uint8_t handshake[64];
    memset(handshake, 0, sizeof(handshake));
    snprintf((char*)handshake, sizeof(handshake), "RELAY_HANDSHAKE:%s:%u", 
             peer_id, session->session_id);
    
    ssize_t sent = send(sock, handshake, strlen((char*)handshake), 0);
    if (sent < 0) {
        RLOG("Failed to send handshake: %s", strerror(errno));
        close(sock);
        session->socket_fd = -1;
        session->state = RELAY_STATE_IDLE;
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    char buffer[256];
    int n = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (n <= 0) {
        RLOG("Failed to receive handshake response");
        close(sock);
        session->socket_fd = -1;
        session->state = RELAY_STATE_IDLE;
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    buffer[n] = '\0';
    if (strstr(buffer, "RELAY_HANDSHAKE_OK") == NULL) {
        RLOG("Invalid handshake response: %s", buffer);
        close(sock);
        session->socket_fd = -1;
        session->state = RELAY_STATE_IDLE;
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    session->state = RELAY_STATE_ESTABLISHED;
    session->last_activity = time(NULL);
    
    pthread_mutex_unlock(&mgr->mutex);
    
    RLOG("Relay connection established to %s", peer_id);
    return 0;
}

int relay_accept(RelayManager* mgr, const char* peer_id, const char* relay_id) {
    if (!mgr || !peer_id) {
        return -1;
    }
    
    RLOG("Accepting relay connection from %s", peer_id);
    
    pthread_mutex_lock(&mgr->mutex);
    
    RelaySession* session = relay_find_session(mgr, peer_id);
    if (!session) {
        session = relay_add_session(mgr, peer_id);
        if (!session) {
            pthread_mutex_unlock(&mgr->mutex);
            return -1;
        }
    }
    
    if (relay_id) {
        strcpy(session->relay_id, relay_id);
    }
    
    session->state = RELAY_STATE_ESTABLISHED;
    session->is_initiator = 0;
    session->last_activity = time(NULL);
    session->socket_fd = -1;
    
    pthread_mutex_unlock(&mgr->mutex);
    
    RLOG("Relay connection accepted for %s", peer_id);
    return 0;
}

int relay_send(RelayManager* mgr, const char* peer_id, const uint8_t* data, size_t len) {
    if (!mgr || !peer_id || !data || len == 0) {
        return -1;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    RelaySession* session = relay_find_session(mgr, peer_id);
    if (!session || session->state != RELAY_STATE_ESTABLISHED) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    if (session->socket_fd < 0) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    int result = relay_send_packet(session, RELAY_TYPE_DATA, data, len);
    
    pthread_mutex_unlock(&mgr->mutex);
    return result;
}

static int relay_send_packet(RelaySession* session, uint8_t type, 
                              const uint8_t* payload, size_t payload_len) {
    if (!session || session->socket_fd < 0) {
        return -1;
    }
    
    size_t packet_size = sizeof(RelayPacket) + payload_len;
    uint8_t* buffer = (uint8_t*)malloc(packet_size);
    if (!buffer) {
        return -1;
    }
    
    RelayPacket* packet = (RelayPacket*)buffer;
    packet->magic = RELAY_MAGIC;
    packet->version = RELAY_PROTOCOL_VERSION;
    packet->type = type;
    packet->session_id = session->session_id;
    packet->sequence = session->last_activity;
    packet->flags = 0;
    packet->payload_len = (uint16_t)payload_len;
    
    if (payload && payload_len > 0) {
        memcpy(packet->payload, payload, payload_len);
    }
    
    ssize_t sent = send(session->socket_fd, buffer, packet_size, 0);
    free(buffer);
    
    if (sent < 0) {
        RLOG("Failed to send packet: %s", strerror(errno));
        return -1;
    }
    
    session->last_activity = time(NULL);
    return 0;
}

int relay_recv(RelayManager* mgr, const char* peer_id, uint8_t* buffer, size_t max_len) {
    if (!mgr || !peer_id || !buffer || max_len == 0) {
        return -1;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    RelaySession* session = relay_find_session(mgr, peer_id);
    if (!session || session->state != RELAY_STATE_ESTABLISHED) {
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

int relay_disconnect(RelayManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) {
        return -1;
    }
    
    RLOG("Disconnecting relay for %s", peer_id);
    
    pthread_mutex_lock(&mgr->mutex);
    
    RelaySession* session = relay_find_session(mgr, peer_id);
    if (session) {
        if (session->socket_fd > 0) {
            relay_send_packet(session, RELAY_TYPE_CLOSE, NULL, 0);
            close(session->socket_fd);
            session->socket_fd = -1;
        }
        session->state = RELAY_STATE_CLOSED;
        
        for (int i = 0; i < mgr->count - 1; i++) {
            if (strcmp(mgr->sessions[i].peer_id, peer_id) == 0) {
                memcpy(&mgr->sessions[i], &mgr->sessions[i + 1], sizeof(RelaySession));
                break;
            }
        }
        mgr->count--;
    }
    
    pthread_mutex_unlock(&mgr->mutex);
    return 0;
}

int relay_discover_peers(RelayManager* mgr, const char* my_id, char relay_ids[][64], int max) {
    if (!mgr || !my_id || !relay_ids || max <= 0) {
        return 0;
    }
    
    RLOG("Discovering relay peers for %s", my_id);
    
    /* Query DHT for relay nodes */
    unsigned char dht_id[20];
    dht_hash(dht_id, 20, "relay", 5, NULL, 0, NULL, 0);
    
    /* Use DHT to find relay nodes */
    /* This is a simplified version - real implementation would use DHT search */
    
    int found = 0;
    
    /* Add some known relays (for testing) */
    if (found < max) {
        strcpy(relay_ids[found++], "relay.example.com:9000");
    }
    
    RLOG("Found %d relay peers", found);
    return found;
}

int relay_announce(RelayManager* mgr, const char* my_id, int port) {
    if (!mgr || !my_id || port <= 0) {
        return -1;
    }
    
    RLOG("Announcing relay service for %s on port %d", my_id, port);
    
    /* Announce to DHT that we are a relay */
    unsigned char dht_id[20];
    dht_hash(dht_id, 20, "relay", 5, NULL, 0, NULL, 0);
    
    /* Store our relay info in DHT */
    /* This is simplified - real implementation would store in DHT */
    
    RLOG("Relay announcement complete");
    return 0;
}

bool relay_is_connected(RelayManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) {
        return 0;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    RelaySession* session = relay_find_session(mgr, peer_id);
    bool connected = session && session->state == RELAY_STATE_ESTABLISHED;
    
    pthread_mutex_unlock(&mgr->mutex);
    return connected;
}

RelayState relay_get_state(RelayManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) {
        return RELAY_STATE_IDLE;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    RelaySession* session = relay_find_session(mgr, peer_id);
    RelayState state = session ? session->state : RELAY_STATE_IDLE;
    
    pthread_mutex_unlock(&mgr->mutex);
    return state;
}

int relay_get_peer_count(RelayManager* mgr) {
    if (!mgr) {
        return 0;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    int count = mgr->count;
    pthread_mutex_unlock(&mgr->mutex);
    
    return count;
}

static void* relay_listener_thread(void* arg) {
    RelayManager* mgr = (RelayManager*)arg;
    if (!mgr) {
        return NULL;
    }
    
    RLOG("Relay listener thread started");
    
    fd_set fds;
    int max_fd = 0;
    struct timeval tv;
    
    while (g_relay_running) {
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
            RLOG("select error: %s", strerror(errno));
            break;
        }
        
        if (ret == 0) {
            continue;
        }
        
        pthread_mutex_lock(&mgr->mutex);
        
        for (int i = 0; i < mgr->count; i++) {
            RelaySession* session = &mgr->sessions[i];
            if (session->socket_fd > 0 && FD_ISSET(session->socket_fd, &fds)) {
                uint8_t buffer[RELAY_BUFFER_SIZE];
                int n = recv(session->socket_fd, buffer, sizeof(buffer), 0);
                
                if (n <= 0) {
                    if (n < 0) {
                        RLOG("recv error for %s: %s", session->peer_id, strerror(errno));
                    } else {
                        RLOG("Connection closed for %s", session->peer_id);
                    }
                    close(session->socket_fd);
                    session->socket_fd = -1;
                    session->state = RELAY_STATE_CLOSED;
                    continue;
                }
                
                /* Process packet */
                if (n >= (int)sizeof(RelayPacket)) {
                    relay_process_packet(session, (const RelayPacket*)buffer, n);
                }
            }
        }
        
        pthread_mutex_unlock(&mgr->mutex);
    }
    
    RLOG("Relay listener thread stopped");
    return NULL;
}

static int relay_process_packet(RelaySession* session, const RelayPacket* packet, 
                                 size_t packet_len) {
    if (!session || !packet || packet_len < sizeof(RelayPacket)) {
        return -1;
    }
    
    if (packet->magic != RELAY_MAGIC) {
        RLOG("Invalid packet magic: 0x%x", packet->magic);
        return -1;
    }
    
    if (packet->version != RELAY_PROTOCOL_VERSION) {
        RLOG("Unsupported protocol version: %d", packet->version);
        return -1;
    }
    
    session->last_activity = time(NULL);
    
    switch (packet->type) {
        case RELAY_TYPE_HANDSHAKE:
            RLOG("Received handshake from %s", session->peer_id);
            relay_send_packet(session, RELAY_TYPE_HANDSHAKE_RESPONSE, NULL, 0);
            break;
            
        case RELAY_TYPE_DATA:
            RLOG("Received data from %s (%d bytes)", session->peer_id, packet->payload_len);
            /* Data would be delivered to application layer */
            break;
            
        case RELAY_TYPE_KEEPALIVE:
            RLOG("Keepalive from %s", session->peer_id);
            break;
            
        case RELAY_TYPE_CLOSE:
            RLOG("Close from %s", session->peer_id);
            session->state = RELAY_STATE_CLOSED;
            break;
            
        default:
            RLOG("Unknown packet type: %d", packet->type);
            break;
    }
    
    return 0;
}

void relay_debug_print(RelayManager* mgr) {
    if (!mgr) {
        printf("Relay manager is NULL\n");
        return;
    }
    
    printf("\n=== RELAY MANAGER DEBUG ===\n");
    printf("Initialized: %s\n", mgr->initialized ? "YES" : "NO");
    printf("Sessions: %d\n", mgr->count);
    
    for (int i = 0; i < mgr->count; i++) {
        RelaySession* s = &mgr->sessions[i];
        printf("  [%d] %s -> %s | state=%d | fd=%d | session_id=%u\n",
               i, s->peer_id, s->relay_id, s->state, s->socket_fd, s->session_id);
    }
    printf("============================\n");
}
