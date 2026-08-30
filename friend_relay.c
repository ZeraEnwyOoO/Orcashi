 #include "friend_relay.h"
#include "dht_node.h"
#include "dht.h"
#include "orca_crypto.h"
#include "state_manager.h"
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
#define RELAY_DHT_KEY "relay_nodes"
#define RELAY_ANNOUNCE_INTERVAL 300

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

typedef enum {
    RELAY_PKT_HANDSHAKE = 1,
    RELAY_PKT_HANDSHAKE_RESPONSE = 2,
    RELAY_PKT_DATA = 3,
    RELAY_PKT_KEEPALIVE = 4,
    RELAY_PKT_CLOSE = 5,
    RELAY_PKT_ROUTE_REQUEST = 6,
    RELAY_PKT_ROUTE_RESPONSE = 7,
    RELAY_PKT_PEER_ANNOUNCE = 8,
    RELAY_PKT_PEER_DISCOVERY = 9
} RelayPacketType;

static RelayManager* g_relay_mgr = NULL;
static pthread_t g_relay_thread = 0;
static bool g_relay_running = false;
static pthread_t g_relay_announce_thread = 0;
static bool g_relay_announce_running = false;

static int relay_send_packet(RelaySession* session, uint8_t type,
                              const uint8_t* payload, size_t payload_len);
static void* relay_listener_thread(void* arg);
static void* relay_announce_thread(void* arg);
static int relay_process_packet(RelaySession* session, const RelayPacket* packet,
                                 size_t packet_len, const struct sockaddr_in* from);
static int relay_resolve_host(const char* host, char* ip_out, size_t ip_size);
static int relay_create_udp_socket(int port);
static int relay_build_route_request(RelayManager* mgr, const char* target_id,
                                      uint8_t* buffer, size_t* len);
static int relay_parse_route_response(const uint8_t* buffer, size_t len,
                                       char* relay_ip, int* relay_port, char* relay_id);
static int relay_verify_handshake(RelaySession* session, const uint8_t* payload, size_t len);
static int relay_generate_session_keys(RelaySession* session);

int relay_manager_init(RelayManager* mgr, const char* my_id, int port) {
    if (!mgr || !my_id) return -1;
    
    memset(mgr, 0, sizeof(RelayManager));
    mgr->count = 0;
    mgr->initialized = true;
    mgr->is_relay_node = false;
    mgr->relay_port = port;
    strcpy(mgr->my_id, my_id);
    mgr->relay_socket = -1;
    
    if (pthread_mutex_init(&mgr->mutex, NULL) != 0) {
        RLOG("Failed to initialize relay mutex");
        return -1;
    }
    
    mgr->relay_socket = relay_create_udp_socket(port);
    if (mgr->relay_socket < 0) {
        RLOG("Failed to create relay socket on port %d", port);
        pthread_mutex_destroy(&mgr->mutex);
        return -1;
    }
    
    g_relay_running = true;
    pthread_create(&g_relay_thread, NULL, relay_listener_thread, mgr);
    
    RLOG("Relay manager initialized for %s on port %d", my_id, port);
    return 0;
}

void relay_manager_cleanup(RelayManager* mgr) {
    if (!mgr || !mgr->initialized) return;
    
    RLOG("Cleaning up relay manager");
    
    g_relay_running = false;
    g_relay_announce_running = false;
    
    if (g_relay_thread) {
        pthread_join(g_relay_thread, NULL);
        g_relay_thread = 0;
    }
    
    if (g_relay_announce_thread) {
        pthread_join(g_relay_announce_thread, NULL);
        g_relay_announce_thread = 0;
    }
    
    pthread_mutex_lock(&mgr->mutex);
    
    for (int i = 0; i < mgr->count; i++) {
        if (mgr->sessions[i].socket_fd > 0) {
            close(mgr->sessions[i].socket_fd);
            mgr->sessions[i].socket_fd = -1;
        }
    }
    mgr->count = 0;
    
    if (mgr->relay_socket >= 0) {
        close(mgr->relay_socket);
        mgr->relay_socket = -1;
    }
    
    mgr->initialized = false;
    
    pthread_mutex_unlock(&mgr->mutex);
    pthread_mutex_destroy(&mgr->mutex);
    
    RLOG("Relay manager cleaned up");
}

int relay_manager_enable_relay(RelayManager* mgr, bool enable) {
    if (!mgr || !mgr->initialized) return -1;
    
    mgr->is_relay_node = enable;
    
    if (enable) {
        RLOG("Relay mode enabled, announcing to DHT");
        relay_announce(mgr, mgr->relay_port);
        
        if (!g_relay_announce_running) {
            g_relay_announce_running = true;
            pthread_create(&g_relay_announce_thread, NULL, relay_announce_thread, mgr);
        }
    } else {
        RLOG("Relay mode disabled");
        g_relay_announce_running = false;
        if (g_relay_announce_thread) {
            pthread_join(g_relay_announce_thread, NULL);
            g_relay_announce_thread = 0;
        }
    }
    
    return 0;
}

int relay_create_udp_socket(int port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        RLOG("Failed to create UDP socket: %s", strerror(errno));
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
        RLOG("Failed to bind relay socket: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    return sock;
}

int relay_resolve_host(const char* host, char* ip_out, size_t ip_size) {
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

RelaySession* relay_find_session(RelayManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) return NULL;
    
    for (int i = 0; i < mgr->count; i++) {
        if (strcmp(mgr->sessions[i].peer_id, peer_id) == 0) {
            return &mgr->sessions[i];
        }
    }
    return NULL;
}

RelaySession* relay_add_session(RelayManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) return NULL;
    
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
    session->hop_count = 0;
    
    RLOG("Added relay session for %s (ID: %u)", peer_id, session->session_id);
    return session;
}

int relay_connect(RelayManager* mgr, const char* peer_id, const char* relay_id,
                  const char* relay_ip, int relay_port) {
    if (!mgr || !peer_id || !relay_ip || relay_port <= 0) {
        RLOG("Invalid parameters for relay_connect");
        return -1;
    }
    
    RLOG("Relay connect to %s via %s:%d (relay: %s)", peer_id, relay_ip, relay_port, relay_id);
    
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
    strcpy(session->ip, relay_ip);
    session->port = relay_port;
    session->is_initiator = true;
    
    pthread_mutex_unlock(&mgr->mutex);
    
    uint8_t handshake[512];
    size_t handshake_len = 0;
    
    char my_id[64];
    OrcaIdentity identity;
    if (orca_identity_load(&identity, NULL) == 0) {
        strcpy(my_id, identity.id);
    } else {
        strcpy(my_id, mgr->my_id);
    }
    
    snprintf((char*)handshake, sizeof(handshake), "RELAY_HANDSHAKE:%s:%u:%s",
             peer_id, session->session_id, my_id);
    handshake_len = strlen((char*)handshake);
    
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(relay_port);
    inet_pton(AF_INET, relay_ip, &target.sin_addr);
    
    ssize_t sent = sendto(mgr->relay_socket, handshake, handshake_len, 0,
                          (struct sockaddr*)&target, sizeof(target));
    
    if (sent < 0) {
        RLOG("Failed to send handshake: %s", strerror(errno));
        pthread_mutex_lock(&mgr->mutex);
        session->state = RELAY_STATE_IDLE;
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    uint8_t buffer[512];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(mgr->relay_socket, &fds);
    
    if (select(mgr->relay_socket + 1, &fds, NULL, NULL, &tv) > 0) {
        int n = recvfrom(mgr->relay_socket, buffer, sizeof(buffer) - 1, 0,
                         (struct sockaddr*)&from, &from_len);
        
        if (n > 0) {
            buffer[n] = '\0';
            if (strstr((char*)buffer, "RELAY_HANDSHAKE_OK") != NULL) {
                pthread_mutex_lock(&mgr->mutex);
                session->state = RELAY_STATE_ESTABLISHED;
                session->last_activity = time(NULL);
                pthread_mutex_unlock(&mgr->mutex);
                
                relay_generate_session_keys(session);
                
                RLOG("Relay connection established to %s", peer_id);
                return 0;
            }
        }
    }
    
    pthread_mutex_lock(&mgr->mutex);
    session->state = RELAY_STATE_IDLE;
    pthread_mutex_unlock(&mgr->mutex);
    
    RLOG("Relay handshake timeout for %s", peer_id);
    return -1;
}

int relay_accept(RelayManager* mgr, const char* peer_id, const char* relay_id) {
    if (!mgr || !peer_id) return -1;
    
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
    session->is_initiator = false;
    session->last_activity = time(NULL);
    
    pthread_mutex_unlock(&mgr->mutex);
    
    relay_generate_session_keys(session);
    
    RLOG("Relay connection accepted for %s", peer_id);
    return 0;
}

int relay_generate_session_keys(RelaySession* session) {
    if (!session) return -1;
    
    unsigned char salt[16];
    orca_random_bytes(salt, 16);
    
    unsigned char shared_secret[32];
    orca_random_bytes(shared_secret, 32);
    
    memcpy(session->shared_secret, shared_secret, 32);
    session->is_secure = true;
    
    return 0;
}

int relay_send_packet(RelaySession* session, uint8_t type,
                       const uint8_t* payload, size_t payload_len) {
    if (!session) return -1;
    
    size_t packet_size = sizeof(RelayPacket) + payload_len;
    uint8_t* buffer = (uint8_t*)malloc(packet_size);
    if (!buffer) return -1;
    
    RelayPacket* packet = (RelayPacket*)buffer;
    packet->magic = RELAY_MAGIC;
    packet->version = RELAY_PROTOCOL_VERSION;
    packet->type = type;
    packet->session_id = session->session_id;
    packet->sequence = (uint32_t)time(NULL);
    packet->flags = 0;
    packet->payload_len = (uint16_t)payload_len;
    
    if (payload && payload_len > 0) {
        memcpy(packet->payload, payload, payload_len);
    }
    
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(session->port);
    inet_pton(AF_INET, session->ip, &target.sin_addr);
    
    int sock = session->socket_fd > 0 ? session->socket_fd : g_relay_mgr->relay_socket;
    
    ssize_t sent = sendto(sock, buffer, packet_size, 0,
                          (struct sockaddr*)&target, sizeof(target));
    free(buffer);
    
    if (sent < 0) {
        RLOG("Failed to send relay packet: %s", strerror(errno));
        return -1;
    }
    
    session->last_activity = time(NULL);
    return 0;
}

int relay_send(RelayManager* mgr, const char* peer_id, const uint8_t* data, size_t len) {
    if (!mgr || !peer_id || !data || len == 0) return -1;
    
    pthread_mutex_lock(&mgr->mutex);
    
    RelaySession* session = relay_find_session(mgr, peer_id);
    if (!session || session->state != RELAY_STATE_ESTABLISHED) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    if (session->is_secure && session->shared_secret[0] != 0) {
        unsigned char nonce[12];
        unsigned char tag[16];
        unsigned char* ciphertext;
        size_t ciphertext_len;
        
        orca_random_bytes(nonce, 12);
        
        if (orca_aes_gcm_encrypt(data, len, session->shared_secret, nonce, tag,
                                  &ciphertext, &ciphertext_len) < 0) {
            pthread_mutex_unlock(&mgr->mutex);
            RLOG("Failed to encrypt relay data");
            return -1;
        }
        
        uint8_t* payload = (uint8_t*)malloc(12 + 16 + ciphertext_len);
        if (!payload) {
            free(ciphertext);
            pthread_mutex_unlock(&mgr->mutex);
            return -1;
        }
        
        memcpy(payload, nonce, 12);
        memcpy(payload + 12, tag, 16);
        memcpy(payload + 12 + 16, ciphertext, ciphertext_len);
        free(ciphertext);
        
        int result = relay_send_packet(session, RELAY_PKT_DATA, payload, 12 + 16 + ciphertext_len);
        free(payload);
        pthread_mutex_unlock(&mgr->mutex);
        return result;
    }
    
    int result = relay_send_packet(session, RELAY_PKT_DATA, data, len);
    pthread_mutex_unlock(&mgr->mutex);
    return result;
}

int relay_recv(RelayManager* mgr, const char* peer_id, uint8_t* buffer, size_t max_len) {
    if (!mgr || !peer_id || !buffer || max_len == 0) return -1;
    
    pthread_mutex_lock(&mgr->mutex);
    
    RelaySession* session = relay_find_session(mgr, peer_id);
    if (!session || session->state != RELAY_STATE_ESTABLISHED) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    uint8_t recv_buffer[RELAY_BUFFER_SIZE];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    
    int n = recvfrom(mgr->relay_socket, recv_buffer, sizeof(recv_buffer), MSG_DONTWAIT,
                     (struct sockaddr*)&from, &from_len);
    
    pthread_mutex_unlock(&mgr->mutex);
    
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    
    if (n < (int)sizeof(RelayPacket)) {
        return -1;
    }
    
    RelayPacket* packet = (RelayPacket*)recv_buffer;
    
    if (packet->magic != RELAY_MAGIC) {
        return -1;
    }
    
    if (packet->session_id != session->session_id) {
        return -1;
    }
    
    if (packet->type == RELAY_PKT_DATA) {
        size_t copy_len = packet->payload_len;
        if (copy_len > max_len) copy_len = max_len;
        memcpy(buffer, packet->payload, copy_len);
        session->last_activity = time(NULL);
        return (int)copy_len;
    }
    
    return 0;
}

int relay_disconnect(RelayManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) return -1;
    
    RLOG("Disconnecting relay for %s", peer_id);
    
    pthread_mutex_lock(&mgr->mutex);
    
    for (int i = 0; i < mgr->count; i++) {
        if (strcmp(mgr->sessions[i].peer_id, peer_id) == 0) {
            mgr->sessions[i].state = RELAY_STATE_CLOSED;
            if (mgr->sessions[i].socket_fd > 0) {
                close(mgr->sessions[i].socket_fd);
                mgr->sessions[i].socket_fd = -1;
            }
            
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

int relay_discover_peers(RelayManager* mgr, char relay_ids[][64], int max) {
    if (!mgr || !relay_ids || max <= 0) return 0;
    
    RLOG("Discovering relay peers");
    
    int found = 0;
    
    unsigned char dht_id[20];
    dht_hash(dht_id, 20, RELAY_DHT_KEY, strlen(RELAY_DHT_KEY), NULL, 0, NULL, 0);
    
    DHTNode* dht = dht_node_create();
    if (!dht) {
        RLOG("Failed to create DHT node for discovery");
        return 0;
    }
    
    if (dht_node_start(dht, 33446) < 0) {
        dht_node_destroy(dht);
        RLOG("Failed to start DHT for discovery");
        return 0;
    }
    
    struct sockaddr_in nodes[16];
    int num_nodes = 16;
    
    if (dht_get_nodes(nodes, &num_nodes, NULL, NULL) > 0) {
        for (int i = 0; i < num_nodes && found < max; i++) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &nodes[i].sin_addr, ip, sizeof(ip));
            int port = ntohs(nodes[i].sin_port);
            
            snprintf(relay_ids[found++], 64, "%s:%d", ip, port);
        }
    }
    
    dht_node_stop(dht);
    dht_node_destroy(dht);
    
    char static_relay[128];
    snprintf(static_relay, sizeof(static_relay), "relay.example.com:9000");
    
    if (found < max) {
        strcpy(relay_ids[found++], static_relay);
    }
    
    RLOG("Found %d relay peers", found);
    return found;
}

int relay_announce(RelayManager* mgr, int port) {
    if (!mgr) return -1;
    
    RLOG("Announcing relay service for %s on port %d", mgr->my_id, port);
    
    unsigned char dht_id[20];
    dht_hash(dht_id, 20, RELAY_DHT_KEY, strlen(RELAY_DHT_KEY), NULL, 0, NULL, 0);
    
    DHTNode* dht = dht_node_create();
    if (!dht) {
        RLOG("Failed to create DHT node for announce");
        return -1;
    }
    
    if (dht_node_start(dht, 33446) < 0) {
        dht_node_destroy(dht);
        RLOG("Failed to start DHT for announce");
        return -1;
    }
    
    char announce_data[256];
    snprintf(announce_data, sizeof(announce_data), "%s:%d", mgr->my_id, port);
    
    dht_node_announce(dht, mgr->my_id, port);
    
    dht_node_stop(dht);
    dht_node_destroy(dht);
    
    RLOG("Relay announcement complete");
    return 0;
}

void* relay_listener_thread(void* arg) {
    RelayManager* mgr = (RelayManager*)arg;
    if (!mgr) return NULL;
    
    RLOG("Relay listener thread started");
    
    uint8_t buffer[RELAY_BUFFER_SIZE];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    fd_set fds;
    struct timeval tv;
    
    while (g_relay_running) {
        FD_ZERO(&fds);
        FD_SET(mgr->relay_socket, &fds);
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(mgr->relay_socket + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (g_relay_running) {
                RLOG("select error: %s", strerror(errno));
            }
            break;
        }
        
        if (ret == 0) continue;
        
        int n = recvfrom(mgr->relay_socket, buffer, sizeof(buffer), 0,
                         (struct sockaddr*)&from, &from_len);
        
        if (n <= 0) continue;
        
        if (n >= (int)sizeof(RelayPacket)) {
            RelayPacket* packet = (RelayPacket*)buffer;
            
            if (packet->magic == RELAY_MAGIC) {
                pthread_mutex_lock(&mgr->mutex);
                
                uint32_t session_id = packet->session_id;
                RelaySession* session = NULL;
                
                for (int i = 0; i < mgr->count; i++) {
                    if (mgr->sessions[i].session_id == session_id) {
                        session = &mgr->sessions[i];
                        break;
                    }
                }
                
                if (!session && packet->type == RELAY_PKT_HANDSHAKE) {
                    char peer_id[64] = {0};
                    char from_id[64] = {0};
                    
                    char* payload = (char*)packet->payload;
                    char* token = strtok(payload, ":");
                    if (token && strcmp(token, "RELAY_HANDSHAKE") == 0) {
                        token = strtok(NULL, ":");
                        if (token) {
                            strcpy(peer_id, token);
                            token = strtok(NULL, ":");
                            if (token) {
                                uint32_t sid = atoi(token);
                                token = strtok(NULL, ":");
                                if (token) {
                                    strcpy(from_id, token);
                                    
                                    session = relay_add_session(mgr, peer_id);
                                    if (session) {
                                        session->session_id = sid;
                                        session->state = RELAY_STATE_ESTABLISHED;
                                        session->is_initiator = false;
                                        session->last_activity = time(NULL);
                                        strcpy(session->ip, inet_ntoa(from.sin_addr));
                                        session->port = ntohs(from.sin_port);
                                        
                                        relay_generate_session_keys(session);
                                        
                                        char response[128];
                                        snprintf(response, sizeof(response), "RELAY_HANDSHAKE_OK:%u", session->session_id);
                                        
                                        sendto(mgr->relay_socket, response, strlen(response), 0,
                                               (struct sockaddr*)&from, from_len);
                                        
                                        RLOG("Accepted handshake from %s (via %s:%d)",
                                             peer_id, session->ip, session->port);
                                    }
                                }
                            }
                        }
                    }
                } else if (session) {
                    relay_process_packet(session, packet, n, &from);
                }
                
                pthread_mutex_unlock(&mgr->mutex);
            } else if (strncmp((char*)buffer, "RELAY_HANDSHAKE", 15) == 0) {
                char peer_id[64] = {0};
                char from_id[64] = {0};
                uint32_t sid = 0;
                
                char* payload = (char*)buffer;
                char* token = strtok(payload, ":");
                if (token && strcmp(token, "RELAY_HANDSHAKE") == 0) {
                    token = strtok(NULL, ":");
                    if (token) {
                        strcpy(peer_id, token);
                        token = strtok(NULL, ":");
                        if (token) {
                            sid = atoi(token);
                            token = strtok(NULL, ":");
                            if (token) {
                                strcpy(from_id, token);
                                
                                pthread_mutex_lock(&mgr->mutex);
                                
                                RelaySession* session = relay_add_session(mgr, peer_id);
                                if (session) {
                                    session->session_id = sid;
                                    session->state = RELAY_STATE_ESTABLISHED;
                                    session->is_initiator = false;
                                    session->last_activity = time(NULL);
                                    strcpy(session->ip, inet_ntoa(from.sin_addr));
                                    session->port = ntohs(from.sin_port);
                                    
                                    relay_generate_session_keys(session);
                                    
                                    char response[128];
                                    snprintf(response, sizeof(response), "RELAY_HANDSHAKE_OK:%u", session->session_id);
                                    
                                    sendto(mgr->relay_socket, response, strlen(response), 0,
                                           (struct sockaddr*)&from, from_len);
                                    
                                    RLOG("Accepted handshake from %s (via %s:%d)",
                                         peer_id, session->ip, session->port);
                                }
                                
                                pthread_mutex_unlock(&mgr->mutex);
                            }
                        }
                    }
                }
            }
        }
    }
    
    RLOG("Relay listener thread stopped");
    return NULL;
}

void* relay_announce_thread(void* arg) {
    RelayManager* mgr = (RelayManager*)arg;
    if (!mgr) return NULL;
    
    RLOG("Relay announce thread started");
    
    while (g_relay_announce_running) {
        sleep(RELAY_ANNOUNCE_INTERVAL);
        
        if (!g_relay_announce_running) break;
        
        if (mgr->is_relay_node) {
            relay_announce(mgr, mgr->relay_port);
        }
    }
    
    RLOG("Relay announce thread stopped");
    return NULL;
}

int relay_process_packet(RelaySession* session, const RelayPacket* packet,
                          size_t packet_len, const struct sockaddr_in* from) {
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
        case RELAY_PKT_HANDSHAKE:
            RLOG("Handshake from %s", session->peer_id);
            break;
            
        case RELAY_PKT_HANDSHAKE_RESPONSE:
            RLOG("Handshake response from %s", session->peer_id);
            session->state = RELAY_STATE_ESTABLISHED;
            break;
            
        case RELAY_PKT_DATA:
            if (session->is_secure && session->shared_secret[0] != 0) {
                if (packet->payload_len >= 28) {
                    unsigned char nonce[12];
                    unsigned char tag[16];
                    const uint8_t* ciphertext = packet->payload + 28;
                    size_t ciphertext_len = packet->payload_len - 28;
                    
                    memcpy(nonce, packet->payload, 12);
                    memcpy(tag, packet->payload + 12, 16);
                    
                    unsigned char* plaintext;
                    size_t plaintext_len;
                    
                    if (orca_aes_gcm_decrypt(ciphertext, ciphertext_len,
                                              session->shared_secret, nonce, tag,
                                              &plaintext, &plaintext_len) == 0) {
                        RLOG("Decrypted data from %s (%zu bytes)", session->peer_id, plaintext_len);
                        free(plaintext);
                    }
                }
            } else {
                RLOG("Data from %s (%d bytes)", session->peer_id, packet->payload_len);
            }
            break;
            
        case RELAY_PKT_KEEPALIVE:
            RLOG("Keepalive from %s", session->peer_id);
            break;
            
        case RELAY_PKT_CLOSE:
            RLOG("Close from %s", session->peer_id);
            session->state = RELAY_STATE_CLOSED;
            break;
            
        default:
            RLOG("Unknown packet type: %d", packet->type);
            break;
    }
    
    return 0;
}

bool relay_is_connected(RelayManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) return false;
    
    pthread_mutex_lock(&mgr->mutex);
    
    RelaySession* session = relay_find_session(mgr, peer_id);
    bool connected = session && session->state == RELAY_STATE_ESTABLISHED;
    
    pthread_mutex_unlock(&mgr->mutex);
    return connected;
}

RelayState relay_get_state(RelayManager* mgr, const char* peer_id) {
    if (!mgr || !peer_id) return RELAY_STATE_IDLE;
    
    pthread_mutex_lock(&mgr->mutex);
    
    RelaySession* session = relay_find_session(mgr, peer_id);
    RelayState state = session ? session->state : RELAY_STATE_IDLE;
    
    pthread_mutex_unlock(&mgr->mutex);
    return state;
}

int relay_get_peer_count(RelayManager* mgr) {
    if (!mgr) return 0;
    
    pthread_mutex_lock(&mgr->mutex);
    int count = mgr->count;
    pthread_mutex_unlock(&mgr->mutex);
    return count;
}

int relay_get_relay_path(RelayManager* mgr, const char* peer_id, char path[][64], int* count) {
    if (!mgr || !peer_id || !path || !count) return -1;
    
    pthread_mutex_lock(&mgr->mutex);
    
    RelaySession* session = relay_find_session(mgr, peer_id);
    if (!session) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    *count = session->hop_count;
    for (int i = 0; i < session->hop_count && i < RELAY_MAX_PATH; i++) {
        strcpy(path[i], session->path[i]);
    }
    
    pthread_mutex_unlock(&mgr->mutex);
    return 0;
}

void relay_debug_print(RelayManager* mgr) {
    if (!mgr) {
        printf("Relay manager is NULL\n");
        return;
    }
    
    printf("\n=== RELAY MANAGER DEBUG ===\n");
    printf("Initialized: %s\n", mgr->initialized ? "YES" : "NO");
    printf("My ID: %s\n", mgr->my_id);
    printf("Relay mode: %s\n", mgr->is_relay_node ? "ENABLED" : "DISABLED");
    printf("Relay port: %d\n", mgr->relay_port);
    printf("Relay socket: %d\n", mgr->relay_socket);
    printf("Sessions: %d\n", mgr->count);
    
    for (int i = 0; i < mgr->count; i++) {
        RelaySession* s = &mgr->sessions[i];
        printf("  [%d] %s -> %s | state=%d | ip=%s:%d | secure=%d | hops=%d\n",
               i, s->peer_id, s->relay_id, s->state, s->ip, s->port,
               s->is_secure, s->hop_count);
    }
    printf("===========================\n");
}
