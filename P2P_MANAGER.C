#include "p2p_manager.h"
#include "dht_node.h"
#include "state_manager.h"
#include "event_loop.h"
#include "orca_crypto.h"
#include "ecdh.h"
#include "aes_gcm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <pthread.h>
#include <time.h>

#define P2P_DEBUG 1

#if P2P_DEBUG
#define PLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[P2P] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define PLOG(fmt, ...) ((void)0)
#endif

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================ */

static int g_p2p_socket = -1;
static P2PPeer g_peers[P2P_MAX_PEERS];
static int g_peer_count = 0;
static pthread_mutex_t g_p2p_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_initialized = false;

/* ============================================================================
 * UTILITY
 * ============================================================================ */

static void normalize_id(const char* input, char* output, size_t size) {
    if (!input || !output || size == 0) return;
    
    size_t i = 0, j = 0;
    size_t len = strlen(input);
    
    for (i = 0; i < len && j < size - 1; i++) {
        if (input[i] != '<' && input[i] != '>') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

static P2PPeer* find_peer(const char* id) {
    char norm_id[64];
    normalize_id(id, norm_id, sizeof(norm_id));
    
    for (int i = 0; i < g_peer_count; i++) {
        char peer_norm[64];
        normalize_id(g_peers[i].id, peer_norm, sizeof(peer_norm));
        if (strcmp(peer_norm, norm_id) == 0) {
            return &g_peers[i];
        }
    }
    return NULL;
}

/* ============================================================================
 * INIT / CLEANUP
 * ============================================================================ */

int p2p_init(void) {
    if (g_initialized) return 0;
    
    PLOG("Initializing P2P manager");
    
    g_p2p_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_p2p_socket < 0) {
        PLOG("Failed to create UDP socket: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    setsockopt(g_p2p_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(P2P_PORT);
    
    if (bind(g_p2p_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        PLOG("Failed to bind UDP socket: %s", strerror(errno));
        close(g_p2p_socket);
        g_p2p_socket = -1;
        return -1;
    }
    
    g_initialized = true;
    PLOG("P2P initialized on port %d", P2P_PORT);
    
    return 0;
}

void p2p_cleanup(void) {
    if (!g_initialized) return;
    
    PLOG("Cleaning up P2P manager");
    
    if (g_p2p_socket >= 0) {
        close(g_p2p_socket);
        g_p2p_socket = -1;
    }
    
    g_peer_count = 0;
    g_initialized = false;
}

/* ============================================================================
 * P2P CONNECTION
 * ============================================================================ */

int p2p_connect(const char* peer_id) {
    if (!g_initialized) {
        PLOG("P2P not initialized");
        return -1;
    }
    
    char norm_id[64];
    normalize_id(peer_id, norm_id, sizeof(norm_id));
    
    PLOG("Connecting to peer %s", norm_id);
    
    /* Check if already connected */
    P2PPeer* existing = find_peer(norm_id);
    if (existing && existing->state >= P2P_STATE_HANDSHAKE) {
        PLOG("Already connected to %s", norm_id);
        return 0;
    }
    
    /* Lookup peer in DHT */
    char ip[INET_ADDRSTRLEN];
    int port;
    
    /* TODO: Call DHT lookup */
    /* For now, use placeholder */
    strcpy(ip, "127.0.0.1");
    port = P2P_PORT;
    
    /* Create peer entry */
    pthread_mutex_lock(&g_p2p_mutex);
    
    if (g_peer_count >= P2P_MAX_PEERS) {
        pthread_mutex_unlock(&g_p2p_mutex);
        return -1;
    }
    
    P2PPeer* peer = NULL;
    
    /* Find existing or create new */
    for (int i = 0; i < g_peer_count; i++) {
        char peer_norm[64];
        normalize_id(g_peers[i].id, peer_norm, sizeof(peer_norm));
        if (strcmp(peer_norm, norm_id) == 0) {
            peer = &g_peers[i];
            break;
        }
    }
    
    if (!peer) {
        peer = &g_peers[g_peer_count++];
        strcpy(peer->id, norm_id);
    }
    
    strcpy(peer->ip, ip);
    peer->port = port;
    peer->state = P2P_STATE_CONNECTING;
    peer->is_initiator = true;
    peer->last_activity = time(NULL);
    
    memset(&peer->addr, 0, sizeof(peer->addr));
    peer->addr.sin_family = AF_INET;
    peer->addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &peer->addr.sin_addr);
    
    pthread_mutex_unlock(&g_p2p_mutex);
    
    /* Start hole punching */
    PLOG("Starting hole punch to %s at %s:%d", norm_id, ip, port);
    p2p_hole_punch(ip, port);
    
    /* TODO: ECDH handshake */
    
    peer->state = P2P_STATE_ESTABLISHED;
    PLOG("Connected to %s", norm_id);
    
    return 0;
}

int p2p_accept(const char* peer_id) {
    char norm_id[64];
    normalize_id(peer_id, norm_id, sizeof(norm_id));
    
    PLOG("Accepting connection from %s", norm_id);
    
    /* Update state */
    pthread_mutex_lock(&g_p2p_mutex);
    
    P2PPeer* peer = find_peer(norm_id);
    if (peer) {
        peer->state = P2P_STATE_ESTABLISHED;
        peer->is_secure = true;
        peer->last_activity = time(NULL);
    }
    
    pthread_mutex_unlock(&g_p2p_mutex);
    
    /* Trigger event */
    Event event = event_create(EVENT_ACCEPT_CONFIRM, norm_id);
    event_queue_push(&event);
    
    return 0;
}

int p2p_disconnect(const char* peer_id) {
    char norm_id[64];
    normalize_id(peer_id, norm_id, sizeof(norm_id));
    
    PLOG("Disconnecting from %s", norm_id);
    
    pthread_mutex_lock(&g_p2p_mutex);
    
    for (int i = 0; i < g_peer_count; i++) {
        char peer_norm[64];
        normalize_id(g_peers[i].id, peer_norm, sizeof(peer_norm));
        if (strcmp(peer_norm, norm_id) == 0) {
            g_peers[i].state = P2P_STATE_DISCONNECTED;
            g_peers[i].is_secure = false;
            break;
        }
    }
    
    pthread_mutex_unlock(&g_p2p_mutex);
    
    return 0;
}

/* ============================================================================
 * P2P MESSAGING
 * ============================================================================ */

int p2p_send(const char* peer_id, const char* message) {
    if (!peer_id || !message) return -1;
    
    char norm_id[64];
    normalize_id(peer_id, norm_id, sizeof(norm_id));
    
    P2PPeer* peer = find_peer(norm_id);
    if (!peer) {
        PLOG("Peer %s not found", norm_id);
        return -1;
    }
    
    if (peer->state != P2P_STATE_ESTABLISHED) {
        PLOG("Peer %s not connected", norm_id);
        return -1;
    }
    
    /* Send via UDP */
    ssize_t sent = sendto(g_p2p_socket, message, strlen(message), 0,
                          (struct sockaddr*)&peer->addr, sizeof(peer->addr));
    
    if (sent < 0) {
        PLOG("Failed to send to %s: %s", norm_id, strerror(errno));
        return -1;
    }
    
    peer->last_activity = time(NULL);
    PLOG("Sent %zd bytes to %s", sent, norm_id);
    
    return 0;
}

int p2p_recv(const char* peer_id, char* message, int max_len) {
    if (!peer_id || !message || max_len <= 0) return -1;
    
    char norm_id[64];
    normalize_id(peer_id, norm_id, sizeof(norm_id));
    
    P2PPeer* peer = find_peer(norm_id);
    if (!peer) {
        return -1;
    }
    
    if (peer->state != P2P_STATE_ESTABLISHED) {
        return -1;
    }
    
    /* Non-blocking receive */
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    
    int n = recvfrom(g_p2p_socket, message, max_len - 1, MSG_DONTWAIT,
                     (struct sockaddr*)&from, &from_len);
    
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;  /* No data */
        }
        return -1;
    }
    
    message[n] = '\0';
    peer->last_activity = time(NULL);
    
    return n;
}

/* ============================================================================
 * P2P HOLE PUNCHING
 * ============================================================================ */

int p2p_hole_punch(const char* ip, int port) {
    if (!ip || port <= 0) return -1;
    
    PLOG("Hole punching to %s:%d", ip, port);
    
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target.sin_addr);
    
    /* Send multiple punch packets */
    const char* punch_msg = "ORCA_PUNCH";
    
    for (int i = 0; i < 10; i++) {
        sendto(g_p2p_socket, punch_msg, strlen(punch_msg), 0,
               (struct sockaddr*)&target, sizeof(target));
        usleep(10000);  /* 10ms */
    }
    
    /* Listen for response */
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    char buffer[256];
    
    /* Set timeout */
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(g_p2p_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    int n = recvfrom(g_p2p_socket, buffer, sizeof(buffer) - 1, 0,
                     (struct sockaddr*)&from, &from_len);
    
    /* Reset timeout */
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(g_p2p_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    if (n > 0) {
        buffer[n] = '\0';
        PLOG("Punch response from %s:%d", ip, ntohs(from.sin_port));
        return 0;
    }
    
    PLOG("No punch response from %s:%d", ip, port);
    return -1;
}

int p2p_punch_listen(char* ip_out, int* port_out) {
    if (!ip_out || !port_out) return -1;
    
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    char buffer[256];
    
    int n = recvfrom(g_p2p_socket, buffer, sizeof(buffer) - 1, 0,
                     (struct sockaddr*)&from, &from_len);
    
    if (n < 0) {
        return -1;
    }
    
    buffer[n] = '\0';
    
    if (strcmp(buffer, "ORCA_PUNCH") == 0) {
        inet_ntop(AF_INET, &from.sin_addr, ip_out, INET_ADDRSTRLEN);
        *port_out = ntohs(from.sin_port);
        PLOG("Received punch from %s:%d", ip_out, *port_out);
        return 0;
    }
    
    return -1;
}

/* ============================================================================
 * P2P STATUS
 * ============================================================================ */

bool p2p_is_connected(const char* peer_id) {
    P2PPeer* peer = find_peer(peer_id);
    return peer && peer->state == P2P_STATE_ESTABLISHED;
}

bool p2p_is_secure(const char* peer_id) {
    P2PPeer* peer = find_peer(peer_id);
    return peer && peer->is_secure;
}

P2PState p2p_get_state(const char* peer_id) {
    P2PPeer* peer = find_peer(peer_id);
    return peer ? peer->state : P2P_STATE_DISCONNECTED;
}

/* ============================================================================
 * P2P BACKGROUND LISTENER
 * ============================================================================ */

static void* p2p_listener_thread(void* arg) {
    (void)arg;
    
    PLOG("Listener thread started");
    
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    char buffer[P2P_BUFFER_SIZE];
    fd_set fds;
    struct timeval tv;
    
    while (g_initialized) {
        FD_ZERO(&fds);
        FD_SET(g_p2p_socket, &fds);
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(g_p2p_socket + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            PLOG("select() error: %s", strerror(errno));
            break;
        }
        
        if (ret == 0) continue;
        
        int n = recvfrom(g_p2p_socket, buffer, sizeof(buffer) - 1, 0,
                         (struct sockaddr*)&from, &from_len);
        
        if (n <= 0) continue;
        buffer[n] = '\0';
        
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
        int port = ntohs(from.sin_port);
        
        PLOG("Received %d bytes from %s:%d", n, ip, port);
        
        /* Check if this is a known peer */
        pthread_mutex_lock(&g_p2p_mutex);
        
        int found = -1;
        for (int i = 0; i < g_peer_count; i++) {
            if (strcmp(g_peers[i].ip, ip) == 0 && g_peers[i].port == port) {
                found = i;
                break;
            }
        }
        
        if (found < 0) {
            /* Unknown peer - could be new connection */
            PLOG("Unknown peer %s:%d", ip, port);
            
            /* Check if this is a punch packet */
            if (strcmp(buffer, "ORCA_PUNCH") == 0) {
                PLOG("Punch from %s:%d", ip, port);
                /* Respond to punch */
                sendto(g_p2p_socket, "ORCA_PUNCH_RESPONSE", 18, 0,
                       (struct sockaddr*)&from, from_len);
            }
        } else {
            /* Known peer - process message */
            P2PPeer* peer = &g_peers[found];
            
            if (strcmp(buffer, "ORCA_PUNCH") == 0) {
                /* Respond to punch */
                sendto(g_p2p_socket, "ORCA_PUNCH_RESPONSE", 18, 0,
                       (struct sockaddr*)&from, from_len);
            } else {
                /* Regular message */
                Event event = event_create(EVENT_MESSAGE_RECEIVED, peer->id);
                strcpy(event.from_id, peer->id);
                strcpy(event.message, buffer);
                event_queue_push(&event);
            }
            
            peer->last_activity = time(NULL);
        }
        
        pthread_mutex_unlock(&g_p2p_mutex);
    }
    
    PLOG("Listener thread stopped");
    return NULL;
}

/* ============================================================================
 * P2P DEBUG
 * ============================================================================ */

void p2p_debug_print(void) {
    printf("\n=== P2P MANAGER DEBUG ===\n");
    printf("Socket: %d\n", g_p2p_socket);
    printf("Peers: %d\n", g_peer_count);
    for (int i = 0; i < g_peer_count; i++) {
        P2PPeer* p = &g_peers[i];
        printf("  [%d] %s | state=%d | ip=%s:%d | secure=%d\n",
               i, p->id, p->state, p->ip, p->port, p->is_secure);
    }
    printf("==========================\n");
}
