 #include "p2p_manager.h"
#include "dht_node.h"
#include "state_manager.h"
#include "event_loop.h"
#include "orca_crypto.h"
#include "ecdh.h"
#include "aes_gcm.h"
#include "nat_classifier.h"
#include "strategy_selector.h"
#include "parallel_runner.h"
#include "ttl_punch.h"
#include "simultaneous_open.h"
#include "friend_relay.h"
#include "turn_client.h"
#include "upnp_client.h"
#include "port_prediction.h"
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
static NATType g_nat_type = NAT_UNKNOWN;
static bool g_has_ipv6 = false;
static bool g_has_upnp = false;
static pthread_t g_listener_thread = 0;
static bool g_listener_running = false;

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

static P2PPeer* add_peer(const char* id) {
    char norm_id[64];
    normalize_id(id, norm_id, sizeof(norm_id));
    
    if (g_peer_count >= P2P_MAX_PEERS) return NULL;
    
    /* Check if exists */
    for (int i = 0; i < g_peer_count; i++) {
        char peer_norm[64];
        normalize_id(g_peers[i].id, peer_norm, sizeof(peer_norm));
        if (strcmp(peer_norm, norm_id) == 0) {
            return &g_peers[i];
        }
    }
    
    P2PPeer* peer = &g_peers[g_peer_count++];
    memset(peer, 0, sizeof(P2PPeer));
    strcpy(peer->id, norm_id);
    peer->state = P2P_STATE_DISCONNECTED;
    peer->created_at = time(NULL);
    peer->nat_type = NAT_UNKNOWN;
    
    return peer;
}

/* ============================================================================
 * INIT / CLEANUP
 * ============================================================================ */

int p2p_init(void) {
    if (g_initialized) return 0;
    
    PLOG("Initializing P2P manager");
    
    /* Create UDP socket */
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
    
    /* Detect capabilities */
    g_nat_type = p2p_detect_nat_type();
    g_has_ipv6 = p2p_has_ipv6();
    g_has_upnp = p2p_has_upnp();
    
    PLOG("NAT type: %d, IPv6: %d, UPnP: %d", g_nat_type, g_has_ipv6, g_has_upnp);
    
    g_initialized = true;
    PLOG("P2P initialized on port %d", P2P_PORT);
    
    /* Start listener thread */
    g_listener_running = true;
    pthread_create(&g_listener_thread, NULL, p2p_listener_thread, NULL);
    
    return 0;
}

void p2p_cleanup(void) {
    if (!g_initialized) return;
    
    PLOG("Cleaning up P2P manager");
    
    g_listener_running = false;
    if (g_listener_thread) {
        pthread_join(g_listener_thread, NULL);
        g_listener_thread = 0;
    }
    
    if (g_p2p_socket >= 0) {
        close(g_p2p_socket);
        g_p2p_socket = -1;
    }
    
    g_peer_count = 0;
    g_initialized = false;
}

/* ============================================================================
 * NAT DETECTION
 * ============================================================================ */

NATType p2p_detect_nat_type(void) {
    PLOG("Detecting NAT type...");
    
    /* Use DHT-based NAT detection */
    NATType type = nat_classify_via_dht(NULL);
    
    PLOG("NAT type detected: %d", type);
    return type;
}

bool p2p_has_ipv6(void) {
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(53);
    inet_pton(AF_INET6, "2001:4860:4860::8888", &addr.sin6_addr);
    
    bool has = (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    close(sock);
    
    PLOG("IPv6: %s", has ? "YES" : "NO");
    return has;
}

bool p2p_has_upnp(void) {
    bool has = upnp_detect();
    PLOG("UPnP: %s", has ? "YES" : "NO");
    return has;
}

/* ============================================================================
 * P2P CONNECTION — MULTI-CANDIDATE RACING
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
    
    /* Get peer info from DHT */
    char ip[INET_ADDRSTRLEN];
    int port;
    PeerCapability remote_cap = {0};
    
    if (!dht_node_lookup(NULL, norm_id, 10, ip, &port)) {
        PLOG("Peer %s not found in DHT", norm_id);
        return -1;
    }
    
    /* Get peer capabilities */
    p2p_get_peer_capability(norm_id, &remote_cap);
    
    PLOG("Peer %s at %s:%d, NAT: %d, IPv6: %d", 
         norm_id, ip, port, remote_cap.nat_type, remote_cap.has_ipv6);
    
    /* Create or update peer */
    P2PPeer* peer = add_peer(norm_id);
    if (!peer) {
        PLOG("Failed to add peer");
        return -1;
    }
    
    strcpy(peer->ip, ip);
    peer->port = port;
    peer->state = P2P_STATE_CONNECTING;
    peer->is_initiator = true;
    peer->last_activity = time(NULL);
    peer->nat_type = remote_cap.nat_type;
    peer->has_ipv6 = remote_cap.has_ipv6;
    if (remote_cap.has_ipv6) {
        strcpy(peer->ipv6, remote_cap.ipv6);
    }
    
    memset(&peer->addr, 0, sizeof(peer->addr));
    peer->addr.sin_family = AF_INET;
    peer->addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &peer->addr.sin_addr);
    
    /* === PHASE 1: Profile the peer === */
    PeerProfile local_profile = {
        .nat_type = g_nat_type,
        .has_ipv6 = g_has_ipv6,
        .has_upnp = g_has_upnp
    };
    
    PeerProfile remote_profile = {
        .nat_type = remote_cap.nat_type,
        .has_ipv6 = remote_cap.has_ipv6,
        .has_upnp = remote_cap.has_upnp
    };
    
    /* === PHASE 2: Filter strategies === */
    StrategyList strategies = {0};
    strategy_filter(&strategies, &local_profile, &remote_profile);
    
    PLOG("Selected %d strategies for parallel racing", strategies.count);
    for (int i = 0; i < strategies.count; i++) {
        PLOG("  Strategy %d: %s", i, strategy_name(strategies.strategies[i]));
    }
    
    /* === PHASE 3: Parallel racing === */
    ConnectionResult result = {0};
    if (parallel_run(&strategies, peer, &result) == 0) {
        PLOG("✅ Connected using strategy: %s", strategy_name(result.strategy));
        
        /* Update peer state */
        peer->state = P2P_STATE_ESTABLISHED;
        peer->is_secure = true;
        peer->last_activity = time(NULL);
        
        /* Trigger event */
        Event event = event_create(EVENT_ACCEPT_CONFIRM, norm_id);
        event_queue_push(&event);
        
        return 0;
    }
    
    PLOG("❌ All connection strategies failed for %s", norm_id);
    peer->state = P2P_STATE_DISCONNECTED;
    return -1;
}

int p2p_accept(const char* peer_id) {
    char norm_id[64];
    normalize_id(peer_id, norm_id, sizeof(norm_id));
    
    PLOG("Accepting connection from %s", norm_id);
    
    pthread_mutex_lock(&g_p2p_mutex);
    
    P2PPeer* peer = find_peer(norm_id);
    if (peer) {
        peer->state = P2P_STATE_ESTABLISHED;
        peer->is_secure = true;
        peer->last_activity = time(NULL);
    }
    
    pthread_mutex_unlock(&g_p2p_mutex);
    
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

int p2p_send_secure(const char* peer_id, const unsigned char* data, size_t len) {
    if (!peer_id || !data || len == 0) return -1;
    
    char norm_id[64];
    normalize_id(peer_id, norm_id, sizeof(norm_id));
    
    P2PPeer* peer = find_peer(norm_id);
    if (!peer || peer->state != P2P_STATE_ESTABLISHED) {
        return -1;
    }
    
    /* TODO: Implement AES-GCM encryption */
    
    return p2p_send(peer_id, (const char*)data);
}

int p2p_recv(const char* peer_id, char* message, int max_len) {
    if (!peer_id || !message || max_len <= 0) return -1;
    
    char norm_id[64];
    normalize_id(peer_id, norm_id, sizeof(norm_id));
    
    P2PPeer* peer = find_peer(norm_id);
    if (!peer || peer->state != P2P_STATE_ESTABLISHED) {
        return -1;
    }
    
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    
    int n = recvfrom(g_p2p_socket, message, max_len - 1, MSG_DONTWAIT,
                     (struct sockaddr*)&from, &from_len);
    
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
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

int p2p_hole_punch(const char* ip, int port, NATType peer_nat) {
    if (!ip || port <= 0) return -1;
    
    PLOG("Hole punching to %s:%d (peer NAT: %d)", ip, port, peer_nat);
    
    /* Use multi-strategy hole punching */
    int result = punch_multi_strategy(ip, port, g_nat_type, peer_nat);
    
    if (result == 0) {
        PLOG("Hole punch successful to %s:%d", ip, port);
    } else {
        PLOG("Hole punch failed to %s:%d", ip, port);
    }
    
    return result;
}

int p2p_punch_listen(char* ip_out, int* port_out) {
    if (!ip_out || !port_out) return -1;
    
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    char buffer[256];
    
    int n = recvfrom(g_p2p_socket, buffer, sizeof(buffer) - 1, 0,
                     (struct sockaddr*)&from, &from_len);
    
    if (n < 0) return -1;
    
    buffer[n] = '\0';
    
    if (strcmp(buffer, "ORCA_PUNCH") == 0 ||
        strcmp(buffer, "ORCA_PUNCH_RESPONSE") == 0) {
        inet_ntop(AF_INET, &from.sin_addr, ip_out, INET_ADDRSTRLEN);
        *port_out = ntohs(from.sin_port);
        PLOG("Received punch from %s:%d", ip_out, *port_out);
        return 0;
    }
    
    return -1;
}

/* ============================================================================
 * PEER CAPABILITIES
 * ============================================================================ */

int p2p_get_peer_capability(const char* peer_id, PeerCapability* cap) {
    if (!peer_id || !cap) return -1;
    
    /* TODO: Get from DHT */
    memset(cap, 0, sizeof(PeerCapability));
    strcpy(cap->id, peer_id);
    cap->nat_type = NAT_UNKNOWN;
    cap->has_ipv6 = false;
    cap->has_upnp = false;
    
    return 0;
}

int p2p_exchange_capabilities(const char* peer_id, PeerCapability* remote) {
    if (!peer_id || !remote) return -1;
    
    /* TODO: Exchange capabilities via DHT */
    return 0;
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

NATType p2p_get_nat_type(void) {
    return g_nat_type;
}

/* ============================================================================
 * P2P BACKGROUND LISTENER THREAD
 * ============================================================================ */

static void* p2p_listener_thread(void* arg) {
    (void)arg;
    
    PLOG("Listener thread started");
    
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    char buffer[P2P_BUFFER_SIZE];
    fd_set fds;
    struct timeval tv;
    
    while (g_listener_running) {
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
            if (strcmp(buffer, "ORCA_PUNCH") == 0 ||
                strcmp(buffer, "ORCA_PUNCH_RESPONSE") == 0) {
                /* Respond to punch */
                sendto(g_p2p_socket, "ORCA_PUNCH_RESPONSE", 18, 0,
                       (struct sockaddr*)&from, from_len);
            }
        } else {
            /* Known peer - process message */
            P2PPeer* peer = &g_peers[found];
            
            if (strcmp(buffer, "ORCA_PUNCH") == 0 ||
                strcmp(buffer, "ORCA_PUNCH_RESPONSE") == 0) {
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
    printf("NAT Type: %d\n", g_nat_type);
    printf("IPv6: %s\n", g_has_ipv6 ? "YES" : "NO");
    printf("UPnP: %s\n", g_has_upnp ? "YES" : "NO");
    printf("Peers: %d\n", g_peer_count);
    for (int i = 0; i < g_peer_count; i++) {
        P2PPeer* p = &g_peers[i];
        printf("  [%d] %s | state=%d | ip=%s:%d | secure=%d\n",
               i, p->id, p->state, p->ip, p->port, p->is_secure);
    }
    printf("==========================\n");
}
