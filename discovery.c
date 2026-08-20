 #define _POSIX_C_SOURCE 200809L

#include "discovery.h"
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#define DISCOVERY_BROADCAST_INTERVAL 30
#define DISCOVERY_ACK_TIMEOUT 10
#define DISCOVERY_ACCEPT_TIMEOUT 60

#define DISCOVERY_DEBUG 1

#if DISCOVERY_DEBUG
#define DLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[DISCOVERY] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define DLOG(fmt, ...) ((void)0)
#endif

/* ============================================================================
 * Static State (My Identity)
 * ============================================================================ */

static struct {
    char id[DISCOVERY_MAX_ID_LEN];
    char ip[DISCOVERY_MAX_IP_LEN];
    int port;
    bool is_secure;
    char name[DISCOVERY_MAX_NAME_LEN];
    char public_key[DISCOVERY_MAX_PUBKEY_LEN];
    char signature[DISCOVERY_MAX_SIG_LEN];
    time_t created_at;
    char role[32];
} g_my_identity = {
    .id = "",
    .ip = "",
    .port = 9000,
    .is_secure = false,
    .name = "",
    .public_key = "",
    .signature = "",
    .created_at = 0,
    .role = "user"
};

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

static void* discovery_listen_thread(void* arg);
static void* discovery_broadcast_thread(void* arg);
static void discovery_parse_packet(Discovery* disc, const char* data, 
                                   size_t data_len, const char* sender_ip,
                                   int sender_port);
static bool discovery_send_udp(Discovery* disc, const char* msg, 
                               const char* ip, int port);
static bool discovery_send_broadcast(Discovery* disc, const char* msg);
static void discovery_handle_presence(Discovery* disc, const char* data,
                                      const char* sender_ip);
static void discovery_handle_who_has(Discovery* disc, const char* data,
                                     const char* sender_ip);
static void discovery_handle_i_am(Discovery* disc, const char* data,
                                  const char* sender_ip);
static void discovery_handle_add_request(Discovery* disc, const char* data,
                                         const char* sender_ip, int sender_port);
static void discovery_handle_add_request_ack(Discovery* disc, const char* data);
static void discovery_handle_accept_confirm(Discovery* disc, const char* data);
static void discovery_handle_search(Discovery* disc, const char* data,
                                    const char* sender_ip);

/* ============================================================================
 * ID Normalization (Single Source of Truth)
 * ============================================================================ */

bool discovery_normalize_id(const char* input, char* output, size_t output_size) {
    if (!input || !output || output_size == 0) {
        return false;
    }
    
    size_t i = 0, j = 0;
    size_t len = strlen(input);
    
    /* Strip angle brackets */
    for (i = 0; i < len && j < output_size - 1; i++) {
        if (input[i] != '<' && input[i] != '>') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
    
    /* Validate: must not be empty */
    if (j == 0) {
        return false;
    }
    
    /* Validate: must contain only digits */
    for (i = 0; i < j; i++) {
        if (!isdigit((unsigned char)output[i])) {
            return false;
        }
    }
    
    return true;
}

bool discovery_is_valid_id(const char* id) {
    if (!id) return false;
    size_t len = strlen(id);
    if (len == 0 || len >= DISCOVERY_MAX_ID_LEN) return false;
    
    /* Check format: <XXX> where X are digits */
    if (len >= 3 && len <= 6) {
        size_t i = 0;
        if (id[0] == '<' && id[len - 1] == '>') {
            for (i = 1; i < len - 1; i++) {
                if (!isdigit((unsigned char)id[i])) {
                    return false;
                }
            }
            return true;
        }
    }
    
    /* Check format: ORCA-XXXXXXXX */
    if (strncmp(id, "ORCA-", 5) == 0) {
        size_t i;
        for (i = 5; i < len; i++) {
            if (!isalnum((unsigned char)id[i])) {
                return false;
            }
        }
        return true;
    }
    
    return false;
}

bool discovery_is_same_id(const char* id1, const char* id2) {
    if (!id1 || !id2) return false;
    
    char n1[DISCOVERY_MAX_ID_LEN];
    char n2[DISCOVERY_MAX_ID_LEN];
    
    if (!discovery_normalize_id(id1, n1, sizeof(n1))) return false;
    if (!discovery_normalize_id(id2, n2, sizeof(n2))) return false;
    
    return strcmp(n1, n2) == 0;
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

Discovery* discovery_create(void) {
    Discovery* disc = (Discovery*)calloc(1, sizeof(Discovery));
    if (!disc) {
        DLOG("discovery_create: calloc failed");
        return NULL;
    }
    
    disc->udp_socket = -1;
    disc->port = DISCOVERY_PORT;
    disc->running = false;
    disc->peer_count = 0;
    disc->pending_count = 0;
    disc->listen_thread_created = false;
    disc->broadcast_thread_created = false;
    disc->registry = NULL;
    disc->request_manager = NULL;
    disc->on_peer_found = NULL;
    disc->on_peer_offline = NULL;
    disc->on_accept_confirm = NULL;
    
    /* Initialize accept state */
    memset(&disc->accept_state, 0, sizeof(disc->accept_state));
    disc->accept_state.received = false;
    disc->accept_state.processed = false;
    
    /* Initialize synchronization primitives */
    if (pthread_mutex_init(&disc->mutex, NULL) != 0) {
        DLOG("discovery_create: pthread_mutex_init failed");
        free(disc);
        return NULL;
    }
    
    if (pthread_cond_init(&disc->accept_cond, NULL) != 0) {
        DLOG("discovery_create: pthread_cond_init failed");
        pthread_mutex_destroy(&disc->mutex);
        free(disc);
        return NULL;
    }
    
    DLOG("discovery_create: created");
    return disc;
}

void discovery_destroy(Discovery* disc) {
    if (!disc) return;
    
    DLOG("discovery_destroy: destroying");
    
    /* Stop running threads */
    discovery_stop(disc);
    
    /* Close socket */
    if (disc->udp_socket >= 0) {
        close(disc->udp_socket);
        disc->udp_socket = -1;
    }
    
    /* Destroy synchronization primitives */
    pthread_cond_destroy(&disc->accept_cond);
    pthread_mutex_destroy(&disc->mutex);
    
    free(disc);
    DLOG("discovery_destroy: destroyed");
}

bool discovery_init(Discovery* disc, int port) {
    if (!disc) {
        DLOG("discovery_init: NULL disc");
        return false;
    }
    
    if (disc->udp_socket >= 0) {
        DLOG("discovery_init: already initialized");
        return true;
    }
    
    disc->port = port;
    
    /* Create UDP socket */
    disc->udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (disc->udp_socket < 0) {
        DLOG("discovery_init: socket failed: %s", strerror(errno));
        return false;
    }
    
    /* Reuse address */
    int opt = 1;
    if (setsockopt(disc->udp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        DLOG("discovery_init: setsockopt SO_REUSEADDR failed: %s", strerror(errno));
        close(disc->udp_socket);
        disc->udp_socket = -1;
        return false;
    }
    
    /* Bind */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(disc->udp_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        DLOG("discovery_init: bind port %d failed: %s", port, strerror(errno));
        close(disc->udp_socket);
        disc->udp_socket = -1;
        return false;
    }
    
    DLOG("discovery_init: bound to port %d (socket %d)", port, disc->udp_socket);
    return true;
}

void discovery_start(Discovery* disc) {
    if (!disc) return;
    if (disc->running) {
        DLOG("discovery_start: already running");
        return;
    }
    if (disc->udp_socket < 0) {
        DLOG("discovery_start: socket not initialized");
        return;
    }
    
    DLOG("discovery_start: starting threads");
    
    disc->running = true;
    
    /* Reset accept state */
    pthread_mutex_lock(&disc->mutex);
    memset(&disc->accept_state, 0, sizeof(disc->accept_state));
    disc->accept_state.received = false;
    disc->accept_state.processed = false;
    pthread_mutex_unlock(&disc->mutex);
    
    /* Create listen thread */
    if (pthread_create(&disc->listen_thread, NULL, discovery_listen_thread, disc) == 0) {
        disc->listen_thread_created = true;
        DLOG("discovery_start: listen thread created");
    } else {
        DLOG("discovery_start: failed to create listen thread");
        disc->running = false;
        return;
    }
    
    /* Create broadcast thread */
    if (pthread_create(&disc->broadcast_thread, NULL, discovery_broadcast_thread, disc) == 0) {
        disc->broadcast_thread_created = true;
        DLOG("discovery_start: broadcast thread created");
    } else {
        DLOG("discovery_start: failed to create broadcast thread");
        disc->running = false;
        /* Stop listen thread if it was created */
        if (disc->listen_thread_created) {
            disc->running = false;
            pthread_join(disc->listen_thread, NULL);
            disc->listen_thread_created = false;
        }
        return;
    }
    
    DLOG("discovery_start: started");
}

void discovery_stop(Discovery* disc) {
    if (!disc) return;
    if (!disc->running) {
        DLOG("discovery_stop: already stopped");
        return;
    }
    
    DLOG("discovery_stop: stopping");
    
    /* Signal running false */
    disc->running = false;
    
    /* Wake up any waiting threads */
    pthread_mutex_lock(&disc->mutex);
    pthread_cond_broadcast(&disc->accept_cond);
    pthread_mutex_unlock(&disc->mutex);
    
    /* Join listen thread */
    if (disc->listen_thread_created) {
        DLOG("discovery_stop: joining listen thread");
        pthread_join(disc->listen_thread, NULL);
        disc->listen_thread_created = false;
        DLOG("discovery_stop: listen thread joined");
    }
    
    /* Join broadcast thread */
    if (disc->broadcast_thread_created) {
        DLOG("discovery_stop: joining broadcast thread");
        pthread_join(disc->broadcast_thread, NULL);
        disc->broadcast_thread_created = false;
        DLOG("discovery_stop: broadcast thread joined");
    }
    
    DLOG("discovery_stop: stopped");
}

bool discovery_is_running(Discovery* disc) {
    return disc && disc->running;
}

/* ============================================================================
 * Identity Configuration
 * ============================================================================ */

void discovery_set_my_identity(Discovery* disc, const char* id, 
                               const char* ip, int port) {
    (void)disc;
    
    if (id) {
        strncpy(g_my_identity.id, id, sizeof(g_my_identity.id) - 1);
        g_my_identity.id[sizeof(g_my_identity.id) - 1] = '\0';
    }
    if (ip) {
        strncpy(g_my_identity.ip, ip, sizeof(g_my_identity.ip) - 1);
        g_my_identity.ip[sizeof(g_my_identity.ip) - 1] = '\0';
    }
    g_my_identity.port = port;
    g_my_identity.is_secure = false;
    
    DLOG("identity set: id='%s' ip='%s' port=%d (normal)", 
         g_my_identity.id, g_my_identity.ip, g_my_identity.port);
}

void discovery_set_my_secure_identity(Discovery* disc, 
                                      const OrcaIdentity* identity) {
    (void)disc;
    if (!identity) return;
    
    strncpy(g_my_identity.id, identity->id, sizeof(g_my_identity.id) - 1);
    g_my_identity.id[sizeof(g_my_identity.id) - 1] = '\0';
    
    strncpy(g_my_identity.name, identity->name, sizeof(g_my_identity.name) - 1);
    g_my_identity.name[sizeof(g_my_identity.name) - 1] = '\0';
    
    strncpy(g_my_identity.public_key, identity->public_key, 
            sizeof(g_my_identity.public_key) - 1);
    g_my_identity.public_key[sizeof(g_my_identity.public_key) - 1] = '\0';
    
    strncpy(g_my_identity.signature, identity->signature, 
            sizeof(g_my_identity.signature) - 1);
    g_my_identity.signature[sizeof(g_my_identity.signature) - 1] = '\0';
    
    g_my_identity.created_at = identity->created_at;
    g_my_identity.is_secure = true;
    
    DLOG("secure identity set: id='%s' name='%s'", 
         g_my_identity.id, g_my_identity.name);
}

/* ============================================================================
 * External References
 * ============================================================================ */

void discovery_set_registry(Discovery* disc, Registry* reg) {
    if (disc) {
        disc->registry = reg;
        DLOG("registry set");
    }
}

void discovery_set_request_manager(Discovery* disc, RequestManager* rm) {
    if (disc) {
        disc->request_manager = rm;
        DLOG("request_manager set");
    }
}

/* ============================================================================
 * Sending UDP (Defensive)
 * ============================================================================ */

static bool discovery_send_udp(Discovery* disc, const char* msg, 
                               const char* ip, int port) {
    if (!disc || !msg || !ip) {
        return false;
    }
    if (disc->udp_socket < 0) {
        DLOG("send_udp: socket not initialized");
        return false;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        DLOG("send_udp: invalid IP '%s'", ip);
        return false;
    }
    
    size_t msg_len = strlen(msg);
    if (msg_len == 0 || msg_len > 4096) {
        DLOG("send_udp: invalid message length %zu", msg_len);
        return false;
    }
    
    ssize_t sent = sendto(disc->udp_socket, msg, msg_len, 0,
                          (struct sockaddr*)&addr, sizeof(addr));
    
    if (sent < 0) {
        DLOG("send_udp: sendto failed: %s", strerror(errno));
        return false;
    }
    
    DLOG("send_udp: sent %zd bytes to %s:%d", sent, ip, port);
    return true;
}

static bool discovery_send_broadcast(Discovery* disc, const char* msg) {
    if (!disc || !msg) return false;
    if (disc->udp_socket < 0) return false;
    
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;
    broadcast_addr.sin_port = htons(disc->port);
    
    int broadcast = 1;
    setsockopt(disc->udp_socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
    
    size_t msg_len = strlen(msg);
    if (msg_len == 0 || msg_len > 4096) return false;
    
    ssize_t sent = sendto(disc->udp_socket, msg, msg_len, 0,
                          (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
    
    if (sent < 0) {
        DLOG("send_broadcast: failed: %s", strerror(errno));
        return false;
    }
    
    DLOG("send_broadcast: sent %zd bytes", sent);
    return true;
}

/* ============================================================================
 * Broadcasting
 * ============================================================================ */

void discovery_broadcast_presence(Discovery* disc, const char* id, 
                                  const char* endpoint) {
    if (!disc || !id || !endpoint) return;
    if (!disc->running) {
        DLOG("broadcast_presence: not running");
        return;
    }
    
    char msg[1024];
    int msg_len;
    
    if (g_my_identity.is_secure) {
        msg_len = snprintf(msg, sizeof(msg),
                          "ORCA_PRESENCE:SECURE:%s:%s:%s:%s:%s",
                          id, endpoint, g_my_identity.name,
                          g_my_identity.public_key, g_my_identity.signature);
    } else {
        msg_len = snprintf(msg, sizeof(msg),
                          "ORCA_PRESENCE:%s:%s", id, endpoint);
    }
    
    if (msg_len > 0 && msg_len < (int)sizeof(msg)) {
        discovery_send_broadcast(disc, msg);
        DLOG("broadcast_presence: %s", msg);
    }
}

void discovery_broadcast_search(Discovery* disc, const char* id) {
    if (!disc || !id) return;
    if (!disc->running) return;
    
    char norm_id[DISCOVERY_MAX_ID_LEN];
    if (!discovery_normalize_id(id, norm_id, sizeof(norm_id))) {
        DLOG("broadcast_search: invalid id '%s'", id);
        return;
    }
    
    char msg[512];
    int msg_len = snprintf(msg, sizeof(msg), "ORCA_SEARCH:%s", norm_id);
    
    if (msg_len > 0 && msg_len < (int)sizeof(msg)) {
        discovery_send_broadcast(disc, msg);
        DLOG("broadcast_search: %s", norm_id);
    }
}

void discovery_query_peer(Discovery* disc, const char* id) {
    if (!disc || !id) return;
    if (!disc->running) return;
    
    char norm_id[DISCOVERY_MAX_ID_LEN];
    if (!discovery_normalize_id(id, norm_id, sizeof(norm_id))) {
        DLOG("query_peer: invalid id '%s'", id);
        return;
    }
    
    char msg[512];
    int msg_len = snprintf(msg, sizeof(msg), "WHO_HAS:%s", norm_id);
    
    if (msg_len > 0 && msg_len < (int)sizeof(msg)) {
        discovery_send_broadcast(disc, msg);
        DLOG("query_peer: %s", norm_id);
    }
}

/* ============================================================================
 * Friend Request Flow
 * ============================================================================ */

void discovery_send_add_request(Discovery* disc, const char* target_id,
                                const char* my_id, const char* my_ip, 
                                int my_port) {
    if (!disc || !target_id || !my_id || !my_ip) {
        DLOG("send_add_request: NULL parameter");
        return;
    }
    
    char norm_target[DISCOVERY_MAX_ID_LEN];
    char norm_my[DISCOVERY_MAX_ID_LEN];
    
    if (!discovery_normalize_id(target_id, norm_target, sizeof(norm_target))) {
        DLOG("send_add_request: invalid target id");
        return;
    }
    if (!discovery_normalize_id(my_id, norm_my, sizeof(norm_my))) {
        DLOG("send_add_request: invalid my id");
        return;
    }
    
    DiscoveryPeerInfo peer;
    if (!discovery_find_peer(disc, target_id, &peer)) {
        DLOG("send_add_request: peer %s not found", target_id);
        return;
    }
    
    char msg[2048];
    int msg_len;
    
    if (g_my_identity.is_secure) {
        msg_len = snprintf(msg, sizeof(msg),
                          "ADD_REQUEST:SECURE:%s:%s:%s:%d:%s:%s:%s",
                          norm_target, norm_my, my_ip, my_port,
                          g_my_identity.name,
                          g_my_identity.public_key,
                          g_my_identity.signature);
    } else {
        msg_len = snprintf(msg, sizeof(msg),
                          "ADD_REQUEST:%s:%s:%s:%d",
                          norm_target, norm_my, my_ip, my_port);
    }
    
    if (msg_len > 0 && msg_len < (int)sizeof(msg)) {
        discovery_send_udp(disc, msg, peer.ip, DISCOVERY_PORT);
        DLOG("send_add_request: sent to %s (%s:%d)", target_id, peer.ip, peer.port);
    }
}

void discovery_send_add_request_secure(Discovery* disc, const char* target_id,
                                       const char* my_id, const char* my_ip,
                                       int my_port, const char* name,
                                       const char* public_key,
                                       const char* signature) {
    if (!disc || !target_id || !my_id || !my_ip) {
        DLOG("send_add_request_secure: NULL parameter");
        return;
    }
    
    char norm_target[DISCOVERY_MAX_ID_LEN];
    char norm_my[DISCOVERY_MAX_ID_LEN];
    
    if (!discovery_normalize_id(target_id, norm_target, sizeof(norm_target))) {
        DLOG("send_add_request_secure: invalid target id");
        return;
    }
    if (!discovery_normalize_id(my_id, norm_my, sizeof(norm_my))) {
        DLOG("send_add_request_secure: invalid my id");
        return;
    }
    
    DiscoveryPeerInfo peer;
    if (!discovery_find_peer(disc, target_id, &peer)) {
        DLOG("send_add_request_secure: peer %s not found", target_id);
        return;
    }
    
    char msg[2048];
    int msg_len = snprintf(msg, sizeof(msg),
                          "ADD_REQUEST:SECURE:%s:%s:%s:%d:%s:%s:%s",
                          norm_target, norm_my, my_ip, my_port,
                          name ? name : "",
                          public_key ? public_key : "",
                          signature ? signature : "");
    
    if (msg_len > 0 && msg_len < (int)sizeof(msg)) {
        discovery_send_udp(disc, msg, peer.ip, DISCOVERY_PORT);
        DLOG("send_add_request_secure: sent to %s", target_id);
    }
}

/* ============================================================================
 * ADD_REQUEST_ACK Flow
 * ============================================================================ */

static void discovery_send_add_request_ack(Discovery* disc, const char* target_id,
                                           const char* from_id) {
    if (!disc || !target_id || !from_id) return;
    
    char norm_target[DISCOVERY_MAX_ID_LEN];
    char norm_from[DISCOVERY_MAX_ID_LEN];
    
    if (!discovery_normalize_id(target_id, norm_target, sizeof(norm_target))) return;
    if (!discovery_normalize_id(from_id, norm_from, sizeof(norm_from))) return;
    
    DiscoveryPeerInfo peer;
    if (!discovery_find_peer(disc, target_id, &peer)) {
        DLOG("send_add_request_ack: peer %s not found", target_id);
        return;
    }
    
    char msg[512];
    int msg_len = snprintf(msg, sizeof(msg),
                          "ADD_REQUEST_ACK:%s:%s", norm_target, norm_from);
    
    if (msg_len > 0 && msg_len < (int)sizeof(msg)) {
        discovery_send_udp(disc, msg, peer.ip, DISCOVERY_PORT);
        DLOG("send_add_request_ack: sent to %s", target_id);
    }
}

/* ============================================================================
 * ACCEPT_CONFIRM Flow
 * ============================================================================ */

void discovery_send_accept_confirm(Discovery* disc, const char* target_id,
                                   const char* my_id, const char* my_ip,
                                   int my_port) {
    if (!disc || !target_id || !my_id || !my_ip) {
        DLOG("send_accept_confirm: NULL parameter");
        return;
    }
    
    char norm_target[DISCOVERY_MAX_ID_LEN];
    char norm_my[DISCOVERY_MAX_ID_LEN];
    
    if (!discovery_normalize_id(target_id, norm_target, sizeof(norm_target))) {
        DLOG("send_accept_confirm: invalid target id");
        return;
    }
    if (!discovery_normalize_id(my_id, norm_my, sizeof(norm_my))) {
        DLOG("send_accept_confirm: invalid my id");
        return;
    }
    
    DiscoveryPeerInfo peer;
    if (!discovery_find_peer(disc, target_id, &peer)) {
        DLOG("send_accept_confirm: peer %s not found", target_id);
        return;
    }
    
    char msg[1024];
    int msg_len = snprintf(msg, sizeof(msg),
                          "ACCEPT_CONFIRM:%s:%s:%s:%d",
                          norm_target, norm_my, my_ip, my_port);
    
    if (msg_len > 0 && msg_len < (int)sizeof(msg)) {
        discovery_send_udp(disc, msg, peer.ip, DISCOVERY_PORT);
        DLOG("send_accept_confirm: sent to %s (%s:%d)", target_id, peer.ip, peer.port);
    }
}

void discovery_send_accept_confirm_secure(Discovery* disc, const char* target_id,
                                          const char* my_id, const char* my_ip,
                                          int my_port, const char* public_key,
                                          const char* signature) {
    if (!disc || !target_id || !my_id || !my_ip) {
        DLOG("send_accept_confirm_secure: NULL parameter");
        return;
    }
    
    char norm_target[DISCOVERY_MAX_ID_LEN];
    char norm_my[DISCOVERY_MAX_ID_LEN];
    
    if (!discovery_normalize_id(target_id, norm_target, sizeof(norm_target))) {
        DLOG("send_accept_confirm_secure: invalid target id");
        return;
    }
    if (!discovery_normalize_id(my_id, norm_my, sizeof(norm_my))) {
        DLOG("send_accept_confirm_secure: invalid my id");
        return;
    }
    
    DiscoveryPeerInfo peer;
    if (!discovery_find_peer(disc, target_id, &peer)) {
        DLOG("send_accept_confirm_secure: peer %s not found", target_id);
        return;
    }
    
    char msg[2048];
    int msg_len = snprintf(msg, sizeof(msg),
                          "ACCEPT_CONFIRM:SECURE:%s:%s:%s:%d:%s:%s",
                          norm_target, norm_my, my_ip, my_port,
                          public_key ? public_key : "",
                          signature ? signature : "");
    
    if (msg_len > 0 && msg_len < (int)sizeof(msg)) {
        discovery_send_udp(disc, msg, peer.ip, DISCOVERY_PORT);
        DLOG("send_accept_confirm_secure: sent to %s", target_id);
    }
}

/* ============================================================================
 * ACCEPT_CONFIRM Waiting (Thread-Safe)
 * ============================================================================ */

bool discovery_wait_for_accept(Discovery* disc, const char* target_id, 
                               int timeout_sec) {
    if (!disc || !target_id) {
        DLOG("wait_for_accept: NULL parameter");
        return false;
    }
    
    if (!disc->running) {
        DLOG("wait_for_accept: discovery not running");
        return false;
    }
    
    char norm_target[DISCOVERY_MAX_ID_LEN];
    if (!discovery_normalize_id(target_id, norm_target, sizeof(norm_target))) {
        DLOG("wait_for_accept: invalid target id");
        return false;
    }
    
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_sec;
    
    pthread_mutex_lock(&disc->mutex);
    
    /* Reset accept state for this target */
    memset(&disc->accept_state, 0, sizeof(disc->accept_state));
    strncpy(disc->accept_state.target_id, norm_target, 
            sizeof(disc->accept_state.target_id) - 1);
    disc->accept_state.target_id[sizeof(disc->accept_state.target_id) - 1] = '\0';
    disc->accept_state.received = false;
    disc->accept_state.processed = false;
    
    DLOG("wait_for_accept: waiting for %s (timeout %ds)", target_id, timeout_sec);
    
    while (!disc->accept_state.received || 
           !discovery_is_same_id(disc->accept_state.from_id, target_id)) {
        int ret = pthread_cond_timedwait(&disc->accept_cond, &disc->mutex, &ts);
        if (ret == ETIMEDOUT) {
            DLOG("wait_for_accept: timeout for %s", target_id);
            pthread_mutex_unlock(&disc->mutex);
            return false;
        }
        if (!disc->running) {
            DLOG("wait_for_accept: discovery stopped");
            pthread_mutex_unlock(&disc->mutex);
            return false;
        }
    }
    
    /* Mark as processed */
    disc->accept_state.processed = true;
    
    DLOG("wait_for_accept: received confirmation from %s", 
         disc->accept_state.from_id);
    
    pthread_mutex_unlock(&disc->mutex);
    return true;
}

void discovery_reset_accept_state(Discovery* disc) {
    if (!disc) return;
    pthread_mutex_lock(&disc->mutex);
    memset(&disc->accept_state, 0, sizeof(disc->accept_state));
    disc->accept_state.received = false;
    disc->accept_state.processed = false;
    pthread_mutex_unlock(&disc->mutex);
    DLOG("reset_accept_state: reset");
}

/* ============================================================================
 * Pending Requests
 * ============================================================================ */

void discovery_push_pending(Discovery* disc, const char* from_id,
                            const char* from_ip, int from_port) {
    if (!disc || !from_id || !from_ip) return;
    
    pthread_mutex_lock(&disc->mutex);
    
    /* Check if already exists */
    for (int i = 0; i < disc->pending_count; i++) {
        if (discovery_is_same_id(disc->pending_requests[i].from_id, from_id)) {
            DLOG("push_pending: already exists from %s", from_id);
            pthread_mutex_unlock(&disc->mutex);
            return;
        }
    }
    
    if (disc->pending_count >= DISCOVERY_MAX_PENDING) {
        DLOG("push_pending: queue full");
        pthread_mutex_unlock(&disc->mutex);
        return;
    }
    
    DiscoveryPendingRequest* req = &disc->pending_requests[disc->pending_count++];
    strncpy(req->from_id, from_id, sizeof(req->from_id) - 1);
    req->from_id[sizeof(req->from_id) - 1] = '\0';
    
    strncpy(req->from_ip, from_ip, sizeof(req->from_ip) - 1);
    req->from_ip[sizeof(req->from_ip) - 1] = '\0';
    
    req->from_port = from_port;
    req->received_at = time(NULL);
    
    DLOG("push_pending: added from %s (total: %d)", from_id, disc->pending_count);
    
    pthread_mutex_unlock(&disc->mutex);
}

bool discovery_pop_pending(Discovery* disc, DiscoveryPendingRequest* out) {
    if (!disc || !out) return false;
    
    pthread_mutex_lock(&disc->mutex);
    
    if (disc->pending_count == 0) {
        pthread_mutex_unlock(&disc->mutex);
        return false;
    }
    
    *out = disc->pending_requests[0];
    
    /* Shift remaining */
    for (int i = 0; i < disc->pending_count - 1; i++) {
        disc->pending_requests[i] = disc->pending_requests[i + 1];
    }
    disc->pending_count--;
    
    DLOG("pop_pending: popped from %s (remaining: %d)", out->from_id, disc->pending_count);
    
    pthread_mutex_unlock(&disc->mutex);
    return true;
}

int discovery_pending_count(Discovery* disc) {
    if (!disc) return 0;
    pthread_mutex_lock(&disc->mutex);
    int count = disc->pending_count;
    pthread_mutex_unlock(&disc->mutex);
    return count;
}

bool discovery_has_pending(Discovery* disc) {
    if (!disc) return false;
    pthread_mutex_lock(&disc->mutex);
    bool has = disc->pending_count > 0;
    pthread_mutex_unlock(&disc->mutex);
    return has;
}

/* ============================================================================
 * Peer Discovery
 * ============================================================================ */

bool discovery_find_peer(Discovery* disc, const char* id, 
                         DiscoveryPeerInfo* out_peer) {
    if (!disc || !id || !out_peer) return false;
    
    char norm_id[DISCOVERY_MAX_ID_LEN];
    if (!discovery_normalize_id(id, norm_id, sizeof(norm_id))) {
        return false;
    }
    
    pthread_mutex_lock(&disc->mutex);
    
    for (int i = 0; i < disc->peer_count; i++) {
        char norm_peer_id[DISCOVERY_MAX_ID_LEN];
        if (!discovery_normalize_id(disc->peers[i].id, norm_peer_id, 
                                    sizeof(norm_peer_id))) {
            continue;
        }
        
        if (strcmp(norm_peer_id, norm_id) == 0 && disc->peers[i].online) {
            *out_peer = disc->peers[i];
            pthread_mutex_unlock(&disc->mutex);
            return true;
        }
    }
    
    pthread_mutex_unlock(&disc->mutex);
    return false;
}

int discovery_get_peers(Discovery* disc, DiscoveryPeerInfo* peers, 
                        int max_peers) {
    if (!disc || !peers || max_peers <= 0) return 0;
    
    pthread_mutex_lock(&disc->mutex);
    
    int count = 0;
    for (int i = 0; i < disc->peer_count && count < max_peers; i++) {
        if (disc->peers[i].online) {
            peers[count++] = disc->peers[i];
        }
    }
    
    pthread_mutex_unlock(&disc->mutex);
    return count;
}

void discovery_cleanup_stale(Discovery* disc) {
    if (!disc) return;
    
    time_t now = time(NULL);
    int stale_count = 0;
    
    pthread_mutex_lock(&disc->mutex);
    
    for (int i = 0; i < disc->peer_count; i++) {
        if (now - disc->peers[i].last_seen > DISCOVERY_PEER_TIMEOUT) {
            disc->peers[i].online = false;
            stale_count++;
            DLOG("cleanup_stale: peer %s marked offline", disc->peers[i].id);
            
            if (disc->on_peer_offline) {
                disc->on_peer_offline(&disc->peers[i]);
            }
        }
    }
    
    if (stale_count > 0) {
        DLOG("cleanup_stale: %d peers marked offline", stale_count);
    }
    
    pthread_mutex_unlock(&disc->mutex);
}

/* ============================================================================
 * Callbacks
 * ============================================================================ */

void discovery_set_on_peer_found(Discovery* disc, 
                                 void (*callback)(DiscoveryPeerInfo*)) {
    if (disc) {
        disc->on_peer_found = callback;
    }
}

void discovery_set_on_peer_offline(Discovery* disc, 
                                   void (*callback)(DiscoveryPeerInfo*)) {
    if (disc) {
        disc->on_peer_offline = callback;
    }
}

void discovery_set_on_accept_confirm(Discovery* disc,
                                     void (*callback)(const char*, const char*,
                                                      int, bool)) {
    if (disc) {
        disc->on_accept_confirm = callback;
    }
}

/* ============================================================================
 * Parser Functions (Defensive, Untrusted Input)
 * ============================================================================ */

static void discovery_handle_presence(Discovery* disc, const char* data,
                                      const char* sender_ip) {
    if (!disc || !data || !sender_ip) return;
    
    size_t data_len = strlen(data);
    bool is_secure = false;
    const char* rest = data;
    
    /* Check for SECURE prefix */
    if (strncmp(rest, "ORCA_PRESENCE:SECURE:", 21) == 0) {
        is_secure = true;
        rest += 21;
    } else if (strncmp(rest, "ORCA_PRESENCE:", 14) == 0) {
        rest += 14;
    } else {
        return;
    }
    
    char id[DISCOVERY_MAX_ID_LEN] = {0};
    char endpoint[DISCOVERY_MAX_ENDPOINT_LEN] = {0};
    char name[DISCOVERY_MAX_NAME_LEN] = {0};
    char public_key[DISCOVERY_MAX_PUBKEY_LEN] = {0};
    char signature[DISCOVERY_MAX_SIG_LEN] = {0};
    
    /* Parse ID */
    const char* colon1 = strchr(rest, ':');
    if (!colon1) return;
    size_t id_len = colon1 - rest;
    if (id_len == 0 || id_len >= sizeof(id)) return;
    memcpy(id, rest, id_len);
    id[id_len] = '\0';
    
    /* Parse endpoint */
    const char* endpoint_start = colon1 + 1;
    if (is_secure) {
        const char* colon2 = strchr(endpoint_start, ':');
        if (!colon2) return;
        size_t endpoint_len = colon2 - endpoint_start;
        if (endpoint_len == 0 || endpoint_len >= sizeof(endpoint)) return;
        memcpy(endpoint, endpoint_start, endpoint_len);
        endpoint[endpoint_len] = '\0';
        
        /* Parse name */
        const char* name_start = colon2 + 1;
        const char* colon3 = strchr(name_start, ':');
        if (!colon3) return;
        size_t name_len = colon3 - name_start;
        if (name_len == 0 || name_len >= sizeof(name)) return;
        memcpy(name, name_start, name_len);
        name[name_len] = '\0';
        
        /* Parse public_key */
        const char* pk_start = colon3 + 1;
        const char* colon4 = strchr(pk_start, ':');
        if (!colon4) return;
        size_t pk_len = colon4 - pk_start;
        if (pk_len == 0 || pk_len >= sizeof(public_key)) return;
        memcpy(public_key, pk_start, pk_len);
        public_key[pk_len] = '\0';
        
        /* Parse signature */
        const char* sig_start = colon4 + 1;
        size_t sig_len = strlen(sig_start);
        if (sig_len == 0 || sig_len >= sizeof(signature)) return;
        memcpy(signature, sig_start, sig_len);
        signature[sig_len] = '\0';
    } else {
        size_t endpoint_len = strlen(endpoint_start);
        if (endpoint_len == 0 || endpoint_len >= sizeof(endpoint)) return;
        memcpy(endpoint, endpoint_start, endpoint_len);
        endpoint[endpoint_len] = '\0';
    }
    
    /* Extract IP from endpoint */
    char peer_ip[DISCOVERY_MAX_IP_LEN] = {0};
    const char* port_colon = strchr(endpoint, ':');
    if (port_colon) {
        size_t ip_len = port_colon - endpoint;
        if (ip_len == 0 || ip_len >= sizeof(peer_ip)) return;
        memcpy(peer_ip, endpoint, ip_len);
        peer_ip[ip_len] = '\0';
    } else {
        strncpy(peer_ip, sender_ip, sizeof(peer_ip) - 1);
    }
    
    int port = 9000;
    if (port_colon) {
        port = atoi(port_colon + 1);
        if (port <= 0 || port > 65535) port = 9000;
    }
    
    /* Store peer in cache */
    pthread_mutex_lock(&disc->mutex);
    
    int found = -1;
    for (int i = 0; i < disc->peer_count; i++) {
        if (discovery_is_same_id(disc->peers[i].id, id)) {
            found = i;
            break;
        }
    }
    
    if (found == -1 && disc->peer_count < DISCOVERY_MAX_PEERS) {
        found = disc->peer_count++;
    }
    
    if (found >= 0) {
        DiscoveryPeerInfo* peer = &disc->peers[found];
        strncpy(peer->id, id, sizeof(peer->id) - 1);
        peer->id[sizeof(peer->id) - 1] = '\0';
        
        strncpy(peer->endpoint, endpoint, sizeof(peer->endpoint) - 1);
        peer->endpoint[sizeof(peer->endpoint) - 1] = '\0';
        
        strncpy(peer->ip, peer_ip, sizeof(peer->ip) - 1);
        peer->ip[sizeof(peer->ip) - 1] = '\0';
        
        peer->port = port;
        peer->last_seen = time(NULL);
        peer->online = true;
        peer->is_secure = is_secure;
        
        if (is_secure) {
            strncpy(peer->name, name, sizeof(peer->name) - 1);
            peer->name[sizeof(peer->name) - 1] = '\0';
            
            strncpy(peer->public_key, public_key, sizeof(peer->public_key) - 1);
            peer->public_key[sizeof(peer->public_key) - 1] = '\0';
            
            strncpy(peer->signature, signature, sizeof(peer->signature) - 1);
            peer->signature[sizeof(peer->signature) - 1] = '\0';
            
            peer->verified = true;
        }
        
        DLOG("handle_presence: updated peer %s at %s:%d", id, peer_ip, port);
        
        if (disc->on_peer_found) {
            disc->on_peer_found(peer);
        }
    }
    
    pthread_mutex_unlock(&disc->mutex);
}

static void discovery_handle_who_has(Discovery* disc, const char* data,
                                     const char* sender_ip) {
    if (!disc || !data || !sender_ip) return;
    
    const char* search_id = data + 8; /* Skip "WHO_HAS:" */
    if (!search_id || strlen(search_id) == 0) return;
    
    char norm_search[DISCOVERY_MAX_ID_LEN];
    char norm_my[DISCOVERY_MAX_ID_LEN];
    
    if (!discovery_normalize_id(search_id, norm_search, sizeof(norm_search))) {
        return;
    }
    if (!discovery_normalize_id(g_my_identity.id, norm_my, sizeof(norm_my))) {
        return;
    }
    
    if (strcmp(norm_search, norm_my) == 0 && strlen(g_my_identity.ip) > 0) {
        /* Respond with I_AM */
        char response[2048];
        int response_len;
        
        if (g_my_identity.is_secure) {
            response_len = snprintf(response, sizeof(response),
                                   "I_AM:SECURE:%s:%s:%s:%ld:%s:%d:%s:%s",
                                   g_my_identity.id,
                                   g_my_identity.name,
                                   g_my_identity.role,
                                   (long)g_my_identity.created_at,
                                   g_my_identity.ip,
                                   g_my_identity.port,
                                   g_my_identity.public_key,
                                   g_my_identity.signature);
        } else {
            response_len = snprintf(response, sizeof(response),
                                   "I_AM:%s:%s:%d",
                                   g_my_identity.id,
                                   g_my_identity.ip,
                                   g_my_identity.port);
        }
        
        if (response_len > 0 && response_len < (int)sizeof(response)) {
            discovery_send_udp(disc, response, sender_ip, DISCOVERY_PORT);
            DLOG("handle_who_has: responded to %s", sender_ip);
        }
    }
}

static void discovery_handle_i_am(Discovery* disc, const char* data,
                                  const char* sender_ip) {
    if (!disc || !data || !sender_ip) return;
    
    const char* rest = data + 5; /* Skip "I_AM:" */
    bool is_secure = false;
    
    if (strncmp(rest, "SECURE:", 7) == 0) {
        is_secure = true;
        rest += 7;
    }
    
    /* Parse ID */
    const char* colon1 = strchr(rest, ':');
    if (!colon1) return;
    char id[DISCOVERY_MAX_ID_LEN] = {0};
    size_t id_len = colon1 - rest;
    if (id_len == 0 || id_len >= sizeof(id)) return;
    memcpy(id, rest, id_len);
    id[id_len] = '\0';
    
    if (!is_secure) {
        /* Normal mode: id:ip:port */
        const char* colon2 = strchr(colon1 + 1, ':');
        if (!colon2) return;
        
        char ip[DISCOVERY_MAX_IP_LEN] = {0};
        size_t ip_len = colon2 - colon1 - 1;
        if (ip_len == 0 || ip_len >= sizeof(ip)) return;
        memcpy(ip, colon1 + 1, ip_len);
        ip[ip_len] = '\0';
        
        int port = atoi(colon2 + 1);
        if (port <= 0 || port > 65535) port = 9000;
        
        /* Store in cache */
        pthread_mutex_lock(&disc->mutex);
        
        int found = -1;
        for (int i = 0; i < disc->peer_count; i++) {
            if (discovery_is_same_id(disc->peers[i].id, id)) {
                found = i;
                break;
            }
        }
        
        if (found == -1 && disc->peer_count < DISCOVERY_MAX_PEERS) {
            found = disc->peer_count++;
        }
        
        if (found >= 0) {
            DiscoveryPeerInfo* peer = &disc->peers[found];
            strncpy(peer->id, id, sizeof(peer->id) - 1);
            peer->id[sizeof(peer->id) - 1] = '\0';
            
            strncpy(peer->ip, sender_ip, sizeof(peer->ip) - 1);
            peer->ip[sizeof(peer->ip) - 1] = '\0';
            
            peer->port = port;
            peer->online = true;
            peer->last_seen = time(NULL);
            peer->is_secure = false;
            peer->verified = false;
            
            snprintf(peer->endpoint, sizeof(peer->endpoint), "%s:%d", sender_ip, port);
            
            DLOG("handle_i_am: stored peer %s at %s:%d", id, sender_ip, port);
            
            if (disc->on_peer_found) {
                disc->on_peer_found(peer);
            }
        }
        
        pthread_mutex_unlock(&disc->mutex);
        return;
    }
    
    /* Secure mode: id:name:role:created_at:ip:port:public_key:signature */
    const char* name_start = colon1 + 1;
    const char* colon2 = strchr(name_start, ':');
    if (!colon2) return;
    char name[DISCOVERY_MAX_NAME_LEN] = {0};
    size_t name_len = colon2 - name_start;
    if (name_len == 0 || name_len >= sizeof(name)) return;
    memcpy(name, name_start, name_len);
    name[name_len] = '\0';
    
    const char* role_start = colon2 + 1;
    const char* colon3 = strchr(role_start, ':');
    if (!colon3) return;
    /* role skipped */
    
    const char* created_at_start = colon3 + 1;
    const char* colon4 = strchr(created_at_start, ':');
    if (!colon4) return;
    time_t created_at = atol(created_at_start);
    (void)created_at;
    
    const char* ip_start = colon4 + 1;
    const char* colon5 = strchr(ip_start, ':');
    if (!colon5) return;
    char ip[DISCOVERY_MAX_IP_LEN] = {0};
    size_t ip_len = colon5 - ip_start;
    if (ip_len == 0 || ip_len >= sizeof(ip)) return;
    memcpy(ip, ip_start, ip_len);
    ip[ip_len] = '\0';
    
    const char* port_start = colon5 + 1;
    const char* colon6 = strchr(port_start, ':');
    if (!colon6) return;
    int port = atoi(port_start);
    if (port <= 0 || port > 65535) port = 9000;
    
    const char* pk_start = colon6 + 1;
    const char* colon7 = strchr(pk_start, ':');
    if (!colon7) return;
    char public_key[DISCOVERY_MAX_PUBKEY_LEN] = {0};
    size_t pk_len = colon7 - pk_start;
    if (pk_len == 0 || pk_len >= sizeof(public_key)) return;
    memcpy(public_key, pk_start, pk_len);
    public_key[pk_len] = '\0';
    
    const char* sig_start = colon7 + 1;
    char signature[DISCOVERY_MAX_SIG_LEN] = {0};
    size_t sig_len = strlen(sig_start);
    if (sig_len == 0 || sig_len >= sizeof(signature)) return;
    memcpy(signature, sig_start, sig_len);
    signature[sig_len] = '\0';
    
    /* Verify signature */
    char data_to_verify[1024];
    snprintf(data_to_verify, sizeof(data_to_verify), "%s|%s|%s|%ld",
             id, name, "user", (long)created_at);
    
    if (!orca_rsa_verify_string(data_to_verify, signature, public_key)) {
        DLOG("handle_i_am: invalid signature from %s", id);
        return;
    }
    
    /* Store in cache */
    pthread_mutex_lock(&disc->mutex);
    
    int found = -1;
    for (int i = 0; i < disc->peer_count; i++) {
        if (discovery_is_same_id(disc->peers[i].id, id)) {
            found = i;
            break;
        }
    }
    
    if (found == -1 && disc->peer_count < DISCOVERY_MAX_PEERS) {
        found = disc->peer_count++;
    }
    
    if (found >= 0) {
        DiscoveryPeerInfo* peer = &disc->peers[found];
        strncpy(peer->id, id, sizeof(peer->id) - 1);
        peer->id[sizeof(peer->id) - 1] = '\0';
        
        strncpy(peer->name, name, sizeof(peer->name) - 1);
        peer->name[sizeof(peer->name) - 1] = '\0';
        
        strncpy(peer->ip, sender_ip, sizeof(peer->ip) - 1);
        peer->ip[sizeof(peer->ip) - 1] = '\0';
        
        peer->port = port;
        peer->online = true;
        peer->last_seen = time(NULL);
        peer->is_secure = true;
        peer->verified = true;
        
        strncpy(peer->public_key, public_key, sizeof(peer->public_key) - 1);
        peer->public_key[sizeof(peer->public_key) - 1] = '\0';
        
        strncpy(peer->signature, signature, sizeof(peer->signature) - 1);
        peer->signature[sizeof(peer->signature) - 1] = '\0';
        
        snprintf(peer->endpoint, sizeof(peer->endpoint), "%s:%d", sender_ip, port);
        
        DLOG("handle_i_am: stored secure peer %s at %s:%d", id, sender_ip, port);
        
        if (disc->on_peer_found) {
            disc->on_peer_found(peer);
        }
    }
    
    pthread_mutex_unlock(&disc->mutex);
}

static void discovery_handle_add_request(Discovery* disc, const char* data,
                                         const char* sender_ip, int sender_port) {
    (void)sender_port;
    if (!disc || !data || !sender_ip) return;
    
    const char* rest = data + 12; /* Skip "ADD_REQUEST:" */
    bool is_secure = false;
    
    if (strncmp(rest, "SECURE:", 7) == 0) {
        is_secure = true;
        rest += 7;
    }
    
    const char* colon1 = strchr(rest, ':');
    const char* colon2 = colon1 ? strchr(colon1 + 1, ':') : NULL;
    const char* colon3 = colon2 ? strchr(colon2 + 1, ':') : NULL;
    
    if (!colon1 || !colon2 || !colon3) {
        DLOG("handle_add_request: malformed packet");
        return;
    }
    
    char target_id[DISCOVERY_MAX_ID_LEN] = {0};
    char from_id[DISCOVERY_MAX_ID_LEN] = {0};
    char from_ip[DISCOVERY_MAX_IP_LEN] = {0};
    int from_port = 0;
    char from_name[DISCOVERY_MAX_NAME_LEN] = {0};
    char public_key[DISCOVERY_MAX_PUBKEY_LEN] = {0};
    char signature[DISCOVERY_MAX_SIG_LEN] = {0};
    
    /* Parse target_id */
    size_t len = colon1 - rest;
    if (len == 0 || len >= sizeof(target_id)) return;
    memcpy(target_id, rest, len);
    target_id[len] = '\0';
    
    /* Parse from_id */
    len = colon2 - colon1 - 1;
    if (len == 0 || len >= sizeof(from_id)) return;
    memcpy(from_id, colon1 + 1, len);
    from_id[len] = '\0';
    
    /* Parse from_ip */
    len = colon3 - colon2 - 1;
    if (len == 0 || len >= sizeof(from_ip)) return;
    memcpy(from_ip, colon2 + 1, len);
    from_ip[len] = '\0';
    
    /* Parse from_port */
    from_port = atoi(colon3 + 1);
    if (from_port <= 0 || from_port > 65535) from_port = 9000;
    
    if (is_secure) {
        const char* secure_rest = colon3 + 1;
        const char* name_start = strchr(secure_rest, ':');
        if (name_start) {
            const char* name_end = strchr(name_start + 1, ':');
            if (name_end) {
                size_t name_len = name_end - name_start - 1;
                if (name_len > 0 && name_len < sizeof(from_name)) {
                    memcpy(from_name, name_start + 1, name_len);
                    from_name[name_len] = '\0';
                }
                
                const char* pk_start = name_end + 1;
                const char* pk_end = strchr(pk_start, ':');
                if (pk_end) {
                    size_t pk_len = pk_end - pk_start;
                    if (pk_len > 0 && pk_len < sizeof(public_key)) {
                        memcpy(public_key, pk_start, pk_len);
                        public_key[pk_len] = '\0';
                    }
                    
                    const char* sig_start = pk_end + 1;
                    size_t sig_len = strlen(sig_start);
                    if (sig_len > 0 && sig_len < sizeof(signature)) {
                        memcpy(signature, sig_start, sig_len);
                        signature[sig_len] = '\0';
                    }
                }
            }
        }
    }
    
    /* Check if this is for us */
    char norm_target[DISCOVERY_MAX_ID_LEN];
    char norm_my[DISCOVERY_MAX_ID_LEN];
    
    if (!discovery_normalize_id(target_id, norm_target, sizeof(norm_target))) {
        DLOG("handle_add_request: invalid target id");
        return;
    }
    if (!discovery_normalize_id(g_my_identity.id, norm_my, sizeof(norm_my))) {
        DLOG("handle_add_request: invalid my id");
        return;
    }
    
    if (strcmp(norm_target, norm_my) != 0) {
        DLOG("handle_add_request: not for me (target=%s)", target_id);
        return;
    }
    
    DLOG("handle_add_request: from %s at %s:%d (secure=%d)", 
         from_id, from_ip, from_port, is_secure);
    
    /* Verify secure identity */
    if (is_secure) {
        if (strlen(public_key) == 0 || strlen(signature) == 0) {
            DLOG("handle_add_request: missing public_key or signature");
            return;
        }
        
        char data_to_verify[1024];
        snprintf(data_to_verify, sizeof(data_to_verify), "%s|%s|%s|%d",
                 target_id, from_id, from_ip, from_port);
        
        if (!orca_rsa_verify_string(data_to_verify, signature, public_key)) {
            DLOG("handle_add_request: invalid signature from %s", from_id);
            return;
        }
        DLOG("handle_add_request: signature verified for %s", from_id);
    }
    
    /* Send ACK */
    discovery_send_add_request_ack(disc, from_id, g_my_identity.id);
    DLOG("handle_add_request: sent ACK to %s", from_id);
    
    /* Store in request manager (pending) */
    if (disc->request_manager) {
        request_send(disc->request_manager, from_id, g_my_identity.id);
        DLOG("handle_add_request: saved to request manager");
    }
    
    /* Store in discovery cache */
    pthread_mutex_lock(&disc->mutex);
    
    int found = -1;
    for (int i = 0; i < disc->peer_count; i++) {
        if (discovery_is_same_id(disc->peers[i].id, from_id)) {
            found = i;
            break;
        }
    }
    
    if (found == -1 && disc->peer_count < DISCOVERY_MAX_PEERS) {
        found = disc->peer_count++;
    }
    
    if (found >= 0) {
        DiscoveryPeerInfo* peer = &disc->peers[found];
        strncpy(peer->id, from_id, sizeof(peer->id) - 1);
        peer->id[sizeof(peer->id) - 1] = '\0';
        
        strncpy(peer->ip, sender_ip, sizeof(peer->ip) - 1);
        peer->ip[sizeof(peer->ip) - 1] = '\0';
        
        peer->port = from_port;
        peer->online = true;
        peer->last_seen = time(NULL);
        peer->is_secure = is_secure;
        
        if (is_secure) {
            strncpy(peer->name, from_name, sizeof(peer->name) - 1);
            peer->name[sizeof(peer->name) - 1] = '\0';
            
            strncpy(peer->public_key, public_key, sizeof(peer->public_key) - 1);
            peer->public_key[sizeof(peer->public_key) - 1] = '\0';
            
            strncpy(peer->signature, signature, sizeof(peer->signature) - 1);
            peer->signature[sizeof(peer->signature) - 1] = '\0';
            
            peer->verified = true;
        }
        
        snprintf(peer->endpoint, sizeof(peer->endpoint), "%s:%d", sender_ip, from_port);
        
        DLOG("handle_add_request: stored peer %s in cache", from_id);
    }
    
    pthread_mutex_unlock(&disc->mutex);
    
    /* Push to pending queue */
    discovery_push_pending(disc, from_id, sender_ip, from_port);
    DLOG("handle_add_request: pushed to pending queue");
    
    /* Print notification */
    printf("\n[ORCA] ========================================\n");
    printf("[ORCA] Friend request from %s (%s:%d)\n", from_id, sender_ip, from_port);
    if (is_secure && strlen(from_name) > 0) {
        printf("[ORCA] Name: %s\n", from_name);
    }
    printf("[ORCA] ========================================\n");
    printf("[ORCA] Press 'y' to accept or 'n' to reject\n");
    fflush(stdout);
}

static void discovery_handle_add_request_ack(Discovery* disc, const char* data) {
    if (!disc || !data) return;
    
    const char* rest = data + 16; /* Skip "ADD_REQUEST_ACK:" */
    const char* colon1 = strchr(rest, ':');
    if (!colon1) return;
    
    char target_id[DISCOVERY_MAX_ID_LEN] = {0};
    char from_id[DISCOVERY_MAX_ID_LEN] = {0};
    
    size_t len = colon1 - rest;
    if (len == 0 || len >= sizeof(target_id)) return;
    memcpy(target_id, rest, len);
    target_id[len] = '\0';
    
    const char* from_start = colon1 + 1;
    size_t from_len = strlen(from_start);
    if (from_len == 0 || from_len >= sizeof(from_id)) return;
    memcpy(from_id, from_start, from_len);
    from_id[from_len] = '\0';
    
    char norm_target[DISCOVERY_MAX_ID_LEN];
    char norm_my[DISCOVERY_MAX_ID_LEN];
    
    if (!discovery_normalize_id(target_id, norm_target, sizeof(norm_target))) return;
    if (!discovery_normalize_id(g_my_identity.id, norm_my, sizeof(norm_my))) return;
    
    if (strcmp(norm_target, norm_my) == 0) {
        DLOG("handle_add_request_ack: request delivered to %s", target_id);
        printf("[ORCA] Friend request delivered to %s\n", target_id);
        
        /* Mark peer online in cache */
        pthread_mutex_lock(&disc->mutex);
        for (int i = 0; i < disc->peer_count; i++) {
            if (discovery_is_same_id(disc->peers[i].id, from_id)) {
                disc->peers[i].online = true;
                disc->peers[i].last_seen = time(NULL);
                DLOG("handle_add_request_ack: marked %s online", from_id);
                break;
            }
        }
        pthread_mutex_unlock(&disc->mutex);
    }
}

static void discovery_handle_accept_confirm(Discovery* disc, const char* data) {
    if (!disc || !data) return;
    
    const char* rest = data + 15; /* Skip "ACCEPT_CONFIRM:" */
    bool is_secure = false;
    
    if (strncmp(rest, "SECURE:", 7) == 0) {
        is_secure = true;
        rest += 7;
    }
    
    const char* colon1 = strchr(rest, ':');
    const char* colon2 = colon1 ? strchr(colon1 + 1, ':') : NULL;
    const char* colon3 = colon2 ? strchr(colon2 + 1, ':') : NULL;
    
    if (!colon1 || !colon2 || !colon3) {
        DLOG("handle_accept_confirm: malformed packet");
        return;
    }
    
    char target_id[DISCOVERY_MAX_ID_LEN] = {0};
    char from_id[DISCOVERY_MAX_ID_LEN] = {0};
    char from_ip[DISCOVERY_MAX_IP_LEN] = {0};
    int from_port = 0;
    char public_key[DISCOVERY_MAX_PUBKEY_LEN] = {0};
    char signature[DISCOVERY_MAX_SIG_LEN] = {0};
    
    /* Parse target_id */
    size_t len = colon1 - rest;
    if (len == 0 || len >= sizeof(target_id)) return;
    memcpy(target_id, rest, len);
    target_id[len] = '\0';
    
    /* Parse from_id */
    len = colon2 - colon1 - 1;
    if (len == 0 || len >= sizeof(from_id)) return;
    memcpy(from_id, colon1 + 1, len);
    from_id[len] = '\0';
    
    /* Parse from_ip */
    len = colon3 - colon2 - 1;
    if (len == 0 || len >= sizeof(from_ip)) return;
    memcpy(from_ip, colon2 + 1, len);
    from_ip[len] = '\0';
    
    /* Parse from_port */
    from_port = atoi(colon3 + 1);
    if (from_port <= 0 || from_port > 65535) from_port = 9000;
    
    if (is_secure) {
        const char* secure_rest = colon3 + 1;
        const char* pk_start = strchr(secure_rest, ':');
        if (pk_start) {
            const char* sig_start = strchr(pk_start + 1, ':');
            if (sig_start) {
                size_t pk_len = sig_start - pk_start - 1;
                if (pk_len > 0 && pk_len < sizeof(public_key)) {
                    memcpy(public_key, pk_start + 1, pk_len);
                    public_key[pk_len] = '\0';
                }
                const char* sig_rest = sig_start + 1;
                size_t sig_len = strlen(sig_rest);
                if (sig_len > 0 && sig_len < sizeof(signature)) {
                    memcpy(signature, sig_rest, sig_len);
                    signature[sig_len] = '\0';
                }
            }
        }
    }
    
    /* Check if this is for us */
    char norm_target[DISCOVERY_MAX_ID_LEN];
    char norm_my[DISCOVERY_MAX_ID_LEN];
    
    if (!discovery_normalize_id(target_id, norm_target, sizeof(norm_target))) return;
    if (!discovery_normalize_id(g_my_identity.id, norm_my, sizeof(norm_my))) return;
    
    if (strcmp(norm_target, norm_my) != 0) {
        DLOG("handle_accept_confirm: not for me (target=%s)", target_id);
        return;
    }
    
    DLOG("handle_accept_confirm: from %s at %s:%d (secure=%d)", 
         from_id, from_ip, from_port, is_secure);
    
    /* Verify secure identity */
    if (is_secure) {
        if (strlen(public_key) == 0 || strlen(signature) == 0) {
            DLOG("handle_accept_confirm: missing public_key or signature");
            return;
        }
        
        char data_to_verify[1024];
        snprintf(data_to_verify, sizeof(data_to_verify), "%s|%s|%s|%d",
                 from_id, from_ip, "9000", (int)time(NULL));
        
        if (!orca_rsa_verify_string(data_to_verify, signature, public_key)) {
            DLOG("handle_accept_confirm: invalid signature from %s", from_id);
            return;
        }
        DLOG("handle_accept_confirm: signature verified for %s", from_id);
    }
    
    /* ===== THREAD-SAFE: Set accept state with mutex ===== */
    pthread_mutex_lock(&disc->mutex);
    
    strncpy(disc->accept_state.from_id, from_id, 
            sizeof(disc->accept_state.from_id) - 1);
    disc->accept_state.from_id[sizeof(disc->accept_state.from_id) - 1] = '\0';
    
    strncpy(disc->accept_state.from_ip, from_ip, 
            sizeof(disc->accept_state.from_ip) - 1);
    disc->accept_state.from_ip[sizeof(disc->accept_state.from_ip) - 1] = '\0';
    
    disc->accept_state.from_port = from_port;
    disc->accept_state.is_secure = is_secure;
    
    if (is_secure) {
        strncpy(disc->accept_state.public_key, public_key, 
                sizeof(disc->accept_state.public_key) - 1);
        disc->accept_state.public_key[sizeof(disc->accept_state.public_key) - 1] = '\0';
        
        strncpy(disc->accept_state.signature, signature, 
                sizeof(disc->accept_state.signature) - 1);
        disc->accept_state.signature[sizeof(disc->accept_state.signature) - 1] = '\0';
    }
    
    disc->accept_state.received = true;
    
    /* Wake up waiting thread */
    pthread_cond_broadcast(&disc->accept_cond);
    
    pthread_mutex_unlock(&disc->mutex);
    
    printf("\n[ORCA] ACCEPT_CONFIRM received from %s!\n", from_id);
    printf("[ORCA] Friendship with %s is now accepted.\n", from_id);
    fflush(stdout);
    
    /* ===== CALLBACK FOR PERSISTENCE ===== */
    if (disc->on_accept_confirm) {
        disc->on_accept_confirm(from_id, from_ip, from_port, is_secure);
    }
}

static void discovery_handle_search(Discovery* disc, const char* data,
                                    const char* sender_ip) {
    if (!disc || !data || !sender_ip) return;
    
    const char* search_id = data + 12; /* Skip "ORCA_SEARCH:" */
    if (!search_id || strlen(search_id) == 0) return;
    
    char norm_search[DISCOVERY_MAX_ID_LEN];
    char norm_my[DISCOVERY_MAX_ID_LEN];
    
    if (!discovery_normalize_id(search_id, norm_search, sizeof(norm_search))) return;
    if (!discovery_normalize_id(g_my_identity.id, norm_my, sizeof(norm_my))) return;
    
    if (strcmp(norm_search, norm_my) == 0 && strlen(g_my_identity.ip) > 0) {
        char response[1024];
        int response_len;
        
        if (g_my_identity.is_secure) {
            response_len = snprintf(response, sizeof(response),
                                   "ORCA_PRESENCE:SECURE:%s:%s:%d:%s:%s:%s",
                                   g_my_identity.id,
                                   g_my_identity.ip,
                                   g_my_identity.port,
                                   g_my_identity.name,
                                   g_my_identity.public_key,
                                   g_my_identity.signature);
        } else {
            response_len = snprintf(response, sizeof(response),
                                   "ORCA_PRESENCE:%s:%s:%d",
                                   g_my_identity.id,
                                   g_my_identity.ip,
                                   g_my_identity.port);
        }
        
        if (response_len > 0 && response_len < (int)sizeof(response)) {
            discovery_send_udp(disc, response, sender_ip, DISCOVERY_PORT);
            DLOG("handle_search: responded to %s", sender_ip);
        }
    }
}

/* ============================================================================
 * Packet Parser (Main Entry Point) - FIXED
 * ============================================================================ */

static void discovery_parse_packet(Discovery* disc, const char* data, 
                                   size_t data_len, const char* sender_ip,
                                   int sender_port) {
    if (!disc || !data || data_len == 0 || !sender_ip) return;
    
    /* ===== FIX: Check null terminator at data[data_len] ===== */
    if (data[data_len] != '\0') {
        DLOG("parse_packet: not null-terminated, ignoring");
        return;
    }
    
    /* Skip empty packets */
    if (data_len <= 1) {
        return;
    }
    
    /* Skip packets from self */
    if (strlen(g_my_identity.ip) > 0 && strcmp(sender_ip, g_my_identity.ip) == 0) {
        DLOG("parse_packet: skipping self");
        return;
    }
    
    /* Dispatch based on packet type */
    if (strncmp(data, "ORCA_PRESENCE:", 14) == 0) {
        discovery_handle_presence(disc, data, sender_ip);
    } else if (strncmp(data, "WHO_HAS:", 8) == 0) {
        discovery_handle_who_has(disc, data, sender_ip);
    } else if (strncmp(data, "I_AM:", 5) == 0) {
        discovery_handle_i_am(disc, data, sender_ip);
    } else if (strncmp(data, "ADD_REQUEST:", 12) == 0) {
        discovery_handle_add_request(disc, data, sender_ip, sender_port);
    } else if (strncmp(data, "ADD_REQUEST_ACK:", 16) == 0) {
        discovery_handle_add_request_ack(disc, data);
    } else if (strncmp(data, "ACCEPT_CONFIRM:", 15) == 0) {
        discovery_handle_accept_confirm(disc, data);
    } else if (strncmp(data, "ORCA_SEARCH:", 12) == 0) {
        discovery_handle_search(disc, data, sender_ip);
    } else {
        DLOG("parse_packet: unknown type: %.20s...", data);
    }
}

/* ============================================================================
 * Listen Thread
 * ============================================================================ */

static void* discovery_listen_thread(void* arg) {
    Discovery* disc = (Discovery*)arg;
    if (!disc) return NULL;
    
    char buffer[DISCOVERY_BUFFER_SIZE];
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);
    fd_set fds;
    struct timeval tv;
    
    DLOG("listen_thread: started (socket %d)", disc->udp_socket);
    
    while (disc->running) {
        FD_ZERO(&fds);
        FD_SET(disc->udp_socket, &fds);
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(disc->udp_socket + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (disc->running) {
                DLOG("listen_thread: select failed: %s", strerror(errno));
            }
            break;
        }
        
        if (ret == 0) {
            /* Periodic cleanup */
            discovery_cleanup_stale(disc);
            continue;
        }
        
        int n = recvfrom(disc->udp_socket, buffer, sizeof(buffer) - 1, 0,
                        (struct sockaddr*)&sender_addr, &addr_len);
        if (n <= 0) {
            continue;
        }
        
        buffer[n] = '\0';
        
        char sender_ip[DISCOVERY_MAX_IP_LEN];
        if (!inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, sizeof(sender_ip))) {
            continue;
        }
        int sender_port = ntohs(sender_addr.sin_port);
        
        DLOG("listen_thread: received %d bytes from %s:%d", n, sender_ip, sender_port);
        
        discovery_parse_packet(disc, buffer, n, sender_ip, sender_port);
    }
    
    DLOG("listen_thread: stopped");
    return NULL;
}

/* ============================================================================
 * Broadcast Thread
 * ============================================================================ */

static void* discovery_broadcast_thread(void* arg) {
    Discovery* disc = (Discovery*)arg;
    if (!disc) return NULL;
    
    DLOG("broadcast_thread: started");
    
    while (disc->running) {
        sleep(DISCOVERY_BROADCAST_INTERVAL);
        
        /* Clean up stale peers */
        discovery_cleanup_stale(disc);
        
        /* Broadcast presence if identity is set */
        if (strlen(g_my_identity.id) > 0 && strlen(g_my_identity.ip) > 0) {
            char endpoint[DISCOVERY_MAX_ENDPOINT_LEN];
            snprintf(endpoint, sizeof(endpoint), "%s:%d", 
                     g_my_identity.ip, g_my_identity.port);
            discovery_broadcast_presence(disc, g_my_identity.id, endpoint);
        }
    }
    
    DLOG("broadcast_thread: stopped");
    return NULL;
}

/* ============================================================================
 * Utility
 * ============================================================================ */

char* discovery_get_local_ip(void) {
    static char ip[DISCOVERY_MAX_IP_LEN];
    struct ifaddrs* ifaddr;
    
    if (getifaddrs(&ifaddr) == -1) {
        strcpy(ip, "127.0.0.1");
        return ip;
    }
    
    for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(ifa->ifa_name, "lo") == 0) continue;
        
        struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        freeifaddrs(ifaddr);
        return ip;
    }
    
    freeifaddrs(ifaddr);
    strcpy(ip, "127.0.0.1");
    return ip;
}
