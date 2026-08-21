 // discovery.c - Full version with ORCA Identity and Crypto integration
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

#define BUFFER_SIZE 4096
#define BROADCAST_INTERVAL 30

#define DEBUG_DISCOVERY 1

#if DEBUG_DISCOVERY
#define DLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[DISCOVERY DEBUG] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define DLOG(fmt, ...) ((void)0)
#endif

static void* listen_loop(void* arg);
static void* broadcast_loop(void* arg);
static void parse_message(Discovery* disc, const char* msg, const char* sender_ip, int sender_port);
static void send_udp(Discovery* disc, const char* msg, const char* ip, int port);

static void handle_presence(Discovery* disc, const char* msg, const char* sender_ip);
static void handle_who_has(Discovery* disc, const char* msg, const char* sender_ip);
static void handle_i_am(Discovery* disc, const char* msg, const char* sender_ip);
static void handle_add_request(Discovery* disc, const char* msg, const char* sender_ip, int sender_port);
static void handle_add_request_ack(Discovery* disc, const char* msg);
static void handle_search(Discovery* disc, const char* msg, const char* sender_ip);

static char g_my_id[64] = {0};
static char g_my_ip[64] = {0};
static int g_my_port = 9000;
static bool g_my_secure = false;
static char g_my_public_key[ORCA_PUBKEY_LEN] = {0};
static char g_my_signature[ORCA_SIG_LEN] = {0};
static char g_my_name[128] = {0};
static char g_my_role[32] = {0};
static time_t g_my_created_at = 0;

static RequestManager* g_request_manager = NULL;
static Registry* g_registry = NULL;

static void normalize_id(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return;
    
    size_t i = 0, j = 0;
    size_t len = strlen(input);
    
    for (i = 0; i < len && j < out_size - 1; i++) {
        if (input[i] != '<' && input[i] != '>') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

static void extract_ip_from_endpoint(const char* endpoint, char* ip_out, size_t out_size) {
    if (!endpoint || !ip_out || out_size == 0) return;
    
    const char* port_colon = strchr(endpoint, ':');
    if (port_colon) {
        int ip_len = port_colon - endpoint;
        if (ip_len < (int)out_size - 1) {
            strncpy(ip_out, endpoint, ip_len);
            ip_out[ip_len] = '\0';
        } else {
            strncpy(ip_out, endpoint, out_size - 1);
            ip_out[out_size - 1] = '\0';
        }
    } else {
        strncpy(ip_out, endpoint, out_size - 1);
        ip_out[out_size - 1] = '\0';
    }
}

void discovery_set_my_identity(Discovery* disc, const char* id, const char* ip, int port) {
    (void)disc;
    if (id) strcpy(g_my_id, id);
    if (ip) strcpy(g_my_ip, ip);
    g_my_port = port;
    g_my_secure = false;
    memset(g_my_role, 0, sizeof(g_my_role));
    g_my_created_at = 0;
    DLOG("Identity set: ID='%s' IP='%s' PORT=%d (NORMAL)", g_my_id, g_my_ip, g_my_port);
}

void discovery_set_my_secure_identity(Discovery* disc, const OrcaIdentity* identity) {
    (void)disc;
    if (!identity) return;
    
    strcpy(g_my_id, identity->id);
    strcpy(g_my_name, identity->name);
    strcpy(g_my_role, identity->role);
    strcpy(g_my_public_key, identity->public_key);
    strcpy(g_my_signature, identity->signature);
    g_my_created_at = identity->created_at;
    g_my_secure = true;
    DLOG("Secure identity set: ID='%s' NAME='%s' ROLE='%s' CREATED=%ld", 
         g_my_id, g_my_name, g_my_role, (long)g_my_created_at);
}

void discovery_set_request_manager(RequestManager* rm) {
    g_request_manager = rm;
    DLOG("RequestManager set");
}

void discovery_set_registry(Registry* reg) {
    g_registry = reg;
    DLOG("Registry set");
}

Discovery* discovery_create(void) {
    Discovery* disc = (Discovery*)calloc(1, sizeof(Discovery));
    if (!disc) return NULL;
    
    disc->udp_socket = -1;
    disc->port = DISCOVERY_PORT;
    disc->running = false;
    disc->peer_count = 0;
    disc->pending_count = 0;
    
    pthread_mutex_init(&disc->mutex, NULL);
    
    DLOG("Discovery created");
    return disc;
}

void discovery_destroy(Discovery* disc) {
    if (!disc) return;
    
    discovery_stop(disc);
    
    if (disc->udp_socket >= 0) {
        close(disc->udp_socket);
        disc->udp_socket = -1;
    }
    
    pthread_mutex_destroy(&disc->mutex);
    free(disc);
    
    DLOG("Discovery destroyed");
}

bool discovery_init(Discovery* disc, int port) {
    if (!disc) return false;
    
    disc->port = port;
    
    disc->udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (disc->udp_socket < 0) {
        fprintf(stderr, "[ERROR] Failed to create UDP socket!\n");
        return false;
    }
    
    int opt = 1;
    setsockopt(disc->udp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(disc->udp_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[ERROR] Failed to bind UDP socket to port %d!\n", port);
        close(disc->udp_socket);
        disc->udp_socket = -1;
        return false;
    }
    
    DLOG("Discovery initialized on port %d, socket=%d", port, disc->udp_socket);
    return true;
}

void discovery_start(Discovery* disc) {
    if (!disc || disc->running) return;
    
    disc->running = true;
    pthread_create(&disc->listen_thread, NULL, listen_loop, disc);
    pthread_create(&disc->broadcast_thread, NULL, broadcast_loop, disc);
    
    DLOG("Discovery started! listen_thread=%lu, broadcast_thread=%lu", 
         (unsigned long)disc->listen_thread, (unsigned long)disc->broadcast_thread);
}

void discovery_stop(Discovery* disc) {
    if (!disc || !disc->running) return;
    
    disc->running = false;
    
    if (disc->listen_thread) {
        pthread_join(disc->listen_thread, NULL);
        disc->listen_thread = 0;
    }
    if (disc->broadcast_thread) {
        pthread_join(disc->broadcast_thread, NULL);
        disc->broadcast_thread = 0;
    }
    
    DLOG("Discovery stopped");
}

void discovery_broadcast_presence(Discovery* disc, const char* id, const char* endpoint) {
    if (!disc) return;
    
    char msg[1024];
    if (g_my_secure) {
        snprintf(msg, sizeof(msg), "ORCA_PRESENCE:SECURE:%s:%s:%s:%s:%s",
                 id, endpoint, g_my_name, g_my_public_key, g_my_signature);
    } else {
        snprintf(msg, sizeof(msg), "ORCA_PRESENCE:%s:%s", id, endpoint);
    }
    
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
    broadcast_addr.sin_port = htons(disc->port);
    
    int broadcast = 1;
    setsockopt(disc->udp_socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
    
    DLOG("Broadcasting presence: %s", msg);
    
    sendto(disc->udp_socket, msg, strlen(msg), 0,
           (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
}

void discovery_broadcast_search(Discovery* disc, const char* id) {
    if (!disc) return;
    
    char msg[512];
    snprintf(msg, sizeof(msg), "ORCA_SEARCH:%s", id);
    
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
    broadcast_addr.sin_port = htons(disc->port);
    
    int broadcast = 1;
    setsockopt(disc->udp_socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
    
    DLOG("Broadcasting search for: %s", id);
    
    sendto(disc->udp_socket, msg, strlen(msg), 0,
           (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
}

void discovery_query_peer(Discovery* disc, const char* id) {
    if (!disc || !id) return;
    
    char norm_id[64];
    normalize_id(id, norm_id, sizeof(norm_id));
    
    char msg[512];
    snprintf(msg, sizeof(msg), "WHO_HAS:%s", norm_id);
    
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
    broadcast_addr.sin_port = htons(disc->port);
    
    int broadcast = 1;
    setsockopt(disc->udp_socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
    
    DLOG("Querying for peer: %s (normalized from %s)", norm_id, id);
    
    int sent = sendto(disc->udp_socket, msg, strlen(msg), 0,
                      (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
    if (sent < 0) {
        DLOG("sendto() FAILED: errno=%d (%s)", errno, strerror(errno));
    } else {
        DLOG("sendto() SUCCESS: sent %d bytes", sent);
    }
}

void discovery_send_add_request_with_ack(Discovery* disc, const char* target_id, 
                                         const char* my_id, const char* my_ip, int my_port) {
    if (!disc || !target_id || !my_id) return;
    
    char norm_target[64], norm_my[64];
    normalize_id(target_id, norm_target, sizeof(norm_target));
    normalize_id(my_id, norm_my, sizeof(norm_my));
    
    char msg[2048];
    if (g_my_secure) {
        snprintf(msg, sizeof(msg), "ADD_REQUEST:SECURE:%s:%s:%s:%d:%s:%s:%s",
                 norm_target, norm_my, my_ip, my_port,
                 g_my_name, g_my_public_key, g_my_signature);
    } else {
        snprintf(msg, sizeof(msg), "ADD_REQUEST:%s:%s:%s:%d",
                 norm_target, norm_my, my_ip, my_port);
    }
    
    PeerInfo peer;
    if (!discovery_find_peer(disc, target_id, &peer)) {
        DLOG("Peer %s not found in discovery, trying registry...", target_id);
        
        RegistryPeer reg_peer;
        if (g_registry && registry_get_peer(g_registry, target_id, &reg_peer)) {
            DLOG("Found peer %s in registry: %s:%s", target_id, reg_peer.ip, reg_peer.port);
            strcpy(peer.id, target_id);
            strcpy(peer.ip, reg_peer.ip);
            peer.port = atoi(reg_peer.port);
            peer.online = true;
        } else {
            DLOG("Cannot send ADD_REQUEST: peer %s not found", target_id);
            printf("[ORCA] Peer %s not found\n", target_id);
            return;
        }
    }
    
    DLOG("Sending ADD_REQUEST to %s (%s:%d)", target_id, peer.ip, peer.port);
    printf("[ORCA] Sending friend request to %s...\n", target_id);
    
    send_udp(disc, msg, peer.ip, DISCOVERY_PORT);
    DLOG("ADD_REQUEST sent to %s (%s:%d)", target_id, peer.ip, peer.port);
    printf("[ORCA] Friend request sent to %s\n", target_id);
}

void discovery_send_add_request_ack(Discovery* disc, const char* target_id, const char* from_id) {
    if (!disc || !target_id || !from_id) return;
    
    char norm_target[64], norm_from[64];
    normalize_id(target_id, norm_target, sizeof(norm_target));
    normalize_id(from_id, norm_from, sizeof(norm_from));
    
    char msg[512];
    snprintf(msg, sizeof(msg), "ADD_REQUEST_ACK:%s:%s", norm_target, norm_from);
    
    PeerInfo peer;
    if (!discovery_find_peer(disc, target_id, &peer)) {
        DLOG("Cannot send ADD_REQUEST_ACK: peer %s not found", target_id);
        return;
    }
    
    send_udp(disc, msg, peer.ip, DISCOVERY_PORT);
    DLOG("ADD_REQUEST_ACK sent to %s (%s:%d): %s", target_id, peer.ip, peer.port, msg);
}

static void send_udp(Discovery* disc, const char* msg, const char* ip, int port) {
    if (!disc || !msg || !ip) return;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    DLOG("Sending UDP to %s:%d: '%s'", ip, port, msg);
    
    sendto(disc->udp_socket, msg, strlen(msg), 0,
           (struct sockaddr*)&addr, sizeof(addr));
}

/* ============================================================================
 * PENDING REQUESTS - Add/remove from pending queue
 * ============================================================================ */

void discovery_push_pending(Discovery* disc, const char* from_id, const char* from_ip, int from_port) {
    if (!disc || !from_id) return;
    
    pthread_mutex_lock(&disc->mutex);
    
    for (int i = 0; i < disc->pending_count; i++) {
        if (strcmp(disc->pending_requests[i].from_id, from_id) == 0) {
            DLOG("Pending request from %s already exists, updating", from_id);
            strcpy(disc->pending_requests[i].from_ip, from_ip);
            disc->pending_requests[i].from_port = from_port;
            pthread_mutex_unlock(&disc->mutex);
            return;
        }
    }
    
    if (disc->pending_count < MAX_PEERS) {
        PendingRequest* req = &disc->pending_requests[disc->pending_count++];
        strcpy(req->from_id, from_id);
        strcpy(req->from_ip, from_ip);
        req->from_port = from_port;
        DLOG("Pending request pushed: %s at %s:%d (total: %d)", from_id, from_ip, from_port, disc->pending_count);
    } else {
        DLOG("Pending queue full! Cannot add %s", from_id);
    }
    
    pthread_mutex_unlock(&disc->mutex);
}

bool discovery_pop_pending(Discovery* disc, PendingRequest* out) {
    if (!disc || !out) return false;
    
    pthread_mutex_lock(&disc->mutex);
    
    if (disc->pending_count == 0) {
        pthread_mutex_unlock(&disc->mutex);
        return false;
    }
    
    *out = disc->pending_requests[0];
    
    for (int i = 0; i < disc->pending_count - 1; i++) {
        disc->pending_requests[i] = disc->pending_requests[i + 1];
    }
    disc->pending_count--;
    
    DLOG("Pop pending request from %s, remaining: %d", out->from_id, disc->pending_count);
    
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
 * parse_message - Message parser
 * ============================================================================ */
static void parse_message(Discovery* disc, const char* msg, const char* sender_ip, int sender_port) {
    (void)sender_port;
    
    DLOG("parse_message: '%s' from %s", msg, sender_ip);
    
    if (strlen(g_my_ip) > 0 && strcmp(sender_ip, g_my_ip) == 0) {
        DLOG("Skipping self-message from %s", sender_ip);
        return;
    }
    
    if (strncmp(msg, "ORCA_PRESENCE:", 14) == 0) {
        DLOG("Handling ORCA_PRESENCE");
        handle_presence(disc, msg, sender_ip);
    }
    else if (strncmp(msg, "WHO_HAS:", 8) == 0) {
        DLOG("Handling WHO_HAS");
        handle_who_has(disc, msg, sender_ip);
    }
    else if (strncmp(msg, "I_AM:", 5) == 0) {
        DLOG("Handling I_AM");
        handle_i_am(disc, msg, sender_ip);
    }
    else if (strncmp(msg, "ADD_REQUEST:", 12) == 0) {
        DLOG("Handling ADD_REQUEST");
        handle_add_request(disc, msg, sender_ip, sender_port);
    }
    else if (strncmp(msg, "ADD_REQUEST_ACK:", 16) == 0) {
        DLOG("Handling ADD_REQUEST_ACK");
        handle_add_request_ack(disc, msg);
    }
    else if (strncmp(msg, "ORCA_SEARCH:", 12) == 0) {
        DLOG("Handling ORCA_SEARCH");
        handle_search(disc, msg, sender_ip);
    } else {
        DLOG("Unknown message type: '%s'", msg);
    }
}

/* ============================================================================
 * handle_presence - Handle ORCA_PRESENCE
 * ============================================================================ */
static void handle_presence(Discovery* disc, const char* msg, const char* sender_ip) {
    (void)sender_ip;
    
    const char* rest = msg + 14;
    bool is_secure = false;
    
    if (strncmp(rest, "SECURE:", 7) == 0) {
        is_secure = true;
        rest += 7;
    }
    
    const char* colon = strchr(rest, ':');
    if (!colon) return;
    
    char id[64];
    char endpoint[128];
    int id_len = colon - rest;
    strncpy(id, rest, id_len);
    id[id_len] = '\0';
    strcpy(endpoint, colon + 1);
    
    char peer_ip[INET_ADDRSTRLEN];
    extract_ip_from_endpoint(endpoint, peer_ip, sizeof(peer_ip));
    
    DLOG("ORCA_PRESENCE: id='%s', endpoint='%s', peer_ip='%s', secure=%d", 
         id, endpoint, peer_ip, is_secure);
    
    char name[128] = {0};
    char public_key[ORCA_PUBKEY_LEN] = {0};
    char signature[ORCA_SIG_LEN] = {0};
    
    if (is_secure) {
        const char* name_start = strchr(colon + 1, ':');
        if (name_start) {
            name_start++;
            const char* name_end = strchr(name_start, ':');
            if (name_end) {
                int len = name_end - name_start;
                if (len < (int)sizeof(name)) {
                    strncpy(name, name_start, len);
                    name[len] = '\0';
                }
                const char* pk_start = name_end + 1;
                const char* pk_end = strchr(pk_start, ':');
                if (pk_end) {
                    int pk_len = pk_end - pk_start;
                    if (pk_len < (int)sizeof(public_key)) {
                        strncpy(public_key, pk_start, pk_len);
                        public_key[pk_len] = '\0';
                    }
                    strcpy(signature, pk_end + 1);
                }
            }
        }
    }
    
    pthread_mutex_lock(&disc->mutex);
    
    int found = -1;
    for (int i = 0; i < disc->peer_count; i++) {
        if (strcmp(disc->peers[i].id, id) == 0) {
            found = i;
            break;
        }
    }
    
    if (found == -1 && disc->peer_count < MAX_PEERS) {
        found = disc->peer_count++;
        DLOG("Added new peer slot %d", found);
    }
    
    if (found >= 0) {
        PeerInfo* peer = &disc->peers[found];
        strcpy(peer->id, id);
        strcpy(peer->endpoint, endpoint);
        strcpy(peer->ip, sender_ip);
        peer->last_seen = time(NULL);
        peer->online = true;
        peer->is_secure = is_secure;
        
        if (is_secure) {
            strcpy(peer->name, name);
            strcpy(peer->public_key, public_key);
            strcpy(peer->signature, signature);
            peer->verified = true;
        }
        
        char* port_colon = strchr(endpoint, ':');
        if (port_colon) {
            peer->port = atoi(port_colon + 1);
        } else {
            peer->port = 9000;
        }
        
        DLOG("Peer updated: %s at %s:%d (secure=%d)", id, peer->ip, peer->port, is_secure);
        
        if (disc->on_peer_found) {
            disc->on_peer_found(peer);
        }
    }
    
    pthread_mutex_unlock(&disc->mutex);
}

/* ============================================================================
 * handle_who_has - Respond to WHO_HAS with I_AM
 * ============================================================================ */
static void handle_who_has(Discovery* disc, const char* msg, const char* sender_ip) {
    const char* search_id = msg + 8;
    
    char norm_search[64], norm_my[64];
    normalize_id(search_id, norm_search, sizeof(norm_search));
    normalize_id(g_my_id, norm_my, sizeof(norm_my));
    
    DLOG("WHO_HAS: search='%s' (normalized='%s'), my='%s' (normalized='%s')", 
         search_id, norm_search, g_my_id, norm_my);
    
    if (strlen(norm_my) > 0 && strcmp(norm_search, norm_my) == 0) {
        DLOG("MATCH! Responding with I_AM");
        
        char response[2048];
        if (g_my_secure) {
            snprintf(response, sizeof(response), 
                    "I_AM:SECURE:%s:%s:%s:%ld:%s:%d:%s:%s", 
                    g_my_id,
                    g_my_name,
                    g_my_role,
                    (long)g_my_created_at,
                    g_my_ip,
                    g_my_port,
                    g_my_public_key,
                    g_my_signature);
        } else {
            snprintf(response, sizeof(response), 
                    "I_AM:%s:%s:%d", 
                    g_my_id, g_my_ip, g_my_port);
        }
        
        DLOG("Sending I_AM to %s:%d", sender_ip, DISCOVERY_PORT);
        
        send_udp(disc, response, sender_ip, DISCOVERY_PORT);
        
        DLOG("Responded to WHO_HAS: %s -> %s:%d", search_id, g_my_ip, g_my_port);
    } else {
        DLOG("No match: '%s' != '%s'", norm_search, norm_my);
    }
}

/* ============================================================================
 * handle_i_am - Store discovered peer in cache (NOT registry!)
 * ============================================================================ */
static void handle_i_am(Discovery* disc, const char* msg, const char* sender_ip) {
    const char* rest = msg + 5;
    bool is_secure = false;
    
    if (strncmp(rest, "SECURE:", 7) == 0) {
        is_secure = true;
        rest += 7;
    }
    
    if (!is_secure) {
        const char* colon1 = strchr(rest, ':');
        const char* colon2 = colon1 ? strchr(colon1 + 1, ':') : NULL;
        
        if (!colon1 || !colon2) return;
        
        char id[64];
        char payload_ip[INET_ADDRSTRLEN];
        int port;
        
        int id_len = colon1 - rest;
        strncpy(id, rest, id_len);
        id[id_len] = '\0';
        
        int ip_len = colon2 - colon1 - 1;
        strncpy(payload_ip, colon1 + 1, ip_len);
        payload_ip[ip_len] = '\0';
        
        port = atoi(colon2 + 1);
        
        DLOG("I_AM (normal): id='%s', payload_ip='%s', port=%d", id, payload_ip, port);
        
        pthread_mutex_lock(&disc->mutex);
        
        int found = -1;
        for (int i = 0; i < disc->peer_count; i++) {
            if (strcmp(disc->peers[i].id, id) == 0) {
                found = i;
                break;
            }
        }
        
        if (found == -1 && disc->peer_count < MAX_PEERS) {
            found = disc->peer_count++;
        }
        
        if (found >= 0) {
            PeerInfo* peer = &disc->peers[found];
            strcpy(peer->id, id);
            strcpy(peer->ip, sender_ip);
            peer->port = port;
            peer->online = true;
            peer->last_seen = time(NULL);
            peer->is_secure = false;
            peer->verified = false;
            snprintf(peer->endpoint, sizeof(peer->endpoint), "%s:%d", sender_ip, port);
            
            DLOG("I_AM (normal) stored in cache: %s at %s:%d", id, peer->ip, peer->port);
        }
        
        pthread_mutex_unlock(&disc->mutex);
        return;
    }
    
    /* ===== SECURE I_AM ===== */
    const char* id_start = rest;
    const char* id_end = strchr(id_start, ':');
    if (!id_end) return;
    char id[64];
    int id_len = id_end - id_start;
    strncpy(id, id_start, id_len);
    id[id_len] = '\0';
    
    const char* name_start = id_end + 1;
    const char* name_end = strchr(name_start, ':');
    if (!name_end) return;
    char name[128];
    int name_len = name_end - name_start;
    strncpy(name, name_start, name_len);
    name[name_len] = '\0';
    
    const char* role_start = name_end + 1;
    const char* role_end = strchr(role_start, ':');
    if (!role_end) return;
    char role[32];
    int role_len = role_end - role_start;
    strncpy(role, role_start, role_len);
    role[role_len] = '\0';
    
    const char* created_at_start = role_end + 1;
    const char* created_at_end = strchr(created_at_start, ':');
    if (!created_at_end) return;
    time_t created_at = atol(created_at_start);
    
    const char* ip_start = created_at_end + 1;
    const char* ip_end = strchr(ip_start, ':');
    if (!ip_end) return;
    char payload_ip[INET_ADDRSTRLEN];
    int ip_len2 = ip_end - ip_start;
    strncpy(payload_ip, ip_start, ip_len2);
    payload_ip[ip_len2] = '\0';
    
    const char* port_start = ip_end + 1;
    const char* port_end = strchr(port_start, ':');
    if (!port_end) return;
    int port = atoi(port_start);
    
    const char* pk_start = port_end + 1;
    const char* pk_end = strchr(pk_start, ':');
    if (!pk_end) return;
    char public_key[ORCA_PUBKEY_LEN];
    int pk_len = pk_end - pk_start;
    strncpy(public_key, pk_start, pk_len);
    public_key[pk_len] = '\0';
    
    const char* signature_start = pk_end + 1;
    char signature[ORCA_SIG_LEN];
    strncpy(signature, signature_start, sizeof(signature) - 1);
    signature[sizeof(signature) - 1] = '\0';
    
    DLOG("I_AM: id='%s', name='%s', role='%s', created_at=%ld, payload_ip='%s', port=%d", 
         id, name, role, (long)created_at, payload_ip, port);
    DLOG("I_AM: sender_ip='%s'", sender_ip);
    
    if (strlen(public_key) == 0 || strlen(signature) == 0) {
        DLOG("Missing public_key or signature — REJECTED");
        return;
    }
    
    char data_to_verify[1024];
    snprintf(data_to_verify, sizeof(data_to_verify), "%s|%s|%s|%ld",
             id, name, role, (long)created_at);
    
    DLOG("Verifying identity data: '%s'", data_to_verify);
    
    if (!orca_rsa_verify_string(data_to_verify, signature, public_key)) {
        DLOG("Invalid identity signature from %s — REJECTED", id);
        return;
    }
    
    DLOG("Identity signature verified: %s", id);
    
    /* ===== Store in discovery cache ONLY (NOT registry!) ===== */
    pthread_mutex_lock(&disc->mutex);
    
    int found = -1;
    for (int i = 0; i < disc->peer_count; i++) {
        if (strcmp(disc->peers[i].id, id) == 0) {
            found = i;
            break;
        }
    }
    
    if (found == -1 && disc->peer_count < MAX_PEERS) {
        found = disc->peer_count++;
    }
    
    if (found >= 0) {
        PeerInfo* peer = &disc->peers[found];
        strcpy(peer->id, id);
        strcpy(peer->name, name);
        strcpy(peer->ip, sender_ip);
        peer->port = port;
        peer->online = true;
        peer->last_seen = time(NULL);
        peer->is_secure = true;
        peer->verified = true;
        strcpy(peer->public_key, public_key);
        strcpy(peer->signature, signature);
        
        snprintf(peer->endpoint, sizeof(peer->endpoint), "%s:%d", sender_ip, port);
        
        DLOG("I_AM stored in cache: %s at %s:%d (secure)", id, peer->ip, peer->port);
        
        if (disc->on_peer_found) {
            disc->on_peer_found(peer);
        }
    }
    
    pthread_mutex_unlock(&disc->mutex);
}

/* ============================================================================
 * handle_add_request - Handle friend request, push to pending queue
 * ============================================================================ */
static void handle_add_request(Discovery* disc, const char* msg, const char* sender_ip, int sender_port) {
    (void)sender_ip;
    (void)sender_port;
    
    const char* rest = msg + 12;
    bool is_secure = false;
    
    if (strncmp(rest, "SECURE:", 7) == 0) {
        is_secure = true;
        rest += 7;
    }
    
    const char* colon1 = strchr(rest, ':');
    const char* colon2 = colon1 ? strchr(colon1 + 1, ':') : NULL;
    const char* colon3 = colon2 ? strchr(colon2 + 1, ':') : NULL;
    
    if (!colon1 || !colon2 || !colon3) return;
    
    char target_id[64], from_id[64], from_ip[INET_ADDRSTRLEN];
    int from_port;
    char from_name[128] = {0};
    char public_key[ORCA_PUBKEY_LEN] = {0};
    char signature[ORCA_SIG_LEN] = {0};
    
    int len = colon1 - rest;
    strncpy(target_id, rest, len);
    target_id[len] = '\0';
    
    len = colon2 - colon1 - 1;
    strncpy(from_id, colon1 + 1, len);
    from_id[len] = '\0';
    
    len = colon3 - colon2 - 1;
    strncpy(from_ip, colon2 + 1, len);
    from_ip[len] = '\0';
    
    from_port = atoi(colon3 + 1);
    
    if (is_secure) {
        const char* secure_rest = colon3 + 1;
        const char* name_start = strchr(secure_rest, ':');
        if (name_start) {
            name_start++;
            const char* name_end = strchr(name_start, ':');
            if (name_end) {
                int name_len = name_end - name_start;
                if (name_len < (int)sizeof(from_name)) {
                    strncpy(from_name, name_start, name_len);
                    from_name[name_len] = '\0';
                }
                const char* pk_start = name_end + 1;
                const char* pk_end = strchr(pk_start, ':');
                if (pk_end) {
                    int pk_len = pk_end - pk_start;
                    if (pk_len < (int)sizeof(public_key)) {
                        strncpy(public_key, pk_start, pk_len);
                        public_key[pk_len] = '\0';
                    }
                    strcpy(signature, pk_end + 1);
                }
            }
        }
    }
    
    DLOG("ADD_REQUEST: target=%s, from=%s at %s:%d, secure=%d", 
         target_id, from_id, from_ip, from_port, is_secure);
    
    if (is_secure) {
        if (strlen(public_key) == 0 || strlen(signature) == 0) {
            DLOG("Missing public_key or signature — REJECTED");
            return;
        }
        
        char data_to_verify[1024];
        snprintf(data_to_verify, sizeof(data_to_verify), "%s|%s|%s|%d", 
                 target_id, from_id, from_ip, from_port);
        
        if (!orca_rsa_verify_string(data_to_verify, signature, public_key)) {
            DLOG("Invalid signature in ADD_REQUEST from %s — REJECTED", from_id);
            return;
        }
        DLOG("Signature verified for ADD_REQUEST from %s", from_id);
    }
    
    char norm_target[64], norm_my[64];
    normalize_id(target_id, norm_target, sizeof(norm_target));
    normalize_id(g_my_id, norm_my, sizeof(norm_my));
    
    if (strcmp(norm_target, norm_my) == 0) {
        /* ===== This is for ME! ===== */
        DLOG("ADD_REQUEST is for me! From: %s", from_id);
        
        /* Send ACK back */
        discovery_send_add_request_ack(disc, from_id, g_my_id);
        
        /* ===== Store in request manager (pending) ===== */
        if (g_request_manager) {
            request_send(g_request_manager, from_id, g_my_id);
            DLOG("ADD_REQUEST saved to request.json from %s", from_id);
        }
        
        /* ===== Store in discovery cache ===== */
        pthread_mutex_lock(&disc->mutex);
        
        int found = -1;
        for (int i = 0; i < disc->peer_count; i++) {
            if (strcmp(disc->peers[i].id, from_id) == 0) {
                found = i;
                break;
            }
        }
        
        if (found == -1 && disc->peer_count < MAX_PEERS) {
            found = disc->peer_count++;
        }
        
        if (found >= 0) {
            PeerInfo* peer = &disc->peers[found];
            strcpy(peer->id, from_id);
            strcpy(peer->ip, sender_ip);
            peer->port = from_port;
            peer->online = true;
            peer->last_seen = time(NULL);
            peer->is_secure = is_secure;
            
            if (is_secure) {
                strcpy(peer->name, from_name);
                strcpy(peer->public_key, public_key);
                strcpy(peer->signature, signature);
                peer->verified = true;
            }
            
            snprintf(peer->endpoint, sizeof(peer->endpoint), "%s:%d", sender_ip, from_port);
            
            DLOG("ADD_REQUEST: stored peer %s in cache at %s:%d", from_id, sender_ip, from_port);
        }
        
        pthread_mutex_unlock(&disc->mutex);
        
        /* ===== Push to pending queue for y/n prompt ===== */
        discovery_push_pending(disc, from_id, sender_ip, from_port);
        DLOG("ADD_REQUEST: pushed to pending queue, pending_count=%d", disc->pending_count);
        
        /* ===== Print notification ===== */
        printf("\n[ORCA] ========================================\n");
        printf("[ORCA] Friend request from %s (%s:%d)\n", from_id, sender_ip, from_port);
        if (is_secure) {
            printf("[ORCA] Secure identity: %s\n", from_name);
        }
        printf("[ORCA] ========================================\n");
        printf("[ORCA] Press Enter to accept or Ctrl+C to ignore\n");
        fflush(stdout);
        
    } else {
        DLOG("ADD_REQUEST not for us: target=%s, my=%s", target_id, g_my_id);
    }
}

/* ============================================================================
 * handle_add_request_ack - Handle ACK from peer
 * ============================================================================ */
static void handle_add_request_ack(Discovery* disc, const char* msg) {
    const char* rest = msg + 16;
    const char* colon1 = strchr(rest, ':');
    
    if (!colon1) return;
    
    char target_id[64], from_id[64];
    
    int len = colon1 - rest;
    strncpy(target_id, rest, len);
    target_id[len] = '\0';
    
    strcpy(from_id, colon1 + 1);
    
    DLOG("ADD_REQUEST_ACK: target=%s, from=%s", target_id, from_id);
    
    char norm_target[64], norm_my[64];
    normalize_id(target_id, norm_target, sizeof(norm_target));
    normalize_id(g_my_id, norm_my, sizeof(norm_my));
    
    if (strcmp(norm_target, norm_my) == 0) {
        DLOG("ADD_REQUEST_ACK: request delivered to %s", target_id);
        printf("[ORCA] Friend request delivered to %s\n", target_id);
        
        pthread_mutex_lock(&disc->mutex);
        
        for (int i = 0; i < disc->peer_count; i++) {
            if (strcmp(disc->peers[i].id, from_id) == 0) {
                disc->peers[i].online = true;
                disc->peers[i].last_seen = time(NULL);
                DLOG("Peer %s marked online (ACK received)", from_id);
                break;
            }
        }
        
        pthread_mutex_unlock(&disc->mutex);
    }
}

/* ============================================================================
 * handle_search - Handle ORCA_SEARCH
 * ============================================================================ */
static void handle_search(Discovery* disc, const char* msg, const char* sender_ip) {
    const char* search_id = msg + 12;
    
    char norm_search[64], norm_my[64];
    normalize_id(search_id, norm_search, sizeof(norm_search));
    normalize_id(g_my_id, norm_my, sizeof(norm_my));
    
    DLOG("ORCA_SEARCH: '%s' (normalized='%s')", search_id, norm_search);
    
    if (strlen(norm_my) > 0 && strcmp(norm_search, norm_my) == 0) {
        char response[1024];
        if (g_my_secure) {
            snprintf(response, sizeof(response), 
                    "ORCA_PRESENCE:SECURE:%s:%s:%d:%s:%s:%s", 
                    g_my_id, g_my_ip, g_my_port,
                    g_my_name, g_my_public_key, g_my_signature);
        } else {
            snprintf(response, sizeof(response), 
                    "ORCA_PRESENCE:%s:%s:%d", 
                    g_my_id, g_my_ip, g_my_port);
        }
        
        DLOG("MATCH! Sending ORCA_PRESENCE response");
        send_udp(disc, response, sender_ip, DISCOVERY_PORT);
    } else {
        DLOG("No match for ORCA_SEARCH");
    }
}

/* ============================================================================
 * discovery_find_peer - Search discovery cache (NOT registry!)
 * ============================================================================ */
bool discovery_find_peer(Discovery* disc, const char* id, PeerInfo* out_peer) {
    if (!disc || !out_peer) return false;
    
    char norm_id[64];
    normalize_id(id, norm_id, sizeof(norm_id));
    
    DLOG("find_peer: looking for '%s' (normalized '%s')", id, norm_id);
    
    pthread_mutex_lock(&disc->mutex);
    
    DLOG("Current cache has %d peers:", disc->peer_count);
    for (int i = 0; i < disc->peer_count; i++) {
        DLOG("  peer[%d]: id='%s', ip='%s', port=%d, online=%d", 
             i, disc->peers[i].id, disc->peers[i].ip, 
             disc->peers[i].port, disc->peers[i].online);
    }
    
    for (int i = 0; i < disc->peer_count; i++) {
        char norm_peer_id[64];
        normalize_id(disc->peers[i].id, norm_peer_id, sizeof(norm_peer_id));
        
        if (strcmp(norm_peer_id, norm_id) == 0 && disc->peers[i].online) {
            *out_peer = disc->peers[i];
            pthread_mutex_unlock(&disc->mutex);
            DLOG("FOUND! %s at %s:%d", id, out_peer->ip, out_peer->port);
            return true;
        }
    }
    
    pthread_mutex_unlock(&disc->mutex);
    DLOG("find_peer: NOT FOUND");
    return false;
}

int discovery_get_peers(Discovery* disc, PeerInfo* peers, int max_peers) {
    if (!disc || !peers) return 0;
    
    pthread_mutex_lock(&disc->mutex);
    
    int count = 0;
    for (int i = 0; i < disc->peer_count && count < max_peers; i++) {
        if (disc->peers[i].online) {
            peers[count++] = disc->peers[i];
        }
    }
    
    pthread_mutex_unlock(&disc->mutex);
    
    DLOG("get_peers: returned %d peers", count);
    return count;
}

static time_t last_cleanup = 0;

void discovery_cleanup_stale(Discovery* disc) {
    if (!disc) return;
    
    time_t now = time(NULL);
    if (now - last_cleanup < 30) return;
    last_cleanup = now;
    
    pthread_mutex_lock(&disc->mutex);
    
    int stale_count = 0;
    for (int i = 0; i < disc->peer_count; i++) {
        if (now - disc->peers[i].last_seen > PEER_TIMEOUT) {
            disc->peers[i].online = false;
            stale_count++;
            DLOG("Peer %s marked offline (last seen %ld)", 
                 disc->peers[i].id, (long)disc->peers[i].last_seen);
            if (disc->on_peer_offline) {
                disc->on_peer_offline(&disc->peers[i]);
            }
        }
    }
    
    if (stale_count > 0) {
        DLOG("Cleaned up %d stale peers", stale_count);
    }
    
    pthread_mutex_unlock(&disc->mutex);
}

/* ============================================================================
 * listen_loop - UDP receive loop
 * ============================================================================ */
static void* listen_loop(void* arg) {
    Discovery* disc = (Discovery*)arg;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);
    fd_set fds;
    struct timeval tv;
    
    DLOG("Listen loop started - socket=%d", disc->udp_socket);
    
    while (disc->running) {
        FD_ZERO(&fds);
        FD_SET(disc->udp_socket, &fds);
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(disc->udp_socket + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            DLOG("select() error: %s", strerror(errno));
            break;
        }
        if (ret == 0) {
            discovery_cleanup_stale(disc);
            continue;
        }
        
        int n = recvfrom(disc->udp_socket, buffer, sizeof(buffer) - 1, 0,
                        (struct sockaddr*)&sender_addr, &addr_len);
        if (n <= 0) {
            DLOG("recvfrom() returned %d, errno=%d (%s)", n, errno, strerror(errno));
            continue;
        }
        
        buffer[n] = '\0';
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_addr.sin_addr, ip, sizeof(ip));
        int port = ntohs(sender_addr.sin_port);
        
        DLOG("RECEIVED %d bytes from %s:%d", n, ip, port);
        DLOG("  Raw: '%s'", buffer);
        
        parse_message(disc, buffer, ip, port);
    }
    
    DLOG("Listen loop stopped");
    return NULL;
}

static void* broadcast_loop(void* arg) {
    Discovery* disc = (Discovery*)arg;
    
    DLOG("Broadcast loop started");
    
    while (disc->running) {
        sleep(BROADCAST_INTERVAL);
        discovery_cleanup_stale(disc);
    }
    
    DLOG("Broadcast loop stopped");
    return NULL;
}

void discovery_set_on_peer_found(Discovery* disc, void (*callback)(PeerInfo*)) {
    if (disc) {
        disc->on_peer_found = callback;
        DLOG("on_peer_found callback set");
    }
}

void discovery_set_on_peer_offline(Discovery* disc, void (*callback)(PeerInfo*)) {
    if (disc) {
        disc->on_peer_offline = callback;
        DLOG("on_peer_offline callback set");
    }
}

char* discovery_get_local_ip(void) {
    static char ip[INET_ADDRSTRLEN];
    struct ifaddrs* ifaddr;
    
    if (getifaddrs(&ifaddr) == -1) {
        strcpy(ip, "127.0.0.1");
        DLOG("get_local_ip: failed, using 127.0.0.1");
        return ip;
    }
    
    for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(ifa->ifa_name, "lo") == 0) continue;
        
        struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        freeifaddrs(ifaddr);
        DLOG("get_local_ip: found %s on %s", ip, ifa->ifa_name);
        return ip;
    }
    
    freeifaddrs(ifaddr);
    strcpy(ip, "127.0.0.1");
    DLOG("get_local_ip: no interface found, using 127.0.0.1");
    return ip;
}
