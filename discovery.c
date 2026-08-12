 #define _POSIX_C_SOURCE 200809L

#include "discovery.h"
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 4096
#define BROADCAST_INTERVAL 30

// ===== DEBUG MACROS =====
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

static char g_my_id[64] = {0};
static char g_my_ip[64] = {0};
static int g_my_port = 9000;

// ===== HELPER: Remove < and > from ID =====
static void normalize_id(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return;
    
    size_t i = 0, j = 0;
    size_t len = strlen(input);
    
    DLOG("normalize_id: input='%s', len=%zu", input, len);
    
    for (i = 0; i < len && j < out_size - 1; i++) {
        if (input[i] != '<' && input[i] != '>') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
    
    DLOG("normalize_id: output='%s'", output);
}

// ===== SET IDENTITY =====
void discovery_set_my_identity(Discovery* disc, const char* id, const char* ip, int port) {
    (void)disc;
    if (id) strcpy(g_my_id, id);
    if (ip) strcpy(g_my_ip, ip);
    g_my_port = port;
    DLOG("Identity set: ID='%s' IP='%s' PORT=%d", g_my_id, g_my_ip, g_my_port);
}

// ===== CREATE =====
Discovery* discovery_create(void) {
    Discovery* disc = (Discovery*)calloc(1, sizeof(Discovery));
    if (!disc) return NULL;
    
    disc->udp_socket = -1;
    disc->port = DISCOVERY_PORT;
    disc->running = false;
    disc->peer_count = 0;
    
    pthread_mutex_init(&disc->mutex, NULL);
    
    DLOG("Discovery created");
    return disc;
}

// ===== DESTROY =====
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

// ===== INIT =====
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

// ===== START =====
void discovery_start(Discovery* disc) {
    if (!disc || disc->running) return;
    
    disc->running = true;
    pthread_create(&disc->listen_thread, NULL, listen_loop, disc);
    pthread_create(&disc->broadcast_thread, NULL, broadcast_loop, disc);
    
    DLOG("Discovery started! listen_thread=%lu, broadcast_thread=%lu", 
         (unsigned long)disc->listen_thread, (unsigned long)disc->broadcast_thread);
}

// ===== STOP =====
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

// ===== LISTEN LOOP =====
static void* listen_loop(void* arg) {
    Discovery* disc = (Discovery*)arg;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);
    fd_set fds;
    struct timeval tv;
    
    DLOG("Listen loop started");
    
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
        if (n <= 0) continue;
        
        buffer[n] = '\0';
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_addr.sin_addr, ip, sizeof(ip));
        int port = ntohs(sender_addr.sin_port);
        
        DLOG("Received %d bytes from %s:%d", n, ip, port);
        DLOG("  Raw: '%s'", buffer);
        
        parse_message(disc, buffer, ip, port);
    }
    
    DLOG("Listen loop stopped");
    return NULL;
}

// ===== BROADCAST LOOP =====
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

// ===== BROADCAST PRESENCE =====
void discovery_broadcast_presence(Discovery* disc, const char* id, const char* endpoint) {
    if (!disc) return;
    
    char msg[512];
    snprintf(msg, sizeof(msg), "ORCA_PRESENCE:%s:%s", id, endpoint);
    
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

// ===== BROADCAST SEARCH =====
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

// ===== ACTIVE QUERY =====
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
    
    sendto(disc->udp_socket, msg, strlen(msg), 0,
           (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
}

// ===== SEND UDP =====
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

// ===== PARSE MESSAGE =====
static void parse_message(Discovery* disc, const char* msg, const char* sender_ip, int sender_port) {
    (void)sender_port;
    
    DLOG("parse_message: '%s' from %s", msg, sender_ip);
    
    // Skip self
    if (strlen(g_my_ip) > 0 && strcmp(sender_ip, g_my_ip) == 0) {
        DLOG("Skipping self-message from %s", sender_ip);
        return;
    }
    
    // ===== HANDLE PRESENCE =====
    if (strncmp(msg, "ORCA_PRESENCE:", 14) == 0) {
        const char* rest = msg + 14;
        const char* colon = strchr(rest, ':');
        if (colon) {
            char id[64];
            char endpoint[128];
            int id_len = colon - rest;
            strncpy(id, rest, id_len);
            id[id_len] = '\0';
            strcpy(endpoint, colon + 1);
            
            DLOG("ORCA_PRESENCE: id='%s', endpoint='%s' from %s", id, endpoint, sender_ip);
            
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
                
                char* port_colon = strchr(endpoint, ':');
                if (port_colon) {
                    peer->port = atoi(port_colon + 1);
                } else {
                    peer->port = 9000;
                }
                
                DLOG("Peer updated: %s at %s:%d", id, peer->ip, peer->port);
                
                if (disc->on_peer_found) {
                    disc->on_peer_found(peer);
                }
            }
            
            pthread_mutex_unlock(&disc->mutex);
        }
    }
    
    // ===== HANDLE WHO_HAS =====
    if (strncmp(msg, "WHO_HAS:", 8) == 0) {
        const char* search_id = msg + 8;
        
        char norm_search[64], norm_my[64];
        normalize_id(search_id, norm_search, sizeof(norm_search));
        normalize_id(g_my_id, norm_my, sizeof(norm_my));
        
        DLOG("WHO_HAS: search='%s' (normalized='%s'), my='%s' (normalized='%s')", 
             search_id, norm_search, g_my_id, norm_my);
        
        if (strlen(norm_my) > 0 && strcmp(norm_search, norm_my) == 0) {
            char response[512];
            snprintf(response, sizeof(response), 
                    "I_AM:%s:%s:%d", 
                    g_my_id, g_my_ip, g_my_port);
            
            DLOG("MATCH! Sending I_AM: %s", response);
            
            send_udp(disc, response, sender_ip, DISCOVERY_PORT);
            
            DLOG("Responded to WHO_HAS: %s -> %s:%d", search_id, g_my_ip, g_my_port);
        } else {
            DLOG("No match: '%s' != '%s'", norm_search, norm_my);
        }
    }
    
    // ===== HANDLE I_AM =====
    if (strncmp(msg, "I_AM:", 5) == 0) {
        const char* rest = msg + 5;
        const char* colon1 = strchr(rest, ':');
        const char* colon2 = colon1 ? strchr(colon1 + 1, ':') : NULL;
        
        if (colon1 && colon2) {
            char id[64];
            char ip[INET_ADDRSTRLEN];
            int port;
            
            int id_len = colon1 - rest;
            strncpy(id, rest, id_len);
            id[id_len] = '\0';
            
            int ip_len = colon2 - colon1 - 1;
            strncpy(ip, colon1 + 1, ip_len);
            ip[ip_len] = '\0';
            
            port = atoi(colon2 + 1);
            
            DLOG("I_AM: id='%s', ip='%s', port=%d", id, ip, port);
            
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
                strcpy(peer->ip, ip);
                peer->port = port;
                peer->online = true;
                peer->last_seen = time(NULL);
                snprintf(peer->endpoint, sizeof(peer->endpoint), "%s:%d", ip, port);
                
                DLOG("I_AM stored: %s at %s:%d", id, ip, port);
            }
            
            pthread_mutex_unlock(&disc->mutex);
        }
    }
    
    // ===== HANDLE SEARCH =====
    if (strncmp(msg, "ORCA_SEARCH:", 12) == 0) {
        const char* search_id = msg + 12;
        
        char norm_search[64], norm_my[64];
        normalize_id(search_id, norm_search, sizeof(norm_search));
        normalize_id(g_my_id, norm_my, sizeof(norm_my));
        
        DLOG("ORCA_SEARCH: '%s' (normalized='%s')", search_id, norm_search);
        
        if (strlen(norm_my) > 0 && strcmp(norm_search, norm_my) == 0) {
            char response[512];
            snprintf(response, sizeof(response), 
                    "ORCA_PRESENCE:%s:%s:%d", 
                    g_my_id, g_my_ip, g_my_port);
            
            DLOG("MATCH! Sending ORCA_PRESENCE response: %s", response);
            
            send_udp(disc, response, sender_ip, DISCOVERY_PORT);
        } else {
            DLOG("No match for ORCA_SEARCH");
        }
    }
}

// ===== FIND PEER =====
bool discovery_find_peer(Discovery* disc, const char* id, PeerInfo* out_peer) {
    if (!disc || !out_peer) return false;
    
    char norm_id[64];
    normalize_id(id, norm_id, sizeof(norm_id));
    
    DLOG("find_peer: looking for '%s' (normalized '%s')", id, norm_id);
    
    pthread_mutex_lock(&disc->mutex);
    
    for (int i = 0; i < disc->peer_count; i++) {
        char norm_peer_id[64];
        normalize_id(disc->peers[i].id, norm_peer_id, sizeof(norm_peer_id));
        
        DLOG("  peer[%d]: '%s' (normalized '%s') online=%d", 
             i, disc->peers[i].id, norm_peer_id, disc->peers[i].online);
        
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

// ===== GET PEERS =====
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

// ===== CLEANUP STALE =====
void discovery_cleanup_stale(Discovery* disc) {
    if (!disc) return;
    
    time_t now = time(NULL);
    
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

// ===== GET LOCAL IP =====
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

// ===== CALLBACKS =====
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
