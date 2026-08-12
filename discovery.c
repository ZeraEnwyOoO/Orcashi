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

static void* listen_loop(void* arg);
static void* broadcast_loop(void* arg);
static void parse_message(Discovery* disc, const char* msg, const char* sender_ip, int sender_port);
static void send_udp(Discovery* disc, const char* msg, const char* ip, int port);

static char g_my_id[64] = {0};
static char g_my_ip[64] = {0};
static int g_my_port = 9000;

// ===== HELPER: Remove < and > from ID for comparison =====
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

// ===== SET IDENTITY =====
void discovery_set_my_identity(Discovery* disc, const char* id, const char* ip, int port) {
    (void)disc;
    if (id) strcpy(g_my_id, id);
    if (ip) strcpy(g_my_ip, ip);
    g_my_port = port;
    printf("[DEBUG] Discovery identity: ID=%s IP=%s PORT=%d\n", g_my_id, g_my_ip, g_my_port);
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

    printf("[ORCA] Discovery initialized on port %d\n", port);
    return true;
}

// ===== START =====
void discovery_start(Discovery* disc) {
    if (!disc || disc->running) return;

    disc->running = true;
    pthread_create(&disc->listen_thread, NULL, listen_loop, disc);
    pthread_create(&disc->broadcast_thread, NULL, broadcast_loop, disc);

    printf("[ORCA] Discovery started!\n");
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

    printf("[ORCA] Discovery stopped.\n");
}

// ===== LISTEN LOOP =====
static void* listen_loop(void* arg) {
    Discovery* disc = (Discovery*)arg;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);
    fd_set fds;
    struct timeval tv;

    while (disc->running) {
        FD_ZERO(&fds);
        FD_SET(disc->udp_socket, &fds);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(disc->udp_socket + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) break;
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

        parse_message(disc, buffer, ip, port);
    }

    return NULL;
}

// ===== BROADCAST LOOP =====
static void* broadcast_loop(void* arg) {
    Discovery* disc = (Discovery*)arg;

    while (disc->running) {
        sleep(BROADCAST_INTERVAL);
        discovery_cleanup_stale(disc);
    }

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

    sendto(disc->udp_socket, msg, strlen(msg), 0,
           (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));

    printf("[ORCA] Broadcasted presence: %s at %s\n", id, endpoint);
}

// ===== BROADCAST SEARCH (OLD - Keep for compatibility) =====
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

    sendto(disc->udp_socket, msg, strlen(msg), 0,
           (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));

    printf("[ORCA] Searching for: %s\n", id);
}

// ===== ACTIVE QUERY - FIXED with normalize_id =====
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

    sendto(disc->udp_socket, msg, strlen(msg), 0,
           (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));

    printf("[ORCA] Querying for peer: %s\n", norm_id);
}

// ===== SEND UDP =====
static void send_udp(Discovery* disc, const char* msg, const char* ip, int port) {
    if (!disc || !msg || !ip) return;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    sendto(disc->udp_socket, msg, strlen(msg), 0,
           (struct sockaddr*)&addr, sizeof(addr));
}

// ===== PARSE MESSAGE - FIXED with normalize_id =====
static void parse_message(Discovery* disc, const char* msg, const char* sender_ip, int sender_port) {
    (void)sender_port;

    // Skip self
    if (strlen(g_my_ip) > 0 && strcmp(sender_ip, g_my_ip) == 0) {
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

                if (disc->on_peer_found) {
                    disc->on_peer_found(peer);
                }

                printf("[ORCA] Found peer: %s at %s\n", id, endpoint);
            }

            pthread_mutex_unlock(&disc->mutex);
        }
    }

    // ===== HANDLE WHO_HAS - FIXED with normalize_id =====
    if (strncmp(msg, "WHO_HAS:", 8) == 0) {
        const char* search_id = msg + 8;

        char norm_search[64], norm_my[64];
        normalize_id(search_id, norm_search, sizeof(norm_search));
        normalize_id(g_my_id, norm_my, sizeof(norm_my));

        printf("[DEBUG] Received WHO_HAS for ID: %s (normalized: %s)\n", search_id, norm_search);
        printf("[DEBUG] My ID: %s (normalized: %s)\n", g_my_id, norm_my);

        if (strlen(norm_my) > 0 && strcmp(norm_search, norm_my) == 0) {
            char response[512];
            snprintf(response, sizeof(response),
                    "I_AM:%s:%s:%d",
                    g_my_id, g_my_ip, g_my_port);

            send_udp(disc, response, sender_ip, DISCOVERY_PORT);

            printf("[ORCA] Responded to WHO_HAS: %s -> %s:%d\n",
                   search_id, g_my_ip, g_my_port);
        } else {
            printf("[DEBUG] ID mismatch after normalization!\n");
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

            printf("[ORCA] Received I_AM: %s at %s:%d\n", id, ip, port);

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
            }

            pthread_mutex_unlock(&disc->mutex);
        }
    }

    // ===== HANDLE SEARCH (OLD - Keep for compatibility) =====
    if (strncmp(msg, "ORCA_SEARCH:", 12) == 0) {
        const char* search_id = msg + 12;

        char norm_search[64], norm_my[64];
        normalize_id(search_id, norm_search, sizeof(norm_search));
        normalize_id(g_my_id, norm_my, sizeof(norm_my));

        if (strlen(norm_my) > 0 && strcmp(norm_search, norm_my) == 0) {
            char response[512];
            snprintf(response, sizeof(response),
                    "ORCA_PRESENCE:%s:%s:%d",
                    g_my_id, g_my_ip, g_my_port);

            send_udp(disc, response, sender_ip, DISCOVERY_PORT);

            printf("[ORCA] Responded to search for %s -> %s:%d\n",
                   search_id, g_my_ip, g_my_port);
        }
    }
}

// ===== FIND PEER - FIXED with normalize_id =====
bool discovery_find_peer(Discovery* disc, const char* id, PeerInfo* out_peer) {
    if (!disc || !out_peer) return false;

    char norm_id[64];
    normalize_id(id, norm_id, sizeof(norm_id));

    pthread_mutex_lock(&disc->mutex);

    for (int i = 0; i < disc->peer_count; i++) {
        char norm_peer_id[64];
        normalize_id(disc->peers[i].id, norm_peer_id, sizeof(norm_peer_id));

        if (strcmp(norm_peer_id, norm_id) == 0 && disc->peers[i].online) {
            *out_peer = disc->peers[i];
            pthread_mutex_unlock(&disc->mutex);
            return true;
        }
    }

    pthread_mutex_unlock(&disc->mutex);
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
    return count;
}

// ===== CLEANUP STALE =====
void discovery_cleanup_stale(Discovery* disc) {
    if (!disc) return;

    time_t now = time(NULL);

    pthread_mutex_lock(&disc->mutex);

    for (int i = 0; i < disc->peer_count; i++) {
        if (now - disc->peers[i].last_seen > PEER_TIMEOUT) {
            disc->peers[i].online = false;
            if (disc->on_peer_offline) {
                disc->on_peer_offline(&disc->peers[i]);
            }
        }
    }

    pthread_mutex_unlock(&disc->mutex);
}

// ===== GET LOCAL IP =====
char* discovery_get_local_ip(void) {
    static char ip[INET_ADDRSTRLEN];
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

// ===== CALLBACKS =====
void discovery_set_on_peer_found(Discovery* disc, void (*callback)(PeerInfo*)) {
    if (disc) disc->on_peer_found = callback;
}

void discovery_set_on_peer_offline(Discovery* disc, void (*callback)(PeerInfo*)) {
    if (disc) disc->on_peer_offline = callback;
}
