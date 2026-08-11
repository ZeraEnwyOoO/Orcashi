 #define _POSIX_C_SOURCE 200809L

#include "orcashi.h"
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/select.h>
#include <ifaddrs.h>

#define MAX_MSG_LEN 4096

// ===== Forward declarations =====
static void orcashi_broadcast_presence(ORCASHI* orcashi);
static void orcashi_show_banner(ORCASHI* orcashi);
static void* heartbeat_loop(void* arg);
static void on_peer_found_callback(PeerInfo* peer);
static void on_peer_offline_callback(PeerInfo* peer);

// ===== Create =====
ORCASHI* orcashi_create(void) {
    ORCASHI* orcashi = (ORCASHI*)calloc(1, sizeof(ORCASHI));
    if (!orcashi) return NULL;
    
    mkdir(ORCASHI_HOME, 0700);
    
    orcashi->plug = plug_create();
    orcashi->discovery = discovery_create();
    orcashi->registry = registry_create();
    orcashi->requests = request_manager_create();
    orcashi->cache = peer_cache_create();
    orcashi->endpoints = endpoint_registry_create();
    orcashi->punch = (PunchState*)calloc(1, sizeof(PunchState));
    
    if (!orcashi->plug || !orcashi->discovery || !orcashi->registry ||
        !orcashi->requests || !orcashi->cache || !orcashi->endpoints || !orcashi->punch) {
        orcashi_destroy(orcashi);
        return NULL;
    }
    
    char* id = orcashi_generate_id();
    strcpy(orcashi->my_id, id);
    free(id);
    
    char* local_ip = orcashi_get_local_ip();
    strcpy(orcashi->local_ip, local_ip);
    free(local_ip);
    
    orcashi->connected = false;
    orcashi->running = false;
    orcashi->registered = false;
    
    pthread_mutex_init(&orcashi->mutex, NULL);
    
    discovery_set_on_peer_found(orcashi->discovery, on_peer_found_callback);
    discovery_set_on_peer_offline(orcashi->discovery, on_peer_offline_callback);
    
    return orcashi;
}

// ===== Destroy =====
void orcashi_destroy(ORCASHI* orcashi) {
    if (!orcashi) return;
    
    orcashi_disconnect(orcashi);
    
    if (orcashi->plug) { plug_destroy(orcashi->plug); orcashi->plug = NULL; }
    if (orcashi->discovery) { discovery_destroy(orcashi->discovery); orcashi->discovery = NULL; }
    if (orcashi->registry) { registry_destroy(orcashi->registry); orcashi->registry = NULL; }
    if (orcashi->requests) { request_manager_destroy(orcashi->requests); orcashi->requests = NULL; }
    if (orcashi->cache) { peer_cache_destroy(orcashi->cache); orcashi->cache = NULL; }
    if (orcashi->endpoints) { endpoint_registry_destroy(orcashi->endpoints); orcashi->endpoints = NULL; }
    if (orcashi->punch) { punch_close(orcashi->punch); free(orcashi->punch); orcashi->punch = NULL; }
    
    pthread_mutex_destroy(&orcashi->mutex);
    free(orcashi);
}

// ===== Init =====
bool orcashi_init(ORCASHI* orcashi) {
    if (!orcashi) return false;
    
    if (!discovery_init(orcashi->discovery, DISCOVERY_PORT)) {
        fprintf(stderr, "[ERROR] Failed to init discovery!\n");
        return false;
    }
    discovery_start(orcashi->discovery);
    
    // SET IDENTITY FOR SEARCH RESPONSES
    discovery_set_my_identity(orcashi->discovery, orcashi->my_id, orcashi->local_ip, ORCASHI_PORT);
    
    registry_load(orcashi->registry);
    request_load(orcashi->requests);
    
    if (punch_init(orcashi->punch, PUNCH_PORT) < 0) {
        fprintf(stderr, "[ERROR] Failed to init NAT punch!\n");
        return false;
    }
    
    bootstrap_init();
    
    printf("[ORCA] Initialized with ID: %s\n", orcashi->my_id);
    
    orcashi->running = true;
    pthread_create(&orcashi->heartbeat_thread, NULL, heartbeat_loop, orcashi);
    
    return true;
}

// ===== Create Room =====
bool orcashi_create_room(ORCASHI* orcashi, int port) {
    if (!orcashi) return false;
    
    printf("\n================================================\n");
    printf("ORCASHI - CREATE ROOM\n");
    printf("================================================\n");
    
    if (plug_create_server(orcashi->plug, port)) {
        orcashi->connected = true;
        
        strcpy(orcashi->peer_ip, plug_get_peer_ip(orcashi->plug));
        strcpy(orcashi->peer_id, orcashi->peer_ip);
        
        orcashi_broadcast_presence(orcashi);
        orcashi_show_banner(orcashi);
        
        return true;
    }
    
    return false;
}

// ===== Join Room =====
bool orcashi_join_room(ORCASHI* orcashi, const char* ip, int port) {
    if (!orcashi) return false;
    
    printf("\n================================================\n");
    printf("ORCASHI - JOIN ROOM\n");
    printf("================================================\n");
    
    if (plug_connect_client(orcashi->plug, ip, port)) {
        orcashi->connected = true;
        
        strcpy(orcashi->peer_ip, ip);
        strcpy(orcashi->peer_id, ip);
        
        CachePeer peer;
        memset(&peer, 0, sizeof(peer));
        strcpy(peer.id, ip);
        strcpy(peer.ip, ip);
        peer.port = port;
        peer.online = true;
        peer.last_seen = time(NULL);
        peer_cache_save_peer(orcashi->cache, &peer);
        
        orcashi_show_banner(orcashi);
        return true;
    }
    
    return false;
}

// ===== Send Message =====
bool orcashi_send_message(ORCASHI* orcashi, const char* msg) {
    if (!orcashi || !orcashi->connected) return false;
    return plug_send_message(orcashi->plug, msg);
}

// ===== Receive Message =====
bool orcashi_receive_message(ORCASHI* orcashi, char* msg, int msg_size, int timeout_ms) {
    if (!orcashi || !orcashi->connected) return false;
    return plug_receive_message(orcashi->plug, msg, msg_size, timeout_ms);
}

// ===== Is Connected =====
bool orcashi_is_connected(ORCASHI* orcashi) {
    return orcashi && orcashi->connected && plug_is_connected(orcashi->plug);
}

// ===== Disconnect =====
void orcashi_disconnect(ORCASHI* orcashi) {
    if (!orcashi) return;
    orcashi->connected = false;
    orcashi->running = false;
    if (orcashi->plug) { plug_close_connection(orcashi->plug); }
    if (orcashi->heartbeat_thread) {
        pthread_join(orcashi->heartbeat_thread, NULL);
        orcashi->heartbeat_thread = 0;
    }
    discovery_stop(orcashi->discovery);
}

// ===== Getters =====
const char* orcashi_get_my_id(ORCASHI* orcashi) {
    return orcashi ? orcashi->my_id : NULL;
}

const char* orcashi_get_peer_id(ORCASHI* orcashi) {
    return orcashi ? orcashi->peer_id : NULL;
}

const char* orcashi_get_peer_ip(ORCASHI* orcashi) {
    return orcashi ? orcashi->peer_ip : NULL;
}

// ===== Register Identity =====
bool orcashi_register_identity(ORCASHI* orcashi) {
    if (!orcashi) return false;
    
    printf("\n");
    printf("  +------------------------------------------+\n");
    printf("  |           ORCA Registration              |\n");
    printf("  +------------------------------------------+\n");
    printf("\n");
    
    printf("  Your ID: %s\n", orcashi->my_id);
    printf("  Enter your IP address (e.g., 192.168.1.5): ");
    fflush(stdout);
    
    char input_ip[INET_ADDRSTRLEN];
    if (!fgets(input_ip, sizeof(input_ip), stdin)) {
        printf("  [ERROR] No input!\n");
        return false;
    }
    input_ip[strcspn(input_ip, "\n")] = '\0';
    
    struct sockaddr_in sa;
    int valid = inet_pton(AF_INET, input_ip, &sa.sin_addr);
    if (valid != 1) {
        printf("  [ERROR] Invalid IP address: %s\n", input_ip);
        return false;
    }
    
    printf("  Using IP: %s\n", input_ip);
    
    if (registry_register_peer(orcashi->registry, orcashi->my_id, 
                               input_ip, "9000")) {
        orcashi->registered = true;
        strcpy(orcashi->local_ip, input_ip);
        
        // Update identity in discovery
        discovery_set_my_identity(orcashi->discovery, orcashi->my_id, input_ip, ORCASHI_PORT);
        
        CachePeer peer;
        memset(&peer, 0, sizeof(peer));
        strcpy(peer.id, orcashi->my_id);
        snprintf(peer.endpoint, sizeof(peer.endpoint), "%s:9000", input_ip);
        strcpy(peer.ip, input_ip);
        peer.port = 9000;
        peer.online = true;
        peer.last_seen = time(NULL);
        peer_cache_save_peer(orcashi->cache, &peer);
        
        orcashi_broadcast_presence(orcashi);
        
        printf("\n  [SUCCESS] Registered!\n");
        printf("  Your ID: %s\n", orcashi->my_id);
        printf("  Your IP: %s\n", input_ip);
        printf("  Your friends can connect using:\n");
        printf("    ./orcashi join %s\n", input_ip);
        return true;
    }
    
    printf("  [ERROR] Registration failed!\n");
    return false;
}

// ===== Connect Peer =====
bool orcashi_connect_peer(ORCASHI* orcashi, const char* id) {
    if (!orcashi) return false;
    
    printf("\n  [ORCA] Looking for %s...\n", id);
    
    // 1. Check Cache
    CachePeer peer;
    if (peer_cache_get_peer(orcashi->cache, id, &peer) && peer.online) {
        printf("  [ORCA] Found in cache: %s:%d\n", peer.ip, peer.port);
        return orcashi_join_room(orcashi, peer.ip, peer.port);
    }
    
    // 2. Check Registry
    RegistryPeer reg_peer;
    if (registry_get_peer(orcashi->registry, id, &reg_peer)) {
        printf("  [ORCA] Found in registry: %s:%s\n", reg_peer.ip, reg_peer.port);
        return orcashi_join_room(orcashi, reg_peer.ip, atoi(reg_peer.port));
    }
    
    // 3. Discovery Broadcast
    discovery_broadcast_search(orcashi->discovery, id);
    printf("  [ORCA] Searching network for %s...\n", id);
    
    time_t start = time(NULL);
    while (time(NULL) - start < 5) {
        if (peer_cache_get_peer(orcashi->cache, id, &peer) && peer.online) {
            printf("  [ORCA] Found on network: %s:%d\n", peer.ip, peer.port);
            return orcashi_join_room(orcashi, peer.ip, peer.port);
        }
        // Also check discovery cache
        PeerInfo p;
        if (discovery_find_peer(orcashi->discovery, id, &p)) {
            printf("  [ORCA] Found via discovery: %s:%d\n", p.ip, p.port);
            return orcashi_join_room(orcashi, p.ip, p.port);
        }
        sleep(1);
    }
    
    printf("  [ERROR] Peer %s not found!\n", id);
    return false;
}

// ===== Show Peers =====
void orcashi_show_peers(ORCASHI* orcashi) {
    if (!orcashi) return;
    CachePeer peers[MAX_CACHE_PEERS];
    int count = peer_cache_get_all(orcashi->cache, peers, MAX_CACHE_PEERS);
    
    printf("\n  Your Peers:\n");
    if (count == 0) {
        printf("    No peers found.\n");
    } else {
        for (int i = 0; i < count; i++) {
            printf("    %s - %s:%d %s\n", 
                   peers[i].id, peers[i].ip, peers[i].port,
                   peers[i].online ? "[ONLINE]" : "[OFFLINE]");
        }
    }
    printf("\n");
}

// ===== Set Callbacks =====
void orcashi_set_callbacks(ORCASHI* orcashi,
                          void (*on_peer_found)(const char*, const char*),
                          void (*on_message_received)(const char*, const char*),
                          void (*on_status_change)(const char*)) {
    if (!orcashi) return;
    orcashi->on_peer_found = on_peer_found;
    orcashi->on_message_received = on_message_received;
    orcashi->on_status_change = on_status_change;
}

// ===== Private Functions =====

static void orcashi_broadcast_presence(ORCASHI* orcashi) {
    if (!orcashi) return;
    char endpoint[128];
    snprintf(endpoint, sizeof(endpoint), "%s:9000", orcashi->local_ip);
    discovery_broadcast_presence(orcashi->discovery, orcashi->my_id, endpoint);
}

static void orcashi_show_banner(ORCASHI* orcashi) {
    if (!orcashi) return;
    printf("\033[36m");
    printf("============================================================\n");
    printf("  ██████╗ ██████╗  ██████╗ █████╗ \n");
    printf(" ██╔═══██╗██╔══██╗██╔════╝██╔══██╗C\n");
    printf(" ██║   ██║██████╔╝██║     ███████╗H\n");
    printf(" ██║   ██║██╔══██╗██║     ██╔══██╗A\n");
    printf(" ╚██████╔╝██║  ██║╚██████╗██║  ██║T\n");
    printf("  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝\n");
    printf("            ORCASHI v3.1 - P2P Chat\n");
    printf("============================================================\n");
    printf("\033[0m");
    printf("Your ID: %s\n", orcashi->my_id);
    printf("Mode: TCP Plug (Pure C)\n");
    printf("Type /help for commands\n");
    printf("============================================================\n");
    printf("\n");
}

static void on_peer_found_callback(PeerInfo* peer) {
    (void)peer;
}

static void on_peer_offline_callback(PeerInfo* peer) {
    (void)peer;
}

static void* heartbeat_loop(void* arg) {
    ORCASHI* orcashi = (ORCASHI*)arg;
    while (orcashi->running) {
        sleep(30);
        endpoint_cleanup_stale(orcashi->endpoints, 60);
        peer_cache_auto_save(orcashi->cache);
        if (orcashi->registered) {
            orcashi_broadcast_presence(orcashi);
        }
    }
    return NULL;
}

// ===== Helpers =====

char* orcashi_generate_id(void) {
    static char id[64];
    FILE* f = fopen(ID_FILE, "r");
    if (f) {
        if (fgets(id, sizeof(id), f)) {
            id[strcspn(id, "\n")] = '\0';
            fclose(f);
            return strdup(id);
        }
        fclose(f);
    }
    srand(time(NULL) ^ getpid());
    int num = (rand() % 999) + 1;
    snprintf(id, sizeof(id), "<%03d>", num);
    f = fopen(ID_FILE, "w");
    if (f) { fprintf(f, "%s", id); fclose(f); }
    return strdup(id);
}

char* orcashi_get_local_ip(void) {
    static char ip[INET_ADDRSTRLEN];
    struct ifaddrs* ifaddr;
    
    if (getifaddrs(&ifaddr) == 0) {
        for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
            if (strcmp(ip, "127.0.0.1") != 0) {
                freeifaddrs(ifaddr);
                return strdup(ip);
            }
        }
        freeifaddrs(ifaddr);
    }
    
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(hostname, NULL, &hints, &res) == 0) {
            struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
            freeaddrinfo(res);
            if (strcmp(ip, "127.0.0.1") != 0) {
                return strdup(ip);
            }
        }
    }
    
    strcpy(ip, "127.0.0.1");
    return strdup(ip);
}

char* orcashi_bytes_to_hex(const unsigned char* bytes, int len) {
    char* hex = (char*)malloc(len * 2 + 1);
    if (!hex) return NULL;
    for (int i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}
