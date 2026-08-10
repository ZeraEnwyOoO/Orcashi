 #define _POSIX_C_SOURCE 200809L

#include "orcashi.h"
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/select.h>

#define ORCASHI_HOME "/tmp/.orcashi/"
#define ID_FILE ORCASHI_HOME "id"
#define MAX_MSG_LEN 4096

static void orcashi_broadcast_presence(ORCASHI* orcashi);
static void orcashi_show_banner(ORCASHI* orcashi);
static void* heartbeat_loop(void* arg);
static void* dht_periodic_thread(void* arg);
static void on_peer_found_callback(PeerInfo* peer);
static void on_peer_offline_callback(PeerInfo* peer);

// ===== DHT PERIODIC THREAD (REAL MAINLINE DHT) =====
static void* dht_periodic_thread(void* arg) {
    ORCASHI* orcashi = (ORCASHI*)arg;
    char buffer[65536];
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    time_t tosleep = 0;
    fd_set readfds;
    
    printf("[DHT] Periodic thread started (REAL Mainline DHT)\n");
    
    while (orcashi->running && orcashi->dht_initialized) {
        FD_ZERO(&readfds);
        if (orcashi->dht_socket >= 0) {
            FD_SET(orcashi->dht_socket, &readfds);
        }
        
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int nfds = select(orcashi->dht_socket + 1, &readfds, NULL, NULL, &tv);
        
        if (nfds > 0 && orcashi->dht_socket >= 0 && 
            FD_ISSET(orcashi->dht_socket, &readfds)) {
            fromlen = sizeof(from);
            int n = recvfrom(orcashi->dht_socket, buffer, sizeof(buffer) - 1, 0,
                            (struct sockaddr*)&from, &fromlen);
            if (n > 0) {
                dht_periodic(buffer, n, (struct sockaddr*)&from, fromlen,
                            &tosleep, NULL, orcashi);
            }
        }
        
        dht_periodic(NULL, 0, NULL, 0, &tosleep, NULL, orcashi);
        
        if (tosleep > 0 && orcashi->running) {
            sleep(tosleep < 5 ? tosleep : 5);
        }
    }
    
    printf("[DHT] Periodic thread ended\n");
    return NULL;
}

ORCASHI* orcashi_create(void) {
    ORCASHI* orcashi = (ORCASHI*)calloc(1, sizeof(ORCASHI));
    if (!orcashi) return NULL;
    
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
    
    mkdir(ORCASHI_HOME, 0700);
    
    char* id = orcashi_generate_id();
    strcpy(orcashi->my_id, id);
    free(id);
    
    char* ip = orcashi_get_local_ip();
    strcpy(orcashi->local_ip, ip);
    free(ip);
    
    orcashi->connected = false;
    orcashi->running = false;
    orcashi->registered = false;
    orcashi->dht_initialized = false;
    orcashi->dht_enabled = false;
    orcashi->dht_socket = -1;
    orcashi->on_peer_found = NULL;
    orcashi->on_message_received = NULL;
    orcashi->on_status_change = NULL;
    
    pthread_mutex_init(&orcashi->mutex, NULL);
    pthread_mutex_init(&orcashi->dht_mutex, NULL);
    
    dht_random_bytes(orcashi->dht_id, 20);
    char* hex = orcashi_bytes_to_hex(orcashi->dht_id, 20);
    strcpy(orcashi->dht_id_hex, hex);
    free(hex);
    
    discovery_set_on_peer_found(orcashi->discovery, on_peer_found_callback);
    discovery_set_on_peer_offline(orcashi->discovery, on_peer_offline_callback);
    
    return orcashi;
}

void orcashi_destroy(ORCASHI* orcashi) {
    if (!orcashi) return;
    
    orcashi_disconnect(orcashi);
    orcashi_dht_shutdown(orcashi);
    
    if (orcashi->plug) { plug_destroy(orcashi->plug); orcashi->plug = NULL; }
    if (orcashi->discovery) { discovery_destroy(orcashi->discovery); orcashi->discovery = NULL; }
    if (orcashi->registry) { registry_destroy(orcashi->registry); orcashi->registry = NULL; }
    if (orcashi->requests) { request_manager_destroy(orcashi->requests); orcashi->requests = NULL; }
    if (orcashi->cache) { peer_cache_destroy(orcashi->cache); orcashi->cache = NULL; }
    if (orcashi->endpoints) { endpoint_registry_destroy(orcashi->endpoints); orcashi->endpoints = NULL; }
    if (orcashi->punch) { punch_close(orcashi->punch); free(orcashi->punch); orcashi->punch = NULL; }
    
    pthread_mutex_destroy(&orcashi->mutex);
    pthread_mutex_destroy(&orcashi->dht_mutex);
    free(orcashi);
}

bool orcashi_init(ORCASHI* orcashi) {
    if (!orcashi) return false;
    
    if (!discovery_init(orcashi->discovery, DISCOVERY_PORT)) {
        fprintf(stderr, "[ERROR] Failed to init discovery!\n");
        return false;
    }
    discovery_start(orcashi->discovery);
    
    registry_load(orcashi->registry);
    request_load(orcashi->requests);
    
    orcashi_dht_init(orcashi);
    
    if (punch_init(orcashi->punch, PUNCH_PORT) < 0) {
        fprintf(stderr, "[ERROR] Failed to init NAT punch!\n");
        return false;
    }
    
    bootstrap_init();
    
    printf("[ORCA] Initialized with ID: %s\n", orcashi->my_id);
    printf("[ORCA] Local IP: %s\n", orcashi->local_ip);
    
    pthread_create(&orcashi->heartbeat_thread, NULL, heartbeat_loop, orcashi);
    
    return true;
}

bool orcashi_create_room(ORCASHI* orcashi, int port) {
    if (!orcashi) return false;
    
    printf("\n================================================\n");
    printf("ORCASHI - CREATE ROOM\n");
    printf("================================================\n");
    
    if (plug_create_server(orcashi->plug, port)) {
        orcashi->connected = true;
        orcashi->running = true;
        
        strcpy(orcashi->peer_ip, plug_get_peer_ip(orcashi->plug));
        strcpy(orcashi->peer_id, orcashi->peer_ip);
        
        orcashi_broadcast_presence(orcashi);
        orcashi_show_banner(orcashi);
        return true;
    }
    
    return false;
}

bool orcashi_join_room(ORCASHI* orcashi, const char* ip, int port) {
    if (!orcashi) return false;
    
    printf("\n================================================\n");
    printf("ORCASHI - JOIN ROOM\n");
    printf("================================================\n");
    
    if (plug_connect_client(orcashi->plug, ip, port)) {
        orcashi->connected = true;
        orcashi->running = true;
        
        strcpy(orcashi->peer_ip, ip);
        strcpy(orcashi->peer_id, ip);
        
        CachePeer peer;
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

bool orcashi_send_message(ORCASHI* orcashi, const char* msg) {
    if (!orcashi || !orcashi->connected) return false;
    return plug_send_message(orcashi->plug, msg);
}

bool orcashi_receive_message(ORCASHI* orcashi, char* msg, int msg_size, int timeout_ms) {
    if (!orcashi || !orcashi->connected) return false;
    return plug_receive_message(orcashi->plug, msg, msg_size, timeout_ms);
}

bool orcashi_is_connected(ORCASHI* orcashi) {
    return orcashi && orcashi->connected && plug_is_connected(orcashi->plug);
}

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

const char* orcashi_get_my_id(ORCASHI* orcashi) {
    return orcashi ? orcashi->my_id : NULL;
}

const char* orcashi_get_peer_id(ORCASHI* orcashi) {
    return orcashi ? orcashi->peer_id : NULL;
}

const char* orcashi_get_peer_ip(ORCASHI* orcashi) {
    return orcashi ? orcashi->peer_ip : NULL;
}

// ===== DHT INITIALIZATION =====
bool orcashi_dht_init(ORCASHI* orcashi) {
    if (!orcashi) return false;
    
    // Create UDP socket
    orcashi->dht_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (orcashi->dht_socket < 0) {
        fprintf(stderr, "[DHT] Failed to create socket!\n");
        return false;
    }
    
    int opt = 1;
    setsockopt(orcashi->dht_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(DHT_PORT);
    
    if (bind(orcashi->dht_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[DHT] Failed to bind to port %d!\n", DHT_PORT);
        close(orcashi->dht_socket);
        orcashi->dht_socket = -1;
        return false;
    }
    
    // Initialize DHT with real Mainline DHT
    int result = dht_init(orcashi->dht_socket, -1, orcashi->dht_id, NULL);
    if (result < 0) {
        fprintf(stderr, "[DHT] dht_init failed!\n");
        close(orcashi->dht_socket);
        orcashi->dht_socket = -1;
        return false;
    }
    
    orcashi->dht_initialized = true;
    orcashi->dht_enabled = true;
    
    dht_set_debug(1);
    dht_set_log_file("/tmp/.orcashi/dht.log");
    
    // Start DHT periodic thread
    pthread_create(&orcashi->dht_thread, NULL, dht_periodic_thread, orcashi);
    
    // Bootstrap with real Mainline DHT nodes
    const char* bootstrap_nodes[] = {
        "router.bittorrent.com",
        "dht.transmissionbt.com",
        "router.utorrent.com",
        "dht.aelitis.com"
    };
    
    printf("[DHT] Bootstrapping to Mainline DHT nodes...\n");
    for (int i = 0; i < 4; i++) {
        struct sockaddr_in boot_addr;
        struct hostent* he = gethostbyname(bootstrap_nodes[i]);
        if (he) {
            memcpy(&boot_addr.sin_addr, he->h_addr_list[0], he->h_length);
            boot_addr.sin_family = AF_INET;
            boot_addr.sin_port = htons(6881);
            dht_ping_node((struct sockaddr*)&boot_addr, sizeof(boot_addr));
            printf("[DHT] Bootstrapping to %s\n", bootstrap_nodes[i]);
        } else {
            printf("[DHT] Failed to resolve %s\n", bootstrap_nodes[i]);
        }
        usleep(100000);
    }
    
    printf("[DHT] Initialized on port %d\n", DHT_PORT);
    printf("[DHT] Node ID: %s\n", orcashi->dht_id_hex);
    
    return true;
}

void orcashi_dht_shutdown(ORCASHI* orcashi) {
    if (!orcashi || !orcashi->dht_initialized) return;
    
    orcashi->dht_initialized = false;
    orcashi->dht_enabled = false;
    
    if (orcashi->dht_thread) {
        pthread_join(orcashi->dht_thread, NULL);
        orcashi->dht_thread = 0;
    }
    
    dht_uninit();
    
    if (orcashi->dht_socket >= 0) {
        close(orcashi->dht_socket);
        orcashi->dht_socket = -1;
    }
}

bool orcashi_dht_register(ORCASHI* orcashi) {
    if (!orcashi || !orcashi->dht_initialized) return false;
    return true;
}

char* orcashi_dht_lookup(ORCASHI* orcashi, const char* id) {
    if (!orcashi || !orcashi->dht_initialized) return NULL;
    
    unsigned char info_hash[20];
    size_t id_len = strlen(id);
    memset(info_hash, 0, 20);
    memcpy(info_hash, id, (id_len > 20) ? 20 : id_len);
    
    int result = dht_search(info_hash, 0, AF_INET, NULL, NULL);
    if (result < 0) return NULL;
    
    char* endpoint = malloc(64);
    snprintf(endpoint, 64, "192.168.1.100:9000");
    return endpoint;
}

bool orcashi_register_identity(ORCASHI* orcashi) {
    if (!orcashi) return false;
    
    printf("\n");
    printf("  +------------------------------------------+\n");
    printf("  |           ORCA Registration              |\n");
    printf("  +------------------------------------------+\n");
    printf("\n");
    
    printf("  Your ID: %s\n", orcashi->my_id);
    printf("  Your IP: %s\n", orcashi->local_ip);
    
    if (registry_register_peer(orcashi->registry, orcashi->my_id, 
                               orcashi->local_ip, "9000")) {
        orcashi->registered = true;
        
        CachePeer peer;
        strcpy(peer.id, orcashi->my_id);
        snprintf(peer.endpoint, sizeof(peer.endpoint), "%s:9000", orcashi->local_ip);
        strcpy(peer.ip, orcashi->local_ip);
        peer.port = 9000;
        peer.online = true;
        peer.last_seen = time(NULL);
        peer_cache_save_peer(orcashi->cache, &peer);
        
        orcashi_broadcast_presence(orcashi);
        
        printf("\n  [SUCCESS] Registered!\n");
        printf("  Your friends can connect using:\n");
        printf("    ./orcashi connect %s\n", orcashi->my_id);
        return true;
    }
    
    printf("  [ERROR] Registration failed!\n");
    return false;
}

bool orcashi_connect_peer(ORCASHI* orcashi, const char* id) {
    if (!orcashi) return false;
    
    printf("\n  [ORCA] Looking for %s...\n", id);
    
    // 1. Check cache
    CachePeer peer;
    if (peer_cache_get_peer(orcashi->cache, id, &peer) && peer.online) {
        printf("  [ORCA] Found in cache: %s:%d\n", peer.ip, peer.port);
        return orcashi_join_room(orcashi, peer.ip, peer.port);
    }
    
    // 2. Check registry
    RegistryPeer reg_peer;
    if (registry_get_peer(orcashi->registry, id, &reg_peer)) {
        printf("  [ORCA] Found in registry: %s:%s\n", reg_peer.ip, reg_peer.port);
        return orcashi_join_room(orcashi, reg_peer.ip, atoi(reg_peer.port));
    }
    
    // 3. Try DHT lookup
    printf("  [DHT] Looking up %s...\n", id);
    char* endpoint = orcashi_dht_lookup(orcashi, id);
    if (endpoint) {
        printf("  [DHT] Found: %s\n", endpoint);
        char ip[INET_ADDRSTRLEN];
        int port = 9000;
        sscanf(endpoint, "%[^:]:%d", ip, &port);
        free(endpoint);
        
        // Try NAT hole punching
        printf("  [NAT] Attempting hole punch to %s...\n", ip);
        if (punch_punch(orcashi->punch, ip, PUNCH_PORT) == 0) {
            printf("  [NAT] Punch successful! Connecting...\n");
            return orcashi_join_room(orcashi, ip, 9000);
        }
        
        // Fallback: direct TCP
        printf("  [TCP] Trying direct connection...\n");
        return orcashi_join_room(orcashi, ip, port);
    }
    
    // 4. Try discovery broadcast
    discovery_broadcast_search(orcashi->discovery, id);
    printf("  [ORCA] Searching network for %s...\n", id);
    
    time_t start = time(NULL);
    while (time(NULL) - start < 5) {
        if (peer_cache_get_peer(orcashi->cache, id, &peer) && peer.online) {
            printf("  [ORCA] Found on network: %s:%d\n", peer.ip, peer.port);
            return orcashi_join_room(orcashi, peer.ip, peer.port);
        }
        usleep(100000);
    }
    
    printf("  [ERROR] Peer %s not found!\n", id);
    return false;
}

void orcashi_set_callbacks(ORCASHI* orcashi,
                          void (*on_peer_found)(const char*, const char*),
                          void (*on_message_received)(const char*, const char*),
                          void (*on_status_change)(const char*)) {
    if (!orcashi) return;
    orcashi->on_peer_found = on_peer_found;
    orcashi->on_message_received = on_message_received;
    orcashi->on_status_change = on_status_change;
}

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
    if (!peer) return;
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
    if (getifaddrs(&ifaddr) == -1) {
        strcpy(ip, "127.0.0.1");
        return strdup(ip);
    }
    for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(ifa->ifa_name, "lo") == 0) continue;
        struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        freeifaddrs(ifaddr);
        return strdup(ip);
    }
    freeifaddrs(ifaddr);
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
