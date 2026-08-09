 // orcashi.c - ORCASHI Main Implementation (REAL)
#include "orcashi.h"

#define ORCASHI_HOME "/tmp/.orcashi/"
#define ID_FILE ORCASHI_HOME "id"
#define MAX_MSG_LEN 4096

static void* heartbeat_loop(void* arg);
static void on_peer_found_callback(PeerInfo* peer);
static void on_peer_offline_callback(PeerInfo* peer);

ORCASHI* orcashi_create(void) {
    ORCASHI* orcashi = (ORCASHI*)calloc(1, sizeof(ORCASHI));
    if (!orcashi) return NULL;
    
    // Create components
    orcashi->plug = plug_create();
    orcashi->discovery = discovery_create();
    orcashi->registry = registry_create();
    orcashi->requests = request_manager_create();
    orcashi->cache = peer_cache_create();
    orcashi->endpoints = endpoint_registry_create();
    
    if (!orcashi->plug || !orcashi->discovery || !orcashi->registry ||
        !orcashi->requests || !orcashi->cache || !orcashi->endpoints) {
        orcashi_destroy(orcashi);
        return NULL;
    }
    
    // Create directory
    mkdir(ORCASHI_HOME, 0700);
    
    // Generate ID
    char* id = orcashi_generate_id();
    strcpy(orcashi->my_id, id);
    free(id);
    
    // Get local IP
    char* ip = orcashi_get_local_ip();
    strcpy(orcashi->local_ip, ip);
    free(ip);
    
    orcashi->connected = false;
    orcashi->running = false;
    orcashi->registered = false;
    
    pthread_mutex_init(&orcashi->mutex, NULL);
    
    // Set discovery callbacks
    discovery_set_on_peer_found(orcashi->discovery, on_peer_found_callback);
    discovery_set_on_peer_offline(orcashi->discovery, on_peer_offline_callback);
    
    return orcashi;
}

void orcashi_destroy(ORCASHI* orcashi) {
    if (!orcashi) return;
    
    orcashi_disconnect(orcashi);
    
    if (orcashi->plug) {
        plug_destroy(orcashi->plug);
        orcashi->plug = NULL;
    }
    
    if (orcashi->discovery) {
        discovery_destroy(orcashi->discovery);
        orcashi->discovery = NULL;
    }
    
    if (orcashi->registry) {
        registry_destroy(orcashi->registry);
        orcashi->registry = NULL;
    }
    
    if (orcashi->requests) {
        request_manager_destroy(orcashi->requests);
        orcashi->requests = NULL;
    }
    
    if (orcashi->cache) {
        peer_cache_destroy(orcashi->cache);
        orcashi->cache = NULL;
    }
    
    if (orcashi->endpoints) {
        endpoint_registry_destroy(orcashi->endpoints);
        orcashi->endpoints = NULL;
    }
    
    pthread_mutex_destroy(&orcashi->mutex);
    free(orcashi);
}

bool orcashi_init(ORCASHI* orcashi) {
    if (!orcashi) return false;
    
    // Initialize discovery
    if (!discovery_init(orcashi->discovery, DISCOVERY_PORT)) {
        fprintf(stderr, "[ERROR] Failed to init discovery!\n");
        return false;
    }
    
    discovery_start(orcashi->discovery);
    
    // Load registry
    registry_load(orcashi->registry);
    
    // Load requests
    request_load(orcashi->requests);
    
    printf("[ORCA] Initialized with ID: %s\n", orcashi->my_id);
    printf("[ORCA] Local IP: %s\n", orcashi->local_ip);
    
    // Start heartbeat
    pthread_create(&orcashi->heartbeat_thread, NULL, heartbeat_loop, orcashi);
    
    return true;
}

bool orcashi_create_room(ORCASHI* orcashi, int port) {
    if (!orcashi) return false;
    
    printf("\n%s\n", "================================================");
    printf("ORCASHI - CREATE ROOM\n");
    printf("%s\n", "================================================");
    
    if (plug_create_server(orcashi->plug, port)) {
        orcashi->connected = true;
        orcashi->running = true;
        
        strcpy(orcashi->peer_ip, plug_get_peer_ip(orcashi->plug));
        strcpy(orcashi->peer_id, orcashi->peer_ip);
        
        // Broadcast presence
        orcashi_broadcast_presence(orcashi);
        
        orcashi_show_banner(orcashi);
        return true;
    }
    
    return false;
}

bool orcashi_join_room(ORCASHI* orcashi, const char* ip, int port) {
    if (!orcashi) return false;
    
    printf("\n%s\n", "================================================");
    printf("ORCASHI - JOIN ROOM\n");
    printf("%s\n", "================================================");
    
    if (plug_connect_client(orcashi->plug, ip, port)) {
        orcashi->connected = true;
        orcashi->running = true;
        
        strcpy(orcashi->peer_ip, ip);
        strcpy(orcashi->peer_id, ip);
        
        // Register peer in cache
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
    
    if (orcashi->plug) {
        plug_close_connection(orcashi->plug);
    }
    
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

bool orcashi_register_identity(ORCASHI* orcashi) {
    if (!orcashi) return false;
    
    printf("\n");
    printf("  +------------------------------------------+\n");
    printf("  |           ORCA Registration              |\n");
    printf("  +------------------------------------------+\n");
    printf("\n");
    
    printf("  Your ID: %s\n", orcashi->my_id);
    printf("  Your IP: %s\n", orcashi->local_ip);
    
    // Register in registry
    if (registry_register_peer(orcashi->registry, orcashi->my_id, 
                               orcashi->local_ip, "9000")) {
        orcashi->registered = true;
        
        // Save to cache
        CachePeer peer;
        strcpy(peer.id, orcashi->my_id);
        snprintf(peer.endpoint, sizeof(peer.endpoint), "%s:9000", orcashi->local_ip);
        strcpy(peer.ip, orcashi->local_ip);
        peer.port = 9000;
        peer.online = true;
        peer.last_seen = time(NULL);
        peer_cache_save_peer(orcashi->cache, &peer);
        
        // Broadcast presence
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
    
    // Check cache first
    CachePeer peer;
    if (peer_cache_get_peer(orcashi->cache, id, &peer) && peer.online) {
        printf("  [ORCA] Found in cache: %s:%d\n", peer.ip, peer.port);
        return orcashi_join_room(orcashi, peer.ip, peer.port);
    }
    
    // Check registry
    RegistryPeer reg_peer;
    if (registry_get_peer(orcashi->registry, id, &reg_peer)) {
        printf("  [ORCA] Found in registry: %s:%s\n", reg_peer.ip, reg_peer.port);
        return orcashi_join_room(orcashi, reg_peer.ip, atoi(reg_peer.port));
    }
    
    // Broadcast search
    discovery_broadcast_search(orcashi->discovery, id);
    printf("  [ORCA] Searching network for %s...\n", id);
    
    // Wait for response (5 seconds)
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

void orcashi_broadcast_presence(ORCASHI* orcashi) {
    if (!orcashi) return;
    
    char endpoint[128];
    snprintf(endpoint, sizeof(endpoint), "%s:9000", orcashi->local_ip);
    discovery_broadcast_presence(orcashi->discovery, orcashi->my_id, endpoint);
}

void orcashi_search_peer(ORCASHI* orcashi, const char* id) {
    if (!orcashi) return;
    discovery_broadcast_search(orcashi->discovery, id);
}

void orcashi_show_peers(ORCASHI* orcashi) {
    if (!orcashi) return;
    
    printf("\n  Your Peers:\n");
    
    CachePeer peers[MAX_CACHE_PEERS];
    int count = peer_cache_get_all(orcashi->cache, peers, MAX_CACHE_PEERS);
    
    if (count == 0) {
        printf("    No peers found.\n");
    } else {
        for (int i = 0; i < count; i++) {
            printf("    %s - %s:%d %s\n", 
                   peers[i].id, 
                   peers[i].ip, 
                   peers[i].port,
                   peers[i].online ? "[ONLINE]" : "[OFFLINE]");
        }
    }
    
    printf("\n");
}

void orcashi_show_requests(ORCASHI* orcashi) {
    if (!orcashi) return;
    
    Request pending[MAX_REQUESTS];
    int count = request_get_pending(orcashi->requests, orcashi->my_id, pending, MAX_REQUESTS);
    
    printf("\n  Pending Requests:\n");
    if (count == 0) {
        printf("    No pending requests.\n");
    } else {
        for (int i = 0; i < count; i++) {
            printf("    %s wants to connect\n", pending[i].from_id);
        }
    }
    printf("\n");
}

bool orcashi_accept_request(ORCASHI* orcashi, const char* from_id) {
    if (!orcashi) return false;
    
    if (request_accept(orcashi->requests, from_id, orcashi->my_id)) {
        return orcashi_connect_peer(orcashi, from_id);
    }
    return false;
}

void orcashi_show_banner(ORCASHI* orcashi) {
    if (!orcashi) return;
    
    printf("\033[36m");
    printf("%s\n", "============================================================");
    printf("  ██████╗ ██████╗  ██████╗ █████╗ \n");
    printf(" ██╔═══██╗██╔══██╗██╔════╝██╔══██╗C\n");
    printf(" ██║   ██║██████╔╝██║     ███████╗H\n");
    printf(" ██║   ██║██╔══██╗██║     ██╔══██╗A\n");
    printf(" ╚██████╔╝██║  ██║╚██████╗██║  ██║T\n");
    printf("  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝\n");
    printf("            ORCASHI v1.0 - P2P Chat\n");
    printf("%s\n", "============================================================");
    printf("\033[0m");
    
    printf("Your ID: %s\n", orcashi->my_id);
    printf("Mode: TCP Plug (Pure C)\n");
    printf("DHT: Not connected (v1.0)\n");
    printf("Type /help for commands\n");
    printf("%s\n", "============================================================");
    printf("\n");
}

void orcashi_show_help(void) {
    printf("\n%s\n", "================================================");
    printf("ORCASHI v1.0 - P2P Chat\n");
    printf("%s\n", "================================================");
    printf("Commands:\n");
    printf("  /help      - Show this help\n");
    printf("  /exit      - Disconnect\n");
    printf("  /status    - Show connection status\n");
    printf("  /register  - Register identity\n");
    printf("  /connect   - Connect to peer by ID\n");
    printf("  /peers     - Show peer list\n");
    printf("  /requests  - Show pending requests\n");
    printf("  /accept    - Accept a request\n");
    printf("\n");
}

// ===== Callbacks =====
static void on_peer_found_callback(PeerInfo* peer) {
    if (!peer) return;
    
    // Save to cache
    CachePeer cache_peer;
    strcpy(cache_peer.id, peer->id);
    strcpy(cache_peer.endpoint, peer->endpoint);
    strcpy(cache_peer.ip, peer->ip);
    cache_peer.port = peer->port;
    cache_peer.online = true;
    cache_peer.last_seen = peer->last_seen;
    
    // Use global ORCASHI instance (simplified)
    // In real code, you'd pass a context pointer
}

static void on_peer_offline_callback(PeerInfo* peer) {
    if (!peer) return;
    // Update cache
}

// ===== Heartbeat =====
static void* heartbeat_loop(void* arg) {
    ORCASHI* orcashi = (ORCASHI*)arg;
    
    while (orcashi->running) {
        sleep(30);
        
        // Cleanup stale endpoints
        endpoint_cleanup_stale(orcashi->endpoints, 60);
        
        // Auto-save cache
        peer_cache_auto_save(orcashi->cache);
        
        // Broadcast presence if registered
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
    if (f) {
        fprintf(f, "%s", id);
        fclose(f);
    }
    
    return strdup(id);
}

char* orcashi_get_local_ip(void) {
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
        return strdup(ip);
    }
    
    freeifaddrs(ifaddr);
    strcpy(ip, "127.0.0.1");
    return strdup(ip);
}
