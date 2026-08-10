 #define _POSIX_C_SOURCE 200809L

#include "orcashi.h"
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/select.h>
#include <ifaddrs.h>

#define ORCASHI_HOME "/tmp/.orcashi/"
#define ID_FILE ORCASHI_HOME "id"
#define MAX_MSG_LEN 4096

static void orcashi_broadcast_presence(ORCASHI* orcashi);
static void orcashi_show_banner(ORCASHI* orcashi);
static void* heartbeat_loop(void* arg);
static void* dht_periodic_thread(void* arg);
static void on_peer_found_callback(PeerInfo* peer);
static void on_peer_offline_callback(PeerInfo* peer);
static void tox_dht_ip_callback(void* object, int32_t number, const IP_Port* ip_port);

// ===== DHT PERIODIC THREAD (TOX DHT) =====
static void* dht_periodic_thread(void* arg) {
    ORCASHI* orcashi = (ORCASHI*)arg;
    
    fprintf(stderr, "[DHT] Tox DHT thread started\n");
    
    while (orcashi->running && orcashi->dht_initialized) {
        if (orcashi->tox_dht) {
            do_dht(orcashi->tox_dht);
        }
        if (orcashi->net_crypto) {
            do_net_crypto(orcashi->net_crypto, orcashi);
        }
        if (orcashi->friend_cons) {
            do_friend_connections(orcashi->friend_cons, orcashi);
        }
        
        usleep(100000);  // 100ms
    }
    
    fprintf(stderr, "[DHT] Tox DHT thread ended\n");
    return NULL;
}

// ===== TOX DHT IP Callback =====
static void tox_dht_ip_callback(void* object, int32_t number, const IP_Port* ip_port) {
    ORCASHI* orcashi = (ORCASHI*)object;
    if (!orcashi) return;
    
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_port->ip.ip.v4, ip, sizeof(ip));
    fprintf(stderr, "[DHT] Found peer at %s:%d\n", ip, ntohs(ip_port->port));
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
    
    strcpy(orcashi->local_ip, "0.0.0.0");
    
    orcashi->connected = false;
    orcashi->running = false;
    orcashi->registered = false;
    orcashi->dht_initialized = false;
    orcashi->dht_enabled = false;
    orcashi->dht_socket = -1;
    orcashi->on_peer_found = NULL;
    orcashi->on_message_received = NULL;
    orcashi->on_status_change = NULL;
    orcashi->tox_dht = NULL;
    orcashi->net = NULL;
    orcashi->onion = NULL;
    orcashi->net_crypto = NULL;
    orcashi->friend_cons = NULL;
    
    pthread_mutex_init(&orcashi->mutex, NULL);
    pthread_mutex_init(&orcashi->dht_mutex, NULL);
    
    // Generate DHT ID (for Tox DHT)
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
    
    printf("[ORCA] Initialized with ID: %s\n", orcashi->my_id);
    
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

// ===== TOX DHT INITIALIZATION =====
bool orcashi_dht_init(ORCASHI* orcashi) {
    if (!orcashi) return false;
    
    // Create UDP socket for DHT
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
    
    // Create Networking_Core
    Networking_Core* net = new_networking(orcashi->dht_socket);
    if (!net) {
        fprintf(stderr, "[DHT] Failed to create Networking_Core!\n");
        close(orcashi->dht_socket);
        orcashi->dht_socket = -1;
        return false;
    }
    orcashi->net = net;
    
    // Create DHT
    DHT* dht = new_dht(stderr, orcashi->dht_id, orcashi->dht_id);
    if (!dht) {
        fprintf(stderr, "[DHT] Failed to create Tox DHT!\n");
        return false;
    }
    orcashi->tox_dht = dht;
    
    // Bootstrap from nodes
    bootstrap_init();
    for (int i = 0; i < BOOTSTRAP_NODES; i++) {
        BootstrapNode node;
        if (bootstrap_get_node(i, &node) == 0 && strlen(node.ip) > 0) {
            IP_Port ip_port;
            ip_port.ip.family = AF_INET;
            inet_pton(AF_INET, node.ip, &ip_port.ip.ip.v4);
            ip_port.port = htons(node.port);
            dht_bootstrap(dht, &ip_port, (const uint8_t*)node.public_key);
            printf("[DHT] Bootstrapping to %s:%d\n", node.ip, node.port);
        }
        usleep(100000);
    }
    
    orcashi->dht_initialized = true;
    orcashi->dht_enabled = true;
    
    // Start DHT thread
    pthread_create(&orcashi->dht_thread, NULL, dht_periodic_thread, orcashi);
    
    printf("[DHT] Tox DHT initialized on port %d\n", DHT_PORT);
    
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
    
    if (orcashi->tox_dht) {
        kill_dht(orcashi->tox_dht);
        orcashi->tox_dht = NULL;
    }
    
    if (orcashi->net) {
        kill_networking(orcashi->net);
        orcashi->net = NULL;
    }
    
    if (orcashi->dht_socket >= 0) {
        close(orcashi->dht_socket);
        orcashi->dht_socket = -1;
    }
}

// ===== DHT REGISTER (TOX DHT) =====
bool orcashi_dht_register(ORCASHI* orcashi) {
    if (!orcashi || !orcashi->dht_initialized) return false;
    
    // Add friend to DHT
    uint32_t lock_token;
    int result = dht_addfriend(orcashi->tox_dht, orcashi->dht_id, 
                               tox_dht_ip_callback, orcashi, 0, &lock_token);
    
    if (result == 0) {
        fprintf(stderr, "[DHT] Registered in Tox DHT!\n");
        return true;
    }
    
    fprintf(stderr, "[DHT] Failed to register in Tox DHT!\n");
    return false;
}

// ===== DHT LOOKUP (TOX DHT) =====
char* orcashi_dht_lookup(ORCASHI* orcashi, const char* id) {
    if (!orcashi || !orcashi->dht_initialized) return NULL;
    
    // Convert ID to public key
    unsigned char public_key[CRYPTO_PUBLIC_KEY_SIZE];
    memset(public_key, 0, CRYPTO_PUBLIC_KEY_SIZE);
    size_t id_len = strlen(id);
    memcpy(public_key, id, id_len > CRYPTO_PUBLIC_KEY_SIZE ? CRYPTO_PUBLIC_KEY_SIZE : id_len);
    
    // Get friend IP
    IP_Port ip_port;
    int result = dht_getfriendip(orcashi->tox_dht, public_key, &ip_port);
    
    if (result == 1 && ip_isset(&ip_port.ip)) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_port.ip.ip.v4, ip, sizeof(ip));
        char* endpoint = malloc(64);
        snprintf(endpoint, 64, "%s:%d", ip, ntohs(ip_port.port));
        return endpoint;
    }
    
    return NULL;
}

// ===== DHT SEARCH =====
char* orcashi_dht_search(ORCASHI* orcashi, const char* id) {
    return orcashi_dht_lookup(orcashi, id);
}

// ===== REGISTER IDENTITY =====
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
        
        CachePeer peer;
        strcpy(peer.id, orcashi->my_id);
        snprintf(peer.endpoint, sizeof(peer.endpoint), "%s:9000", input_ip);
        strcpy(peer.ip, input_ip);
        peer.port = 9000;
        peer.online = true;
        peer.last_seen = time(NULL);
        peer_cache_save_peer(orcashi->cache, &peer);
        
        orcashi_broadcast_presence(orcashi);
        
        // Register in DHT
        if (orcashi->dht_enabled) {
            if (orcashi_dht_register(orcashi)) {
                printf("  [DHT] Registered in Tox DHT!\n");
            } else {
                printf("  [DHT] Failed to register in Tox DHT!\n");
            }
        }
        
        printf("\n  [SUCCESS] Registered!\n");
        printf("  Your ID: %s\n", orcashi->my_id);
        printf("  Your IP: %s\n", input_ip);
        printf("  Your friends can connect using:\n");
        printf("    ./orcashi connect %s\n", orcashi->my_id);
        return true;
    }
    
    printf("  [ERROR] Registration failed!\n");
    return false;
}

// ===== CONNECT PEER =====
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
    
    // 3. Try Tox DHT lookup
    printf("  [DHT] Looking up %s in Tox DHT...\n", id);
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
    printf("DHT: Tox DHT\n");
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
