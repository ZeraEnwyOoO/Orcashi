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
        // Run Tox DHT
        do_dht(orcashi->tox_dht);
        do_net_crypto(orcashi->net_crypto, orcashi);
        do_friend_connections(orcashi->friend_cons, orcashi);
        
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
    Networking_Core* net = new_networking(orcashi->dht_socket, orcashi->log, orcashi->rng);
    if (!net) {
        fprintf(stderr, "[DHT] Failed to create Networking_Core!\n");
        close(orcashi->dht_socket);
        orcashi->dht_socket = -1;
        return false;
    }
    orcashi->net = net;
    
    // Create DHT
    DHT* dht = new_dht(orcashi->log, orcashi->mem, orcashi->rng, orcashi->ns, 
                       orcashi->mono_time, net, true, true);
    if (!dht) {
        fprintf(stderr, "[DHT] Failed to create Tox DHT!\n");
        return false;
    }
    orcashi->tox_dht = dht;
    
    // Set DHT keys
    dht_set_self_public_key(dht, orcashi->dht_id);
    dht_set_self_secret_key(dht, orcashi->dht_secret_key);
    
    // Bootstrap from nodes
    bootstrap_init();
    for (int i = 0; i < BOOTSTRAP_NODES; i++) {
        BootstrapNode node;
        if (bootstrap_get_node(i, &node) == 0 && strlen(node.ip) > 0) {
            IP_Port ip_port;
            ip_port.ip.family = AF_INET;
            inet_pton(AF_INET, node.ip, &ip_port.ip.ip.v4);
            ip_port.port = htons(node.port);
            dht_bootstrap(dht, &ip_port, node.public_key);
        }
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
    memcpy(public_key, id, strlen(id) > CRYPTO_PUBLIC_KEY_SIZE ? CRYPTO_PUBLIC_KEY_SIZE : strlen(id));
    
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

// ===== ORCASHI INIT =====
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

// ... rest of orcashi.c (same as before) ...
