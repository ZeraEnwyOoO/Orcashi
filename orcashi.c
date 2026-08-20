 // orcashi.c - Full version with ORCA Identity and Crypto
#define _POSIX_C_SOURCE 200809L

#include "orcashi.h"
#include "peer_list.h"
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/select.h>
#include <ifaddrs.h>

/* ============================================================================
 * External References from main.c
 * ============================================================================ */

extern ORCASHI* g_orcashi;
extern PeerList* g_peer_list;

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

#define MAX_MSG_LEN 4096

static void micro_sleep(long microseconds);
static void orcashi_broadcast_presence(ORCASHI* orcashi);
static void orcashi_show_banner(ORCASHI* orcashi);
static void* heartbeat_loop(void* arg);
static void on_peer_found_callback(DiscoveryPeerInfo* peer);
static void on_peer_offline_callback(DiscoveryPeerInfo* peer);

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

ORCASHI* orcashi_create(void) {
    ORCASHI* orcashi = (ORCASHI*)calloc(1, sizeof(ORCASHI));
    if (!orcashi) return NULL;
    
    mkdir(ORCASHI_HOME, 0700);
    
    /* Initialize crypto */
    orca_init_crypto();
    orca_identity_storage_init();
    
    /* Create components */
    orcashi->plug = plug_create();
    orcashi->discovery = discovery_create();
    orcashi->registry = registry_create();
    orcashi->requests = request_manager_create();
    orcashi->cache = peer_cache_create();
    orcashi->endpoints = endpoint_registry_create();
    orcashi->punch = (PunchState*)calloc(1, sizeof(PunchState));
    orcashi->dht = dht_node_create();
    orcashi->session = NULL;
    orcashi->session_established = false;
    orcashi->heartbeat_thread_created = false;
    
    if (!orcashi->plug || !orcashi->discovery || !orcashi->registry ||
        !orcashi->requests || !orcashi->cache || !orcashi->endpoints ||
        !orcashi->punch || !orcashi->dht) {
        orcashi_destroy(orcashi);
        return NULL;
    }
    
    /* Check identity exists but DON'T load without passcode */
    orcashi->has_identity = orca_identity_exists(NULL);
    if (orcashi->has_identity) {
        orcashi->my_id[0] = '\0';
    } else {
        char* id = orcashi_generate_id();
        if (id) {
            strcpy(orcashi->my_id, id);
            free(id);
        }
    }
    
    char* local_ip = orcashi_get_local_ip();
    if (local_ip) {
        strcpy(orcashi->local_ip, local_ip);
        free(local_ip);
    } else {
        strcpy(orcashi->local_ip, "127.0.0.1");
    }
    
    orcashi->connected = false;
    orcashi->running = false;
    orcashi->registered = false;
    
    if (pthread_mutex_init(&orcashi->mutex, NULL) != 0) {
        orcashi_destroy(orcashi);
        return NULL;
    }
    
    /* Set discovery callbacks and references */
    discovery_set_on_peer_found(orcashi->discovery, on_peer_found_callback);
    discovery_set_on_peer_offline(orcashi->discovery, on_peer_offline_callback);
    discovery_set_registry(orcashi->discovery, orcashi->registry);
    discovery_set_request_manager(orcashi->discovery, orcashi->requests);
    
    return orcashi;
}

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
    if (orcashi->dht) { dht_node_destroy(orcashi->dht); orcashi->dht = NULL; }
    if (orcashi->session) { orca_ecdh_session_destroy(orcashi->session); free(orcashi->session); orcashi->session = NULL; }
    
    pthread_mutex_destroy(&orcashi->mutex);
    free(orcashi);
}

bool orcashi_init(ORCASHI* orcashi) {
    if (!orcashi) return false;
    
    /* Load requests from disk */
    request_load(orcashi->requests);
    
    /* Initialize NAT punch */
    if (punch_init(orcashi->punch, PUNCH_PORT) < 0) {
        fprintf(stderr, "[ERROR] Failed to init NAT punch!\n");
        return false;
    }
    
    /* Initialize bootstrap */
    bootstrap_init();
    
    /* Start DHT Node */
    if (dht_node_start(orcashi->dht, DHT_NODE_PORT) < 0) {
        fprintf(stderr, "[WARNING] Failed to start DHT node!\n");
    }
    
    printf("[ORCA] Initialized\n");
    if (orcashi->has_identity && strlen(orcashi->my_id) > 0) {
        printf("[ORCA] ID: %s\n", orcashi->my_id);
        if (orcashi->identity.mode == ORCA_IDENTITY_MODE_SECURE) {
            printf("[ORCA] Mode: SECURE\n");
        }
    } else if (orcashi->has_identity) {
        printf("[ORCA] Identity found (locked) - use './orcashi listen' to unlock\n");
    } else {
        printf("[ORCA] ID: %s (temporary - register to create identity)\n", orcashi->my_id);
    }
    
    orcashi->running = true;
    
    /* Create heartbeat thread */
    if (pthread_create(&orcashi->heartbeat_thread, NULL, heartbeat_loop, orcashi) == 0) {
        orcashi->heartbeat_thread_created = true;
    } else {
        fprintf(stderr, "[WARNING] Failed to create heartbeat thread\n");
    }
    
    return true;
}

/* ============================================================================
 * ROOM MANAGEMENT
 * ============================================================================ */

bool orcashi_create_room(ORCASHI* orcashi, int port) {
    if (!orcashi) return false;
    
    printf("\n================================================\n");
    printf("ORCASHI - CREATE ROOM\n");
    printf("================================================\n");
    
    if (plug_create_server(orcashi->plug, port)) {
        orcashi->connected = true;
        
        strcpy(orcashi->peer_ip, plug_get_peer_ip(orcashi->plug));
        strcpy(orcashi->peer_id, orcashi->peer_ip);
        
        if (orcashi->has_identity && orcashi->identity.mode == ORCA_IDENTITY_MODE_SECURE) {
            printf("[ORCA] Initiating ECDH secure channel...\n");
            if (plug_initiate_ecdh(orcashi->plug)) {
                printf("[ORCA] ECDH handshake initiated\n");
            } else {
                printf("[WARNING] Failed to initiate ECDH\n");
            }
        }
        
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
        
        strcpy(orcashi->peer_ip, ip);
        strcpy(orcashi->peer_id, ip);
        
        if (orcashi->has_identity && orcashi->identity.mode == ORCA_IDENTITY_MODE_SECURE) {
            printf("[ORCA] Initiating ECDH secure channel...\n");
            if (plug_initiate_ecdh(orcashi->plug)) {
                printf("[ORCA] ECDH handshake initiated\n");
            } else {
                printf("[WARNING] Failed to initiate ECDH\n");
            }
        }
        
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

/* ============================================================================
 * MESSAGING - FIXED: ONLY use plug.c
 * ============================================================================ */

bool orcashi_send_message(ORCASHI* orcashi, const char* msg) {
    if (!orcashi || !orcashi->connected) return false;
    
    /* ===== FIX: Use plug.c's secure channel exclusively ===== */
    if (plug_ecdh_complete(orcashi->plug)) {
        return plug_send_secure(orcashi->plug, msg);
    }
    
    /* Plaintext only - no legacy secure path */
    return plug_send_message(orcashi->plug, msg);
}

/* Legacy secure message - kept for API compatibility but uses plug.c */
bool orcashi_send_secure_message(ORCASHI* orcashi, const char* msg) {
    if (!orcashi || !orcashi->connected) return false;
    
    /* ===== FIX: Use plug.c exclusively ===== */
    if (plug_ecdh_complete(orcashi->plug)) {
        return plug_send_secure(orcashi->plug, msg);
    }
    
    return false;
}

bool orcashi_receive_message(ORCASHI* orcashi, char* msg, int msg_size, int timeout_ms) {
    if (!orcashi || !orcashi->connected) return false;
    
    /* ===== FIX: Use plug.c's secure channel exclusively ===== */
    if (plug_ecdh_complete(orcashi->plug)) {
        return plug_receive_secure(orcashi->plug, msg, msg_size);
    }
    
    /* Plaintext only - no legacy secure path */
    char raw_msg[MAX_MSG_LEN];
    if (!plug_receive_message(orcashi->plug, raw_msg, sizeof(raw_msg), timeout_ms)) {
        return false;
    }
    
    /* If we get a SECURE: message but no secure channel, it's an error */
    if (strncmp(raw_msg, "SECURE:", 7) == 0) {
        fprintf(stderr, "[ORCA] Received SECURE message but no secure channel!\n");
        return false;
    }
    
    strncpy(msg, raw_msg, msg_size - 1);
    msg[msg_size - 1] = '\0';
    return true;
}

/* ============================================================================
 * CONNECTION
 * ============================================================================ */

bool orcashi_is_connected(ORCASHI* orcashi) {
    return orcashi && orcashi->connected && plug_is_connected(orcashi->plug);
}

void orcashi_disconnect(ORCASHI* orcashi) {
    if (!orcashi) return;
    
    orcashi->connected = false;
    orcashi->running = false;
    orcashi->session_established = false;
    
    if (orcashi->plug) {
        plug_close_connection(orcashi->plug);
    }
    
    /* Join heartbeat thread if it was created */
    if (orcashi->heartbeat_thread_created) {
        pthread_join(orcashi->heartbeat_thread, NULL);
        orcashi->heartbeat_thread_created = false;
    }
    
    discovery_stop(orcashi->discovery);
    dht_node_stop(orcashi->dht);
    
    if (orcashi->session) {
        orca_ecdh_session_destroy(orcashi->session);
        free(orcashi->session);
        orcashi->session = NULL;
    }
}

/* ============================================================================
 * IDENTITY
 * ============================================================================ */

const char* orcashi_get_my_id(ORCASHI* orcashi) {
    if (!orcashi) return NULL;
    if (strlen(orcashi->my_id) == 0) {
        return NULL;
    }
    return orcashi->my_id;
}

const char* orcashi_get_peer_id(ORCASHI* orcashi) {
    return orcashi ? orcashi->peer_id : NULL;
}

const char* orcashi_get_peer_ip(ORCASHI* orcashi) {
    return orcashi ? orcashi->peer_ip : NULL;
}

bool orcashi_load_identity(ORCASHI* orcashi, const char* passcode) {
    if (!orcashi) return false;
    
    if (orca_identity_load(&orcashi->identity, passcode) < 0) {
        return false;
    }
    
    strcpy(orcashi->my_id, orcashi->identity.id);
    orcashi->has_identity = true;
    return true;
}

bool orcashi_has_identity(ORCASHI* orcashi) {
    return orcashi && orcashi->has_identity && strlen(orcashi->my_id) > 0;
}

/* ============================================================================
 * SECURE SESSION - FIXED: Use plug.c exclusively
 * ============================================================================ */

bool orcashi_init_secure_session(ORCASHI* orcashi) {
    if (!orcashi || !orcashi->plug) return false;
    
    /* ===== FIX: Use plug.c exclusively ===== */
    return plug_initiate_ecdh(orcashi->plug);
}

bool orcashi_complete_secure_session(ORCASHI* orcashi, const char* peer_public_key_hex) {
    if (!orcashi || !orcashi->plug) return false;
    
    /* ===== FIX: Use plug.c exclusively ===== */
    return plug_complete_ecdh(orcashi->plug, peer_public_key_hex);
}

bool orcashi_session_established(ORCASHI* orcashi) {
    if (!orcashi || !orcashi->plug) return false;
    
    /* ===== FIX: Use plug.c exclusively ===== */
    return plug_ecdh_complete(orcashi->plug);
}

/* ============================================================================
 * PEER MANAGEMENT
 * ============================================================================ */

bool orcashi_register_identity(ORCASHI* orcashi) {
    if (!orcashi) return false;
    
    printf("\n");
    printf("  +------------------------------------------+\n");
    printf("  |           ORCA Registration              |\n");
    printf("  +------------------------------------------+\n");
    printf("\n");
    
    if (orcashi->has_identity) {
        printf("  You are already registered!\n");
        printf("  ID: %s\n", orcashi->identity.id);
        if (orcashi->identity.mode == ORCA_IDENTITY_MODE_SECURE) {
            printf("  Name: %s\n", orcashi->identity.name);
            printf("  Mode: SECURE\n");
        } else {
            printf("  Mode: NORMAL\n");
        }
        printf("  Use './orcashi identity' to view details\n");
        return false;
    }
    
    printf("  Your ID will be: %s\n", orcashi->my_id);
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
    
    strcpy(orcashi->local_ip, input_ip);
    orcashi_save_ip(input_ip);
    
    if (orcashi->identity.mode == ORCA_IDENTITY_MODE_SECURE) {
        discovery_set_my_secure_identity(orcashi->discovery, &orcashi->identity);
    } else {
        discovery_set_my_identity(orcashi->discovery, orcashi->my_id, input_ip, ORCASHI_PORT);
    }
    
    if (registry_register_peer(orcashi->registry, orcashi->my_id, input_ip, "9000")) {
        orcashi->registered = true;
        
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
        
        dht_node_announce(orcashi->dht, orcashi->my_id, ORCASHI_PORT);
        
        printf("\n  [SUCCESS] Registered!\n");
        printf("  Your ID: %s\n", orcashi->my_id);
        printf("  Your IP: %s\n", input_ip);
        printf("  Your friends can connect using:\n");
        printf("    ./orcashi join %s\n", input_ip);
        printf("  Or using your ID (DHT):\n");
        printf("    ./orcashi add %s\n", orcashi->my_id);
        return true;
    }
    
    printf("  [ERROR] Registration failed!\n");
    return false;
}

bool orcashi_connect_peer(ORCASHI* orcashi, const char* id) {
    if (!orcashi) return false;
    
    char norm_id[64];
    if (!discovery_normalize_id(id, norm_id, sizeof(norm_id))) {
        printf("[ERROR] Invalid ID format: %s\n", id);
        return false;
    }
    
    printf("\n  [ORCA] Looking for %s...\n", id);
    
    RegistryPeer reg_peer;
    if (registry_get_peer(orcashi->registry, norm_id, &reg_peer)) {
        printf("  [ORCA] Found in registry: %s:%s (status: %s, mode: %s)\n", 
               reg_peer.ip, reg_peer.port, reg_peer.status,
               registry_get_mode_string(&reg_peer));
        
        if (strlen(reg_peer.ip) > 0 && 
            strcmp(reg_peer.ip, "0.0.0.0") != 0 &&
            strcmp(reg_peer.status, "accepted") == 0) {
            
            if (reg_peer.mode == REG_MODE_SECURE && orcashi->has_identity) {
                strcpy(orcashi->peer_public_key_hex, reg_peer.public_key);
            }
            
            return orcashi_join_room(orcashi, reg_peer.ip, atoi(reg_peer.port));
        } else {
            printf("  [ORCA] Peer %s registered but IP unknown or not accepted, trying cache...\n", id);
        }
    }
    
    CachePeer peer;
    if (peer_cache_get_peer(orcashi->cache, norm_id, &peer) && peer.online) {
        if (strlen(peer.ip) > 0 && strcmp(peer.ip, "0.0.0.0") != 0) {
            printf("  [ORCA] Found in cache: %s:%d\n", peer.ip, peer.port);
            return orcashi_join_room(orcashi, peer.ip, peer.port);
        }
    }
    
    printf("  [ORCA] Not found in registry/cache, querying network...\n");
    discovery_query_peer(orcashi->discovery, norm_id);
    
    time_t start = time(NULL);
    while (time(NULL) - start < 10) {
        DiscoveryPeerInfo p;
        if (discovery_find_peer(orcashi->discovery, norm_id, &p)) {
            printf("  [ORCA] Found peer via discovery: %s at %s:%d\n", id, p.ip, p.port);
            char port_str[16];
            snprintf(port_str, sizeof(port_str), "%d", p.port);
            
            if (p.is_secure && orcashi->has_identity) {
                strcpy(orcashi->peer_public_key_hex, p.public_key);
            }
            
            registry_update_peer(orcashi->registry, norm_id, p.ip, port_str);
            
            CachePeer cache_peer;
            memset(&cache_peer, 0, sizeof(cache_peer));
            strcpy(cache_peer.id, norm_id);
            strcpy(cache_peer.ip, p.ip);
            cache_peer.port = p.port;
            cache_peer.online = true;
            cache_peer.last_seen = time(NULL);
            peer_cache_save_peer(orcashi->cache, &cache_peer);
            
            return orcashi_join_room(orcashi, p.ip, p.port);
        }
        
        if (peer_cache_get_peer(orcashi->cache, norm_id, &peer) && peer.online) {
            if (strlen(peer.ip) > 0 && strcmp(peer.ip, "0.0.0.0") != 0) {
                printf("  [ORCA] Found in cache during search: %s:%d\n", peer.ip, peer.port);
                return orcashi_join_room(orcashi, peer.ip, peer.port);
            }
        }
        micro_sleep(100000);
    }
    
    printf("  [ORCA] Trying DHT lookup for %s (can take up to 20s)...\n", id);
    char dht_ip[INET_ADDRSTRLEN];
    int dht_port;
    if (dht_node_lookup(orcashi->dht, norm_id, 20, dht_ip, &dht_port)) {
        printf("  [ORCA] Found via DHT: %s:%d\n", dht_ip, dht_port);
        
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", dht_port);
        registry_update_peer(orcashi->registry, norm_id, dht_ip, port_str);
        
        CachePeer cache_peer;
        memset(&cache_peer, 0, sizeof(cache_peer));
        strcpy(cache_peer.id, norm_id);
        strcpy(cache_peer.ip, dht_ip);
        cache_peer.port = dht_port;
        cache_peer.online = true;
        cache_peer.last_seen = time(NULL);
        peer_cache_save_peer(orcashi->cache, &cache_peer);
        
        return orcashi_join_room(orcashi, dht_ip, dht_port);
    }
    
    printf("  [ERROR] Peer %s not found!\n", id);
    return false;
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

/* ============================================================================
 * CALLBACKS
 * ============================================================================ */

void orcashi_set_callbacks(ORCASHI* orcashi,
                          void (*on_peer_found)(const char*, const char*),
                          void (*on_message_received)(const char*, const char*),
                          void (*on_status_change)(const char*)) {
    if (!orcashi) return;
    orcashi->on_peer_found = on_peer_found;
    orcashi->on_message_received = on_message_received;
    orcashi->on_status_change = on_status_change;
}

/* ============================================================================
 * INTERNAL FUNCTIONS
 * ============================================================================ */

static void micro_sleep(long microseconds) {
    struct timespec ts;
    ts.tv_sec = microseconds / 1000000;
    ts.tv_nsec = (microseconds % 1000000) * 1000;
    nanosleep(&ts, NULL);
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
    printf("  ORCASHI v4.0 - Secure P2P Chat\n");
    printf("============================================================\n");
    printf("\033[0m");
    
    if (strlen(orcashi->my_id) > 0) {
        printf("Your ID: %s\n", orcashi->my_id);
    } else if (orcashi->has_identity) {
        printf("Your ID: (locked - use './orcashi listen' to unlock)\n");
    } else {
        printf("Your ID: (none - use './orcashi register')\n");
    }
    
    if (orcashi->has_identity && orcashi->identity.mode == ORCA_IDENTITY_MODE_SECURE) {
        printf("Secure Mode: %s\n", orcashi->identity.name);
    }
    
    /* ===== FIX: Use plug.c exclusively for secure status ===== */
    if (plug_ecdh_complete(orcashi->plug)) {
        printf("Secure Session: ENABLED (ECDH+AES-GCM)\n");
    } else {
        printf("Secure Session: DISABLED (Plaintext)\n");
    }
    
    printf("Type /help for commands\n");
    printf("============================================================\n");
    printf("\n");
}

static void on_peer_found_callback(DiscoveryPeerInfo* peer) {
    (void)peer;
    /* This is called when discovery finds a peer on the network */
}

static void on_peer_offline_callback(DiscoveryPeerInfo* peer) {
    (void)peer;
    /* This is called when a peer goes offline */
}

static void* heartbeat_loop(void* arg) {
    ORCASHI* orcashi = (ORCASHI*)arg;
    int tick = 0;
    
    while (orcashi && orcashi->running) {
        sleep(30);
        tick++;
        
        endpoint_cleanup_stale(orcashi->endpoints, 60);
        peer_cache_auto_save(orcashi->cache);
        dht_node_periodic(orcashi->dht);
        
        if (orcashi->registered) {
            orcashi_broadcast_presence(orcashi);
            if (tick % 50 == 0) {
                dht_node_announce(orcashi->dht, orcashi->my_id, ORCASHI_PORT);
            }
        }
    }
    return NULL;
}

/* ============================================================================
 * UTILITY
 * ============================================================================ */

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

bool orcashi_save_ip(const char* ip) {
    if (!ip) return false;
    char ip_file[512];
    snprintf(ip_file, sizeof(ip_file), "%s/ip", ORCASHI_HOME);
    FILE* f = fopen(ip_file, "w");
    if (!f) return false;
    fprintf(f, "%s", ip);
    fclose(f);
    return true;
}
