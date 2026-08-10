 // orcashi.c - DHT Core
#define _POSIX_C_SOURCE 200809L
#include "orcashi.h"
#include <sys/select.h>
#include <sys/time.h>

// ============================================================
//  STATIC FUNCTIONS
// ============================================================

static void* dht_periodic_thread(void* arg);
static void* tcp_receive_thread(void* arg);
static void* tcp_send_thread(void* arg);
static void dht_nodes_response_callback(const DHT* dht, const Node_format* node, void* user_data);
static void dht_lookup_callback(void* closure, int event, const unsigned char* info_hash,
                                const void* data, size_t data_len);

// ============================================================
//  DHT CALLBACKS (from Tox)
// ============================================================

// Tox DHT needs these functions
int dht_sendto(int sockfd, const void* buf, int len, int flags,
               const struct sockaddr* dest_addr, int addrlen) {
    if (!buf || len <= 0 || sockfd < 0) return -1;
    ssize_t sent = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    if (sent < 0) {
        log_debug("[DHT] sendto failed: %s", strerror(errno));
        return -1;
    }
    return (int)sent;
}

int dht_blacklisted(const struct sockaddr* sa, int salen) {
    (void)sa; (void)salen;
    return 0;
}

int dht_random_bytes(void* buf, size_t size) {
    // Use Tox's random
    if (buf == NULL || size == 0) return -1;
    // Simple fallback
    unsigned char* b = (unsigned char*)buf;
    for (size_t i = 0; i < size; i++) {
        b[i] = (unsigned char)(rand() & 0xFF);
    }
    return 0;
}

void dht_hash(void* hash_return, int hash_size,
              const void* data1, int len1,
              const void* data2, int len2,
              const void* data3, int len3) {
    // Simple SHA256 using openssl
    unsigned char hash[32];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(hash_return, 0, hash_size); return; }
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data1, len1);
    if (data2 && len2 > 0) EVP_DigestUpdate(ctx, data2, len2);
    if (data3 && len3 > 0) EVP_DigestUpdate(ctx, data3, len3);
    unsigned int len = 32;
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    int copy_size = (hash_size < 32) ? hash_size : 32;
    memcpy(hash_return, hash, copy_size);
}

// ============================================================
//  ORCASHI CREATE / DESTROY
// ============================================================

ORCASHI* orcashi_create(void) {
    ORCASHI* orcashi = (ORCASHI*)calloc(1, sizeof(ORCASHI));
    if (!orcashi) return NULL;
    
    srand(time(NULL) ^ getpid());
    
    // Initialize mutexes
    pthread_mutex_init(&orcashi->dht_mutex, NULL);
    pthread_mutex_init(&orcashi->peer_mutex, NULL);
    pthread_mutex_init(&orcashi->tcp_mutex, NULL);
    pthread_cond_init(&orcashi->tcp_cond, NULL);
    
    // Initialize queue
    orcashi->queue_capacity = 100;
    orcashi->message_queue = (char**)calloc(orcashi->queue_capacity, sizeof(char*));
    orcashi->send_queue = (char**)calloc(orcashi->queue_capacity, sizeof(char*));
    
    // Generate ID
    char* id = orcashi_generate_id();
    strcpy(orcashi->self_id_hex, id);
    free(id);
    
    // Set default bootstrap nodes
    static BootstrapNode default_bootstrap[] = {
        {"router.bittorrent.com", 6881},
        {"dht.transmissionbt.com", 6881},
        {"router.utorrent.com", 6881},
        {"dht.aelitis.com", 6881},
        {"bootstrap.jami.net", 6881},
        {"dht.libtorrent.org", 6881}
    };
    
    orcashi->bootstrap_nodes = default_bootstrap;
    orcashi->bootstrap_count = 6;
    
    orcashi->running = false;
    orcashi->dht_initialized = false;
    orcashi->connected = false;
    orcashi->tcp_socket = -1;
    orcashi->dht_socket = -1;
    orcashi->peer_count = 0;
    
    log_info("[ORCASHI] Created with ID: %s", orcashi->self_id_hex);
    
    return orcashi;
}

void orcashi_destroy(ORCASHI* orcashi) {
    if (!orcashi) return;
    
    orcashi->running = false;
    orcashi_disconnect(orcashi);
    orcashi_dht_shutdown(orcashi);
    
    // Free queues
    if (orcashi->message_queue) {
        for (int i = 0; i < orcashi->message_count; i++) {
            if (orcashi->message_queue[i]) free(orcashi->message_queue[i]);
        }
        free(orcashi->message_queue);
    }
    if (orcashi->send_queue) {
        for (int i = 0; i < orcashi->send_count; i++) {
            if (orcashi->send_queue[i]) free(orcashi->send_queue[i]);
        }
        free(orcashi->send_queue);
    }
    
    pthread_mutex_destroy(&orcashi->dht_mutex);
    pthread_mutex_destroy(&orcashi->peer_mutex);
    pthread_mutex_destroy(&orcashi->tcp_mutex);
    pthread_cond_destroy(&orcashi->tcp_cond);
    
    free(orcashi);
}

// ============================================================
//  DHT INITIALIZATION (USING TOX DHT)
// ============================================================

bool orcashi_dht_init(ORCASHI* orcashi) {
    if (!orcashi) return false;
    
    pthread_mutex_lock(&orcashi->dht_mutex);
    
    log_info("[DHT] Initializing DHT...");
    
    // Create socket
    orcashi->dht_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (orcashi->dht_socket < 0) {
        log_error("[DHT] Failed to create socket: %s", strerror(errno));
        pthread_mutex_unlock(&orcashi->dht_mutex);
        return false;
    }
    
    int opt = 1;
    setsockopt(orcashi->dht_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(orcashi->dht_socket, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(DHT_PORT);
    
    if (bind(orcashi->dht_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("[DHT] Failed to bind port %d: %s", DHT_PORT, strerror(errno));
        close(orcashi->dht_socket);
        orcashi->dht_socket = -1;
        pthread_mutex_unlock(&orcashi->dht_mutex);
        return false;
    }
    
    // Generate DHT keypair
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = rand() & 0xFF;
    crypto_sign_seed_keypair(orcashi->self_public_key, orcashi->self_secret_key, seed);
    crypto_memzero(seed, 32);
    
    // Convert to hex
    orcashi_bytes_to_hex(orcashi->self_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    
    log_info("[DHT] Node ID: %s", orcashi->self_id_hex);
    
    // Initialize DHT with Tox
    int result = dht_init(orcashi->dht_socket, -1, orcashi->self_public_key, NULL);
    if (result < 0) {
        log_error("[DHT] dht_init failed: %d", result);
        close(orcashi->dht_socket);
        orcashi->dht_socket = -1;
        pthread_mutex_unlock(&orcashi->dht_mutex);
        return false;
    }
    
    orcashi->dht_initialized = true;
    orcashi->running = true;
    
    // Start DHT thread
    pthread_create(&orcashi->dht_thread, NULL, dht_periodic_thread, orcashi);
    
    log_info("[DHT] Initialized on port %d", DHT_PORT);
    
    // Bootstrap
    for (int i = 0; i < orcashi->bootstrap_count; i++) {
        BootstrapNode* node = &orcashi->bootstrap_nodes[i];
        struct hostent* he = gethostbyname(node->host);
        if (he && he->h_addr_list[0]) {
            struct sockaddr_in boot_addr;
            memset(&boot_addr, 0, sizeof(boot_addr));
            boot_addr.sin_family = AF_INET;
            boot_addr.sin_port = htons(node->port);
            memcpy(&boot_addr.sin_addr, he->h_addr_list[0], he->h_length);
            
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &boot_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
            log_info("[DHT] Bootstrapping to %s (%s)", node->host, ip_str);
            
            dht_ping_node((struct sockaddr*)&boot_addr, sizeof(boot_addr));
            usleep(100000);
        } else {
            log_warn("[DHT] Failed to resolve %s", node->host);
        }
    }
    
    pthread_mutex_unlock(&orcashi->dht_mutex);
    return true;
}

void orcashi_dht_shutdown(ORCASHI* orcashi) {
    if (!orcashi || !orcashi->dht_initialized) return;
    
    orcashi->running = false;
    orcashi->dht_initialized = false;
    
    if (orcashi->dht_thread) {
        pthread_join(orcashi->dht_thread, NULL);
        orcashi->dht_thread = 0;
    }
    
    dht_uninit();
    
    if (orcashi->dht_socket >= 0) {
        close(orcashi->dht_socket);
        orcashi->dht_socket = -1;
    }
    
    log_info("[DHT] Shutdown complete");
}

// ============================================================
//  DHT PERIODIC THREAD
// ============================================================

static void* dht_periodic_thread(void* arg) {
    ORCASHI* orcashi = (ORCASHI*)arg;
    char buffer[65536];
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    time_t tosleep = 0;
    fd_set readfds;
    struct timeval tv;
    
    log_info("[DHT] Thread started");
    
    while (orcashi->running && orcashi->dht_initialized) {
        FD_ZERO(&readfds);
        if (orcashi->dht_socket >= 0) {
            FD_SET(orcashi->dht_socket, &readfds);
        }
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int nfds = select(orcashi->dht_socket + 1, &readfds, NULL, NULL, &tv);
        
        if (nfds > 0 && orcashi->dht_socket >= 0 && 
            FD_ISSET(orcashi->dht_socket, &readfds)) {
            fromlen = sizeof(from);
            int n = recvfrom(orcashi->dht_socket, buffer, sizeof(buffer) - 1, 0,
                            (struct sockaddr*)&from, &fromlen);
            if (n > 0) {
                buffer[n] = '\0';
                // Log DHT packet
                char ip_str[INET_ADDRSTRLEN];
                int port = 0;
                if (from.ss_family == AF_INET) {
                    struct sockaddr_in* sin = (struct sockaddr_in*)&from;
                    inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
                    port = ntohs(sin->sin_port);
                }
                log_dht_packet("RECV", ip_str, port, n);
                
                dht_periodic(buffer, n, (struct sockaddr*)&from, fromlen,
                            &tosleep, dht_lookup_callback, orcashi);
            }
        }
        
        // Run periodic DHT tasks
        dht_periodic(NULL, 0, NULL, 0, &tosleep, dht_lookup_callback, orcashi);
        
        // DHT status
        static time_t last_status = 0;
        time_t now = time(NULL);
        if (now - last_status > 30) {
            last_status = now;
            int good, dubious, cached, incoming;
            dht_nodes(AF_INET, &good, &dubious, &cached, &incoming);
            log_info("[DHT] Nodes: %d good, %d dubious, %d cached, %d incoming",
                     good, dubious, cached, incoming);
            
            if (good > 0) {
                log_info("[DHT] Connected to DHT network!");
            }
        }
        
        if (tosleep > 0 && orcashi->running) {
            usleep((tosleep < 5 ? tosleep : 5) * 1000000);
        }
    }
    
    log_info("[DHT] Thread ended");
    return NULL;
}

// ============================================================
//  DHT LOOKUP (FIND PEER BY ID) - USING TOX DHT
// ============================================================

static void dht_lookup_callback(void* closure, int event, const unsigned char* info_hash,
                                const void* data, size_t data_len) {
    DHTLookup* lookup = (DHTLookup*)closure;
    if (!lookup) return;
    
    pthread_mutex_lock(&lookup->mutex);
    
    if (event == DHT_EVENT_VALUES || event == DHT_EVENT_VALUES6) {
        if (data && data_len > 0 && data_len < sizeof(lookup->endpoint)) {
            memcpy(lookup->endpoint, data, data_len);
            lookup->endpoint[data_len] = '\0';
            lookup->success = 1;
            lookup->done = 1;
            log_info("[DHT] Found peer: %s", lookup->endpoint);
            pthread_cond_signal(&lookup->cond);
        }
    }
    
    if (event == DHT_EVENT_SEARCH_DONE || event == DHT_EVENT_SEARCH_DONE6) {
        lookup->done = 1;
        if (!lookup->success) {
            log_info("[DHT] Search done, peer not found");
            pthread_cond_signal(&lookup->cond);
        }
    }
    
    pthread_mutex_unlock(&lookup->mutex);
}

char* orcashi_dht_lookup(ORCASHI* orcashi, const char* id) {
    if (!orcashi || !orcashi->dht_initialized) {
        log_error("[DHT] Cannot lookup: DHT not initialized");
        return NULL;
    }
    
    log_info("[DHT] Looking up peer: %s", id);
    
    // Convert hex ID to bytes
    uint8_t info_hash[CRYPTO_PUBLIC_KEY_SIZE];
    if (orcashi_hex_to_bytes(id, info_hash, CRYPTO_PUBLIC_KEY_SIZE) < 0) {
        log_error("[DHT] Invalid ID format: %s", id);
        return NULL;
    }
    
    DHTLookup lookup;
    memset(&lookup, 0, sizeof(lookup));
    strcpy(lookup.id, id);
    lookup.done = 0;
    lookup.success = 0;
    pthread_mutex_init(&lookup.mutex, NULL);
    pthread_cond_init(&lookup.cond, NULL);
    
    // Start DHT search
    int result = dht_search(info_hash, 0, AF_INET, dht_lookup_callback, &lookup);
    if (result < 0) {
        log_error("[DHT] dht_search failed: %d", result);
        pthread_mutex_destroy(&lookup.mutex);
        pthread_cond_destroy(&lookup.cond);
        return NULL;
    }
    
    // Wait for result
    pthread_mutex_lock(&lookup.mutex);
    int timeout = DHT_LOOKUP_TIMEOUT;
    while (!lookup.done && timeout > 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        pthread_cond_timedwait(&lookup.cond, &lookup.mutex, &ts);
        timeout--;
        if (timeout % 5 == 0) {
            log_info("[DHT] Waiting for response... (%ds left)", timeout);
        }
    }
    pthread_mutex_unlock(&lookup.mutex);
    
    pthread_mutex_destroy(&lookup.mutex);
    pthread_cond_destroy(&lookup.cond);
    
    if (lookup.success && strlen(lookup.endpoint) > 0) {
        log_info("[DHT] Found peer at: %s", lookup.endpoint);
        return strdup(lookup.endpoint);
    }
    
    log_info("[DHT] Peer not found: %s", id);
    return NULL;
}

char* orcashi_dht_search(ORCASHI* orcashi, const char* id) {
    return orcashi_dht_lookup(orcashi, id);
}

// ============================================================
//  DHT REGISTER (STORE ID → IP)
// ============================================================

bool orcashi_dht_register(ORCASHI* orcashi) {
    if (!orcashi || !orcashi->dht_initialized) {
        log_error("[DHT] Cannot register: DHT not initialized");
        return false;
    }
    
    // Use ID as info_hash
    uint8_t info_hash[CRYPTO_PUBLIC_KEY_SIZE];
    if (orcashi_hex_to_bytes(orcashi->self_id_hex, info_hash, CRYPTO_PUBLIC_KEY_SIZE) < 0) {
        log_error("[DHT] Invalid ID format");
        return false;
    }
    
    log_info("[DHT] Registering ID in DHT...");
    
    // Get local IP
    char* local_ip = orcashi_get_local_ip();
    log_info("[DHT] Registering at %s:%d", local_ip, ORCASHI_PORT);
    free(local_ip);
    
    // Start announce
    int result = dht_search(info_hash, ORCASHI_PORT, AF_INET, NULL, NULL);
    
    if (result >= 0) {
        log_info("[DHT] Registration started successfully!");
        return true;
    }
    
    log_error("[DHT] Registration failed! (result=%d)", result);
    return false;
}

// ============================================================
//  TOX DHT NODES RESPONSE CALLBACK
// ============================================================

static void dht_nodes_response_callback(const DHT* dht, const Node_format* node, void* user_data) {
    (void)dht;
    ORCASHI* orcashi = (ORCASHI*)user_data;
    if (!orcashi || !node) return;
    
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &node->ip_port.ip.ip.v4, ip_str, sizeof(ip_str));
    
    log_dht("[DHT] New node discovered: %s:%d", ip_str, ntohs(node->ip_port.port));
    
    // Add to peer cache
    char hex_id[CRYPTO_PUBLIC_KEY_SIZE * 2 + 1];
    orcashi_bytes_to_hex(node->public_key, CRYPTO_PUBLIC_KEY_SIZE);
    orcashi_add_peer(orcashi, hex_id, ip_str, ntohs(node->ip_port.port));
}

// ============================================================
//  MAIN INIT
// ============================================================

bool orcashi_init(ORCASHI* orcashi) {
    if (!orcashi) return false;
    
    log_info("[ORCASHI] Initializing v%s", ORCASHI_VERSION);
    
    // Initialize DHT
    if (!orcashi_dht_init(orcashi)) {
        log_error("[ORCASHI] Failed to initialize DHT");
        return false;
    }
    
    // Set DHT callback
    dht_callback_nodes_response(orcashi->dht, dht_nodes_response_callback);
    
    log_info("[ORCASHI] Initialization complete");
    log_info("[ORCASHI] My ID: %s", orcashi->self_id_hex);
    
    return true;
}

// ============================================================
//  PEER MANAGEMENT
// ============================================================

bool orcashi_add_peer(ORCASHI* orcashi, const char* id, const char* ip, int port) {
    if (!orcashi || !id || !ip) return false;
    
    pthread_mutex_lock(&orcashi->peer_mutex);
    
    // Check if exists
    for (int i = 0; i < orcashi->peer_count; i++) {
        if (strcmp(orcashi->peers[i].id, id) == 0) {
            // Update
            strcpy(orcashi->peers[i].ip, ip);
            orcashi->peers[i].port = port;
            orcashi->peers[i].last_seen = time(NULL);
            orcashi->peers[i].online = true;
            pthread_mutex_unlock(&orcashi->peer_mutex);
            return true;
        }
    }
    
    // Add new
    if (orcashi->peer_count >= MAX_PEER_CACHE) {
        log_warn("[PEER] Cache full, removing oldest");
        // Remove oldest
        time_t oldest = orcashi->peers[0].last_seen;
        int oldest_idx = 0;
        for (int i = 1; i < orcashi->peer_count; i++) {
            if (orcashi->peers[i].last_seen < oldest) {
                oldest = orcashi->peers[i].last_seen;
                oldest_idx = i;
            }
        }
        // Shift
        for (int i = oldest_idx; i < orcashi->peer_count - 1; i++) {
            orcashi->peers[i] = orcashi->peers[i + 1];
        }
        orcashi->peer_count--;
    }
    
    Peer* peer = &orcashi->peers[orcashi->peer_count++];
    strcpy(peer->id, id);
    strcpy(peer->ip, ip);
    peer->port = port;
    peer->online = true;
    peer->last_seen = time(NULL);
    
    // Convert hex to bytes
    orcashi_hex_to_bytes(id, peer->public_key, CRYPTO_PUBLIC_KEY_SIZE);
    
    pthread_mutex_unlock(&orcashi->peer_mutex);
    
    log_info("[PEER] Added: %s at %s:%d", id, ip, port);
    
    if (orcashi->on_peer_found) {
        orcashi->on_peer_found(id, ip);
    }
    
    return true;
}

bool orcashi_find_peer(ORCASHI* orcashi, const char* id, Peer* out_peer) {
    if (!orcashi || !id || !out_peer) return false;
    
    pthread_mutex_lock(&orcashi->peer_mutex);
    
    for (int i = 0; i < orcashi->peer_count; i++) {
        if (strcmp(orcashi->peers[i].id, id) == 0 && orcashi->peers[i].online) {
            *out_peer = orcashi->peers[i];
            pthread_mutex_unlock(&orcashi->peer_mutex);
            return true;
        }
    }
    
    pthread_mutex_unlock(&orcashi->peer_mutex);
    return false;
}

void orcashi_show_peers(ORCASHI* orcashi) {
    if (!orcashi) return;
    
    pthread_mutex_lock(&orcashi->peer_mutex);
    
    printf("\n");
    printf("  +------------------------------------------+\n");
    printf("  |              Your Peers                   |\n");
    printf("  +------------------------------------------+\n");
    printf("\n");
    
    if (orcashi->peer_count == 0) {
        printf("    No peers found.\n");
    } else {
        for (int i = 0; i < orcashi->peer_count; i++) {
            Peer* p = &orcashi->peers[i];
            printf("    %s - %s:%d %s\n",
                   p->id, p->ip, p->port,
                   p->online ? "[ONLINE]" : "[OFFLINE]");
        }
    }
    
    printf("\n");
    pthread_mutex_unlock(&orcashi->peer_mutex);
}

// ============================================================
//  CONNECT PEER BY ID
// ============================================================

bool orcashi_connect_peer(ORCASHI* orcashi, const char* id) {
    if (!orcashi || !id) return false;
    
    log_info("[ORCASHI] Looking for peer: %s", id);
    
    // 1. Check local cache
    Peer peer;
    if (orcashi_find_peer(orcashi, id, &peer) && peer.online) {
        log_info("[ORCASHI] Found in cache: %s:%d", peer.ip, peer.port);
        return orcashi_join_room(orcashi, peer.ip, peer.port);
    }
    
    // 2. Try DHT lookup
    char* endpoint = orcashi_dht_lookup(orcashi, id);
    if (endpoint) {
        char ip[INET_ADDRSTRLEN];
        int port = ORCASHI_PORT;
        sscanf(endpoint, "%[^:]:%d", ip, &port);
        free(endpoint);
        
        log_info("[ORCASHI] Found via DHT: %s:%d", ip, port);
        return orcashi_join_room(orcashi, ip, port);
    }
    
    log_error("[ORCASHI] Peer not found: %s", id);
    return false;
}

// ============================================================
//  TCP CHAT IMPLEMENTATION
// ============================================================

bool orcashi_create_room(ORCASHI* orcashi, int port) {
    if (!orcashi) return false;
    
    log_info("[TCP] Creating room on port %d", port);
    
    orcashi->tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (orcashi->tcp_socket < 0) {
        log_error("[TCP] Failed to create socket: %s", strerror(errno));
        return false;
    }
    
    int opt = 1;
    setsockopt(orcashi->tcp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(orcashi->tcp_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("[TCP] Failed to bind: %s", strerror(errno));
        close(orcashi->tcp_socket);
        orcashi->tcp_socket = -1;
        return false;
    }
    
    if (listen(orcashi->tcp_socket, 5) < 0) {
        log_error("[TCP] Failed to listen: %s", strerror(errno));
        close(orcashi->tcp_socket);
        orcashi->tcp_socket = -1;
        return false;
    }
    
    log_info("[TCP] Waiting for connection...");
    
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_sock = accept(orcashi->tcp_socket, (struct sockaddr*)&client_addr, &addr_len);
    
    if (client_sock < 0) {
        log_error("[TCP] Failed to accept: %s", strerror(errno));
        close(orcashi->tcp_socket);
        orcashi->tcp_socket = -1;
        return false;
    }
    
    close(orcashi->tcp_socket);
    orcashi->tcp_socket = client_sock;
    
    inet_ntop(AF_INET, &client_addr.sin_addr, orcashi->peer_ip, sizeof(orcashi->peer_ip));
    log_info("[TCP] Client connected from %s", orcashi->peer_ip);
    
    orcashi->connected = true;
    orcashi->running = true;
    
    // Start TCP threads
    pthread_create(&orcashi->tcp_receive_thread, NULL, tcp_receive_thread, orcashi);
    pthread_create(&orcashi->tcp_send_thread, NULL, tcp_send_thread, orcashi);
    
    return true;
}

bool orcashi_join_room(ORCASHI* orcashi, const char* ip, int port) {
    if (!orcashi) return false;
    
    log_info("[TCP] Joining %s:%d", ip, port);
    
    orcashi->tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (orcashi->tcp_socket < 0) {
        log_error("[TCP] Failed to create socket: %s", strerror(errno));
        return false;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    if (connect(orcashi->tcp_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("[TCP] Failed to connect: %s", strerror(errno));
        close(orcashi->tcp_socket);
        orcashi->tcp_socket = -1;
        return false;
    }
    
    strcpy(orcashi->peer_ip, ip);
    log_info("[TCP] Connected to %s", ip);
    
    orcashi->connected = true;
    orcashi->running = true;
    
    // Start TCP threads
    pthread_create(&orcashi->tcp_receive_thread, NULL, tcp_receive_thread, orcashi);
    pthread_create(&orcashi->tcp_send_thread, NULL, tcp_send_thread, orcashi);
    
    return true;
}

// ============================================================
//  TCP THREADS
// ============================================================

static void* tcp_receive_thread(void* arg) {
    ORCASHI* orcashi = (ORCASHI*)arg;
    char buffer[4096];
    char* accumulated = (char*)calloc(1, 8192);
    int acc_len = 0;
    fd_set fds;
    struct timeval tv;
    
    while (orcashi->running && orcashi->connected) {
        FD_ZERO(&fds);
        FD_SET(orcashi->tcp_socket, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(orcashi->tcp_socket + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) break;
        if (ret == 0) continue;
        
        int n = recv(orcashi->tcp_socket, buffer, sizeof(buffer) - 1, 0);
        if (n <= 0) {
            log_info("[TCP] Connection closed by peer");
            orcashi->connected = false;
            break;
        }
        
        buffer[n] = '\0';
        log_dht("[TCP] Received %d bytes", n);
        
        if (acc_len + n < 8192) {
            memcpy(accumulated + acc_len, buffer, n);
            acc_len += n;
        }
        
        char* pos = accumulated;
        char* newline;
        while ((newline = strchr(pos, '\n')) != NULL) {
            *newline = '\0';
            if (strlen(pos) > 0) {
                char* msg = (char*)malloc(strlen(pos) + 1);
                strcpy(msg, pos);
                
                pthread_mutex_lock(&orcashi->tcp_mutex);
                if (orcashi->message_count < orcashi->queue_capacity) {
                    orcashi->message_queue[orcashi->message_count++] = msg;
                    log_dht("[TCP] Queued message (%d bytes)", (int)strlen(msg));
                } else {
                    free(msg);
                    log_warn("[TCP] Message queue full");
                }
                pthread_cond_signal(&orcashi->tcp_cond);
                pthread_mutex_unlock(&orcashi->tcp_mutex);
                
                if (orcashi->on_message_received) {
                    orcashi->on_message_received(orcashi->peer_ip, pos);
                }
            }
            pos = newline + 1;
        }
        
        if (pos > accumulated) {
            acc_len = strlen(pos);
            memmove(accumulated, pos, acc_len + 1);
        }
    }
    
    free(accumulated);
    log_info("[TCP] Receive thread ended");
    return NULL;
}

static void* tcp_send_thread(void* arg) {
    ORCASHI* orcashi = (ORCASHI*)arg;
    
    while (orcashi->running && orcashi->connected) {
        char* msg = NULL;
        
        pthread_mutex_lock(&orcashi->tcp_mutex);
        while (orcashi->send_count == 0 && orcashi->running) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 1;
            pthread_cond_timedwait(&orcashi->tcp_cond, &orcashi->tcp_mutex, &ts);
        }
        
        if (!orcashi->running) {
            pthread_mutex_unlock(&orcashi->tcp_mutex);
            break;
        }
        
        if (orcashi->send_count > 0) {
            msg = orcashi->send_queue[0];
            for (int i = 0; i < orcashi->send_count - 1; i++) {
                orcashi->send_queue[i] = orcashi->send_queue[i + 1];
            }
            orcashi->send_count--;
        }
        pthread_mutex_unlock(&orcashi->tcp_mutex);
        
        if (msg) {
            ssize_t sent = send(orcashi->tcp_socket, msg, strlen(msg), MSG_NOSIGNAL);
            if (sent < 0) {
                log_error("[TCP] Send failed: %s", strerror(errno));
                orcashi->connected = false;
            } else {
                log_dht("[TCP] Sent %d bytes", (int)sent);
            }
            free(msg);
        }
    }
    
    log_info("[TCP] Send thread ended");
    return NULL;
}

// ============================================================
//  TCP PUBLIC FUNCTIONS
// ============================================================

bool orcashi_send_message(ORCASHI* orcashi, const char* msg) {
    if (!orcashi || !orcashi->connected || !msg) return false;
    
    pthread_mutex_lock(&orcashi->tcp_mutex);
    if (orcashi->send_count >= orcashi->queue_capacity) {
        pthread_mutex_unlock(&orcashi->tcp_mutex);
        log_warn("[TCP] Send queue full");
        return false;
    }
    
    char* msg_copy = (char*)malloc(strlen(msg) + 2);
    sprintf(msg_copy, "%s\n", msg);
    orcashi->send_queue[orcashi->send_count++] = msg_copy;
    pthread_cond_signal(&orcashi->tcp_cond);
    pthread_mutex_unlock(&orcashi->tcp_mutex);
    
    log_dht("[TCP] Queued message for send: %s", msg);
    return true;
}

bool orcashi_receive_message(ORCASHI* orcashi, char* msg, int msg_size, int timeout_ms) {
    if (!orcashi || !msg) return false;
    
    pthread_mutex_lock(&orcashi->tcp_mutex);
    
    if (orcashi->message_count == 0) {
        if (timeout_ms > 0) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += timeout_ms / 1000;
            ts.tv_nsec += (timeout_ms % 1000) * 1000000;
            if (ts.tv_nsec >= 1000000000) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000;
            }
            pthread_cond_timedwait(&orcashi->tcp_cond, &orcashi->tcp_mutex, &ts);
        } else {
            pthread_cond_wait(&orcashi->tcp_cond, &orcashi->tcp_mutex);
        }
    }
    
    if (orcashi->message_count == 0) {
        pthread_mutex_unlock(&orcashi->tcp_mutex);
        return false;
    }
    
    char* msg_ptr = orcashi->message_queue[0];
    strncpy(msg, msg_ptr, msg_size - 1);
    msg[msg_size - 1] = '\0';
    free(msg_ptr);
    
    for (int i = 0; i < orcashi->message_count - 1; i++) {
        orcashi->message_queue[i] = orcashi->message_queue[i + 1];
    }
    orcashi->message_count--;
    
    pthread_mutex_unlock(&orcashi->tcp_mutex);
    return true;
}

bool orcashi_is_connected(ORCASHI* orcashi) {
    return orcashi && orcashi->connected;
}

void orcashi_disconnect(ORCASHI* orcashi) {
    if (!orcashi) return;
    
    orcashi->running = false;
    orcashi->connected = false;
    
    if (orcashi->tcp_socket >= 0) {
        close(orcashi->tcp_socket);
        orcashi->tcp_socket = -1;
    }
    
    pthread_cond_broadcast(&orcashi->tcp_cond);
    
    if (orcashi->tcp_receive_thread) {
        pthread_join(orcashi->tcp_receive_thread, NULL);
        orcashi->tcp_receive_thread = 0;
    }
    if (orcashi->tcp_send_thread) {
        pthread_join(orcashi->tcp_send_thread, NULL);
        orcashi->tcp_send_thread = 0;
    }
    
    log_info("[TCP] Disconnected");
}

// ============================================================
//  HELPERS
// ============================================================

char* orcashi_generate_id(void) {
    static char id[CRYPTO_PUBLIC_KEY_SIZE * 2 + 1];
    // Generate random bytes
    uint8_t bytes[CRYPTO_PUBLIC_KEY_SIZE];
    for (int i = 0; i < CRYPTO_PUBLIC_KEY_SIZE; i++) {
        bytes[i] = rand() & 0xFF;
    }
    orcashi_bytes_to_hex(bytes, CRYPTO_PUBLIC_KEY_SIZE);
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
    
    strcpy(ip, "127.0.0.1");
    return strdup(ip);
}

char* orcashi_bytes_to_hex(const uint8_t* bytes, int len) {
    static char hex[CRYPTO_PUBLIC_KEY_SIZE * 2 + 1];
    for (int i = 0; i < len && i < CRYPTO_PUBLIC_KEY_SIZE; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

int orcashi_hex_to_bytes(const char* hex, uint8_t* bytes, int len) {
    int hex_len = strlen(hex);
    if (hex_len != len * 2) return -1;
    for (int i = 0; i < len; i++) {
        if (sscanf(hex + (i * 2), "%02hhx", &bytes[i]) != 1) return -1;
    }
    return 0;
}

// ============================================================
//  GETTERS
// ============================================================

const char* orcashi_get_my_id(ORCASHI* orcashi) {
    return orcashi ? orcashi->self_id_hex : NULL;
}

const char* orcashi_get_peer_id(ORCASHI* orcashi) {
    return orcashi ? orcashi->peer_id : NULL;
}

const char* orcashi_get_peer_ip(ORCASHI* orcashi) {
    return orcashi ? orcashi->peer_ip : NULL;
}

// ============================================================
//  CALLBACKS
// ============================================================

void orcashi_set_callbacks(ORCASHI* orcashi,
                          void (*on_peer_found)(const char*, const char*),
                          void (*on_message_received)(const char*, const char*),
                          void (*on_status_change)(const char*)) {
    if (!orcashi) return;
    orcashi->on_peer_found = on_peer_found;
    orcashi->on_message_received = on_message_received;
    orcashi->on_status_change = on_status_change;
}

bool orcashi_register_identity(ORCASHI* orcashi) {
    if (!orcashi) return false;
    
    printf("\n");
    printf("  +------------------------------------------+\n");
    printf("  |           ORCA Registration              |\n");
    printf("  +------------------------------------------+\n");
    printf("\n");
    printf("  Your ID: %s\n", orcashi->self_id_hex);
    printf("  Enter your IP (or press Enter for auto): ");
    fflush(stdout);
    
    char input_ip[INET_ADDRSTRLEN];
    if (!fgets(input_ip, sizeof(input_ip), stdin)) {
        return false;
    }
    input_ip[strcspn(input_ip, "\n")] = '\0';
    
    char* ip = input_ip;
    if (strlen(ip) == 0) {
        ip = orcashi_get_local_ip();
        printf("  Using IP: %s\n", ip);
    }
    
    // Register in DHT
    if (orcashi_dht_register(orcashi)) {
        printf("\n  [SUCCESS] Registered in DHT!\n");
        printf("  Your ID: %s\n", orcashi->self_id_hex);
        printf("  Your IP: %s\n", ip);
        printf("\n  Others can connect using:\n");
        printf("    ./orcashi connect %s\n", orcashi->self_id_hex);
        return true;
    }
    
    printf("  [ERROR] Registration failed!\n");
    return false;
}
