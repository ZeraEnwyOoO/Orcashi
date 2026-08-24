 #include "orcashi.h"
#include <ifaddrs.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>

/* ============================================================================
 * STATIC HELPERS
 * ============================================================================ */

static void orcashi_set_defaults(Orcashi* orcashi) {
    if (!orcashi) return;
    
    memset(orcashi, 0, sizeof(Orcashi));
    orcashi->p2p_port = ORCASHI_P2P_PORT;
    orcashi->dht_port = ORCASHI_DHT_PORT;
    orcashi->initialized = false;
    orcashi->daemon_running = false;
    orcashi->is_listening = false;
    orcashi->start_time = time(NULL);
    
    /* Get local IP */
    char* ip = orcashi_get_local_ip();
    if (ip) {
        strcpy(orcashi->local_ip, ip);
        free(ip);
    } else {
        strcpy(orcashi->local_ip, "127.0.0.1");
    }
    
    /* Get public IP */
    char* pub_ip = orcashi_get_public_ip();
    if (pub_ip) {
        strcpy(orcashi->public_ip, pub_ip);
        free(pub_ip);
    } else {
        strcpy(orcashi->public_ip, orcashi->local_ip);
    }
}

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

int orcashi_init(Orcashi* orcashi) {
    if (!orcashi) return -1;
    
    orcashi_set_defaults(orcashi);
    
    /* Initialize crypto */
    orca_init_crypto();
    orca_identity_storage_init();
    
    /* Create home directory */
    mkdir(ORCASHI_HOME, 0700);
    
    /* Initialize logger */
    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%s/orcashi.log", ORCASHI_HOME);
    logger_init(log_path);
    logger_set_level(LOG_LEVEL_INFO);
    
    LOG_INFO("Orcashi v%s initialized", ORCASHI_VERSION);
    LOG_INFO("Local IP: %s", orcashi->local_ip);
    LOG_INFO("Public IP: %s", orcashi->public_ip);
    
    /* Initialize state manager */
    state_init();
    
    /* Initialize P2P manager */
    p2p_init();
    
    orcashi->initialized = true;
    
    return 0;
}

int orcashi_init_with_config(Orcashi* orcashi, const char* config_path) {
    (void)config_path;
    return orcashi_init(orcashi);
}

void orcashi_cleanup(Orcashi* orcashi) {
    if (!orcashi) return;
    
    LOG_INFO("Orcashi cleaning up...");
    
    /* Stop daemon if running */
    if (orcashi->daemon_running) {
        orcashi_stop_daemon(orcashi);
    }
    
    /* Cleanup P2P */
    p2p_cleanup();
    
    /* Save state */
    state_save();
    
    /* Cleanup crypto */
    orca_cleanup_crypto();
    
    /* Close logger */
    logger_close();
    
    orcashi->initialized = false;
    
    LOG_INFO("Orcashi cleaned up");
}

/* ============================================================================
 * DAEMON
 * ============================================================================ */

int orcashi_start_daemon(Orcashi* orcashi) {
    if (!orcashi || !orcashi->initialized) return -1;
    
    if (orcashi->daemon_running) {
        LOG_WARN("Daemon already running");
        return 0;
    }
    
    LOG_INFO("Starting daemon...");
    
    if (daemon_start() == 0) {
        orcashi->daemon_running = true;
        LOG_INFO("Daemon started");
        return 0;
    }
    
    LOG_ERROR("Failed to start daemon");
    return -1;
}

int orcashi_stop_daemon(Orcashi* orcashi) {
    if (!orcashi) return -1;
    
    if (!orcashi->daemon_running) {
        LOG_WARN("Daemon not running");
        return 0;
    }
    
    LOG_INFO("Stopping daemon...");
    
    daemon_stop();
    orcashi->daemon_running = false;
    
    LOG_INFO("Daemon stopped");
    return 0;
}

bool orcashi_is_daemon_running(Orcashi* orcashi) {
    if (!orcashi) return false;
    return orcashi->daemon_running && daemon_is_running();
}

/* ============================================================================
 * IDENTITY
 * ============================================================================ */

int orcashi_register_identity(Orcashi* orcashi, const char* passcode) {
    if (!orcashi || !passcode) return -1;
    
    LOG_INFO("Registering identity...");
    
    /* Check if identity already exists */
    if (orca_identity_exists(NULL)) {
        LOG_WARN("Identity already exists");
        return -1;
    }
    
    /* Generate ID */
    char id[64];
    orca_identity_generate_normal_id(id);
    strcpy(orcashi->id, id);
    
    /* Create identity */
    OrcaIdentity identity;
    if (orca_identity_create_secure_3digit(id, passcode, "orcashi", "user", &identity) < 0) {
        LOG_ERROR("Failed to create identity: %s", orca_get_last_error());
        return -1;
    }
    
    /* Save identity */
    if (orca_identity_save(&identity) < 0) {
        LOG_ERROR("Failed to save identity");
        return -1;
    }
    
    orcashi->has_identity = true;
    orcashi->is_secure = true;
    strcpy(orcashi->name, identity.name);
    
    LOG_INFO("Identity registered: %s", orcashi->id);
    return 0;
}

int orcashi_load_identity(Orcashi* orcashi, const char* passcode) {
    if (!orcashi) return -1;
    
    OrcaIdentity identity;
    if (orca_identity_load(&identity, passcode) < 0) {
        LOG_ERROR("Failed to load identity: %s", orca_get_last_error());
        return -1;
    }
    
    strcpy(orcashi->id, identity.id);
    strcpy(orcashi->name, identity.name);
    orcashi->has_identity = true;
    orcashi->is_secure = (identity.mode == ORCA_IDENTITY_MODE_SECURE);
    
    LOG_INFO("Identity loaded: %s", orcashi->id);
    return 0;
}

void orcashi_print_identity(Orcashi* orcashi) {
    if (!orcashi) return;
    
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|                    ORCASHI IDENTITY                       |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|  ID        : %s\n", orcashi->id);
    printf("|  Name      : %s\n", orcashi->name);
    printf("|  Mode      : %s\n", orcashi->is_secure ? "SECURE" : "NORMAL");
    printf("|  IP        : %s\n", orcashi->public_ip);
    printf("|  Port      : %d\n", orcashi->p2p_port);
    printf("|  Daemon    : %s\n", orcashi->daemon_running ? "RUNNING" : "STOPPED");
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
}

/* ============================================================================
 * PEER
 * ============================================================================ */

int orcashi_search_peer(Orcashi* orcashi, const char* peer_id) {
    if (!orcashi || !peer_id) return -1;
    
    /* Check if daemon is running */
    if (!orcashi_is_daemon_running(orcashi)) {
        LOG_ERROR("Daemon not running. Use './orcashi listen' first.");
        return -1;
    }
    
    char cmd[256];
    char response[1024];
    snprintf(cmd, sizeof(cmd), "search %s", peer_id);
    
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    LOG_ERROR("Failed to search for peer %s", peer_id);
    return -1;
}

int orcashi_add_peer(Orcashi* orcashi, const char* peer_id) {
    if (!orcashi || !peer_id) return -1;
    
    /* Check if daemon is running */
    if (!orcashi_is_daemon_running(orcashi)) {
        LOG_ERROR("Daemon not running. Use './orcashi listen' first.");
        return -1;
    }
    
    char cmd[256];
    char response[1024];
    snprintf(cmd, sizeof(cmd), "add %s", peer_id);
    
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    LOG_ERROR("Failed to add peer %s", peer_id);
    return -1;
}

int orcashi_accept_peer(Orcashi* orcashi, const char* peer_id) {
    if (!orcashi || !peer_id) return -1;
    
    /* Check if daemon is running */
    if (!orcashi_is_daemon_running(orcashi)) {
        LOG_ERROR("Daemon not running. Use './orcashi listen' first.");
        return -1;
    }
    
    char cmd[256];
    char response[1024];
    snprintf(cmd, sizeof(cmd), "accept %s", peer_id);
    
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    LOG_ERROR("Failed to accept peer %s", peer_id);
    return -1;
}

int orcashi_reject_peer(Orcashi* orcashi, const char* peer_id) {
    if (!orcashi || !peer_id) return -1;
    
    /* Check if daemon is running */
    if (!orcashi_is_daemon_running(orcashi)) {
        LOG_ERROR("Daemon not running. Use './orcashi listen' first.");
        return -1;
    }
    
    char cmd[256];
    char response[1024];
    snprintf(cmd, sizeof(cmd), "reject %s", peer_id);
    
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    LOG_ERROR("Failed to reject peer %s", peer_id);
    return -1;
}

int orcashi_remove_peer(Orcashi* orcashi, const char* peer_id) {
    if (!orcashi || !peer_id) return -1;
    
    /* Check if daemon is running */
    if (!orcashi_is_daemon_running(orcashi)) {
        LOG_ERROR("Daemon not running. Use './orcashi listen' first.");
        return -1;
    }
    
    char cmd[256];
    char response[1024];
    snprintf(cmd, sizeof(cmd), "remove %s", peer_id);
    
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    LOG_ERROR("Failed to remove peer %s", peer_id);
    return -1;
}

void orcashi_list_peers(Orcashi* orcashi) {
    if (!orcashi) return;
    
    char response[4096];
    if (command_send_to_daemon("peers", response, sizeof(response)) == 0) {
        printf("%s", response);
    } else {
        printf("[ORCA] No daemon running. Use './orcashi listen' first.\n");
    }
}

/* ============================================================================
 * CHAT
 * ============================================================================ */

int orcashi_chat_start(Orcashi* orcashi, const char* peer_id) {
    if (!orcashi || !peer_id) return -1;
    
    /* Check if daemon is running */
    if (!orcashi_is_daemon_running(orcashi)) {
        LOG_ERROR("Daemon not running. Use './orcashi listen' first.");
        return -1;
    }
    
    /* Check if peer exists */
    Peer* peer = state_get_peer(peer_id);
    if (!peer) {
        LOG_ERROR("Peer %s not found", peer_id);
        return -1;
    }
    
    if (peer->state != PEER_FRIEND) {
        LOG_ERROR("Peer %s is not a friend. Send request first.", peer_id);
        return -1;
    }
    
    printf("\n");
    printf("============================================================\n");
    printf("  ORCASHI CHAT\n");
    printf("============================================================\n");
    printf("  Peer: %s\n", peer_id);
    printf("  Status: %s\n", peer->online ? "ONLINE" : "OFFLINE");
    printf("  IP: %s:%d\n", peer->ip, peer->port);
    printf("============================================================\n");
    printf("  Type /exit to quit\n");
    printf("  Type /status to check\n");
    printf("  Type /secure to enable encryption\n");
    printf("============================================================\n");
    printf("\n");
    
    /* Start chat session */
    char input[4096];
    char response[4096];
    
    while (1) {
        printf("[you] ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';
        
        if (strcmp(input, "/exit") == 0) break;
        if (strcmp(input, "/status") == 0) {
            Peer* p = state_get_peer(peer_id);
            printf("[CHAT] Status: %s\n", p ? (p->online ? "ONLINE" : "OFFLINE") : "UNKNOWN");
            continue;
        }
        if (strcmp(input, "/secure") == 0) {
            printf("[CHAT] Enabling secure channel...\n");
            /* TODO: Implement secure channel via p2p_manager */
            continue;
        }
        
        /* Send message via daemon */
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "chat_send %s %s", peer_id, input);
        command_send_to_daemon(cmd, response, sizeof(response));
    }
    
    printf("\n[CHAT] Session ended.\n");
    return 0;
}

int orcashi_chat_send(Orcashi* orcashi, const char* peer_id, const char* message) {
    if (!orcashi || !peer_id || !message) return -1;
    
    /* Check if daemon is running */
    if (!orcashi_is_daemon_running(orcashi)) {
        LOG_ERROR("Daemon not running.");
        return -1;
    }
    
    char cmd[512];
    char response[1024];
    snprintf(cmd, sizeof(cmd), "chat_send %s %s", peer_id, message);
    
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        return 0;
    }
    
    LOG_ERROR("Failed to send message to %s", peer_id);
    return -1;
}

int orcashi_ghost_send(Orcashi* orcashi, const char* peer_id, const char* message) {
    if (!orcashi || !peer_id || !message) return -1;
    
    /* Check if daemon is running */
    if (!orcashi_is_daemon_running(orcashi)) {
        LOG_ERROR("Daemon not running. Use './orcashi listen' first.");
        return -1;
    }
    
    char cmd[512];
    char response[1024];
    snprintf(cmd, sizeof(cmd), "ghost %s %s", peer_id, message);
    
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    LOG_ERROR("Failed to send ghost message to %s", peer_id);
    return -1;
}

/* ============================================================================
 * VOICE CALL (Ghost Call)
 * ============================================================================ */

int orcashi_call_start(Orcashi* orcashi, const char* peer_id) {
    if (!orcashi || !peer_id) return -1;
    
    /* Check if daemon is running */
    if (!orcashi_is_daemon_running(orcashi)) {
        LOG_ERROR("Daemon not running. Use './orcashi listen' first.");
        return -1;
    }
    
    /* Get peer IP and port */
    Peer* peer = state_get_peer(peer_id);
    if (!peer) {
        LOG_ERROR("Peer %s not found", peer_id);
        return -1;
    }
    
    /* Generate random room */
    int room = (rand() % 49) + 1;
    
    /* Build command */
    char cmd[512];
    char response[1024];
    snprintf(cmd, sizeof(cmd), "call %s %s %d", peer_id, peer->ip, room);
    
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    LOG_ERROR("Failed to start call with %s", peer_id);
    return -1;
}

int orcashi_call_answer(Orcashi* orcashi, const char* caller_id, int room) {
    if (!orcashi || !caller_id) return -1;
    
    /* Check if daemon is running */
    if (!orcashi_is_daemon_running(orcashi)) {
        LOG_ERROR("Daemon not running. Use './orcashi listen' first.");
        return -1;
    }
    
    /* Get caller IP */
    Peer* peer = state_get_peer(caller_id);
    if (!peer) {
        LOG_ERROR("Caller %s not found", caller_id);
        return -1;
    }
    
    char cmd[512];
    char response[1024];
    snprintf(cmd, sizeof(cmd), "call_answer %s %s %d", caller_id, peer->ip, room);
    
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    LOG_ERROR("Failed to answer call from %s", caller_id);
    return -1;
}

bool orcashi_call_is_active(Orcashi* orcashi) {
    if (!orcashi) return false;
    
    char response[1024];
    if (command_send_to_daemon("call_status", response, sizeof(response)) == 0) {
        return strstr(response, "active") != NULL;
    }
    return false;
}

/* ============================================================================
 * NOTES (Orcanote)
 * ============================================================================ */

int orcashi_note_add(Orcashi* orcashi, const char* content) {
    if (!orcashi || !content) return -1;
    
    /* Check if daemon is running */
    if (!orcashi_is_daemon_running(orcashi)) {
        LOG_ERROR("Daemon not running. Use './orcashi listen' first.");
        return -1;
    }
    
    char cmd[512];
    char response[1024];
    snprintf(cmd, sizeof(cmd), "note_add %s", content);
    
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    LOG_ERROR("Failed to add note");
    return -1;
}

void orcashi_note_view(Orcashi* orcashi) {
    if (!orcashi) return;
    
    char response[4096];
    if (command_send_to_daemon("note_view", response, sizeof(response)) == 0) {
        printf("%s", response);
    } else {
        printf("[ORCA] No daemon running.\n");
    }
}

int orcashi_note_find(Orcashi* orcashi, const char* hash) {
    if (!orcashi || !hash) return -1;
    
    char cmd[256];
    char response[1024];
    snprintf(cmd, sizeof(cmd), "note_find %s", hash);
    
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    LOG_ERROR("Failed to find note");
    return -1;
}

/* ============================================================================
 * MIXED ID
 * ============================================================================ */

int orcashi_get_mixed_id(Orcashi* orcashi, char* out, size_t size) {
    if (!orcashi || !out || size == 0) return -1;
    
    return mixed_id_encode(orcashi->id, orcashi->public_ip, orcashi->p2p_port, out, size);
}

int orcashi_connect_mixed_id(Orcashi* orcashi, const char* mixed_id) {
    if (!orcashi || !mixed_id) return -1;
    
    char id[64], ip[INET_ADDRSTRLEN];
    int port;
    
    if (mixed_id_decode(mixed_id, id, ip, &port) < 0) {
        LOG_ERROR("Invalid Mixed ID: %s", mixed_id);
        return -1;
    }
    
    LOG_INFO("Connecting via Mixed ID: %s -> %s:%d", id, ip, port);
    
    /* Update peer info */
    state_set_ip(id, ip);
    state_set_port(id, port);
    
    /* Connect */
    return orcashi_add_peer(orcashi, id);
}

/* ============================================================================
 * UTILITY - FIXED: No C++ code!
 * ============================================================================ */

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

char* orcashi_get_public_ip(void) {
    static char ip[INET_ADDRSTRLEN];
    
    const char* services[] = {"api.ipify.org", "icanhazip.com", "ifconfig.me"};
    
    for (int i = 0; i < 3; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        if (getaddrinfo(services[i], "80", &hints, &res) != 0) {
            close(sock);
            continue;
        }
        
        if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
            freeaddrinfo(res);
            close(sock);
            continue;
        }
        freeaddrinfo(res);
        
        char request[256];
        snprintf(request, sizeof(request), "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", services[i]);
        send(sock, request, strlen(request), 0);
        
        char buffer[4096];
        char response[8192] = {0};
        int total = 0;
        int n;
        
        while ((n = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0 && total < (int)sizeof(response) - 1) {
            buffer[n] = '\0';
            memcpy(response + total, buffer, n);
            total += n;
        }
        close(sock);
        
        /* Find body after HTTP headers */
        char* body = strstr(response, "\r\n\r\n");
        if (body) {
            body += 4;  /* Skip \r\n\r\n */
            
            /* Remove trailing whitespace/newlines */
            char* end = body + strlen(body) - 1;
            while (end > body && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
                end--;
            }
            *(end + 1) = '\0';
            
            /* Remove leading whitespace */
            while (*body == ' ' || *body == '\n' || *body == '\r' || *body == '\t') {
                body++;
            }
            
            if (strlen(body) > 0) {
                strcpy(ip, body);
                return strdup(ip);
            }
        }
    }
    
    strcpy(ip, "127.0.0.1");
    return strdup(ip);
}

char* orcashi_generate_id(void) {
    static char id[64];
    srand(time(NULL) ^ getpid());
    int num = (rand() % 999) + 1;
    snprintf(id, sizeof(id), "<%03d>", num);
    return strdup(id);
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

/* ============================================================================
 * CALLBACKS
 * ============================================================================ */

void orcashi_set_on_peer_found(Orcashi* orcashi, 
                                void (*callback)(const char*, const char*, int)) {
    if (orcashi) orcashi->on_peer_found = callback;
}

void orcashi_set_on_message_received(Orcashi* orcashi,
                                      void (*callback)(const char*, const char*)) {
    if (orcashi) orcashi->on_message_received = callback;
}

void orcashi_set_on_status_change(Orcashi* orcashi,
                                   void (*callback)(const char*)) {
    if (orcashi) orcashi->on_status_change = callback;
}

void orcashi_set_on_call_received(Orcashi* orcashi,
                                   void (*callback)(const char*, int)) {
    if (orcashi) orcashi->on_call_received = callback;
}

/* ============================================================================
 * DEBUG
 * ============================================================================ */

void orcashi_debug_print(Orcashi* orcashi) {
    if (!orcashi) return;
    
    printf("\n=== ORCASHI DEBUG ===\n");
    printf("Version: %s\n", ORCASHI_VERSION);
    printf("Initialized: %s\n", orcashi->initialized ? "YES" : "NO");
    printf("ID: %s\n", orcashi->id);
    printf("Name: %s\n", orcashi->name);
    printf("Has Identity: %s\n", orcashi->has_identity ? "YES" : "NO");
    printf("Secure Mode: %s\n", orcashi->is_secure ? "YES" : "NO");
    printf("Local IP: %s\n", orcashi->local_ip);
    printf("Public IP: %s\n", orcashi->public_ip);
    printf("P2P Port: %d\n", orcashi->p2p_port);
    printf("Daemon Running: %s\n", orcashi->daemon_running ? "YES" : "NO");
    printf("Listening: %s\n", orcashi->is_listening ? "YES" : "NO");
    printf("Uptime: %ld seconds\n", (long)(time(NULL) - orcashi->start_time));
    printf("====================\n");
}

void orcashi_debug_dump_state(Orcashi* orcashi) {
    if (!orcashi) return;
    
    printf("\n=== ORCASHI STATE DUMP ===\n");
    state_debug_print();
    printf("===========================\n");
}
