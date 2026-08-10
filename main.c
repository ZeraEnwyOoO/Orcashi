 // main.c
#include "orcashi.h"
#include <signal.h>

static ORCASHI* g_orcashi = NULL;
static volatile int running = 1;

void signal_handler(int sig) {
    (void)sig;
    printf("\nShutting down...\n");
    running = 0;
    if (g_orcashi) orcashi_disconnect(g_orcashi);
    exit(0);
}

void show_help(void) {
    printf("\n");
    printf("ORCASHI v3.2 - P2P Chat (Tox DHT Engine)\n");
    printf("==========================================\n");
    printf("Usage:\n");
    printf("  ./orcashi create          - Create room (server)\n");
    printf("  ./orcashi join <ip>       - Join room by IP\n");
    printf("  ./orcashi register        - Register identity in DHT\n");
    printf("  ./orcashi connect <id>    - Connect by ID (DHT lookup)\n");
    printf("  ./orcashi search <id>     - Search peer in DHT\n");
    printf("  ./orcashi peers           - List peers\n");
    printf("  ./orcashi help            - Show help\n");
    printf("\n");
    printf("Chat commands:\n");
    printf("  /exit                     - Exit chat\n");
    printf("\n");
}

void chat_loop(ORCASHI* orcashi) {
    printf("\nType /exit to quit\n");
    printf("---\n");
    
    char input[4096];
    char msg[4096];
    
    while (running && orcashi_is_connected(orcashi)) {
        // Check for incoming messages
        while (orcashi_receive_message(orcashi, msg, sizeof(msg), 10)) {
            printf("[%s] %s\n", orcashi_get_peer_ip(orcashi), msg);
            fflush(stdout);
        }
        
        printf("> ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';
        
        if (strcmp(input, "/exit") == 0) break;
        
        if (strlen(input) > 0) {
            orcashi_send_message(orcashi, input);
            printf("[You] %s\n", input);
        }
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize logger
    logger_init("/tmp/orcashi.log", LOG_LEVEL_DEBUG);
    logger_set_color(true);
    
    if (argc < 2) {
        show_help();
        return 0;
    }
    
    g_orcashi = orcashi_create();
    if (!g_orcashi) {
        log_error("Failed to create ORCASHI!");
        return 1;
    }
    
    if (!orcashi_init(g_orcashi)) {
        log_error("Failed to initialize ORCASHI!");
        orcashi_destroy(g_orcashi);
        return 1;
    }
    
    log_info("My ID: %s", orcashi_get_my_id(g_orcashi));
    log_info("---");
    
    char* cmd = argv[1];
    
    if (strcmp(cmd, "create") == 0) {
        int port = (argc >= 3) ? atoi(argv[2]) : ORCASHI_PORT;
        log_info("Creating room on port %d...", port);
        
        if (!orcashi_create_room(g_orcashi, port)) {
            log_error("Failed to create room!");
            orcashi_destroy(g_orcashi);
            return 1;
        }
        
        log_info("Room created! Connected to: %s", orcashi_get_peer_ip(g_orcashi));
        chat_loop(g_orcashi);
        
        log_info("Disconnected.");
        orcashi_disconnect(g_orcashi);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "join") == 0 && argc >= 3) {
        char* ip = argv[2];
        int port = (argc >= 4) ? atoi(argv[3]) : ORCASHI_PORT;
        log_info("Joining %s:%d...", ip, port);
        
        if (!orcashi_join_room(g_orcashi, ip, port)) {
            log_error("Failed to join!");
            orcashi_destroy(g_orcashi);
            return 1;
        }
        
        log_info("Connected to: %s", orcashi_get_peer_ip(g_orcashi));
        chat_loop(g_orcashi);
        
        log_info("Disconnected.");
        orcashi_disconnect(g_orcashi);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "register") == 0) {
        orcashi_register_identity(g_orcashi);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "connect") == 0 && argc >= 3) {
        char* id = argv[2];
        log_info("Connecting to %s...", id);
        
        if (!orcashi_connect_peer(g_orcashi, id)) {
            log_error("Failed to connect!");
            orcashi_destroy(g_orcashi);
            return 1;
        }
        
        log_info("Connected to: %s", orcashi_get_peer_ip(g_orcashi));
        chat_loop(g_orcashi);
        
        log_info("Disconnected.");
        orcashi_disconnect(g_orcashi);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "search") == 0 && argc >= 3) {
        char* id = argv[2];
        log_info("Searching for %s in DHT...", id);
        char* result = orcashi_dht_search(g_orcashi, id);
        if (result) {
            printf("\n  Found: %s\n", result);
            free(result);
        } else {
            printf("\n  Not found!\n");
        }
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "peers") == 0) {
        orcashi_show_peers(g_orcashi);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "help") == 0) {
        show_help();
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else {
        printf("Unknown command: %s\n", cmd);
        printf("Use ./orcashi help for usage.\n");
        orcashi_destroy(g_orcashi);
        return 1;
    }
}
