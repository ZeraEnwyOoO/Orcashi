 #include "orcashi.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    printf("ORCASHI v3.1 - P2P Chat\n");
    printf("Usage:\n");
    printf("  ./orcashi create          - Create room (server)\n");
    printf("  ./orcashi join <ip>       - Join room by IP\n");
    printf("  ./orcashi register        - Register identity\n");
    printf("  ./orcashi connect <id>    - Connect by ID (NAT hole punch)\n");
    printf("  ./orcashi search <id>     - Search peer in DHT\n");
    printf("  ./orcashi peers           - List peers\n");
    printf("  ./orcashi help            - Show help\n");
    printf("\n");
    printf("Chat commands:\n");
    printf("  /exit                     - Exit chat\n");
    printf("\n");
}

// ===== Chat Loop =====
void chat_loop(void) {
    printf("Type /exit to quit\n");
    printf("---\n");
    
    char input[4096];
    char msg[4096];
    
    while (running && orcashi_is_connected(g_orcashi)) {
        // Check for incoming messages
        while (orcashi_receive_message(g_orcashi, msg, sizeof(msg), 10)) {
            printf("[%s] %s\n", orcashi_get_peer_id(g_orcashi), msg);
            fflush(stdout);
        }
        
        // Check for user input
        printf("> ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';
        
        if (strcmp(input, "/exit") == 0) break;
        
        if (strlen(input) > 0) {
            orcashi_send_message(g_orcashi, input);
        }
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (argc < 2) {
        show_help();
        return 0;
    }
    
    g_orcashi = orcashi_create();
    if (!g_orcashi) {
        fprintf(stderr, "Failed to create ORCASHI!\n");
        return 1;
    }
    
    if (!orcashi_init(g_orcashi)) {
        fprintf(stderr, "Failed to initialize ORCASHI!\n");
        orcashi_destroy(g_orcashi);
        return 1;
    }
    
    printf("ID: %s\n", orcashi_get_my_id(g_orcashi));
    printf("IP: %s\n", orcashi_get_local_ip());
    printf("---\n");
    
    char* cmd = argv[1];
    
    if (strcmp(cmd, "create") == 0) {
        printf("Creating room on port 9000...\n");
        if (!orcashi_create_room(g_orcashi, 9000)) {
            fprintf(stderr, "Failed to create room!\n");
            orcashi_destroy(g_orcashi);
            return 1;
        }
        printf("Room created! Waiting for connection...\n");
        printf("---\n");
        
        while (running && !orcashi_is_connected(g_orcashi)) {
            sleep(1);
        }
        
        if (!running) {
            orcashi_destroy(g_orcashi);
            return 0;
        }
        
        printf("Connected to: %s\n", orcashi_get_peer_ip(g_orcashi));
        chat_loop();
        
        printf("Disconnected.\n");
        orcashi_disconnect(g_orcashi);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "join") == 0 && argc >= 3) {
        char* ip = argv[2];
        int port = (argc >= 4) ? atoi(argv[3]) : 9000;
        printf("Joining %s:%d...\n", ip, port);
        
        if (!orcashi_join_room(g_orcashi, ip, port)) {
            fprintf(stderr, "Failed to join!\n");
            orcashi_destroy(g_orcashi);
            return 1;
        }
        
        printf("Connected to: %s\n", orcashi_get_peer_ip(g_orcashi));
        chat_loop();
        
        printf("Disconnected.\n");
        orcashi_disconnect(g_orcashi);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "register") == 0) {
        if (orcashi_register_identity(g_orcashi)) {
            printf("Registered!\n");
            printf("ID: %s\n", orcashi_get_my_id(g_orcashi));
            printf("IP: %s\n", orcashi_get_local_ip());
        } else {
            fprintf(stderr, "Registration failed!\n");
        }
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "connect") == 0 && argc >= 3) {
        char* id = argv[2];
        printf("Connecting to %s...\n", id);
        
        if (!orcashi_connect_peer(g_orcashi, id)) {
            fprintf(stderr, "Failed to connect!\n");
            orcashi_destroy(g_orcashi);
            return 1;
        }
        
        printf("Connected to: %s\n", orcashi_get_peer_ip(g_orcashi));
        chat_loop();
        
        printf("Disconnected.\n");
        orcashi_disconnect(g_orcashi);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "search") == 0 && argc >= 3) {
        char* id = argv[2];
        printf("Searching for %s in DHT...\n", id);
        char* result = orcashi_dht_lookup(g_orcashi, id);
        if (result) {
            printf("Found: %s\n", result);
            free(result);
        } else {
            printf("Not found!\n");
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
