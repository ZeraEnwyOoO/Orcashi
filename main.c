 #include "orcashi.h"
#include "ui.h"
#include <signal.h>
#include <getopt.h>

static ORCASHI* g_orcashi = NULL;
static UI* g_ui = NULL;
static volatile int running = 1;

void signal_handler(int sig) {
    (void)sig;
    printf("\n");
    running = 0;
    if (g_orcashi) orcashi_disconnect(g_orcashi);
    if (g_ui) ui_stop(g_ui);
}

void on_peer_found(const char* id, const char* ip) {
    if (g_ui) ui_show_peer(g_ui, id, ip, true);
}

void on_message_received(const char* from, const char* msg) {
    if (g_ui) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), "[%s] %s", from, msg);
        ui_show_message(g_ui, "MESSAGE", buffer);
    }
}

void on_status_change(const char* status) {
    if (g_ui) ui_show_status(g_ui, status);
}

void command_handler(const char* cmd) {
    if (!cmd || !g_orcashi) return;
    
    if (strcmp(cmd, "/exit") == 0 || strcmp(cmd, "/quit") == 0) {
        running = 0;
        orcashi_disconnect(g_orcashi);
        if (g_ui) ui_stop(g_ui);
    }
    else if (strcmp(cmd, "/help") == 0) {
        printf("\n");
        printf("  ORCASHI Commands:\n");
        printf("    /help     - Show this help\n");
        printf("    /peers    - List connected peers\n");
        printf("    /register - Register with DHT\n");
        printf("    /connect  - Connect to peer by ID\n");
        printf("    /search   - Search peer in DHT\n");
        printf("    /create   - Create room\n");
        printf("    /join     - Join room by IP or ID\n");
        printf("    /status   - Show status\n");
        printf("    /exit     - Exit program\n");
        printf("\n");
        fflush(stdout);
    }
    else if (strcmp(cmd, "/peers") == 0) {
        orcashi_show_peers(g_orcashi);
    }
    else if (strcmp(cmd, "/register") == 0) {
        if (orcashi_register_identity(g_orcashi)) {
            if (g_ui) ui_show_status(g_ui, "Registered with DHT!");
        } else {
            if (g_ui) ui_show_message(g_ui, "ERROR", "Registration failed!");
        }
    }
    else if (strcmp(cmd, "/search") == 0) {
        if (g_ui) {
            ui_show_message(g_ui, "INFO", "Enter peer ID to search: ");
            char* id = ui_get_input();
            if (id && strlen(id) > 0) {
                ui_show_status(g_ui, "Searching...");
                char* result = orcashi_dht_lookup(g_orcashi, id);
                if (result) {
                    ui_show_message(g_ui, "FOUND", result);
                    free(result);
                } else {
                    ui_show_message(g_ui, "NOT FOUND", "Peer not found in DHT!");
                }
            }
            free(id);
        }
    }
    else if (strcmp(cmd, "/connect") == 0) {
        if (g_ui) {
            ui_show_message(g_ui, "INFO", "Enter peer ID: ");
            char* id = ui_get_input();
            if (id && strlen(id) > 0) {
                if (orcashi_connect_peer(g_orcashi, id)) {
                    ui_show_status(g_ui, "Connected!");
                } else {
                    ui_show_message(g_ui, "ERROR", "Connection failed!");
                }
            }
            free(id);
        }
    }
    else if (strcmp(cmd, "/create") == 0) {
        if (orcashi_create_room(g_orcashi, 9000)) {
            if (g_ui) ui_show_status(g_ui, "Room created! Waiting for connection...");
        } else {
            if (g_ui) ui_show_message(g_ui, "ERROR", "Failed to create room!");
        }
    }
    else if (strcmp(cmd, "/join") == 0) {
        if (g_ui) {
            ui_show_message(g_ui, "INFO", "Enter IP or ID: ");
            char* input = ui_get_input();
            if (input && strlen(input) > 0) {
                if (strchr(input, '.') != NULL) {
                    if (orcashi_join_room(g_orcashi, input, 9000)) {
                        ui_show_status(g_ui, "Connected!");
                    } else {
                        ui_show_message(g_ui, "ERROR", "Connection failed!");
                    }
                } else {
                    if (orcashi_connect_peer(g_orcashi, input)) {
                        ui_show_status(g_ui, "Connected!");
                    } else {
                        ui_show_message(g_ui, "ERROR", "Connection failed!");
                    }
                }
            }
            free(input);
        }
    }
    else if (strcmp(cmd, "/status") == 0) {
        printf("\n");
        printf("  Status:\n");
        printf("    ID: %s\n", orcashi_get_my_id(g_orcashi));
        printf("    Connected: %s\n", orcashi_is_connected(g_orcashi) ? "Yes" : "No");
        printf("    Registered: %s\n", g_orcashi->registered ? "Yes" : "No");
        printf("    DHT: %s\n", g_orcashi->dht_enabled ? "Enabled" : "Disabled");
        printf("    Local IP: %s\n", orcashi_get_local_ip());
        if (orcashi_is_connected(g_orcashi)) {
            printf("    Peer ID: %s\n", orcashi_get_peer_id(g_orcashi));
            printf("    Peer IP: %s\n", orcashi_get_peer_ip(g_orcashi));
        }
        printf("\n");
        fflush(stdout);
    }
    else if (strlen(cmd) > 0 && cmd[0] == '/') {
        if (g_ui) ui_show_message(g_ui, "ERROR", "Unknown command! Type /help");
    }
    else if (strlen(cmd) > 0) {
        if (orcashi_is_connected(g_orcashi)) {
            orcashi_send_message(g_orcashi, cmd);
        } else {
            if (g_ui) ui_show_message(g_ui, "WARNING", "Not connected! Use /connect or /create");
        }
    }
}

void show_info_screen(void) {
    printf("%s", COLOR_CLEAR);
    printf("\n");
    printf("  ============================================\n");
    printf("        ██████╗ ██████╗  ██████╗ █████╗ \n");
    printf("       ██╔═══██╗██╔══██╗██╔════╝██╔══██╗\n");
    printf("       ██║   ██║██████╔╝██║     ███████║\n");
    printf("       ██║   ██║██╔══██╗██║     ██╔══██║\n");
    printf("       ╚██████╔╝██║  ██║╚██████╗██║  ██║\n");
    printf("        ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝\n");
    printf("  ============================================\n");
    printf("\n");
    printf("  ORCASHI v3.1 - P2P Encrypted Chat\n");
    printf("  No Servers, No Tracking, No Censorship\n");
    printf("\n");
    printf("  Usage:\n");
    printf("    ./orcashi              - Interactive mode with glitch animation\n");
    printf("    ./orcashi help         - Show help\n");
    printf("    ./orcashi register     - Register identity with DHT\n");
    printf("    ./orcashi peers        - List all saved peers\n");
    printf("    ./orcashi connect <id> - Connect to peer by ID\n");
    printf("    ./orcashi search <id>  - Search peer in DHT\n");
    printf("    ./orcashi create       - Create a room (server)\n");
    printf("    ./orcashi join <id/ip> - Join room by ID or IP\n");
    printf("\n");
    printf("  Interactive Commands:\n");
    printf("    /help     - Show commands\n");
    printf("    /peers    - List connected peers\n");
    printf("    /register - Register with DHT\n");
    printf("    /connect  - Connect to peer by ID\n");
    printf("    /search   - Search peer in DHT\n");
    printf("    /create   - Create room\n");
    printf("    /join     - Join room by IP or ID\n");
    printf("    /status   - Show status\n");
    printf("    /exit     - Exit program\n");
    printf("\n");
    printf("  Press Ctrl+C to exit anytime\n");
    printf("\n");
    fflush(stdout);
}

void show_help(void) {
    printf("\n");
    printf("  ORCASHI v3.1 - Help\n");
    printf("  ================================\n");
    printf("\n");
    printf("  Commands:\n");
    printf("    ./orcashi              - Interactive mode with glitch animation\n");
    printf("    ./orcashi help         - Show help\n");
    printf("    ./orcashi register     - Register identity with DHT\n");
    printf("    ./orcashi peers        - List all saved peers\n");
    printf("    ./orcashi connect <id> - Connect to peer by ID\n");
    printf("    ./orcashi search <id>  - Search peer in DHT\n");
    printf("    ./orcashi create       - Create a room (server)\n");
    printf("    ./orcashi join <id/ip> - Join room by ID or IP\n");
    printf("\n");
    printf("  Interactive Commands:\n");
    printf("    /help     - Show commands\n");
    printf("    /peers    - List connected peers\n");
    printf("    /register - Register with DHT\n");
    printf("    /connect  - Connect to peer by ID\n");
    printf("    /search   - Search peer in DHT\n");
    printf("    /create   - Create room\n");
    printf("    /join     - Join room by IP or ID\n");
    printf("    /status   - Show status\n");
    printf("    /exit     - Exit program\n");
    printf("\n");
    printf("  Press Ctrl+C to exit anytime\n");
    printf("\n");
    fflush(stdout);
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (argc > 1) {
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
        
        char* cmd = argv[1];
        
        if (strcmp(cmd, "help") == 0) {
            show_help();
            orcashi_destroy(g_orcashi);
            return 0;
        }
        else if (strcmp(cmd, "register") == 0) {
            if (orcashi_register_identity(g_orcashi)) {
                printf("  [SUCCESS] Registered successfully!\n");
                printf("  ID: %s\n", orcashi_get_my_id(g_orcashi));
                printf("  IP: %s\n", orcashi_get_local_ip());
            } else {
                printf("  [ERROR] Registration failed!\n");
            }
            orcashi_destroy(g_orcashi);
            return 0;
        }
        else if (strcmp(cmd, "peers") == 0) {
            printf("\n  Saved Peers:\n");
            orcashi_show_peers(g_orcashi);
            orcashi_destroy(g_orcashi);
            return 0;
        }
        else if (strcmp(cmd, "connect") == 0 && argc >= 3) {
            char* id = argv[2];
            printf("  [ORCA] Connecting to %s...\n", id);
            if (orcashi_connect_peer(g_orcashi, id)) {
                printf("  [SUCCESS] Connected!\n");
                g_ui = ui_create();
                if (g_ui) {
                    ui_set_command_callback(g_ui, command_handler);
                    ui_init(g_ui);
                    ui_start(g_ui);
                    
                    while (running && orcashi_is_connected(g_orcashi)) {
                        char* input = ui_get_input();
                        if (!input) break;
                        if (strlen(input) > 0) command_handler(input);
                        free(input);
                    }
                    
                    if (g_ui) {
                        ui_stop(g_ui);
                        ui_destroy(g_ui);
                        g_ui = NULL;
                    }
                }
            } else {
                printf("  [ERROR] Connection failed!\n");
            }
            orcashi_destroy(g_orcashi);
            return 0;
        }
        else if (strcmp(cmd, "search") == 0 && argc >= 3) {
            char* id = argv[2];
            printf("  [DHT] Searching for %s...\n", id);
            char* result = orcashi_dht_lookup(g_orcashi, id);
            if (result) {
                printf("  [FOUND] %s\n", result);
                free(result);
            } else {
                printf("  [NOT FOUND] Peer not found in DHT!\n");
            }
            orcashi_destroy(g_orcashi);
            return 0;
        }
        else if (strcmp(cmd, "create") == 0) {
            printf("  [ORCA] Creating room on port 9000...\n");
            if (orcashi_create_room(g_orcashi, 9000)) {
                printf("  [SUCCESS] Room created!\n");
                printf("  ID: %s\n", orcashi_get_my_id(g_orcashi));
                printf("  Waiting for connection...\n");
                
                while (!orcashi_is_connected(g_orcashi) && running) {
                    usleep(100000);
                }
                
                if (orcashi_is_connected(g_orcashi)) {
                    printf("  [SUCCESS] Connected!\n");
                    g_ui = ui_create();
                    if (g_ui) {
                        ui_set_command_callback(g_ui, command_handler);
                        ui_init(g_ui);
                        ui_start(g_ui);
                        
                        while (running && orcashi_is_connected(g_orcashi)) {
                            char* input = ui_get_input();
                            if (!input) break;
                            if (strlen(input) > 0) command_handler(input);
                            free(input);
                        }
                        
                        if (g_ui) {
                            ui_stop(g_ui);
                            ui_destroy(g_ui);
                            g_ui = NULL;
                        }
                    }
                }
            } else {
                printf("  [ERROR] Failed to create room!\n");
            }
            orcashi_destroy(g_orcashi);
            return 0;
        }
        else if (strcmp(cmd, "join") == 0 && argc >= 3) {
            char* target = argv[2];
            int port = (argc >= 4) ? atoi(argv[3]) : 9000;
            
            if (strchr(target, '.') != NULL) {
                printf("  [ORCA] Joining %s:%d...\n", target, port);
                if (orcashi_join_room(g_orcashi, target, port)) {
                    printf("  [SUCCESS] Connected!\n");
                    g_ui = ui_create();
                    if (g_ui) {
                        ui_set_command_callback(g_ui, command_handler);
                        ui_init(g_ui);
                        ui_start(g_ui);
                        
                        while (running && orcashi_is_connected(g_orcashi)) {
                            char* input = ui_get_input();
                            if (!input) break;
                            if (strlen(input) > 0) command_handler(input);
                            free(input);
                        }
                        
                        if (g_ui) {
                            ui_stop(g_ui);
                            ui_destroy(g_ui);
                            g_ui = NULL;
                        }
                    }
                } else {
                    printf("  [ERROR] Connection failed!\n");
                }
            } else {
                printf("  [ORCA] Connecting to %s...\n", target);
                if (orcashi_connect_peer(g_orcashi, target)) {
                    printf("  [SUCCESS] Connected!\n");
                    g_ui = ui_create();
                    if (g_ui) {
                        ui_set_command_callback(g_ui, command_handler);
                        ui_init(g_ui);
                        ui_start(g_ui);
                        
                        while (running && orcashi_is_connected(g_orcashi)) {
                            char* input = ui_get_input();
                            if (!input) break;
                            if (strlen(input) > 0) command_handler(input);
                            free(input);
                        }
                        
                        if (g_ui) {
                            ui_stop(g_ui);
                            ui_destroy(g_ui);
                            g_ui = NULL;
                        }
                    }
                } else {
                    printf("  [ERROR] Connection failed!\n");
                }
            }
            orcashi_destroy(g_orcashi);
            return 0;
        }
        else {
            printf("  Unknown command: %s\n", cmd);
            printf("  Use ./orcashi help for usage.\n");
            orcashi_destroy(g_orcashi);
            return 1;
        }
    }
    
    // Interactive Mode
    g_orcashi = orcashi_create();
    if (!g_orcashi) {
        fprintf(stderr, "Failed to create ORCASHI!\n");
        return 1;
    }
    
    orcashi_set_callbacks(g_orcashi, on_peer_found, on_message_received, on_status_change);
    
    if (!orcashi_init(g_orcashi)) {
        fprintf(stderr, "Failed to initialize ORCASHI!\n");
        orcashi_destroy(g_orcashi);
        return 1;
    }
    
    g_ui = ui_create();
    if (g_ui) {
        ui_set_command_callback(g_ui, command_handler);
        ui_init(g_ui);
        ui_start(g_ui);
    }
    
    show_info_screen();
    
    printf("  > ");
    fflush(stdout);
    
    while (running) {
        char* input = ui_get_input();
        if (!input) break;
        if (strlen(input) > 0) command_handler(input);
        free(input);
        if (running) {
            printf("  > ");
            fflush(stdout);
        }
    }
    
    if (g_ui) {
        ui_stop(g_ui);
        ui_destroy(g_ui);
        g_ui = NULL;
    }
    
    if (g_orcashi) {
        orcashi_disconnect(g_orcashi);
        orcashi_destroy(g_orcashi);
        g_orcashi = NULL;
    }
    
    printf("\n  Goodbye!\n");
    
    return 0;
}
