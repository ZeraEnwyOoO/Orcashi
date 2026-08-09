 #include "orcashi.h"
#include "ui.h"
#include <signal.h>
#include <getopt.h>

static ORCASHI* g_orcashi = NULL;
static UI* g_ui = NULL;
static volatile int running = 1;

// ===== Signal Handler =====
void signal_handler(int sig) {
    (void)sig;
    printf("\n");
    running = 0;
    if (g_orcashi) orcashi_disconnect(g_orcashi);
    if (g_ui) ui_stop(g_ui);
}

// ===== ORCASHI Callbacks =====
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

// ===== Command Handler (Interactive Mode) =====
void command_handler(const char* cmd) {
    if (!cmd || !g_orcashi) return;
    
    if (strcmp(cmd, "/exit") == 0 || strcmp(cmd, "/quit") == 0) {
        running = 0;
        orcashi_disconnect(g_orcashi);
        if (g_ui) ui_stop(g_ui);
    }
    else if (strcmp(cmd, "/help") == 0) {
        printf("\n");
        printf("  %s%sORCASHI Commands:%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
        printf("  %s  /help     - Show this help%s\n", COLOR_BOLD, COLOR_RESET);
        printf("  %s  /peers    - List connected peers%s\n", COLOR_BOLD, COLOR_RESET);
        printf("  %s  /register - Register with DHT%s\n", COLOR_BOLD, COLOR_RESET);
        printf("  %s  /connect  - Connect to peer by ID%s\n", COLOR_BOLD, COLOR_RESET);
        printf("  %s  /search   - Search peer in DHT%s\n", COLOR_BOLD, COLOR_RESET);
        printf("  %s  /create   - Create room%s\n", COLOR_BOLD, COLOR_RESET);
        printf("  %s  /join     - Join room by IP or ID%s\n", COLOR_BOLD, COLOR_RESET);
        printf("  %s  /status   - Show status%s\n", COLOR_BOLD, COLOR_RESET);
        printf("  %s  /exit     - Exit program%s\n", COLOR_BOLD, COLOR_RESET);
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
        printf("\n  %sStatus:%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
        printf("  ID: %s\n", orcashi_get_my_id(g_orcashi));
        printf("  Connected: %s\n", orcashi_is_connected(g_orcashi) ? "Yes" : "No");
        printf("  Registered: %s\n", g_orcashi->registered ? "Yes" : "No");
        printf("  DHT: %s\n", g_orcashi->dht_enabled ? "Enabled" : "Disabled");
        printf("  Local IP: %s\n", orcashi_get_local_ip());
        if (orcashi_is_connected(g_orcashi)) {
            printf("  Peer ID: %s\n", orcashi_get_peer_id(g_orcashi));
            printf("  Peer IP: %s\n", orcashi_get_peer_ip(g_orcashi));
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

// ===== Show Info Screen (Default) =====
void show_info_screen(void) {
    printf("%s", COLOR_CLEAR);
    printf("\n");
    printf("  %s============================================%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("  %s        ██████╗ ██████╗  ██████╗ █████╗ %s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("  %s       ██╔═══██╗██╔══██╗██╔════╝██╔══██╗%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("  %s       ██║   ██║██████╔╝██║     ███████║%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("  %s       ██║   ██║██╔══██╗██║     ██╔══██║%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("  %s       ╚██████╔╝██║  ██║╚██████╗██║  ██║%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("  %s        ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("  %s============================================%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("\n");
    printf("  %sORCASHI v3.1 - P2P Encrypted Chat%s\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("  %sNo Servers, No Tracking, No Censorship%s\n", COLOR_BOLD, COLOR_YELLOW, COLOR_RESET);
    printf("\n");
    printf("  %sUsage:%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("    %s./orcashi%s              - Interactive mode with glitch animation\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s./orcashi help%s         - Show help\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s./orcashi register%s     - Register identity with DHT\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s./orcashi peers%s        - List all saved peers\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s./orcashi connect <id>%s - Connect to peer by ID\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s./orcashi search <id>%s  - Search peer in DHT\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s./orcashi create%s       - Create a room (server)\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s./orcashi join <id/ip>%s - Join room by ID or IP\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("\n");
    printf("  %sInteractive Commands:%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("    %s/help%s     - Show commands\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/peers%s    - List connected peers\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/register%s - Register with DHT\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/connect%s  - Connect to peer by ID\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/search%s   - Search peer in DHT\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/create%s   - Create room\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/join%s     - Join room by IP or ID\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/status%s   - Show status\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/exit%s     - Exit program\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("\n");
    printf("  %sPress Ctrl+C to exit anytime%s\n", COLOR_BOLD, COLOR_YELLOW, COLOR_RESET);
    printf("\n");
    fflush(stdout);
}

// ===== Show Help =====
void show_help(void) {
    printf("\n");
    printf("  %sORCASHI v3.1 - Help%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("  %s================================%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("\n");
    printf("  %sCommands:%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("    %s./orcashi%s              - Interactive mode with glitch animation\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s./orcashi help%s         - Show this help\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s./orcashi register%s     - Register identity with DHT\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s./orcashi peers%s        - List all saved peers\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s./orcashi connect <id>%s - Connect to peer by ID\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s./orcashi search <id>%s  - Search peer in DHT\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s./orcashi create%s       - Create a room (server)\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s./orcashi join <id/ip>%s - Join room by ID or IP\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("\n");
    printf("  %sInteractive Commands:%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("    %s/help%s     - Show commands\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/peers%s    - List connected peers\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/register%s - Register with DHT\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/connect%s  - Connect to peer by ID\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/search%s   - Search peer in DHT\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/create%s   - Create room\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/join%s     - Join room by IP or ID\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/status%s   - Show status\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("    %s/exit%s     - Exit program\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    printf("\n");
    printf("  %sPress Ctrl+C to exit anytime%s\n", COLOR_BOLD, COLOR_YELLOW, COLOR_RESET);
    printf("\n");
    fflush(stdout);
}

// ===== Main =====
int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // ===== Parse Command Line Arguments (No Dash Style) =====
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
            printf("\n  %sSaved Peers:%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
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
    
    // ===== Interactive Mode (Default) =====
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
    
    // ===== Show Info Screen with Glitch Animation =====
    g_ui = ui_create();
    if (g_ui) {
        ui_set_command_callback(g_ui, command_handler);
        ui_init(g_ui);
        ui_start(g_ui);  // Glitch animation starts here
    }
    
    // Show info screen after glitch starts
    show_info_screen();
    
    // Show prompt
    printf("  %s> %s", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    fflush(stdout);
    
    while (running) {
        char* input = ui_get_input();
        if (!input) break;
        if (strlen(input) > 0) command_handler(input);
        free(input);
        if (running) {
            printf("  %s> %s", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
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
    
    printf("\n  %s%sGoodbye!%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    
    return 0;
}
