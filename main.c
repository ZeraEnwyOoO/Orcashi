 // main.c - ORCASHI with UI (Separation of Concerns)
#include "orcashi.h"
#include "ui.h"
#include <signal.h>

static ORCASHI* g_orcashi = NULL;
static UI* g_ui = NULL;
static volatile int running = 1;

// ===== Signal Handler =====
void signal_handler(int sig) {
    printf("\n");
    running = 0;
    if (g_orcashi) {
        orcashi_disconnect(g_orcashi);
    }
    if (g_ui) {
        ui_stop(g_ui);
    }
}

// ===== ORCASHI Callbacks (UI gets data from ORCASHI) =====
void on_peer_found(const char* id, const char* ip) {
    if (g_ui) {
        ui_show_peer(id, ip, true);
    }
}

void on_message_received(const char* from, const char* msg) {
    if (g_ui) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), "[%s] %s", from, msg);
        ui_show_message("MESSAGE", buffer);
    }
}

void on_status_change(const char* status) {
    if (g_ui) {
        ui_show_status(status);
    }
}

// ===== Command Handler (UI -> ORCASHI) =====
void command_handler(const char* cmd) {
    if (!cmd || !g_orcashi) return;
    
    if (strcmp(cmd, "/exit") == 0 || strcmp(cmd, "/quit") == 0) {
        running = 0;
        orcashi_disconnect(g_orcashi);
        if (g_ui) ui_stop(g_ui);
    }
    else if (strcmp(cmd, "/help") == 0) {
        if (g_ui) ui_show_help();
    }
    else if (strcmp(cmd, "/peers") == 0) {
        // ORCASHI handles peers
        // UI just displays via callback
        ui_show_status("Fetching peers...");
    }
    else if (strcmp(cmd, "/register") == 0) {
        if (orcashi_register_identity(g_orcashi)) {
            if (g_ui) ui_show_status("Registered with DHT!");
        } else {
            if (g_ui) ui_show_message("ERROR", "Registration failed!");
        }
    }
    else if (strcmp(cmd, "/connect") == 0) {
        if (g_ui) {
            ui_show_message("INFO", "Enter peer ID: ");
            char* id = ui_get_input();
            if (id && strlen(id) > 0) {
                if (orcashi_connect_peer(g_orcashi, id)) {
                    ui_show_status("Connected!");
                } else {
                    ui_show_message("ERROR", "Connection failed!");
                }
            }
            free(id);
        }
    }
    else if (strlen(cmd) > 0 && cmd[0] == '/') {
        if (g_ui) ui_show_message("ERROR", "Unknown command!");
    }
    else if (strlen(cmd) > 0) {
        // Send message via ORCASHI
        if (orcashi_is_connected(g_orcashi)) {
            orcashi_send_message(g_orcashi, cmd);
        } else {
            if (g_ui) ui_show_message("WARNING", "Not connected!");
        }
    }
}

// ===== Main =====
int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // ===== Create ORCASHI (Application Layer) =====
    g_orcashi = orcashi_create();
    if (!g_orcashi) {
        fprintf(stderr, "Failed to create ORCASHI!\n");
        return 1;
    }
    
    // Set callbacks
    orcashi_set_callbacks(g_orcashi, on_peer_found, on_message_received, on_status_change);
    
    // Initialize ORCASHI
    if (!orcashi_init(g_orcashi)) {
        fprintf(stderr, "Failed to initialize ORCASHI!\n");
        orcashi_destroy(g_orcashi);
        return 1;
    }
    
    // ===== Create UI (Presentation Layer) =====
    g_ui = ui_create();
    if (!g_ui) {
        fprintf(stderr, "Failed to create UI!\n");
        orcashi_destroy(g_orcashi);
        return 1;
    }
    
    // Set callback (UI -> ORCASHI)
    ui_set_command_callback(g_ui, command_handler);
    
    // Initialize and start UI
    ui_init(g_ui);
    ui_start(g_ui);
    
    // ===== Main Loop =====
    while (running) {
        char* input = ui_get_input();
        if (!input) break;
        
        if (strlen(input) > 0) {
            command_handler(input);
        }
        free(input);
    }
    
    // ===== Cleanup =====
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
    
    printf("%s", COLOR_SHOW);
    printf("\n  %s%sGoodbye!%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    
    return 0;
}
