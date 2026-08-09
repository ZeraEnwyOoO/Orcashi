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
        ui_show_peer(g_ui, id, ip, true);  // ← បន្ថែម g_ui
    }
}

void on_message_received(const char* from, const char* msg) {
    if (g_ui) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), "[%s] %s", from, msg);
        ui_show_message(g_ui, "MESSAGE", buffer);  // ← បន្ថែម g_ui
    }
}

void on_status_change(const char* status) {
    if (g_ui) {
        ui_show_status(g_ui, status);  // ← បន្ថែម g_ui
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
        if (g_ui) ui_show_help(g_ui);  // ← បន្ថែម g_ui
    }
    else if (strcmp(cmd, "/peers") == 0) {
        if (g_ui) ui_show_status(g_ui, "Fetching peers...");  // ← បន្ថែម g_ui
    }
    else if (strcmp(cmd, "/register") == 0) {
        if (orcashi_register_identity(g_orcashi)) {
            if (g_ui) ui_show_status(g_ui, "Registered with DHT!");  // ← បន្ថែម g_ui
        } else {
            if (g_ui) ui_show_message(g_ui, "ERROR", "Registration failed!");  // ← បន្ថែម g_ui
        }
    }
    else if (strcmp(cmd, "/connect") == 0) {
        if (g_ui) {
            ui_show_message(g_ui, "INFO", "Enter peer ID: ");  // ← បន្ថែម g_ui
            char* id = ui_get_input();
            if (id && strlen(id) > 0) {
                if (orcashi_connect_peer(g_orcashi, id)) {
                    ui_show_status(g_ui, "Connected!");  // ← បន្ថែម g_ui
                } else {
                    ui_show_message(g_ui, "ERROR", "Connection failed!");  // ← បន្ថែម g_ui
                }
            }
            free(id);
        }
    }
    else if (strlen(cmd) > 0 && cmd[0] == '/') {
        if (g_ui) ui_show_message(g_ui, "ERROR", "Unknown command!");  // ← បន្ថែម g_ui
    }
    else if (strlen(cmd) > 0) {
        // Send message via ORCASHI
        if (orcashi_is_connected(g_orcashi)) {
            orcashi_send_message(g_orcashi, cmd);
        } else {
            if (g_ui) ui_show_message(g_ui, "WARNING", "Not connected!");  // ← បន្ថែម g_ui
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
