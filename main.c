 #include "orcashi.h"
#include "ui.h"
#include <signal.h>

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
        if (g_ui) ui_show_help(g_ui);
    }
    else if (strcmp(cmd, "/peers") == 0) {
        if (g_ui) ui_show_status(g_ui, "Fetching peers...");
    }
    else if (strcmp(cmd, "/register") == 0) {
        if (orcashi_register_identity(g_orcashi)) {
            if (g_ui) ui_show_status(g_ui, "Registered with DHT!");
        } else {
            if (g_ui) ui_show_message(g_ui, "ERROR", "Registration failed!");
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
            ui_show_message(g_ui, "INFO", "Enter IP: ");
            char* ip = ui_get_input();
            if (ip && strlen(ip) > 0) {
                if (orcashi_join_room(g_orcashi, ip, 9000)) {
                    ui_show_status(g_ui, "Connected!");
                } else {
                    ui_show_message(g_ui, "ERROR", "Connection failed!");
                }
            }
            free(ip);
        }
    }
    else if (strlen(cmd) > 0 && cmd[0] == '/') {
        if (g_ui) ui_show_message(g_ui, "ERROR", "Unknown command!");
    }
    else if (strlen(cmd) > 0) {
        if (orcashi_is_connected(g_orcashi)) {
            orcashi_send_message(g_orcashi, cmd);
        } else {
            if (g_ui) ui_show_message(g_ui, "WARNING", "Not connected!");
        }
    }
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
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
    if (!g_ui) {
        fprintf(stderr, "Failed to create UI!\n");
        orcashi_destroy(g_orcashi);
        return 1;
    }
    
    ui_set_command_callback(g_ui, command_handler);
    ui_init(g_ui);
    ui_start(g_ui);
    
    while (running) {
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
    if (g_orcashi) {
        orcashi_disconnect(g_orcashi);
        orcashi_destroy(g_orcashi);
        g_orcashi = NULL;
    }
    
    printf("\n  %s%sGoodbye!%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    
    return 0;
}
