  #define _POSIX_C_SOURCE 200809L
#include "ui.h"
#include <unistd.h>
#include <time.h>

UI* ui_create(void) {
    UI* ui = (UI*)calloc(1, sizeof(UI));
    if (!ui) return NULL;
    ui->running = false;
    ui->on_command = NULL;
    ui->on_message = NULL;
    pthread_mutex_init(&ui->mutex, NULL);
    pthread_mutex_init(&ui->stdout_mutex, NULL);
    return ui;
}

void ui_destroy(UI* ui) {
    if (!ui) return;
    ui_stop(ui);
    pthread_mutex_destroy(&ui->mutex);
    pthread_mutex_destroy(&ui->stdout_mutex);
    free(ui);
}

void ui_init(UI* ui) {
    if (!ui) return;
    fflush(stdout);
    ui_show_banner();
}

void ui_start(UI* ui) {
    if (!ui || ui->running) return;
    ui->running = true;
}

void ui_stop(UI* ui) {
    if (!ui || !ui->running) return;
    ui->running = false;
    fflush(stdout);
}

void ui_show_banner(void) {
    const char* banner[] = {
        "  ============================================",
        "        ██████╗ ██████╗  ██████╗ █████╗ ",
        "       ██╔═══██╗██╔══██╗██╔════╝██╔══██╗",
        "       ██║   ██║██████╔╝██║     ███████║",
        "       ██║   ██║██╔══██╗██║     ██╔══██║",
        "       ╚██████╔╝██║  ██║╚██████╗██║  ██║",
        "        ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝",
        "  ============================================",
        "",
        "  ORCASHI v3.1 - P2P Encrypted Chat",
        "  No Servers, No Tracking, No Censorship",
        ""
    };
    printf("%s", COLOR_CLEAR);
    fflush(stdout);
    for (int i = 0; i < 12; i++) {
        printf("%s%s%s\n", COLOR_BOLD, COLOR_CYAN, banner[i]);
    }
    printf("%s", COLOR_RESET);
    fflush(stdout);
}

void ui_show_message(UI* ui, const char* level, const char* msg) {
    if (!ui) return;
    const char* color = COLOR_GREEN;
    if (strcmp(level, "ERROR") == 0) color = COLOR_RED;
    else if (strcmp(level, "WARNING") == 0) color = COLOR_YELLOW;
    else if (strcmp(level, "INFO") == 0) color = COLOR_CYAN;
    
    pthread_mutex_lock(&ui->stdout_mutex);
    printf("\n\033[K  %s%s[%s] %s%s%s\n", 
           COLOR_BOLD, color, level, COLOR_RESET, msg, COLOR_RESET);
    fflush(stdout);
    pthread_mutex_unlock(&ui->stdout_mutex);
}

void ui_show_status(UI* ui, const char* status) {
    if (!ui) return;
    pthread_mutex_lock(&ui->stdout_mutex);
    printf("\n\033[K  %s%s[STATUS] %s%s\n", 
           COLOR_BOLD, COLOR_GREEN, status, COLOR_RESET);
    fflush(stdout);
    pthread_mutex_unlock(&ui->stdout_mutex);
}

void ui_show_peer(UI* ui, const char* id, const char* ip, bool online) {
    if (!ui) return;
    const char* status = online ? "ONLINE" : "OFFLINE";
    const char* color = online ? COLOR_GREEN : COLOR_RED;
    pthread_mutex_lock(&ui->stdout_mutex);
    printf("\n\033[K  %s%s%s%s - %s %s%s\n",
           COLOR_BOLD, color, id, COLOR_RESET,
           ip, COLOR_BOLD, status);
    fflush(stdout);
    pthread_mutex_unlock(&ui->stdout_mutex);
}

void ui_show_help(UI* ui) {
    if (!ui) return;
    pthread_mutex_lock(&ui->stdout_mutex);
    printf("\n\033[K  %s%sORCASHI Commands:%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("  %s  /help     - Show this help%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s  /peers    - List connected peers%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s  /register - Register with DHT%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s  /connect  - Connect to peer by ID%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s  /search   - Search peer in DHT%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s  /create   - Create room%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s  /join     - Join room by IP or ID%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s  /status   - Show status%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s  /exit     - Exit program%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s\n", COLOR_RESET);
    fflush(stdout);
    pthread_mutex_unlock(&ui->stdout_mutex);
}

char* ui_get_input(void) {
    char* buffer = NULL;
    size_t bufsize = 0;
    getline(&buffer, &bufsize, stdin);
    if (buffer) {
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }
    }
    return buffer;
}

void ui_set_command_callback(UI* ui, void (*callback)(const char*)) {
    if (ui) ui->on_command = callback;
}

void ui_set_message_callback(UI* ui, void (*callback)(const char*)) {
    if (ui) ui->on_message = callback;
}
