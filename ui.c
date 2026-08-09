 #define _POSIX_C_SOURCE 200809L
#include "ui.h"
#include <unistd.h>
#include <time.h>

static const char* glitch_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/01";
static const char* default_slogans[] = {
    "You are not alone here.",
    "Welcome to ORCASHI v3.1",
    "Talk Freely, Stay Anonymous"
};

int ui_random_int(int min, int max) {
    if (min > max) { int temp = min; min = max; max = temp; }
    return (rand() % (max - min + 1)) + min;
}

char ui_random_glitch_char(void) {
    int len = strlen(glitch_chars);
    return glitch_chars[ui_random_int(0, len - 1)];
}

char* ui_apply_glitch(const char* text, int intensity) {
    if (!text) return NULL;
    int len = strlen(text);
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;
    for (int i = 0; i < len; i++) {
        if (text[i] != ' ' && ui_random_int(1, 100) <= intensity) {
            result[i] = ui_random_glitch_char();
        } else {
            result[i] = text[i];
        }
    }
    result[len] = '\0';
    return result;
}

UI* ui_create(void) {
    UI* ui = (UI*)calloc(1, sizeof(UI));
    if (!ui) return NULL;
    ui->running = false;
    ui->glitch_enabled = true;
    ui->glitch_intensity = 40;
    ui->slogan_count = 0;
    ui->slogan_index = 0;
    ui->current_slogan = NULL;
    ui->on_command = NULL;
    ui->on_message = NULL;
    ui->glitch_paused = false;
    pthread_mutex_init(&ui->mutex, NULL);
    pthread_mutex_init(&ui->stdout_mutex, NULL);
    srand(time(NULL) ^ getpid());
    int default_count = sizeof(default_slogans) / sizeof(default_slogans[0]);
    ui_set_slogans(ui, default_slogans, default_count);
    return ui;
}

void ui_destroy(UI* ui) {
    if (!ui) return;
    ui_stop(ui);
    if (ui->current_slogan) { free(ui->current_slogan); ui->current_slogan = NULL; }
    if (ui->slogans) {
        for (int i = 0; i < ui->slogan_count; i++) {
            if (ui->slogans[i]) free(ui->slogans[i]);
        }
        free(ui->slogans);
        ui->slogans = NULL;
    }
    pthread_mutex_destroy(&ui->mutex);
    pthread_mutex_destroy(&ui->stdout_mutex);
    free(ui);
}

void ui_set_slogans(UI* ui, const char** slogans, int count) {
    if (!ui || !slogans || count <= 0) return;
    pthread_mutex_lock(&ui->mutex);
    if (ui->slogans) {
        for (int i = 0; i < ui->slogan_count; i++) {
            if (ui->slogans[i]) free(ui->slogans[i]);
        }
        free(ui->slogans);
    }
    ui->slogan_count = count;
    ui->slogans = (char**)malloc(count * sizeof(char*));
    for (int i = 0; i < count; i++) {
        ui->slogans[i] = strdup(slogans[i]);
    }
    ui->slogan_index = 0;
    if (ui->current_slogan) { free(ui->current_slogan); ui->current_slogan = NULL; }
    pthread_mutex_unlock(&ui->mutex);
}

void ui_add_slogan(UI* ui, const char* slogan) {
    if (!ui || !slogan) return;
    pthread_mutex_lock(&ui->mutex);
    ui->slogan_count++;
    ui->slogans = (char**)realloc(ui->slogans, ui->slogan_count * sizeof(char*));
    ui->slogans[ui->slogan_count - 1] = strdup(slogan);
    pthread_mutex_unlock(&ui->mutex);
}

void ui_next_slogan(UI* ui) {
    if (!ui || ui->slogan_count == 0) return;
    pthread_mutex_lock(&ui->mutex);
    ui->slogan_index = (ui->slogan_index + 1) % ui->slogan_count;
    if (ui->current_slogan) { free(ui->current_slogan); ui->current_slogan = NULL; }
    pthread_mutex_unlock(&ui->mutex);
}

static void* glitch_loop(void* arg) {
    UI* ui = (UI*)arg;
    char* current_text = NULL;
    int line = 12;  // Glitch at line 12 (below banner)
    
    while (ui->running) {
        if (ui->glitch_paused) {
            usleep(50000);
            continue;
        }
        
        if (ui->slogan_count == 0) { sleep(1); continue; }
        
        pthread_mutex_lock(&ui->mutex);
        char* target_slogan = ui->slogans[ui->slogan_index];
        pthread_mutex_unlock(&ui->mutex);
        if (!target_slogan) { sleep(1); continue; }
        
        if (!current_text) {
            current_text = strdup(target_slogan);
            
            pthread_mutex_lock(&ui->stdout_mutex);
            printf("\033[%d;0H", line);
            printf("\033[K  ");
            fflush(stdout);
            pthread_mutex_unlock(&ui->stdout_mutex);
            
            int len = strlen(current_text);
            for (int i = 0; i < len && ui->running; i++) {
                if (ui->glitch_paused) {
                    usleep(50000);
                    continue;
                }
                
                char* typed = strndup(current_text, i + 1);
                char* glitched = ui_apply_glitch(typed, ui_random_int(30, 60));
                const char* colors[] = {COLOR_CYAN, COLOR_MAGENTA, COLOR_RED, COLOR_YELLOW, COLOR_GREEN};
                const char* color = colors[ui_random_int(0, 4)];
                
                pthread_mutex_lock(&ui->stdout_mutex);
                printf("\033[%d;0H", line);
                printf("\033[K  %s%s%s", COLOR_BOLD, color, glitched);
                fflush(stdout);
                pthread_mutex_unlock(&ui->stdout_mutex);
                
                free(typed); free(glitched);
                usleep(ui_random_int(30000, 70000));
            }
        }
        
        if (!ui->running) break;
        
        for (int burst = 0; burst < 3 && ui->running; burst++) {
            for (int frame = 0; frame < 15 && ui->running; frame++) {
                if (ui->glitch_paused) {
                    usleep(50000);
                    break;
                }
                
                char* glitched = ui_apply_glitch(current_text, 30 + (burst * 20));
                const char* colors[] = {COLOR_MAGENTA, COLOR_RED, COLOR_YELLOW, COLOR_CYAN, COLOR_GREEN};
                const char* color = colors[frame % 5];
                
                pthread_mutex_lock(&ui->stdout_mutex);
                printf("\033[%d;0H", line);
                printf("\033[K  %s%s%s", COLOR_BOLD, color, glitched);
                fflush(stdout);
                pthread_mutex_unlock(&ui->stdout_mutex);
                
                free(glitched);
                usleep(ui_random_int(20000, 50000));
            }
            if (!ui->running) break;
            
            pthread_mutex_lock(&ui->stdout_mutex);
            printf("\033[%d;0H", line);
            printf("\033[K  %s%s%s", COLOR_BOLD, COLOR_WHITE, current_text);
            fflush(stdout);
            pthread_mutex_unlock(&ui->stdout_mutex);
            usleep(100000);
        }
        
        if (!ui->running) break;
        
        pthread_mutex_lock(&ui->stdout_mutex);
        printf("\033[%d;0H", line);
        printf("\033[K  %s%s%s", COLOR_BOLD, COLOR_WHITE, current_text);
        fflush(stdout);
        pthread_mutex_unlock(&ui->stdout_mutex);
        sleep(3);
        
        if (!ui->running) break;
        
        pthread_mutex_lock(&ui->stdout_mutex);
        printf("\033[%d;0H", line);
        printf("\033[K  ");
        fflush(stdout);
        pthread_mutex_unlock(&ui->stdout_mutex);
        
        int len = strlen(current_text);
        for (int i = 0; i < len && ui->running; i++) {
            if (ui->glitch_paused) {
                usleep(50000);
                continue;
            }
            
            int remaining_len = len - i - 1;
            char* remaining = strndup(current_text, remaining_len);
            char* glitched = ui_apply_glitch(remaining, ui_random_int(40, 70));
            const char* colors[] = {COLOR_RED, COLOR_MAGENTA, COLOR_YELLOW, COLOR_CYAN};
            const char* color = colors[ui_random_int(0, 3)];
            
            pthread_mutex_lock(&ui->stdout_mutex);
            printf("\033[%d;0H", line);
            printf("\033[K  %s%s%s", COLOR_BOLD, color, glitched);
            fflush(stdout);
            pthread_mutex_unlock(&ui->stdout_mutex);
            
            free(remaining); free(glitched);
            usleep(ui_random_int(20000, 50000));
        }
        
        if (!ui->running) break;
        
        pthread_mutex_lock(&ui->stdout_mutex);
        printf("\033[%d;0H", line);
        printf("\033[K  ");
        fflush(stdout);
        pthread_mutex_unlock(&ui->stdout_mutex);
        usleep(300000);
        
        free(current_text);
        current_text = NULL;
        ui_next_slogan(ui);
    }
    
    if (current_text) free(current_text);
    return NULL;
}

void ui_init(UI* ui) {
    if (!ui) return;
    printf("%s", COLOR_HIDE);
    fflush(stdout);
    ui_show_banner();
    ui_show_prompt(ui);
}

void ui_start(UI* ui) {
    if (!ui || ui->running) return;
    ui->running = true;
    pthread_create(&ui->glitch_thread, NULL, glitch_loop, ui);
}

void ui_stop(UI* ui) {
    if (!ui || !ui->running) return;
    ui->running = false;
    if (ui->glitch_thread) {
        pthread_join(ui->glitch_thread, NULL);
        ui->glitch_thread = 0;
    }
    printf("%s", COLOR_SHOW);
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
        "",  // line 9
        "",  // line 10
        "",  // line 11
        "",  // line 12 - Glitch
        "",  // line 13
        "",  // line 14
        "  Commands: /help, /peers, /register, /exit",  // line 15
        "  > "  // line 16
    };
    printf("%s", COLOR_CLEAR);
    fflush(stdout);
    for (int i = 0; i < 17; i++) {
        printf("%s%s%s\n", COLOR_BOLD, COLOR_CYAN, banner[i]);
    }
    printf("%s", COLOR_RESET);
    fflush(stdout);
}

void ui_show_prompt(UI* ui) {
    if (!ui) return;
    pthread_mutex_lock(&ui->stdout_mutex);
    printf("\033[15;0H");  // Prompt at line 15
    printf("  %s%sCommands: /help, /peers, /register, /exit%s\n", 
           COLOR_BOLD, COLOR_YELLOW, COLOR_RESET);
    printf("  %s%s> %s", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    fflush(stdout);
    pthread_mutex_unlock(&ui->stdout_mutex);
}

void ui_show_message(UI* ui, const char* level, const char* msg) {
    if (!ui) return;
    const char* color = COLOR_GREEN;
    if (strcmp(level, "ERROR") == 0) color = COLOR_RED;
    else if (strcmp(level, "WARNING") == 0) color = COLOR_YELLOW;
    else if (strcmp(level, "INFO") == 0) color = COLOR_CYAN;
    
    ui->glitch_paused = true;
    usleep(50000);
    
    pthread_mutex_lock(&ui->stdout_mutex);
    printf("\n\033[K  %s%s[%s] %s%s%s\n", 
           COLOR_BOLD, color, level, COLOR_RESET, msg, COLOR_RESET);
    printf("  %s%s> %s", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    fflush(stdout);
    pthread_mutex_unlock(&ui->stdout_mutex);
    
    usleep(50000);
    ui->glitch_paused = false;
}

void ui_show_status(UI* ui, const char* status) {
    if (!ui) return;
    ui->glitch_paused = true;
    usleep(50000);
    
    pthread_mutex_lock(&ui->stdout_mutex);
    printf("\n\033[K  %s%s✓ %s%s\n", 
           COLOR_BOLD, COLOR_GREEN, status, COLOR_RESET);
    printf("  %s%s> %s", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    fflush(stdout);
    pthread_mutex_unlock(&ui->stdout_mutex);
    
    usleep(50000);
    ui->glitch_paused = false;
}

void ui_show_peer(UI* ui, const char* id, const char* ip, bool online) {
    if (!ui) return;
    const char* status = online ? "ONLINE" : "OFFLINE";
    const char* color = online ? COLOR_GREEN : COLOR_RED;
    
    ui->glitch_paused = true;
    usleep(50000);
    
    pthread_mutex_lock(&ui->stdout_mutex);
    printf("\n\033[K  %s%s%s%s - %s %s%s\n",
           COLOR_BOLD, color, id, COLOR_RESET,
           ip, COLOR_BOLD, status);
    printf("  %s%s> %s", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    fflush(stdout);
    pthread_mutex_unlock(&ui->stdout_mutex);
    
    usleep(50000);
    ui->glitch_paused = false;
}

void ui_show_help(UI* ui) {
    if (!ui) return;
    ui->glitch_paused = true;
    usleep(50000);
    
    pthread_mutex_lock(&ui->stdout_mutex);
    printf("\n\033[K  %s%sORCASHI Commands:%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("  %s  /help     - Show this help%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s  /peers    - List connected peers%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s  /register - Register with DHT%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s  /connect  - Connect to peer by ID%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s  /create   - Create room%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s  /join     - Join room by IP%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s  /exit     - Exit program%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s%s> %s", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    fflush(stdout);
    pthread_mutex_unlock(&ui->stdout_mutex);
    
    usleep(50000);
    ui->glitch_paused = false;
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

void ui_glitch_text(const char* text, int intensity, int delay_ms) {
    if (!text) return;
    int len = strlen(text);
    for (int i = 0; i < len; i++) {
        char* partial = strndup(text, i + 1);
        char* glitched = ui_apply_glitch(partial, intensity);
        const char* colors[] = {COLOR_CYAN, COLOR_MAGENTA, COLOR_RED, COLOR_YELLOW, COLOR_GREEN};
        const char* color = colors[ui_random_int(0, 4)];
        printf("\r\033[K  %s%s%s", COLOR_BOLD, color, glitched);
        fflush(stdout);
        free(partial); free(glitched);
        usleep(delay_ms * 1000);
    }
    printf("\n");
}

void ui_type_text(const char* text, int delay_ms) {
    if (!text) return;
    int len = strlen(text);
    for (int i = 0; i < len; i++) {
        printf("%c", text[i]);
        fflush(stdout);
        usleep(delay_ms * 1000);
    }
    printf("\n");
}
