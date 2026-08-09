 // ui.h - PURE PRESENTATION LAYER (No DHT/TCP)
#ifndef UI_H
#define UI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>

// ===== ANSI Colors =====
#define COLOR_CYAN     "\033[36m"
#define COLOR_MAGENTA  "\033[35m"
#define COLOR_RED      "\033[31m"
#define COLOR_GREEN    "\033[32m"
#define COLOR_YELLOW   "\033[33m"
#define COLOR_BLUE     "\033[34m"
#define COLOR_WHITE    "\033[37m"
#define COLOR_BOLD     "\033[1m"
#define COLOR_RESET    "\033[0m"
#define COLOR_CLEAR    "\033[2J\033[H"
#define COLOR_HIDE     "\033[?25l"
#define COLOR_SHOW     "\033[?25h"

// ===== UI Structure (PURE PRESENTATION) =====
typedef struct {
    bool running;
    bool glitch_enabled;
    int glitch_intensity;
    pthread_t glitch_thread;
    pthread_mutex_t mutex;
    
    // UI State (NOT DHT/TCP)
    char* current_slogan;
    char** slogans;
    int slogan_count;
    int slogan_index;
    
    // Command callback (to application layer)
    void (*on_command)(const char* cmd);
    void (*on_message)(const char* msg);
} UI;

// ===== UI Functions (PURE PRESENTATION) =====
UI* ui_create(void);
void ui_destroy(UI* ui);

void ui_init(UI* ui);
void ui_start(UI* ui);
void ui_stop(UI* ui);

// Display functions (NO DHT/TCP)
void ui_show_banner(void);
void ui_show_prompt(void);
void ui_show_message(const char* level, const char* msg);
void ui_show_status(const char* status);
void ui_show_peer(const char* id, const char* ip, bool online);
void ui_show_help(void);

// Glitch effects (PURE VISUAL)
void ui_glitch_text(const char* text, int intensity, int delay_ms);
void ui_type_text(const char* text, int delay_ms);
char* ui_apply_glitch(const char* text, int intensity);

// Input (PURE USER INPUT)
char* ui_get_input(void);
void ui_set_command_callback(UI* ui, void (*callback)(const char*));
void ui_set_message_callback(UI* ui, void (*callback)(const char*));

// Slogans (PURE UI)
void ui_add_slogan(UI* ui, const char* slogan);
void ui_set_slogans(UI* ui, const char** slogans, int count);
void ui_next_slogan(UI* ui);

// Helpers (PURE UI)
int ui_random_int(int min, int max);
char ui_random_glitch_char(void);

#endif
