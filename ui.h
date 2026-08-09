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

typedef struct {
    bool running;
    pthread_mutex_t mutex;
    pthread_mutex_t stdout_mutex;
    void (*on_command)(const char* cmd);
    void (*on_message)(const char* msg);
} UI;

UI* ui_create(void);
void ui_destroy(UI* ui);

void ui_init(UI* ui);
void ui_start(UI* ui);
void ui_stop(UI* ui);

void ui_show_banner(void);
void ui_show_message(UI* ui, const char* level, const char* msg);
void ui_show_status(UI* ui, const char* status);
void ui_show_peer(UI* ui, const char* id, const char* ip, bool online);
void ui_show_help(UI* ui);

char* ui_get_input(void);
void ui_set_command_callback(UI* ui, void (*callback)(const char*));
void ui_set_message_callback(UI* ui, void (*callback)(const char*));

#endif
