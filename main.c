 // main.c - ORCASHI Main Program in C
#include "orcashi.h"
#include <pthread.h>
#include <signal.h>

static volatile int running = 1;

void signal_handler(int sig) {
    printf("\n[ORCA] Shutting down...\n");
    running = 0;
}

static void* chat_thread(void* arg) {
    ORCASHI* orcashi = (ORCASHI*)arg;
    char msg[MAX_MSG_LEN];
    
    while (running && orcashi_is_connected(orcashi)) {
        if (orcashi_receive_message(orcashi, msg, sizeof(msg), 100)) {
            printf("\r\033[K  [%s] %s\n", orcashi_get_peer_id(orcashi), msg);
            printf("  > ");
            fflush(stdout);
        }
    }
    
    return NULL;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    
    ORCASHI* orcashi = orcashi_create();
    if (!orcashi) {
        fprintf(stderr, "[ERROR] Failed to create ORCASHI!\n");
        return 1;
    }
    
    orcashi_init(orcashi);
    
    if (argc < 2) {
        // Interactive mode
        printf("\n");
        printf("  +------------------------------------------+\n");
        printf("  |           ORCASHI v1.0                  |\n");
        printf("  |           Your ID: %s                  |\n", orcashi_get_my_id(orcashi));
        printf("  +------------------------------------------+\n");
        printf("\n");
        printf("  Commands: /help, /register, /connect, /peers, /exit\n");
        printf("\n");
        
        char input[256];
        while (running) {
            printf("  > ");
            if (!fgets(input, sizeof(input), stdin)) break;
            input[strcspn(input, "\n")] = '\0';
            
            if (strcmp(input, "/exit") == 0) {
                break;
            } else if (strcmp(input, "/help") == 0) {
                orcashi_show_help();
            } else if (strcmp(input, "/register") == 0) {
                orcashi_register_identity(orcashi);
            } else if (strcmp(input, "/connect") == 0) {
                printf("  Enter peer ID: ");
                char id[64];
                if (fgets(id, sizeof(id), stdin)) {
                    id[strcspn(id, "\n")] = '\0';
                    orcashi_connect_peer(orcashi, id);
                }
            } else if (strcmp(input, "/peers") == 0) {
                orcashi_show_peers(orcashi);
            } else {
                printf("  Unknown command. Type /help\n");
            }
        }
        
        orcashi_destroy(orcashi);
        return 0;
    }
    
    char* cmd = argv[1];
    
    if (strcmp(cmd, "register") == 0) {
        orcashi_register_identity(orcashi);
    }
    else if (strcmp(cmd, "connect") == 0 && argc >= 3) {
        char* id = argv[2];
        
        if (orcashi_connect_peer(orcashi, id)) {
            printf("\n  [ORCA] Connected! Type /help for commands\n\n");
            
            pthread_t thread;
            pthread_create(&thread, NULL, chat_thread, orcashi);
            
            char input[MAX_MSG_LEN];
            while (running && orcashi_is_connected(orcashi)) {
                printf("  > ");
                fflush(stdout);
                if (!fgets(input, sizeof(input), stdin)) break;
                input[strcspn(input, "\n")] = '\0';
                
                if (strcmp(input, "/exit") == 0) {
                    break;
                } else if (strcmp(input, "/help") == 0) {
                    orcashi_show_help();
                } else if (strcmp(input, "/status") == 0) {
                    printf("  Connected to: %s\n", orcashi_get_peer_id(orcashi));
                    printf("  IP: %s\n", orcashi_get_peer_ip(orcashi));
                } else if (strlen(input) > 0) {
                    orcashi_send_message(orcashi, input);
                }
            }
            
            running = 0;
            pthread_join(thread, NULL);
            orcashi_disconnect(orcashi);
        }
    }
    else if (strcmp(cmd, "create") == 0) {
        printf("\n  [ORCA] Creating room...\n");
        if (orcashi_create_room(orcashi, 9000)) {
            printf("  [ORCA] Waiting for connection...\n");
            printf("  [ORCA] Your ID: %s\n\n", orcashi_get_my_id(orcashi));
            
            while (!orcashi_is_connected(orcashi)) {
                usleep(100000);
            }
            
            printf("  [ORCA] Connected! Type /help for commands\n\n");
            
            pthread_t thread;
            pthread_create(&thread, NULL, chat_thread, orcashi);
            
            char input[MAX_MSG_LEN];
            while (running && orcashi_is_connected(orcashi)) {
                printf("  > ");
                fflush(stdout);
                if (!fgets(input, sizeof(input), stdin)) break;
                input[strcspn(input, "\n")] = '\0';
                
                if (strcmp(input, "/exit") == 0) {
                    break;
                } else if (strcmp(input, "/help") == 0) {
                    orcashi_show_help();
                } else if (strlen(input) > 0) {
                    orcashi_send_message(orcashi, input);
                }
            }
            
            running = 0;
            pthread_join(thread, NULL);
            orcashi_disconnect(orcashi);
        }
    }
    else if (strcmp(cmd, "join") == 0 && argc >= 3) {
        char* ip = argv[2];
        printf("\n  [ORCA] Joining %s...\n", ip);
        
        if (orcashi_join_room(orcashi, ip, 9000)) {
            printf("  [ORCA] Connected! Type /help for commands\n\n");
            
            pthread_t thread;
            pthread_create(&thread, NULL, chat_thread, orcashi);
            
            char input[MAX_MSG_LEN];
            while (running && orcashi_is_connected(orcashi)) {
                printf("  > ");
                fflush(stdout);
                if (!fgets(input, sizeof(input), stdin)) break;
                input[strcspn(input, "\n")] = '\0';
                
                if (strcmp(input, "/exit") == 0) {
                    break;
                } else if (strcmp(input, "/help") == 0) {
                    orcashi_show_help();
                } else if (strlen(input) > 0) {
                    orcashi_send_message(orcashi, input);
                }
            }
            
            running = 0;
            pthread_join(thread, NULL);
            orcashi_disconnect(orcashi);
        }
    }
    else {
        printf("\n  Unknown command: %s\n", cmd);
        printf("  Usage:\n");
        printf("    ./orcashi create      - Create room\n");
        printf("    ./orcashi join <ip>   - Join by IP\n");
        printf("    ./orcashi register    - Register ID\n");
        printf("    ./orcashi connect <id> - Connect by ID\n");
        printf("\n");
    }
    
    orcashi_destroy(orcashi);
    return 0;
}
