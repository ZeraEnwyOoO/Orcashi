 #include "orcashi.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

static ORCASHI* g_orcashi = NULL;
static volatile int running = 1;

void signal_handler(int sig) {
    (void)sig;
    printf("\nShutting down...\n");
    running = 0;
    if (g_orcashi) orcashi_disconnect(g_orcashi);
    exit(0);
}

void show_help(void) {
    printf("\n");
    printf("ORCASHI v3.1 - P2P Chat\n");
    printf("Usage:\n");
    printf("  ./orcashi create          - Create room (server)\n");
    printf("  ./orcashi join <ip>       - Join room by IP\n");
    printf("  ./orcashi register        - Register identity (foreground)\n");
    printf("  ./orcashi register -d     - Register as daemon (background)\n");
    printf("  ./orcashi connect <id>    - Connect by ID\n");
    printf("  ./orcashi peers           - List peers\n");
    printf("  ./orcashi stop            - Stop background daemon\n");
    printf("  ./orcashi status          - Check if daemon is running\n");
    printf("  ./orcashi help            - Show help\n");
    printf("\n");
    printf("Chat commands:\n");
    printf("  /exit                     - Exit chat\n");
    printf("\n");
}

#define PID_FILE "/tmp/.orcashi/orcashi.pid"
#define LOG_FILE "/tmp/.orcashi/orcashi.log"

void daemonize(void) {
    pid_t pid = fork();
    
    if (pid < 0) {
        fprintf(stderr, "Failed to fork!\n");
        exit(1);
    }
    
    if (pid > 0) {
        FILE* f = fopen(PID_FILE, "w");
        if (f) {
            fprintf(f, "%d", pid);
            fclose(f);
        }
        printf("Daemon started (PID: %d)\n", pid);
        printf("Log file: %s\n", LOG_FILE);
        printf("PID file: %s\n", PID_FILE);
        printf("Use './orcashi stop' to stop\n");
        printf("Use './orcashi status' to check\n");
        exit(0);
    }
    
    setsid();
    
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    open("/dev/null", O_RDWR);
    int log_fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    dup2(log_fd, STDOUT_FILENO);
    dup2(log_fd, STDERR_FILENO);
    
    chdir("/tmp");
    
    while (running) {
        sleep(1);
    }
}

int check_daemon(void) {
    FILE* f = fopen(PID_FILE, "r");
    if (!f) return 0;
    
    int pid;
    if (fscanf(f, "%d", &pid) != 1) {
        fclose(f);
        return 0;
    }
    fclose(f);
    
    if (kill(pid, 0) == 0) {
        return pid;
    }
    
    unlink(PID_FILE);
    return 0;
}

void stop_daemon(void) {
    int pid = check_daemon();
    if (!pid) {
        printf("No daemon running\n");
        return;
    }
    
    printf("Stopping daemon (PID: %d)...\n", pid);
    kill(pid, SIGTERM);
    sleep(1);
    unlink(PID_FILE);
    printf("Daemon stopped\n");
}

void chat_loop(void) {
    printf("Type /exit to quit\n");
    printf("---\n");
    
    char input[4096];
    char msg[4096];
    
    while (running && orcashi_is_connected(g_orcashi)) {
        while (orcashi_receive_message(g_orcashi, msg, sizeof(msg), 10)) {
            printf("[%s] %s\n", orcashi_get_peer_id(g_orcashi), msg);
            fflush(stdout);
        }
        
        printf("> ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';
        
        if (strcmp(input, "/exit") == 0) break;
        
        if (strlen(input) > 0) {
            orcashi_send_message(g_orcashi, input);
        }
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (argc < 2) {
        show_help();
        return 0;
    }
    
    char* cmd = argv[1];
    
    if (strcmp(cmd, "stop") == 0) {
        stop_daemon();
        return 0;
    }
    
    if (strcmp(cmd, "status") == 0) {
        int pid = check_daemon();
        if (pid) {
            printf("Daemon is running (PID: %d)\n", pid);
        } else {
            printf("No daemon running\n");
        }
        return 0;
    }
    
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
    
    printf("ID: %s\n", orcashi_get_my_id(g_orcashi));
    printf("---\n");
    
    int is_daemon = 0;
    if (strcmp(cmd, "register") == 0 && argc >= 3 && strcmp(argv[2], "-d") == 0) {
        is_daemon = 1;
    }
    
    if (strcmp(cmd, "create") == 0) {
        printf("Creating room on port 9000...\n");
        if (!orcashi_create_room(g_orcashi, 9000)) {
            fprintf(stderr, "Failed to create room!\n");
            orcashi_destroy(g_orcashi);
            return 1;
        }
        printf("Room created! Waiting for connection...\n");
        printf("---\n");
        
        while (running && !orcashi_is_connected(g_orcashi)) {
            sleep(1);
        }
        
        if (!running) {
            orcashi_destroy(g_orcashi);
            return 0;
        }
        
        printf("Connected to: %s\n", orcashi_get_peer_ip(g_orcashi));
        chat_loop();
        
        printf("Disconnected.\n");
        orcashi_disconnect(g_orcashi);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "join") == 0 && argc >= 3) {
        char* ip = argv[2];
        int port = (argc >= 4) ? atoi(argv[3]) : 9000;
        printf("Joining %s:%d...\n", ip, port);
        
        if (!orcashi_join_room(g_orcashi, ip, port)) {
            fprintf(stderr, "Failed to join!\n");
            orcashi_destroy(g_orcashi);
            return 1;
        }
        
        printf("Connected to: %s\n", orcashi_get_peer_ip(g_orcashi));
        chat_loop();
        
        printf("Disconnected.\n");
        orcashi_disconnect(g_orcashi);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "register") == 0) {
        if (orcashi_register_identity(g_orcashi)) {
            printf("Registered!\n");
            printf("ID: %s\n", orcashi_get_my_id(g_orcashi));
            
            if (is_daemon) {
                printf("Starting daemon mode...\n");
                daemonize();
            } else {
                printf("Standing by - listening for connection requests...\n");
                printf("Press Ctrl+C to stop\n");
                while (running) {
                    sleep(1);
                }
            }
        } else {
            fprintf(stderr, "Registration failed!\n");
        }
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "connect") == 0 && argc >= 3) {
        char* id = argv[2];
        printf("Connecting to %s...\n", id);
        
        if (!orcashi_connect_peer(g_orcashi, id)) {
            fprintf(stderr, "Failed to connect!\n");
            orcashi_destroy(g_orcashi);
            return 1;
        }
        
        printf("Connected to: %s\n", orcashi_get_peer_ip(g_orcashi));
        chat_loop();
        
        printf("Disconnected.\n");
        orcashi_disconnect(g_orcashi);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "peers") == 0) {
        orcashi_show_peers(g_orcashi);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "help") == 0) {
        show_help();
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else {
        printf("Unknown command: %s\n", cmd);
        printf("Use ./orcashi help for usage.\n");
        orcashi_destroy(g_orcashi);
        return 1;
    }
}
