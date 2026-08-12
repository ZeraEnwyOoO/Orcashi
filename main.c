 #include "orcashi.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>

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
    printf("ORCASHI v3.1 - P2P Friend Network\n");
    printf("Usage:\n");
    printf("  ./orcashi create          - Create room (server)\n");
    printf("  ./orcashi join <ip>       - Join room by IP\n");
    printf("  ./orcashi register        - Register identity (foreground)\n");
    printf("  ./orcashi register -d     - Register as daemon (background)\n");
    printf("  ./orcashi add <id>        - Send friend request\n");
    printf("  ./orcashi accept <id>     - Accept friend request\n");
    printf("  ./orcashi reject <id>     - Reject friend request\n");
    printf("  ./orcashi peers           - Show interactive peer list\n");
    printf("  ./orcashi chat <id>       - Start chat with peer\n");
    printf("  ./orcashi remove <id>     - Remove peer\n");
    printf("  ./orcashi stop            - Stop background daemon\n");
    printf("  ./orcashi status          - Check if daemon is running\n");
    printf("  ./orcashi help            - Show help\n");
    printf("\n");
    printf("Peers interactive commands:\n");
    printf("  c <num>  - Chat with peer (by number)\n");
    printf("  r <num>  - Remove peer (by number)\n");
    printf("  q        - Quit\n");
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

// ===== FIXED: Non-blocking chat loop (REAL-TIME!) =====
void chat_loop(void) {
    printf("Type /exit to quit\n");
    printf("---\n");
    
    char input[4096];
    char msg[4096];
    fd_set fds;
    struct timeval tv;
    
    while (running && orcashi_is_connected(g_orcashi)) {
        while (orcashi_receive_message(g_orcashi, msg, sizeof(msg), 1)) {
            printf("[%s] %s\n", orcashi_get_peer_id(g_orcashi), msg);
            fflush(stdout);
        }
        
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        
        int ret = select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
        if (ret > 0) {
            if (!fgets(input, sizeof(input), stdin)) break;
            input[strcspn(input, "\n")] = '\0';
            
            if (strcmp(input, "/exit") == 0) break;
            
            if (strlen(input) > 0) {
                orcashi_send_message(g_orcashi, input);
            }
        }
    }
}

// ===== Show interactive peers =====
void show_peers_interactive(ORCASHI* orcashi) {
    printf("\n");
    printf("ORCASHI PEERS\n");
    printf("────────────────────────────────────────────\n");
    
    Request pending[MAX_REQUESTS];
    int count = request_get_pending(orcashi->requests, orcashi->my_id, pending, MAX_REQUESTS);
    if (count > 0) {
        printf("PENDING REQUESTS:\n");
        for (int i = 0; i < count; i++) {
            printf("  [%s] from %s\n", pending[i].from_id, pending[i].from_id);
        }
        printf("\n");
    }
    
    RegistryPeer peers[MAX_REGISTRY_PEERS];
    int peer_count = registry_get_all_peers(orcashi->registry, peers, MAX_REGISTRY_PEERS);
    
    if (peer_count == 0 && count == 0) {
        printf("  No peers yet. Use './orcashi add <id>' to add friends.\n");
    } else {
        printf("ACCEPTED PEERS:\n");
        for (int i = 0; i < peer_count; i++) {
            PeerInfo p;
            bool online = false;
            if (discovery_find_peer(orcashi->discovery, peers[i].id, &p)) {
                online = p.online;
            }
            printf("  [%d] %s  %s  %s\n", 
                   i + 1,
                   peers[i].id, 
                   peers[i].ip,
                   online ? "ONLINE" : "OFFLINE");
        }
    }
    
    printf("\n");
    printf("  c <num> = chat  |  r <num> = remove  |  q = quit\n");
    printf("────────────────────────────────────────────\n");
    printf("> ");
    fflush(stdout);
    
    char input[64];
    if (!fgets(input, sizeof(input), stdin)) return;
    input[strcspn(input, "\n")] = '\0';
    
    if (strcmp(input, "q") == 0) return;
    
    if (input[0] == 'c' && strlen(input) > 2) {
        int idx = atoi(input + 2);
        if (idx > 0 && idx <= peer_count) {
            char* id = peers[idx - 1].id;
            printf("Chatting with %s...\n", id);
            RegistryPeer reg_peer;
            if (registry_get_peer(orcashi->registry, id, &reg_peer)) {
                if (orcashi_join_room(orcashi, reg_peer.ip, atoi(reg_peer.port))) {
                    chat_loop();
                } else {
                    printf("Failed to connect to %s\n", id);
                }
            }
        } else {
            printf("Invalid peer number\n");
        }
    } else if (input[0] == 'r' && strlen(input) > 2) {
        int idx = atoi(input + 2);
        if (idx > 0 && idx <= peer_count) {
            char* id = peers[idx - 1].id;
            if (registry_remove_peer(orcashi->registry, id)) {
                peer_cache_remove_peer(orcashi->cache, id);
                printf("Removed peer %s\n", id);
            }
        } else {
            printf("Invalid peer number\n");
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
    // ===== FIXED: ADD COMMAND with 30s timeout + correct IP =====
    else if (strcmp(cmd, "add") == 0 && argc >= 3) {
        char* id = argv[2];
        
        // Fix: Set correct IP
        char* local_ip = orcashi_get_local_ip();
        if (local_ip && strlen(local_ip) > 0) {
            strcpy(g_orcashi->local_ip, local_ip);
            discovery_set_my_identity(g_orcashi->discovery, g_orcashi->my_id, local_ip, ORCASHI_PORT);
        }
        free(local_ip);
        
        printf("Sending friend request to %s...\n", id);
        
        discovery_query_peer(g_orcashi->discovery, id);
        
        // Fix: Wait up to 30 seconds (was 5s)
        int waited = 0;
        PeerInfo p;
        while (waited < 30) {
            if (discovery_find_peer(g_orcashi->discovery, id, &p)) {
                break;
            }
            sleep(1);
            waited++;
            if (waited % 5 == 0) {
                printf("  Still searching... (%d seconds)\n", waited);
            }
        }
        
        if (discovery_find_peer(g_orcashi->discovery, id, &p)) {
            registry_register_peer(g_orcashi->registry, id, p.ip, "9000");
            if (request_send(g_orcashi->requests, g_orcashi->my_id, id)) {
                printf("Friend request sent to %s\n", id);
                printf("Use './orcashi peers' to check status\n");
            }
        } else {
            printf("Peer %s not found after 30 seconds.\n", id);
        }
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "accept") == 0 && argc >= 3) {
        char* id = argv[2];
        if (request_accept(g_orcashi->requests, id, g_orcashi->my_id)) {
            printf("Accepted friend request from %s\n", id);
            RegistryPeer reg_peer;
            if (!registry_get_peer(g_orcashi->registry, id, &reg_peer)) {
                PeerInfo p;
                if (discovery_find_peer(g_orcashi->discovery, id, &p)) {
                    registry_register_peer(g_orcashi->registry, id, p.ip, "9000");
                    printf("Peer %s added to registry at %s\n", id, p.ip);
                }
            }
        } else {
            printf("No pending request from %s\n", id);
        }
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "reject") == 0 && argc >= 3) {
        char* id = argv[2];
        if (request_reject(g_orcashi->requests, id, g_orcashi->my_id)) {
            printf("Rejected friend request from %s\n", id);
        } else {
            printf("No pending request from %s\n", id);
        }
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "peers") == 0) {
        show_peers_interactive(g_orcashi);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "chat") == 0 && argc >= 3) {
        char* id = argv[2];
        RegistryPeer reg_peer;
        if (registry_get_peer(g_orcashi->registry, id, &reg_peer)) {
            printf("Connecting to %s at %s:%s...\n", id, reg_peer.ip, reg_peer.port);
            if (orcashi_join_room(g_orcashi, reg_peer.ip, atoi(reg_peer.port))) {
                chat_loop();
            } else {
                printf("Failed to connect to %s\n", id);
            }
        } else {
            printf("Peer %s not found. Use './orcashi add %s' first.\n", id, id);
        }
        orcashi_destroy(g_orcashi);
        return 0;
    }
    else if (strcmp(cmd, "remove") == 0 && argc >= 3) {
        char* id = argv[2];
        if (registry_remove_peer(g_orcashi->registry, id)) {
            peer_cache_remove_peer(g_orcashi->cache, id);
            printf("Removed peer %s\n", id);
        } else {
            printf("Peer %s not found\n", id);
        }
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
