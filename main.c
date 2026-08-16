 // main.c - Full version with ORCA Identity + Crypto integration
#include "orcashi.h"
#include "orca_identity.h"
#include "orca_crypto.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>
#include <termios.h>
#include <time.h>

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
    printf("ORCASHI v4.0 - Secure P2P Friend Network\n");
    printf("Usage:\n");
    printf("  ./orcashi register          - Register identity (with mode selection)\n");
    printf("  ./orcashi identity          - Show your identity\n");
    printf("  ./orcashi reset --force     - Reset identity (with confirmation)\n");
    printf("  ./orcashi my_ip <ip>        - Change your IP address\n");
    printf("  ./orcashi create            - Create room (server)\n");
    printf("  ./orcashi join <ip>         - Join room by IP\n");
    printf("  ./orcashi join <id>         - Join room by peer ID (uses discovery)\n");
    printf("  ./orcashi listen            - Start listening for connection requests\n");
    printf("  ./orcashi add <id>          - Send friend request\n");
    printf("  ./orcashi accept <id>       - Accept friend request\n");
    printf("  ./orcashi reject <id>       - Reject friend request\n");
    printf("  ./orcashi peers             - Show interactive peer list\n");
    printf("  ./orcashi chat <id>         - Start chat with peer\n");
    printf("  ./orcashi remove <id>       - Remove peer\n");
    printf("  ./orcashi stop              - Stop background daemon\n");
    printf("  ./orcashi status            - Check if daemon is running\n");
    printf("  ./orcashi help              - Show help\n");
    printf("\n");
    printf("Peers interactive commands:\n");
    printf("  c <num>  - Chat with peer (by number)\n");
    printf("  r <num>  - Remove peer (by number)\n");
    printf("  q        - Quit\n");
    printf("\n");
}

#define PID_FILE "/tmp/.orcashi/orcashi.pid"
#define LOG_FILE "/tmp/.orcashi/orcashi.log"

static int register_normal(ORCASHI* orcashi) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════════════╗\n");
    printf("║                    NORMAL REGISTRATION                              ║\n");
    printf("╠═══════════════════════════════════════════════════════════════════════╣\n");
    printf("║                                                                      ║\n");
    printf("║  Your ID will be a 3-digit number (e.g., <087>)                     ║\n");
    printf("║  Enter your IP address (e.g., 192.168.1.5): ");
    fflush(stdout);
    
    char ip[INET_ADDRSTRLEN];
    if (!fgets(ip, sizeof(ip), stdin)) {
        printf("No input!\n");
        return 1;
    }
    ip[strcspn(ip, "\n")] = '\0';
    
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        printf("Invalid IP!\n");
        return 1;
    }
    
    srand(time(NULL) ^ getpid());
    int num = (rand() % 999) + 1;
    char id[64];
    snprintf(id, sizeof(id), "<%03d>", num);
    
    OrcaIdentity identity;
    memset(&identity, 0, sizeof(OrcaIdentity));
    strcpy(identity.id, id);
    strcpy(identity.name, "normal");
    strcpy(identity.role, "user");
    identity.mode = ORCA_IDENTITY_MODE_NORMAL;
    identity.created_at = time(NULL);
    identity.last_used = identity.created_at;
    identity.verified = true;
    strcpy(identity.version, ORCA_IDENTITY_VERSION);
    
    strcpy(orcashi->local_ip, ip);
    
    if (orca_identity_save(&identity) < 0) {
        printf("Failed to save identity!\n");
        return 1;
    }
    
    registry_register_peer(orcashi->registry, id, ip, "9000");
    
    printf("║                                                                      ║\n");
    printf("║  ✅ Registered!                                                     ║\n");
    printf("║     ID: %s\n", id);
    printf("║     IP: %s\n", ip);
    printf("║                                                                      ║\n");
    printf("║  Use './orcashi listen' to start listening                         ║\n");
    printf("║  Use './orcashi add %s' to add friend\n", id);
    printf("╚═══════════════════════════════════════════════════════════════════════╝\n");
    
    return 0;
}

static int register_secure(ORCASHI* orcashi) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════════════╗\n");
    printf("║                    SECURE REGISTRATION                              ║\n");
    printf("╠═══════════════════════════════════════════════════════════════════════╣\n");
    printf("║                                                                      ║\n");
    
    if (orca_identity_exists(NULL)) {
        printf("║  ❌ Identity already exists!                                     ║\n");
        printf("║  Use './orcashi identity' to view                               ║\n");
        printf("║  Use './orcashi reset --force' to reset                        ║\n");
        printf("╚═══════════════════════════════════════════════════════════════════════╝\n");
        return 1;
    }
    
    printf("║  Enter your name (don't use real name): ");
    fflush(stdout);
    
    char name[128];
    if (!fgets(name, sizeof(name), stdin)) {
        printf("No input!\n");
        return 1;
    }
    name[strcspn(name, "\n")] = '\0';
    
    printf("║  Enter passcode (min 8 chars): ");
    fflush(stdout);
    
    struct termios oldt, newt;
    char passcode[128];
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    if (!fgets(passcode, sizeof(passcode), stdin)) {
        printf("No input!\n");
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        return 1;
    }
    passcode[strcspn(passcode, "\n")] = '\0';
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
    
    if (strlen(passcode) < 8) {
        printf("║  ❌ Passcode must be at least 8 characters!\n");
        printf("╚═══════════════════════════════════════════════════════════════════════╝\n");
        return 1;
    }
    
    printf("║  Confirm passcode: ");
    fflush(stdout);
    
    char confirm[128];
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    if (!fgets(confirm, sizeof(confirm), stdin)) {
        printf("No input!\n");
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        return 1;
    }
    confirm[strcspn(confirm, "\n")] = '\0';
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
    
    if (strcmp(passcode, confirm) != 0) {
        printf("║  ❌ Passcodes don't match!\n");
        printf("╚═══════════════════════════════════════════════════════════════════════╝\n");
        return 1;
    }
    
    printf("║                                                                      ║\n");
    printf("║  [orca-chan] Generating RSA 2048-bit keypair...                    ║\n");
    
    OrcaIdentity identity;
    if (orca_identity_create(name, passcode, "orcashi", &identity) < 0) {
        printf("║  ❌ Failed to create identity: %s\n", orca_get_last_error());
        printf("╚═══════════════════════════════════════════════════════════════════════╝\n");
        return 1;
    }
    
    if (orca_identity_save(&identity) < 0) {
        printf("║  ❌ Failed to save identity: %s\n", orca_get_last_error());
        printf("╚═══════════════════════════════════════════════════════════════════════╝\n");
        return 1;
    }
    
    strcpy(orcashi->my_id, identity.id);
    char* local_ip = orcashi_get_local_ip();
    strcpy(orcashi->local_ip, local_ip);
    free(local_ip);
    
    registry_register_peer(orcashi->registry, identity.id, orcashi->local_ip, "9000");
    
    printf("║                                                                      ║\n");
    printf("║  ✅ Registered!                                                     ║\n");
    printf("║     ID: %s\n", identity.id);
    printf("║     Name: %s\n", identity.name);
    printf("║     IP: %s\n", orcashi->local_ip);
    printf("║     Location: ~/.orcashi/identity/\n");
    printf("║                                                                      ║\n");
    printf("║  Use './orcashi listen' to start listening                         ║\n");
    printf("║  Use './orcashi add %s' to add friend\n", identity.id);
    printf("╚═══════════════════════════════════════════════════════════════════════╝\n");
    
    return 0;
}

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
    if (log_fd >= 0) {
        dup2(log_fd, STDOUT_FILENO);
        dup2(log_fd, STDERR_FILENO);
        close(log_fd);
    }
    
    chdir("/tmp");
    
    while (running) {
        if (g_orcashi) {
            int pending = discovery_pending_count(g_orcashi->discovery);
            
            if (pending > 0) {
                PendingRequest req;
                if (discovery_pop_pending(g_orcashi->discovery, &req)) {
                    fprintf(stderr, "[ORCA] Friend request from %s (%s:%d)\n", 
                            req.from_id, req.from_ip, req.from_port);
                    fprintf(stderr, "[ORCA] Use './orcashi accept %s' to accept\n", req.from_id);
                    fflush(stderr);
                }
            }
            
            if (orcashi_is_connected(g_orcashi)) {
                char msg[4096];
                if (orcashi_receive_message(g_orcashi, msg, sizeof(msg), 1)) {
                    fprintf(stderr, "[%s] %s\n", orcashi_get_peer_id(g_orcashi), msg);
                    fflush(stderr);
                }
            }
        }
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

static int get_answer(const char* prompt, char* answer, size_t size) {
    printf("%s", prompt);
    fflush(stdout);
    
    if (fgets(answer, size, stdin)) {
        answer[strcspn(answer, "\n")] = '\0';
        return 1;
    }
    return 0;
}

void show_peers_interactive(ORCASHI* orcashi) {
    printf("\n");
    printf("ORCASHI PEERS\n");
    printf("────────────────────────────────────────────\n");
    
    registry_load(orcashi->registry);
    
    RegistryPeer pending[MAX_REGISTRY_PEERS];
    int pending_count = registry_get_pending_peers(orcashi->registry, pending, MAX_REGISTRY_PEERS);
    if (pending_count > 0) {
        printf("PENDING REQUESTS:\n");
        for (int i = 0; i < pending_count; i++) {
            printf("  [%s] from %s\n", pending[i].id, pending[i].id);
        }
        printf("\n");
    }
    
    RegistryPeer peers[MAX_REGISTRY_PEERS];
    int peer_count = registry_get_accepted_peers(orcashi->registry, peers, MAX_REGISTRY_PEERS);
    
    if (peer_count == 0 && pending_count == 0) {
        printf("  No peers yet. Use './orcashi add <id>' to add friends.\n");
    } else {
        if (peer_count > 0) {
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
    
    if (strcmp(cmd, "register") == 0) {
        printf("\n");
        printf("╔═══════════════════════════════════════════════════════════════════════╗\n");
        printf("║                    ORCASHI REGISTRATION                              ║\n");
        printf("╠═══════════════════════════════════════════════════════════════════════╣\n");
        printf("║                                                                      ║\n");
        printf("║  Choose registration mode:                                          ║\n");
        printf("║    1. Normal (3-digit ID) - Quick and simple                        ║\n");
        printf("║    2. Secure (RSA + Passcode) - Full encryption                     ║\n");
        printf("║                                                                      ║\n");
        printf("║  Enter choice (1 or 2): ");
        fflush(stdout);
        
        char choice[16];
        if (!fgets(choice, sizeof(choice), stdin)) {
            printf("No input!\n");
            return 1;
        }
        choice[strcspn(choice, "\n")] = '\0';
        
        int reg_result;
        if (strcmp(choice, "1") == 0) {
            reg_result = register_normal(g_orcashi);
        } else if (strcmp(choice, "2") == 0) {
            reg_result = register_secure(g_orcashi);
        } else {
            printf("Invalid choice!\n");
            return 1;
        }
        
        if (is_daemon && reg_result == 0) {
            printf("Starting daemon mode...\n");
            daemonize();
        }
        orcashi_destroy(g_orcashi);
        return reg_result;
    }
    
    else if (strcmp(cmd, "identity") == 0) {
        OrcaIdentity identity;
        if (orca_identity_load(&identity, NULL) < 0) {
            printf("No identity found! Use './orcashi register' first.\n");
            orcashi_destroy(g_orcashi);
            return 1;
        }
        orca_identity_print(&identity);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    
    // ===== FIXED: reset command with proper comparison =====
    else if (strcmp(cmd, "reset") == 0) {
        bool force = (argc >= 3 && strcmp(argv[2], "--force") == 0);
        if (orca_identity_reset(force) != 0) {
            orcashi_destroy(g_orcashi);
            return 1;
        }
        orcashi_destroy(g_orcashi);
        return 0;
    }
    
    else if (strcmp(cmd, "my_ip") == 0 && argc >= 3) {
        char* new_ip = argv[2];
        struct sockaddr_in sa;
        if (inet_pton(AF_INET, new_ip, &sa.sin_addr) != 1) {
            printf("Invalid IP: %s\n", new_ip);
            orcashi_destroy(g_orcashi);
            return 1;
        }
        strcpy(g_orcashi->local_ip, new_ip);
        printf("IP updated to %s\n", new_ip);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    
    else if (strcmp(cmd, "create") == 0) {
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
        char* target = argv[2];
        
        struct sockaddr_in sa;
        int is_ip = inet_pton(AF_INET, target, &sa.sin_addr);
        
        if (is_ip == 1) {
            int port = (argc >= 4) ? atoi(argv[3]) : 9000;
            printf("Joining %s:%d...\n", target, port);
            
            if (!orcashi_join_room(g_orcashi, target, port)) {
                fprintf(stderr, "Failed to join!\n");
                orcashi_destroy(g_orcashi);
                return 1;
            }
            
            printf("Connected to: %s\n", orcashi_get_peer_ip(g_orcashi));
            chat_loop();
        } else {
            printf("Looking for peer %s...\n", target);
            if (!orcashi_connect_peer(g_orcashi, target)) {
                fprintf(stderr, "Failed to find/connect to peer %s!\n", target);
                orcashi_destroy(g_orcashi);
                return 1;
            }
            chat_loop();
        }
        
        printf("Disconnected.\n");
        orcashi_disconnect(g_orcashi);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    
    else if (strcmp(cmd, "listen") == 0) {
        printf("Listening for connection requests...\n");
        printf("Press Ctrl+C to stop\n");
        printf("\n");
        
        while (running) {
            int pending = discovery_pending_count(g_orcashi->discovery);
            
            if (pending > 0) {
                PendingRequest req;
                if (discovery_pop_pending(g_orcashi->discovery, &req)) {
                    printf("\n");
                    printf("================================================\n");
                    printf("[ORCA] NEW FRIEND REQUEST\n");
                    printf("================================================\n");
                    printf("  From: %s\n", req.from_id);
                    printf("  IP:   %s\n", req.from_ip);
                    printf("  Port: %d\n", req.from_port);
                    printf("================================================\n");
                    
                    char answer[16];
                    if (get_answer("  Accept? (y/n): ", answer, sizeof(answer))) {
                        if (strcmp(answer, "y") == 0 || strcmp(answer, "Y") == 0 || 
                            strcmp(answer, "yes") == 0 || strcmp(answer, "YES") == 0) {
                            registry_update_status(g_orcashi->registry, req.from_id, "accepted");
                            printf("  Accepted friend request from %s\n", req.from_id);
                        } else if (strlen(answer) > 0) {
                            registry_update_status(g_orcashi->registry, req.from_id, "rejected");
                            printf("  Rejected friend request from %s\n", req.from_id);
                        } else {
                            printf("  No input - keeping pending\n");
                        }
                    } else {
                        printf("  No input - keeping pending\n");
                    }
                    printf("================================================\n\n");
                }
            }
            
            if (orcashi_is_connected(g_orcashi)) {
                char msg[4096];
                if (orcashi_receive_message(g_orcashi, msg, sizeof(msg), 1)) {
                    printf("[%s] %s\n", orcashi_get_peer_id(g_orcashi), msg);
                    fflush(stdout);
                }
            }
            
            sleep(1);
        }
        orcashi_destroy(g_orcashi);
        return 0;
    }
    
    else if (strcmp(cmd, "add") == 0 && argc >= 3) {
        char* id = argv[2];
        
        char* local_ip = orcashi_get_local_ip();
        if (local_ip && strlen(local_ip) > 0) {
            strcpy(g_orcashi->local_ip, local_ip);
            discovery_set_my_identity(g_orcashi->discovery, g_orcashi->my_id, local_ip, ORCASHI_PORT);
        }
        free(local_ip);
        
        printf("Sending friend request to %s...\n", id);
        
        discovery_query_peer(g_orcashi->discovery, id);
        
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
            
            discovery_send_add_request_with_ack(g_orcashi->discovery, id, 
                                               g_orcashi->my_id, 
                                               g_orcashi->local_ip, 
                                               ORCASHI_PORT);
            
            printf("Friend request sent to %s\n", id);
            printf("Use './orcashi peers' to check status\n");
        } else {
            printf("Peer %s not found after 30 seconds.\n", id);
        }
        orcashi_destroy(g_orcashi);
        return 0;
    }
    
    else if (strcmp(cmd, "accept") == 0 && argc >= 3) {
        char* id = argv[2];
        
        char norm_from[64], norm_my[64];
        strip_brackets(id, norm_from, sizeof(norm_from));
        strip_brackets(g_orcashi->my_id, norm_my, sizeof(norm_my));
        
        registry_update_status(g_orcashi->registry, norm_from, "accepted");
        printf("Accepted friend request from %s\n", id);
        
        orcashi_destroy(g_orcashi);
        return 0;
    }
    
    else if (strcmp(cmd, "reject") == 0 && argc >= 3) {
        char* id = argv[2];
        
        char norm_from[64], norm_my[64];
        strip_brackets(id, norm_from, sizeof(norm_from));
        strip_brackets(g_orcashi->my_id, norm_my, sizeof(norm_my));
        
        registry_update_status(g_orcashi->registry, norm_from, "rejected");
        printf("Rejected friend request from %s\n", id);
        
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
