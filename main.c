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
#include <sys/utsname.h>

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
    printf("  ./orcashi register          - Register identity (secure 3-digit mode)\n");
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

/* ============================================================================
 * iSH DETECTION - UX HINT ONLY, NOT SECURITY
 * ============================================================================ */

static int is_ish_environment(void) {
    struct utsname buf;
    if (uname(&buf) == 0) {
        if (strstr(buf.sysname, "iSH") != NULL ||
            strstr(buf.version, "iSH") != NULL ||
            strstr(buf.machine, "iSH") != NULL) {
            return 1;
        }
    }
    
    FILE* f = fopen("/proc/version", "r");
    if (f) {
        char line[256];
        if (fgets(line, sizeof(line), f)) {
            if (strstr(line, "iSH") != NULL) {
                fclose(f);
                return 1;
            }
        }
        fclose(f);
    }
    
    return 0;
}

/* ============================================================================
 * PASSWORD INPUT HELPERS
 * ============================================================================ */

static int read_password(const char* prompt, char* passcode, size_t size) {
    struct termios oldt, newt;
    
    printf("%s", prompt);
    fflush(stdout);
    
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    if (!fgets(passcode, size, stdin)) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        return -1;
    }
    passcode[strcspn(passcode, "\n")] = '\0';
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
    return 0;
}

static int read_input(const char* prompt, char* output, size_t size) {
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(output, size, stdin)) return -1;
    output[strcspn(output, "\n")] = '\0';
    return 0;
}

/* ============================================================================
 * REGISTER COMMAND - SECURE 3-DIGIT IDENTITY
 * ============================================================================ */

static int register_secure_3digit(ORCASHI* orcashi) {
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|              ORCASHI REGISTRATION                          |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
    
    if (orca_identity_exists(NULL)) {
        printf("[ORCA] Identity already exists!\n");
        printf("[ORCA] Use './orcashi identity' to view\n");
        printf("[ORCA] Use './orcashi reset --force' to reset\n");
        return 1;
    }
    
    /* iSH detection - UX hint only */
    if (is_ish_environment()) {
        printf("[ORCA] iSH environment detected.\n");
        printf("[ORCA] 3-digit identity mode.\n\n");
    }
    
    /* Generate 3-digit ID */
    char id[64];
    orca_identity_generate_normal_id(id);
    printf("Your ID: %s\n\n", id);
    
    /* Get IP address */
    char ip[INET_ADDRSTRLEN];
    char* local_ip = orcashi_get_local_ip();
    
    if (local_ip && strcmp(local_ip, "127.0.0.1") != 0) {
        printf("Detected IP: %s\n", local_ip);
        printf("Enter your IP (press Enter to use detected): ");
        fflush(stdout);
        if (fgets(ip, sizeof(ip), stdin)) {
            ip[strcspn(ip, "\n")] = '\0';
            if (strlen(ip) == 0) {
                strcpy(ip, local_ip);
            }
        } else {
            strcpy(ip, local_ip);
        }
    } else {
        if (read_input("Enter your IP address: ", ip, sizeof(ip)) < 0) {
            printf("[ERROR] No input!\n");
            free(local_ip);
            return 1;
        }
    }
    free(local_ip);
    
    /* Validate IP */
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        printf("[ERROR] Invalid IP address: %s\n", ip);
        return 1;
    }
    
    /* Get passcode */
    char passcode[128];
    if (read_password("Enter passcode (min 8 chars): ", passcode, sizeof(passcode)) < 0) {
        printf("[ERROR] No input!\n");
        return 1;
    }
    if (strlen(passcode) < 8) {
        printf("[ERROR] Passcode must be at least 8 characters!\n");
        return 1;
    }
    
    /* Confirm passcode */
    char confirm[128];
    if (read_password("Confirm passcode: ", confirm, sizeof(confirm)) < 0) {
        printf("[ERROR] No input!\n");
        zeroize(passcode, strlen(passcode));
        return 1;
    }
    if (strcmp(passcode, confirm) != 0) {
        printf("[ERROR] Passcodes do not match!\n");
        zeroize(passcode, strlen(passcode));
        zeroize(confirm, strlen(confirm));
        return 1;
    }
    zeroize(confirm, sizeof(confirm));
    
    printf("\n[ORCA] Creating identity...\n");
    printf("[ORCA] Generating RSA 2048-bit keypair...\n");
    
    /* Create secure 3-digit identity */
    OrcaIdentity identity;
    if (orca_identity_create_secure_3digit(id, passcode, "orcashi", "user", &identity) < 0) {
        printf("[ERROR] Failed to create identity: %s\n", orca_get_last_error());
        zeroize(passcode, strlen(passcode));
        return 1;
    }
    zeroize(passcode, sizeof(passcode));
    
    printf("[ORCA] Encrypting private key...\n");
    
    /* Save identity */
    if (orca_identity_save(&identity) < 0) {
        printf("[ERROR] Failed to save identity: %s\n", orca_get_last_error());
        return 1;
    }
    
    /* Register in registry */
    registry_register_peer(orcashi->registry, identity.id, ip, "9000");
    orcashi->registered = true;
    strcpy(orcashi->my_id, identity.id);
    strcpy(orcashi->local_ip, ip);
    orcashi_save_ip(ip);
    
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|                    REGISTRATION COMPLETE                   |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|  ID           : %s\n", identity.id);
    printf("|  IP           : %s\n", ip);
    printf("|  Mode         : SECURE (RSA 2048-bit)\n");
    printf("|  Location     : %s\n", ORCA_IDENTITY_HOME);
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
    printf("[ORCA] Use './orcashi listen' to start listening\n");
    printf("[ORCA] Use './orcashi add <id>' to add friends\n");
    printf("[ORCA] Use './orcashi peers' to see your peers\n");
    
    return 0;
}

/* ============================================================================
 * LISTEN COMMAND - UNLOCK IDENTITY WITH PASSCODE
 * ============================================================================ */

static int listen_command(ORCASHI* orcashi) {
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|              ORCASHI LISTEN                                |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
    
    /* Check if identity exists */
    if (!orca_identity_exists(NULL)) {
        printf("[ERROR] No identity found!\n");
        printf("[ORCA] Use './orcashi register' first\n");
        return 1;
    }
    
    /* Load identity metadata first (to show ID) */
    OrcaIdentity identity;
    memset(&identity, 0, sizeof(identity));
    
    char* json = read_file_content(ORCA_IDENTITY_FILE);
    if (!json) {
        printf("[ERROR] Failed to read identity file!\n");
        return 1;
    }
    if (orca_identity_from_json(json, &identity) < 0) {
        free(json);
        printf("[ERROR] Failed to parse identity!\n");
        return 1;
    }
    free(json);
    
    printf("[ORCA] Identity found: %s\n", identity.id);
    
    /* Get passcode */
    char passcode[128];
    if (read_password("Enter passcode: ", passcode, sizeof(passcode)) < 0) {
        printf("[ERROR] No input!\n");
        return 1;
    }
    
    printf("[ORCA] Unlocking identity...\n");
    
    /* Load full identity with passcode */
    if (orca_identity_load(&identity, passcode) < 0) {
        printf("[ERROR] Wrong passcode or corrupted identity!\n");
        zeroize(passcode, sizeof(passcode));
        return 1;
    }
    zeroize(passcode, sizeof(passcode));
    
    /* Verify identity */
    if (!orca_identity_verify(&identity)) {
        printf("[ERROR] Identity verification failed!\n");
        return 1;
    }
    
    printf("[ORCA] Identity verified.\n");
    printf("[ORCA] ID: %s\n", identity.id);
    printf("[ORCA] Mode: SECURE\n");
    printf("[ORCA] Public Key: %.30s...\n", identity.public_key);
    printf("\n");
    
    /* Copy identity to orcashi */
    orcashi->identity = identity;
    orcashi->has_identity = true;
    strcpy(orcashi->my_id, identity.id);
    
    /* Start discovery */
    printf("[ORCA] Starting discovery...\n");
    if (!discovery_init(orcashi->discovery, DISCOVERY_PORT)) {
        printf("[ERROR] Failed to init discovery!\n");
        return 1;
    }
    discovery_set_my_secure_identity(orcashi->discovery, &identity);
    discovery_start(orcashi->discovery);
    printf("[ORCA] Discovery started on port %d\n", DISCOVERY_PORT);
    
    /* Start DHT */
    printf("[ORCA] Starting DHT...\n");
    if (dht_node_start(orcashi->dht, DHT_NODE_PORT) < 0) {
        printf("[WARNING] Failed to start DHT!\n");
    } else {
        printf("[ORCA] DHT started on port %d\n", DHT_NODE_PORT);
    }
    
    /* Announce presence */
    char endpoint[128];
    snprintf(endpoint, sizeof(endpoint), "%s:9000", orcashi->local_ip);
    discovery_broadcast_presence(orcashi->discovery, identity.id, endpoint);
    dht_node_announce(orcashi->dht, identity.id, ORCASHI_PORT);
    
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|                    ORCASHI LISTENING                       |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|  ID           : %s\n", identity.id);
    printf("|  IP           : %s\n", orcashi->local_ip);
    printf("|  Discovery    : port %d\n", DISCOVERY_PORT);
    printf("|  DHT          : port %d\n", DHT_NODE_PORT);
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
    printf("[ORCA] Press Ctrl+C to stop\n");
    printf("[ORCA] Waiting for friend requests...\n\n");
    
    /* Main listen loop */
    while (running) {
        /* Check for pending friend requests */
        if (discovery_pending_count(orcashi->discovery) > 0) {
            PendingRequest req;
            if (discovery_pop_pending(orcashi->discovery, &req)) {
                printf("\n");
                printf("+-----------------------------------------------------------+\n");
                printf("|                NEW FRIEND REQUEST                          |\n");
                printf("+-----------------------------------------------------------+\n");
                printf("|  From : %s\n", req.from_id);
                printf("|  IP   : %s\n", req.from_ip);
                printf("|  Port : %d\n", req.from_port);
                if (req.is_secure) {
                    printf("|  Mode : SECURE\n");
                }
                printf("+-----------------------------------------------------------+\n");
                printf("\n");
                printf("[ORCA] Use './orcashi accept %s' to accept\n", req.from_id);
                printf("[ORCA] Use './orcashi reject %s' to reject\n", req.from_id);
                printf("\n");
            }
        }
        
        /* Check for incoming connections (if in chat mode) */
        if (orcashi_is_connected(g_orcashi)) {
            char msg[4096];
            if (orcashi_receive_message(g_orcashi, msg, sizeof(msg), 1)) {
                printf("[%s] %s\n", orcashi_get_peer_id(g_orcashi), msg);
                fflush(stdout);
            }
        }
        
        sleep(1);
    }
    
    return 0;
}

/* ============================================================================
 * LEGACY NORMAL REGISTER (kept for compatibility)
 * ============================================================================ */

static int register_normal(ORCASHI* orcashi) {
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|              NORMAL REGISTRATION (LEGACY)                  |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
    printf("[WARNING] Normal mode is deprecated. Use secure mode instead.\n");
    printf("\n");
    
    if (orca_identity_exists(NULL)) {
        printf("[ORCA] Identity already exists!\n");
        return 1;
    }
    
    char id[64];
    orca_identity_generate_normal_id(id);
    printf("Your ID: %s\n", id);
    
    char ip[INET_ADDRSTRLEN];
    if (read_input("Enter your IP address: ", ip, sizeof(ip)) < 0) {
        printf("[ERROR] No input!\n");
        return 1;
    }
    
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        printf("[ERROR] Invalid IP address: %s\n", ip);
        return 1;
    }
    
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
        printf("[ERROR] Failed to save identity!\n");
        return 1;
    }
    
    registry_register_peer(orcashi->registry, id, ip, "9000");
    
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|              REGISTRATION COMPLETE                         |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|  ID           : %s\n", id);
    printf("|  IP           : %s\n", ip);
    printf("|  Mode         : NORMAL (NO CRYPTO)\n");
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
    printf("[WARNING] Normal mode has NO cryptographic verification!\n");
    printf("[ORCA] Use secure mode for real security.\n");
    
    return 0;
}

/* ============================================================================
 * LEGACY SECURE REGISTER (kept for compatibility)
 * ============================================================================ */

static int register_secure(ORCASHI* orcashi) {
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|              SECURE REGISTRATION (LEGACY)                  |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
    printf("[WARNING] This creates ORCA-xxxx ID. Use secure 3-digit instead.\n");
    printf("\n");
    
    if (orca_identity_exists(NULL)) {
        printf("[ORCA] Identity already exists!\n");
        return 1;
    }
    
    char name[128];
    if (read_input("Enter your name: ", name, sizeof(name)) < 0) {
        printf("[ERROR] No input!\n");
        return 1;
    }
    
    char passcode[128];
    if (read_password("Enter passcode (min 8 chars): ", passcode, sizeof(passcode)) < 0) {
        printf("[ERROR] No input!\n");
        return 1;
    }
    if (strlen(passcode) < 8) {
        printf("[ERROR] Passcode must be at least 8 characters!\n");
        return 1;
    }
    
    char confirm[128];
    if (read_password("Confirm passcode: ", confirm, sizeof(confirm)) < 0) {
        printf("[ERROR] No input!\n");
        zeroize(passcode, strlen(passcode));
        return 1;
    }
    if (strcmp(passcode, confirm) != 0) {
        printf("[ERROR] Passcodes do not match!\n");
        zeroize(passcode, strlen(passcode));
        zeroize(confirm, strlen(confirm));
        return 1;
    }
    zeroize(confirm, sizeof(confirm));
    
    OrcaIdentity identity;
    if (orca_identity_create(name, passcode, "orcashi", &identity) < 0) {
        printf("[ERROR] Failed to create identity: %s\n", orca_get_last_error());
        zeroize(passcode, strlen(passcode));
        return 1;
    }
    zeroize(passcode, sizeof(passcode));
    
    if (orca_identity_save(&identity) < 0) {
        printf("[ERROR] Failed to save identity: %s\n", orca_get_last_error());
        return 1;
    }
    
    char* local_ip = orcashi_get_local_ip();
    strcpy(orcashi->local_ip, local_ip);
    free(local_ip);
    
    registry_register_peer(orcashi->registry, identity.id, orcashi->local_ip, "9000");
    
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|              REGISTRATION COMPLETE                         |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|  ID           : %s\n", identity.id);
    printf("|  Name         : %s\n", identity.name);
    printf("|  IP           : %s\n", orcashi->local_ip);
    printf("|  Mode         : SECURE (ORCA-xxxx)\n");
    printf("+-----------------------------------------------------------+\n");
    
    return 0;
}

/* ============================================================================
 * DAEMON FUNCTIONS
 * ============================================================================ */

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

/* ============================================================================
 * CHAT LOOP
 * ============================================================================ */

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

/* ============================================================================
 * PEERS INTERACTIVE
 * ============================================================================ */

void show_peers_interactive(ORCASHI* orcashi) {
    printf("\n");
    printf("ORCASHI PEERS\n");
    printf("------------------------------------------------------------\n");
    
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
    printf("------------------------------------------------------------\n");
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

/* ============================================================================
 * MAIN
 * ============================================================================ */

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
    
    /* REGISTER COMMAND - NEW SECURE 3-DIGIT MODE */
    if (strcmp(cmd, "register") == 0) {
        int reg_result = register_secure_3digit(g_orcashi);
        
        if (is_daemon && reg_result == 0) {
            printf("Starting daemon mode...\n");
            daemonize();
        }
        orcashi_destroy(g_orcashi);
        return reg_result;
    }
    
    /* LISTEN COMMAND */
    else if (strcmp(cmd, "listen") == 0) {
        int result = listen_command(g_orcashi);
        orcashi_destroy(g_orcashi);
        return result;
    }
    
    /* IDENTITY COMMAND */
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
    
    /* RESET COMMAND */
    else if (strcmp(cmd, "reset") == 0) {
        bool force = (argc >= 3 && strcmp(argv[2], "--force") == 0);
        if (orca_identity_reset(force) != 0) {
            orcashi_destroy(g_orcashi);
            return 1;
        }
        orcashi_destroy(g_orcashi);
        return 0;
    }
    
    /* MY_IP COMMAND */
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
    
    /* CREATE COMMAND */
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
    
    /* JOIN COMMAND */
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
    
    /* ADD COMMAND */
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
    
    /* ACCEPT COMMAND */
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
    
    /* REJECT COMMAND */
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
    
    /* PEERS COMMAND */
    else if (strcmp(cmd, "peers") == 0) {
        show_peers_interactive(g_orcashi);
        orcashi_destroy(g_orcashi);
        return 0;
    }
    
    /* CHAT COMMAND */
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
    
    /* REMOVE COMMAND */
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
    
    /* HELP COMMAND */
    else if (strcmp(cmd, "help") == 0) {
        show_help();
        orcashi_destroy(g_orcashi);
        return 0;
    }
    
    /* UNKNOWN COMMAND */
    else {
        printf("Unknown command: %s\n", cmd);
        printf("Use ./orcashi help for usage.\n");
        orcashi_destroy(g_orcashi);
        return 1;
    }
}
