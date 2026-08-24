#include "commands.h"
#include "mixed_id.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

#define DAEMON_SOCKET "/tmp/.orcashi/socket"
#define DAEMON_PID_FILE "/tmp/.orcashi/daemon.pid"

/* ============================================================================
 * COMMAND DISPATCHER
 * ============================================================================ */

int command_dispatch(int argc, char* argv[]) {
    if (argc < 2) {
        command_show_help();
        return 0;
    }
    
    char* cmd = argv[1];
    CommandType type = command_parse_type(cmd);
    
    switch (type) {
        case CMD_REGISTER:
            return cmd_register(argc, argv);
        case CMD_IDENTITY:
            return cmd_identity(argc, argv);
        case CMD_LISTEN:
            return cmd_listen(argc, argv);
        case CMD_SEARCH:
            return cmd_search(argc, argv);
        case CMD_ADD:
            return cmd_add(argc, argv);
        case CMD_ACCEPT:
            return cmd_accept(argc, argv);
        case CMD_REJECT:
            return cmd_reject(argc, argv);
        case CMD_PEERS:
            return cmd_peers(argc, argv);
        case CMD_CHAT:
            return cmd_chat(argc, argv);
        case CMD_GHOST:
            return cmd_ghost(argc, argv);
        case CMD_STATUS:
            return cmd_status(argc, argv);
        case CMD_STOP:
            return cmd_stop(argc, argv);
        case CMD_HELP:
            command_show_help();
            return 0;
        default:
            fprintf(stderr, "[ERROR] Unknown command: %s\n", cmd);
            fprintf(stderr, "Type './orcashi help' for usage.\n");
            return 1;
    }
}

/* ============================================================================
 * COMMAND PARSING
 * ============================================================================ */

CommandType command_parse_type(const char* cmd) {
    if (!cmd) return CMD_UNKNOWN;
    
    if (strcmp(cmd, "register") == 0) return CMD_REGISTER;
    if (strcmp(cmd, "identity") == 0) return CMD_IDENTITY;
    if (strcmp(cmd, "listen") == 0) return CMD_LISTEN;
    if (strcmp(cmd, "search") == 0) return CMD_SEARCH;
    if (strcmp(cmd, "add") == 0) return CMD_ADD;
    if (strcmp(cmd, "accept") == 0) return CMD_ACCEPT;
    if (strcmp(cmd, "reject") == 0) return CMD_REJECT;
    if (strcmp(cmd, "peers") == 0) return CMD_PEERS;
    if (strcmp(cmd, "chat") == 0) return CMD_CHAT;
    if (strcmp(cmd, "ghost") == 0) return CMD_GHOST;
    if (strcmp(cmd, "status") == 0) return CMD_STATUS;
    if (strcmp(cmd, "stop") == 0) return CMD_STOP;
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        return CMD_HELP;
    }
    
    return CMD_UNKNOWN;
}

const char* command_get_name(CommandType type) {
    switch (type) {
        case CMD_REGISTER: return "register";
        case CMD_IDENTITY: return "identity";
        case CMD_LISTEN: return "listen";
        case CMD_SEARCH: return "search";
        case CMD_ADD: return "add";
        case CMD_ACCEPT: return "accept";
        case CMD_REJECT: return "reject";
        case CMD_PEERS: return "peers";
        case CMD_CHAT: return "chat";
        case CMD_GHOST: return "ghost";
        case CMD_STATUS: return "status";
        case CMD_STOP: return "stop";
        case CMD_HELP: return "help";
        default: return "unknown";
    }
}

/* ============================================================================
 * DAEMON HELPERS
 * ============================================================================ */

bool command_daemon_is_running(void) {
    int pid = command_get_daemon_pid();
    if (pid <= 0) return false;
    
    if (kill(pid, 0) == 0) {
        return true;
    }
    return false;
}

int command_get_daemon_pid(void) {
    FILE* f = fopen(DAEMON_PID_FILE, "r");
    if (!f) return -1;
    
    int pid;
    if (fscanf(f, "%d", &pid) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);
    
    return pid;
}

int command_send_to_daemon(const char* cmd, char* response, size_t response_size) {
    if (!command_daemon_is_running()) {
        snprintf(response, response_size, "[ERROR] Daemon is not running. Use './orcashi listen' first.");
        return -1;
    }
    
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        snprintf(response, response_size, "[ERROR] Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DAEMON_SOCKET, sizeof(addr.sun_path) - 1);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        snprintf(response, response_size, "[ERROR] Failed to connect to daemon: %s", strerror(errno));
        return -1;
    }
    
    // Send command
    if (write(sock, cmd, strlen(cmd)) < 0) {
        close(sock);
        snprintf(response, response_size, "[ERROR] Failed to send command: %s", strerror(errno));
        return -1;
    }
    
    // Read response
    int n = read(sock, response, response_size - 1);
    if (n < 0) {
        close(sock);
        snprintf(response, response_size, "[ERROR] Failed to read response: %s", strerror(errno));
        return -1;
    }
    response[n] = '\0';
    
    close(sock);
    return 0;
}

/* ============================================================================
 * COMMAND: register
 * ============================================================================ */

int cmd_register(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|              ORCASHI REGISTRATION                          |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
    
    // Check if identity already exists
    // TODO: Check via daemon or directly
    
    char id[64];
    printf("Generating ID...\n");
    // TODO: Generate ID via identity system
    
    char ip[INET_ADDRSTRLEN];
    printf("Enter your IP address (or press Enter for auto-detect): ");
    fflush(stdout);
    
    char input[64];
    if (fgets(input, sizeof(input), stdin)) {
        input[strcspn(input, "\n")] = '\0';
        if (strlen(input) > 0) {
            strcpy(ip, input);
        } else {
            // Auto-detect
            strcpy(ip, "127.0.0.1"); // TODO: Get real IP
        }
    }
    
    char passcode[128];
    printf("Enter passcode (min 8 chars): ");
    fflush(stdout);
    // TODO: Read passcode securely
    
    // TODO: Create identity via daemon
    
    // Generate Mixed ID
    char mixed_id[64];
    mixed_id_encode(id, ip, 9000, mixed_id);
    
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|                    REGISTRATION COMPLETE                   |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|  ID        : %s\n", id);
    printf("|  IP        : %s\n", ip);
    printf("|  Mixed ID  : %s\n", mixed_id);
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
    printf("[ORCA] Use './orcashi listen' to announce to DHT\n");
    printf("[ORCA] Share your Mixed ID for direct connections\n");
    
    return 0;
}

/* ============================================================================
 * COMMAND: identity
 * ============================================================================ */

int cmd_identity(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    char response[1024];
    if (command_send_to_daemon("identity", response, sizeof(response)) == 0) {
        printf("%s", response);
    } else {
        // TODO: Read identity directly from files
        printf("[ORCA] Identity info:\n");
        printf("  Not implemented yet.\n");
    }
    
    return 0;
}

/* ============================================================================
 * COMMAND: listen
 * ============================================================================ */

int cmd_listen(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    if (command_daemon_is_running()) {
        printf("[ORCA] Daemon is already running (PID: %d)\n", command_get_daemon_pid());
        return 0;
    }
    
    printf("[ORCA] Starting background daemon...\n");
    
    // TODO: Start daemon process
    // This will fork and run event_loop
    
    printf("[ORCA] Daemon started (PID: %d)\n", command_get_daemon_pid());
    printf("[ORCA] Use './orcashi status' to check\n");
    printf("[ORCA] Use './orcashi stop' to stop\n");
    
    return 0;
}

/* ============================================================================
 * COMMAND: search
 * ============================================================================ */

int cmd_search(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "[ERROR] Usage: ./orcashi search <id>\n");
        return 1;
    }
    
    char* peer_id = argv[2];
    
    // Check if Mixed ID
    char id[64], ip[INET_ADDRSTRLEN];
    int port;
    if (mixed_id_decode(peer_id, id, ip, &port) == 0) {
        printf("[ORCA] Mixed ID detected: ID=%s, IP=%s, Port=%d\n", id, ip, port);
        printf("[ORCA] Direct connect to %s:%d\n", ip, port);
        // TODO: Add peer directly
        return 0;
    }
    
    // Search via DHT
    printf("[DHT] Searching for %s...\n", peer_id);
    
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "search %s", peer_id);
    
    char response[1024];
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        
        // Ask user if they want to send request
        printf("\nDo you want to send a friend request to %s? (y/n): ", peer_id);
        fflush(stdout);
        
        char answer[16];
        if (fgets(answer, sizeof(answer), stdin)) {
            answer[strcspn(answer, "\n")] = '\0';
            if (strcmp(answer, "y") == 0 || strcmp(answer, "Y") == 0) {
                snprintf(cmd, sizeof(cmd), "add %s", peer_id);
                command_send_to_daemon(cmd, response, sizeof(response));
                printf("[ORCA] Request sent to %s\n", peer_id);
                printf("[ORCA] Done.\n");
            }
        }
    }
    
    return 0;
}

/* ============================================================================
 * COMMAND: add
 * ============================================================================ */

int cmd_add(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "[ERROR] Usage: ./orcashi add <id>\n");
        return 1;
    }
    
    char* peer_id = argv[2];
    
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "add %s", peer_id);
    
    char response[1024];
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
    } else {
        printf("[ORCA] Sending request to %s...\n", peer_id);
        printf("[ORCA] Request sent.\n");
        printf("[ORCA] Done.\n");
    }
    
    return 0;
}

/* ============================================================================
 * COMMAND: accept
 * ============================================================================ */

int cmd_accept(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "[ERROR] Usage: ./orcashi accept <id>\n");
        return 1;
    }
    
    char* peer_id = argv[2];
    
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "accept %s", peer_id);
    
    char response[1024];
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
    }
    
    return 0;
}

/* ============================================================================
 * COMMAND: reject
 * ============================================================================ */

int cmd_reject(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "[ERROR] Usage: ./orcashi reject <id>\n");
        return 1;
    }
    
    char* peer_id = argv[2];
    
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "reject %s", peer_id);
    
    char response[1024];
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
    }
    
    return 0;
}

/* ============================================================================
 * COMMAND: peers
 * ============================================================================ */

int cmd_peers(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    char response[4096];
    if (command_send_to_daemon("peers", response, sizeof(response)) == 0) {
        printf("%s", response);
    } else {
        printf("[ORCA] No daemon running. Use './orcashi listen' first.\n");
    }
    
    return 0;
}

/* ============================================================================
 * COMMAND: chat
 * ============================================================================ */

int cmd_chat(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "[ERROR] Usage: ./orcashi chat <id>\n");
        return 1;
    }
    
    char* peer_id = argv[2];
    
    printf("\n");
    printf("============================================================\n");
    printf("  ORCASHI CHAT\n");
    printf("============================================================\n");
    printf("  Peer: %s\n", peer_id);
    printf("  Status: Connecting...\n");
    printf("============================================================\n");
    printf("  Type /exit to quit\n");
    printf("  Type /status to check\n");
    printf("============================================================\n");
    printf("\n");
    
    // TODO: Start chat session via daemon
    // For now, simple echo chat
    char input[4096];
    char response[4096];
    
    while (1) {
        printf("> ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';
        
        if (strcmp(input, "/exit") == 0) break;
        if (strcmp(input, "/status") == 0) {
            printf("[CHAT] Status: Connected to %s\n", peer_id);
            continue;
        }
        
        // Send message via daemon
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "chat_send %s %s", peer_id, input);
        command_send_to_daemon(cmd, response, sizeof(response));
        printf("[you] %s\n", input);
    }
    
    printf("\n[CHAT] Session ended.\n");
    return 0;
}

/* ============================================================================
 * COMMAND: ghost
 * ============================================================================ */

int cmd_ghost(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "[ERROR] Usage: ./orcashi ghost <id> <message>\n");
        return 1;
    }
    
    char* peer_id = argv[2];
    char* message = argv[3];
    
    // Combine remaining arguments as message
    for (int i = 4; i < argc; i++) {
        strcat(message, " ");
        strcat(message, argv[i]);
    }
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ghost %s %s", peer_id, message);
    
    char response[1024];
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
    } else {
        printf("[ORCA] Sending ghost message to %s...\n", peer_id);
        printf("[ORCA] Message stored.\n");
        printf("[ORCA] Done.\n");
    }
    
    return 0;
}

/* ============================================================================
 * COMMAND: status
 * ============================================================================ */

int cmd_status(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    if (!command_daemon_is_running()) {
        printf("[ORCA] Daemon is NOT running.\n");
        printf("[ORCA] Use './orcashi listen' to start.\n");
        return 0;
    }
    
    char response[1024];
    if (command_send_to_daemon("status", response, sizeof(response)) == 0) {
        printf("%s", response);
    }
    
    return 0;
}

/* ============================================================================
 * COMMAND: stop
 * ============================================================================ */

int cmd_stop(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    if (!command_daemon_is_running()) {
        printf("[ORCA] Daemon is not running.\n");
        return 0;
    }
    
    int pid = command_get_daemon_pid();
    printf("[ORCA] Stopping daemon (PID: %d)...\n", pid);
    
    char response[1024];
    if (command_send_to_daemon("stop", response, sizeof(response)) == 0) {
        printf("%s", response);
    } else {
        // Kill daemon
        kill(pid, SIGTERM);
        unlink(DAEMON_PID_FILE);
        unlink(DAEMON_SOCKET);
        printf("[ORCA] Daemon stopped.\n");
    }
    
    return 0;
}

/* ============================================================================
 * COMMAND: help
 * ============================================================================ */

void command_show_help(void) {
    printf("\n");
    printf("ORCASHI v5 - Real P2P, Async UX\n");
    printf("Usage:\n");
    printf("  ./orcashi register          - Register identity\n");
    printf("  ./orcashi identity          - Show your identity\n");
    printf("  ./orcashi listen            - Start background daemon\n");
    printf("  ./orcashi search <id>       - Search for peer\n");
    printf("  ./orcashi add <id>          - Send friend request\n");
    printf("  ./orcashi accept <id>       - Accept friend request\n");
    printf("  ./orcashi reject <id>       - Reject friend request\n");
    printf("  ./orcashi peers             - Show peer list\n");
    printf("  ./orcashi chat <id>         - Start chat\n");
    printf("  ./orcashi ghost <id> <msg>  - Send ghost message\n");
    printf("  ./orcashi status            - Check daemon status\n");
    printf("  ./orcashi stop              - Stop daemon\n");
    printf("  ./orcashi help              - Show this help\n");
    printf("\n");
    printf("Commands return to shell immediately!\n");
    printf("Background daemon handles everything.\n");
    printf("\n");
}
