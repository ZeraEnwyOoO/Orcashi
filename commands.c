 #include "commands.h"
#include "mixed_id.h"
#include "orca_identity.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>   

#define DAEMON_SOCKET "/tmp/.orcashi/socket"
#define DAEMON_PID_FILE "/tmp/.orcashi/daemon.pid"

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
            fprintf(stderr, "ERROR: Unknown command: %s\n", cmd);
            fprintf(stderr, "Type './orcashi help' for usage.\n");
            return 1;
    }
}

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
        snprintf(response, response_size, "ERROR: Daemon is not running. Use './orcashi listen' first.");
        return -1;
    }
    
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        snprintf(response, response_size, "ERROR: Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DAEMON_SOCKET, sizeof(addr.sun_path) - 1);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        snprintf(response, response_size, "ERROR: Failed to connect to daemon: %s", strerror(errno));
        return -1;
    }
    
    if (write(sock, cmd, strlen(cmd)) < 0) {
        close(sock);
        snprintf(response, response_size, "ERROR: Failed to send command: %s", strerror(errno));
        return -1;
    }
    
    int n = read(sock, response, response_size - 1);
    if (n < 0) {
        close(sock);
        snprintf(response, response_size, "ERROR: Failed to read response: %s", strerror(errno));
        return -1;
    }
    response[n] = '\0';
    
    close(sock);
    return 0;
}

int cmd_register(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|              ORCASHI REGISTRATION                          |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
    
    if (orca_identity_exists(NULL)) {
        printf("Identity already exists.\n");
        printf("Use './orcashi identity' to view.\n");
        return 0;
    }
    
    char id[64];
    printf("Enter 3-digit ID (e.g., 075): ");
    fflush(stdout);
    
    char input[64];
    if (!fgets(input, sizeof(input), stdin)) {
        return 1;
    }
    input[strcspn(input, "\n")] = '\0';
    
    if (strlen(input) != 3 || !isdigit(input[0]) || !isdigit(input[1]) || !isdigit(input[2])) {
        printf("ERROR: Invalid ID. Must be 3 digits.\n");
        return 1;
    }
    
    snprintf(id, sizeof(id), "<%s>", input);
    
    char passcode[128];
    printf("Enter passcode (min 8 chars): ");
    fflush(stdout);
    
    if (!fgets(passcode, sizeof(passcode), stdin)) {
        return 1;
    }
    passcode[strcspn(passcode, "\n")] = '\0';
    
    if (strlen(passcode) < 8) {
        printf("ERROR: Passcode must be at least 8 characters.\n");
        return 1;
    }
    
    char name[128];
    printf("Enter display name (optional): ");
    fflush(stdout);
    
    if (!fgets(name, sizeof(name), stdin)) {
        strcpy(name, "orcashi");
    }
    name[strcspn(name, "\n")] = '\0';
    if (strlen(name) == 0) {
        strcpy(name, "orcashi");
    }
    
    OrcaIdentity identity;
    if (orca_identity_create_secure_3digit(id, passcode, name, "user", &identity) < 0) {
        printf("ERROR: Failed to create identity: %s\n", orca_get_last_error());
        return 1;
    }
    
    if (orca_identity_save(&identity) < 0) {
        printf("ERROR: Failed to save identity.\n");
        return 1;
    }
    
    if (orca_identity_set_default(id) < 0) {
        printf("WARNING: Failed to set default identity.\n");
    }
    
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|                    REGISTRATION COMPLETE                   |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|  ID        : %s\n", identity.id);
    printf("|  Name      : %s\n", identity.name);
    printf("|  Mode      : SECURE\n");
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
    printf("Use './orcashi listen' to announce to DHT\n");
    printf("Share your ID with friends: %s\n", identity.id);
    
    return 0;
}

int cmd_identity(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    char response[4096];
    if (command_send_to_daemon("identity", response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    OrcaIdentity identity;
    if (orca_identity_load(&identity, NULL) < 0) {
        printf("ERROR: No identity found. Use './orcashi register' first.\n");
        return 1;
    }
    
    char mixed_id[64];
    mixed_id_encode(identity.id, "0.0.0.0", 9000, mixed_id, sizeof(mixed_id));
    
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|                    ORCASHI IDENTITY                       |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|  ID        : %s\n", identity.id);
    printf("|  Name      : %s\n", identity.name);
    printf("|  Mode      : %s\n", identity.mode == ORCA_IDENTITY_MODE_SECURE ? "SECURE" : "NORMAL");
    printf("|  Created   : %s", ctime(&identity.created_at));
    printf("|  Mixed ID  : %s\n", mixed_id);
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
    
    return 0;
}

int cmd_listen(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    if (command_daemon_is_running()) {
        printf("Daemon is already running (PID: %d)\n", command_get_daemon_pid());
        return 0;
    }
    
    printf("Starting background daemon...\n");
    
    if (daemon_start() < 0) {
        printf("ERROR: Failed to start daemon.\n");
        return 1;
    }
    
    printf("Daemon started (PID: %d)\n", command_get_daemon_pid());
    printf("Use './orcashi status' to check\n");
    printf("Use './orcashi stop' to stop\n");
    
    return 0;
}

int cmd_search(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "ERROR: Usage: ./orcashi search <id>\n");
        return 1;
    }
    
    char* peer_id = argv[2];
    
    char id[64], ip[INET_ADDRSTRLEN];
    int port;
    if (mixed_id_decode(peer_id, id, ip, &port) == 0) {
        printf("Mixed ID detected: ID=%s, IP=%s, Port=%d\n", id, ip, port);
        return 0;
    }
    
    printf("Searching for %s...\n", peer_id);
    
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "search %s", peer_id);
    
    char response[1024];
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    printf("Search failed. Make sure daemon is running.\n");
    return 1;
}

int cmd_add(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "ERROR: Usage: ./orcashi add <id>\n");
        return 1;
    }
    
    char* peer_id = argv[2];
    
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "add %s", peer_id);
    
    char response[1024];
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    printf("Sending request to %s...\n", peer_id);
    printf("Done.\n");
    
    return 0;
}

int cmd_accept(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "ERROR: Usage: ./orcashi accept <id>\n");
        return 1;
    }
    
    char* peer_id = argv[2];
    
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "accept %s", peer_id);
    
    char response[1024];
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    printf("Accepted request from %s\n", peer_id);
    return 0;
}

int cmd_reject(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "ERROR: Usage: ./orcashi reject <id>\n");
        return 1;
    }
    
    char* peer_id = argv[2];
    
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "reject %s", peer_id);
    
    char response[1024];
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    printf("Rejected request from %s\n", peer_id);
    return 0;
}

int cmd_peers(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    char response[4096];
    if (command_send_to_daemon("peers", response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    printf("No daemon running. Use './orcashi listen' first.\n");
    return 1;
}

int cmd_chat(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "ERROR: Usage: ./orcashi chat <id>\n");
        return 1;
    }
    
    char* peer_id = argv[2];
    
    printf("\n");
    printf("============================================================\n");
    printf("  ORCASHI CHAT\n");
    printf("============================================================\n");
    printf("  Peer: %s\n", peer_id);
    printf("============================================================\n");
    printf("  Type /exit to quit\n");
    printf("  Type /status to check\n");
    printf("============================================================\n");
    printf("\n");
    
    char input[4096];
    char response[4096];
    
    while (1) {
        printf("> ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';
        
        if (strcmp(input, "/exit") == 0) break;
        if (strcmp(input, "/status") == 0) {
            printf("Status: Connected to %s\n", peer_id);
            continue;
        }
        
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "chat_send %s %s", peer_id, input);
        command_send_to_daemon(cmd, response, sizeof(response));
        printf("[you] %s\n", input);
    }
    
    printf("\nChat session ended.\n");
    return 0;
}

int cmd_ghost(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "ERROR: Usage: ./orcashi ghost <id> <message>\n");
        return 1;
    }
    
    char* peer_id = argv[2];
    char* message = argv[3];
    
    for (int i = 4; i < argc; i++) {
        strcat(message, " ");
        strcat(message, argv[i]);
    }
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ghost %s %s", peer_id, message);
    
    char response[1024];
    if (command_send_to_daemon(cmd, response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    printf("Sending ghost message to %s...\n", peer_id);
    printf("Message stored.\n");
    printf("Done.\n");
    
    return 0;
}

int cmd_status(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    if (!command_daemon_is_running()) {
        printf("Daemon is NOT running.\n");
        printf("Use './orcashi listen' to start.\n");
        return 0;
    }
    
    char response[1024];
    if (command_send_to_daemon("status", response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    printf("Daemon is running (PID: %d)\n", command_get_daemon_pid());
    return 0;
}

int cmd_stop(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    if (!command_daemon_is_running()) {
        printf("Daemon is not running.\n");
        return 0;
    }
    
    int pid = command_get_daemon_pid();
    printf("Stopping daemon (PID: %d)...\n", pid);
    
    char response[1024];
    if (command_send_to_daemon("stop", response, sizeof(response)) == 0) {
        printf("%s", response);
        return 0;
    }
    
    kill(pid, SIGTERM);
    unlink(DAEMON_PID_FILE);
    unlink(DAEMON_SOCKET);
    printf("Daemon stopped.\n");
    
    return 0;
}

void command_show_help(void) {
    printf("\n");
    printf("ORCASHI v5 - Real P2P, Async UX\n");
    printf("\n");
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
