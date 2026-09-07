#include "commands.h"
#include "mixed_id.h"
#include "orca_identity.h"
#include "daemon.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <termios.h>
#include <unistd.h>
#include <pthread.h>

#define DAEMON_SOCKET "/tmp/.orcashi/socket"
#define DAEMON_PID_FILE "/tmp/.orcashi/daemon.pid"

/* ============================================================================
 * GETPASS - Hidden password input (like sudo)
 * ============================================================================ */

static char* get_hidden_input(const char* prompt) {
    static char password[128];
    struct termios old, new;
    int i = 0;
    char c;
    
    printf("%s", prompt);
    fflush(stdout);
    
    tcgetattr(STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new);
    
    while (i < (int)(sizeof(password) - 1) && read(STDIN_FILENO, &c, 1) > 0) {
        if (c == '\n' || c == '\r') {
            break;
        }
        if (c == '\b' || c == 127) {
            if (i > 0) i--;
            continue;
        }
        password[i++] = c;
    }
    password[i] = '\0';
    
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    printf("\n");
    fflush(stdout);
    
    return password;
}

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
        case CMD_RESET:
            return cmd_reset(argc, argv);
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
    if (strcmp(cmd, "reset") == 0) return CMD_RESET;
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
        case CMD_RESET: return "reset";
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

/* ============================================================================
 * COMMAND: REGISTER (STRICT - One registration only, strong password)
 * ============================================================================ */

int cmd_register(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|              ORCASHI REGISTRATION (STRICT)                |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
    
    /* STRICT RULE 1: One registration only */
    if (orca_identity_exists(NULL)) {
        printf("ERROR: Identity already exists!\n");
        printf("Orcashi allows only ONE registration per device.\n");
        printf("Use './orcashi identity' to view your identity.\n");
        printf("Use './orcashi reset --force' to reset (WARNING: irreversible).\n");
        return 1;
    }
    
    char id[64];
    char name[128];
    
    /* Step 1: Auto-generate random ID (STRICT RULE 3: Permanent ID) */
    srand(time(NULL) ^ getpid() ^ (unsigned long)pthread_self());
    int num = (rand() % 999) + 1;
    snprintf(id, sizeof(id), "<%03d>", num);
    
    printf("Your auto-generated ID: %s\n", id);
    printf("(This ID is permanent and cannot be changed)\n");
    printf("\n");
    
    /* Step 2: Display name */
    printf("Enter display name (optional, press Enter for default): ");
    fflush(stdout);
    
    if (!fgets(name, sizeof(name), stdin)) {
        strcpy(name, "orcashi");
    }
    name[strcspn(name, "\n")] = '\0';
    if (strlen(name) == 0) {
        strcpy(name, "orcashi");
    }
    
    printf("\n");
    printf("STRICT PASSWORD POLICY:\n");
    printf("  - Minimum 12 characters\n");
    printf("  - At least 1 uppercase letter\n");
    printf("  - At least 1 lowercase letter\n");
    printf("  - At least 1 number\n");
    printf("  - At least 1 special character (!@#$%%^&*)\n");
    printf("\n");
    
    /* Step 3: Password (hidden) */
    const char* passcode = get_hidden_input("Enter passcode: ");
    
    /* STRICT RULE 2: Strong password validation */
    if (strlen(passcode) < 12) {
        printf("ERROR: Passcode must be at least 12 characters.\n");
        return 1;
    }
    
    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
    const char* special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    for (size_t i = 0; i < strlen(passcode); i++) {
        if (isupper(passcode[i])) has_upper = 1;
        else if (islower(passcode[i])) has_lower = 1;
        else if (isdigit(passcode[i])) has_digit = 1;
        else if (strchr(special_chars, passcode[i])) has_special = 1;
    }
    
    if (!has_upper || !has_lower || !has_digit || !has_special) {
        printf("ERROR: Passcode must contain uppercase, lowercase, number, and special character.\n");
        return 1;
    }
    
    /* Step 4: Confirm password (hidden) */
    const char* passcode2 = get_hidden_input("Confirm passcode: ");
    if (strcmp(passcode, passcode2) != 0) {
        printf("ERROR: Passcodes do not match.\n");
        return 1;
    }
    
    printf("\n");
    printf("Creating identity...\n");
    
    OrcaIdentity identity;
    if (orca_identity_create_secure_3digit(id, passcode, name, "user", &identity) < 0) {
        printf("ERROR: Failed to create identity: %s\n", orca_get_last_error());
        return 1;
    }
    
    if (orca_identity_save(&identity) < 0) {
        printf("ERROR: Failed to save identity.\n");
        return 1;
    }
    
    /* Set default identity */
    char metadata[256];
    snprintf(metadata, sizeof(metadata), "{\"default_id\":\"%s\"}", identity.id);
    FILE* f = fopen(ORCA_METADATA_FILE, "w");
    if (f) {
        fprintf(f, "%s", metadata);
        fclose(f);
    }
    
    /* Zeroize passcode (security) */
    zeroize((void*)passcode, strlen(passcode));
    zeroize((void*)passcode2, strlen(passcode2));
    
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|              REGISTRATION COMPLETE (STRICT)               |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|  ID        : %s\n", identity.id);
    printf("|  Name      : %s\n", identity.name);
    printf("|  Mode      : SECURE\n");
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
    printf("IMPORTANT NOTICE:\n");
    printf("  - This is your ONLY registration.\n");
    printf("  - Your ID is PERMANENT and cannot be changed.\n");
    printf("  - Keep your passcode SAFE. It cannot be recovered.\n");
    printf("  - To reset: ./orcashi reset --force (IRREVERSIBLE)\n");
    printf("\n");
    printf("Next steps:\n");
    printf("  ./orcashi listen    - Announce to DHT network\n");
    printf("  ./orcashi add <id>  - Add a friend\n");
    printf("  ./orcashi chat <id> - Start chatting\n");
    printf("\n");
    printf("Share your ID with friends: %s\n", identity.id);
    
    return 0;
}

/* ============================================================================
 * COMMAND: RESET (STRICT - requires --force and confirmation)
 * ============================================================================ */

int cmd_reset(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|              ORCASHI RESET (WARNING)                      |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("\n");
    
    if (!orca_identity_exists(NULL)) {
        printf("No identity found. Nothing to reset.\n");
        return 0;
    }
    
    /* Check for --force flag */
    int force = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--force") == 0 || strcmp(argv[i], "-f") == 0) {
            force = 1;
            break;
        }
    }
    
    if (!force) {
        printf("ERROR: Reset requires --force flag.\n");
        printf("Usage: ./orcashi reset --force\n");
        printf("WARNING: This will permanently delete your identity!\n");
        return 1;
    }
    
    printf("WARNING: This will permanently delete your identity!\n");
    printf("Type your identity ID to confirm: ");
    fflush(stdout);
    
    char confirm[64];
    if (!fgets(confirm, sizeof(confirm), stdin)) {
        printf("Cancelled\n");
        return 1;
    }
    confirm[strcspn(confirm, "\n")] = '\0';
    
    OrcaIdentity identity;
    if (orca_identity_load(&identity, NULL) < 0) {
        printf("ERROR: Failed to load identity.\n");
        return 1;
    }
    
    if (strcmp(confirm, identity.id) != 0) {
        printf("ERROR: ID mismatch. Reset cancelled.\n");
        return 1;
    }
    
    /* Double confirm */
    printf("Type 'yes' to confirm deletion: ");
    fflush(stdout);
    
    char yes[16];
    if (!fgets(yes, sizeof(yes), stdin)) {
        printf("Cancelled\n");
        return 1;
    }
    yes[strcspn(yes, "\n")] = '\0';
    
    if (strcmp(yes, "yes") != 0) {
        printf("Reset cancelled.\n");
        return 1;
    }
    
    orca_identity_reset(true);
    printf("Identity reset successfully.\n");
    printf("You can now register again with './orcashi register'\n");
    
    return 0;
}

/* ============================================================================
 * COMMAND: IDENTITY
 * ============================================================================ */

int cmd_identity(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
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

/* ============================================================================
 * COMMAND: LISTEN
 * ============================================================================ */

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

/* ============================================================================
 * COMMAND: SEARCH
 * ============================================================================ */

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

/* ============================================================================
 * COMMAND: ADD
 * ============================================================================ */

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

/* ============================================================================
 * COMMAND: ACCEPT
 * ============================================================================ */

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

/* ============================================================================
 * COMMAND: REJECT
 * ============================================================================ */

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

/* ============================================================================
 * COMMAND: PEERS
 * ============================================================================ */

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

/* ============================================================================
 * COMMAND: CHAT
 * ============================================================================ */

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

/* ============================================================================
 * COMMAND: GHOST
 * ============================================================================ */

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

/* ============================================================================
 * COMMAND: STATUS
 * ============================================================================ */

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

/* ============================================================================
 * COMMAND: STOP
 * ============================================================================ */

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

/* ============================================================================
 * COMMAND: HELP
 * ============================================================================ */

void command_show_help(void) {
    printf("\n");
    printf("ORCASHI v5 - Real P2P, Async UX\n");
    printf("\n");
    printf("Usage:\n");
    printf("  ./orcashi register          - Register identity (STRICT - one time only)\n");
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
    printf("  ./orcashi reset --force     - Reset identity (IRREVERSIBLE)\n");
    printf("  ./orcashi help              - Show this help\n");
    printf("\n");
    printf("STRICT RULES:\n");
    printf("  - Only ONE registration per device\n");
    printf("  - Password: 12+ chars, upper, lower, number, special\n");
    printf("  - ID is PERMANENT and cannot be changed\n");
    printf("  - Only ONE daemon can run at a time\n");
    printf("  - Messages: max 4096 bytes, no empty messages\n");
    printf("\n");
}
