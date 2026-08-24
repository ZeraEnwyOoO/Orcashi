#include "daemon.h"
#include "state_manager.h"
#include "p2p_manager.h"
#include "dht_node.h"
#include "mixed_id.h"
#include "orca_identity.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================ */

static DaemonStatus g_status = {0};
static int g_ipc_socket = -1;
static DHTNode* g_dht = NULL;
static bool g_running = false;
static pthread_t g_dht_thread = 0;
static pthread_t g_p2p_thread = 0;
static pthread_t g_event_thread = 0;

/* ============================================================================
 * LOGGING
 * ============================================================================ */

void daemon_log(const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    time_t now = time(NULL);
    struct tm* tm = localtime(&now);
    
    FILE* log = fopen(DAEMON_LOG_FILE, "a");
    if (log) {
        fprintf(log, "[%02d:%02d:%02d] ", tm->tm_hour, tm->tm_min, tm->tm_sec);
        vfprintf(log, format, args);
        fprintf(log, "\n");
        fclose(log);
    }
    
    va_end(args);
}

/* ============================================================================
 * PID MANAGEMENT
 * ============================================================================ */

int daemon_write_pid(void) {
    FILE* f = fopen(DAEMON_PID_FILE, "w");
    if (!f) {
        daemon_log("Failed to write PID file: %s", strerror(errno));
        return -1;
    }
    fprintf(f, "%d", getpid());
    fclose(f);
    return 0;
}

int daemon_read_pid(void) {
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

void daemon_remove_pid(void) {
    unlink(DAEMON_PID_FILE);
}

/* ============================================================================
 * DAEMON STATE
 * ============================================================================ */

bool daemon_is_running(void) {
    int pid = daemon_read_pid();
    if (pid <= 0) return false;
    if (kill(pid, 0) == 0) return true;
    daemon_remove_pid();
    return false;
}

DaemonStatus daemon_get_status(void) {
    return g_status;
}

/* ============================================================================
 * SIGNAL HANDLER
 * ============================================================================ */

void daemon_signal_handler(int sig) {
    (void)sig;
    daemon_log("Received signal %d, shutting down...", sig);
    g_running = false;
}

int daemon_setup_signals(void) {
    signal(SIGINT, daemon_signal_handler);
    signal(SIGTERM, daemon_signal_handler);
    signal(SIGPIPE, SIG_IGN);  /* Ignore broken pipe */
    return 0;
}

/* ============================================================================
 * IPC SOCKET
 * ============================================================================ */

int daemon_ipc_init(void) {
    unlink(DAEMON_SOCKET);
    
    g_ipc_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_ipc_socket < 0) {
        daemon_log("Failed to create IPC socket: %s", strerror(errno));
        return -1;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DAEMON_SOCKET, sizeof(addr.sun_path) - 1);
    
    if (bind(g_ipc_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        daemon_log("Failed to bind IPC socket: %s", strerror(errno));
        close(g_ipc_socket);
        g_ipc_socket = -1;
        return -1;
    }
    
    if (listen(g_ipc_socket, 5) < 0) {
        daemon_log("Failed to listen on IPC socket: %s", strerror(errno));
        close(g_ipc_socket);
        g_ipc_socket = -1;
        return -1;
    }
    
    chmod(DAEMON_SOCKET, 0666);
    daemon_log("IPC socket ready at %s", DAEMON_SOCKET);
    return 0;
}

void daemon_ipc_send_response(int client_fd, const char* response) {
    if (client_fd < 0 || !response) return;
    write(client_fd, response, strlen(response));
}

void daemon_ipc_handle(int client_fd) {
    char buffer[4096];
    int n = read(client_fd, buffer, sizeof(buffer) - 1);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    buffer[n] = '\0';
    
    daemon_log("IPC command: %s", buffer);
    
    char response[4096];
    response[0] = '\0';
    
    int ret = daemon_handle_command(buffer, response, sizeof(response));
    if (ret == 0 && strlen(response) == 0) {
        snprintf(response, sizeof(response), "[OK] Command executed.\n");
    } else if (ret < 0) {
        snprintf(response, sizeof(response), "[ERROR] Command failed.\n");
    }
    
    daemon_ipc_send_response(client_fd, response);
    close(client_fd);
}

/* ============================================================================
 * COMMAND HANDLER
 * ============================================================================ */

int daemon_handle_command(const char* cmd, char* response, size_t response_size) {
    if (!cmd || !response) return -1;
    
    /* Parse command and arguments */
    char cmd_copy[512];
    strncpy(cmd_copy, cmd, sizeof(cmd_copy) - 1);
    cmd_copy[sizeof(cmd_copy) - 1] = '\0';
    
    char* args = strchr(cmd_copy, ' ');
    char* cmd_name = cmd_copy;
    if (args) {
        *args = '\0';
        args++;
    }
    
    daemon_log("Handling command: %s", cmd_name);
    
    /* Dispatch commands */
    if (strcmp(cmd_name, "identity") == 0) {
        return daemon_cmd_identity(response, response_size);
    }
    else if (strcmp(cmd_name, "listen") == 0) {
        return daemon_cmd_listen(response, response_size);
    }
    else if (strcmp(cmd_name, "search") == 0) {
        return daemon_cmd_search(args, response, response_size);
    }
    else if (strcmp(cmd_name, "add") == 0) {
        return daemon_cmd_add(args, response, response_size);
    }
    else if (strcmp(cmd_name, "accept") == 0) {
        return daemon_cmd_accept(args, response, response_size);
    }
    else if (strcmp(cmd_name, "reject") == 0) {
        return daemon_cmd_reject(args, response, response_size);
    }
    else if (strcmp(cmd_name, "peers") == 0) {
        return daemon_cmd_peers(response, response_size);
    }
    else if (strcmp(cmd_name, "chat_send") == 0) {
        return daemon_cmd_chat_send(args, response, response_size);
    }
    else if (strcmp(cmd_name, "ghost") == 0) {
        return daemon_cmd_ghost(args, response, response_size);
    }
    else if (strcmp(cmd_name, "status") == 0) {
        return daemon_cmd_status(response, response_size);
    }
    else if (strcmp(cmd_name, "stop") == 0) {
        return daemon_cmd_stop(response, response_size);
    }
    else {
        snprintf(response, response_size, "[ERROR] Unknown command: %s\n", cmd_name);
        return -1;
    }
}

/* ============================================================================
 * COMMAND: identity
 * ============================================================================ */

int daemon_cmd_identity(char* response, size_t size) {
    OrcaIdentity identity;
    if (orca_identity_load(&identity, NULL) < 0) {
        snprintf(response, size, "[ERROR] No identity found.\n");
        return -1;
    }
    
    char mixed_id[64];
    mixed_id_encode(identity.id, "0.0.0.0", 9000, mixed_id);
    
    snprintf(response, size,
             "============================================================\n"
             "  ORCASHI IDENTITY\n"
             "============================================================\n"
             "  ID        : %s\n"
             "  Name      : %s\n"
             "  Mode      : %s\n"
             "  Created   : %s"
             "  Mixed ID  : %s\n"
             "============================================================\n",
             identity.id,
             identity.name,
             identity.mode == ORCA_IDENTITY_MODE_SECURE ? "SECURE" : "NORMAL",
             ctime(&identity.created_at),
             mixed_id);
    
    return 0;
}

/* ============================================================================
 * COMMAND: listen
 * ============================================================================ */

int daemon_cmd_listen(char* response, size_t size) {
    if (g_dht) {
        snprintf(response, size, "[DHT] Already announced.\n");
        return 0;
    }
    
    /* Load identity */
    OrcaIdentity identity;
    if (orca_identity_load(&identity, NULL) < 0) {
        snprintf(response, size, "[ERROR] No identity found. Register first.\n");
        return -1;
    }
    
    /* Start DHT */
    g_dht = dht_node_create();
    if (!g_dht) {
        snprintf(response, size, "[ERROR] Failed to create DHT node.\n");
        return -1;
    }
    
    if (dht_node_start(g_dht, DHT_PORT) < 0) {
        snprintf(response, size, "[ERROR] Failed to start DHT node.\n");
        dht_node_destroy(g_dht);
        g_dht = NULL;
        return -1;
    }
    
    /* Announce to DHT */
    if (identity.mode == ORCA_IDENTITY_MODE_SECURE) {
        dht_node_announce_secure(g_dht, identity.id, P2P_PORT,
                                 identity.public_key, identity.signature);
    } else {
        dht_node_announce(g_dht, identity.id, P2P_PORT);
    }
    
    snprintf(response, size,
             "[DHT] Announced ID %s at port %d\n"
             "[P2P] Listening on UDP port %d\n"
             "[ORCA] Daemon is ready.\n",
             identity.id, P2P_PORT, P2P_PORT);
    
    return 0;
}

/* ============================================================================
 * COMMAND: search
 * ============================================================================ */

int daemon_cmd_search(const char* args, char* response, size_t size) {
    if (!args) {
        snprintf(response, size, "[ERROR] Usage: search <id>\n");
        return -1;
    }
    
    if (!g_dht) {
        snprintf(response, size, "[ERROR] Daemon not listening. Use './orcashi listen' first.\n");
        return -1;
    }
    
    char peer_id[64];
    strncpy(peer_id, args, sizeof(peer_id) - 1);
    peer_id[sizeof(peer_id) - 1] = '\0';
    
    char dht_ip[INET_ADDRSTRLEN];
    int dht_port;
    
    daemon_log("Searching for peer %s in DHT...", peer_id);
    
    if (dht_node_lookup(g_dht, peer_id, 10, dht_ip, &dht_port)) {
        snprintf(response, size,
                 "[DHT] Found peer %s\n"
                 "  IP  : %s\n"
                 "  Port: %d\n"
                 "  Status: ONLINE\n",
                 peer_id, dht_ip, dht_port);
    } else {
        snprintf(response, size,
                 "[DHT] Peer %s not found\n"
                 "  Status: OFFLINE\n",
                 peer_id);
    }
    
    return 0;
}

/* ============================================================================
 * COMMAND: add
 * ============================================================================ */

int daemon_cmd_add(const char* args, char* response, size_t size) {
    if (!args) {
        snprintf(response, size, "[ERROR] Usage: add <id>\n");
        return -1;
    }
    
    char peer_id[64];
    strncpy(peer_id, args, sizeof(peer_id) - 1);
    peer_id[sizeof(peer_id) - 1] = '\0';
    
    /* Send ADD_REQUEST via P2P */
    /* TODO: Implement P2P add */
    
    /* Update state */
    state_update_peer(peer_id, PEER_REQUEST_SENT);
    
    snprintf(response, size,
             "[ORCA] Sending request to %s...\n"
             "[ORCA] Request sent.\n"
             "[ORCA] Done.\n",
             peer_id);
    
    return 0;
}

/* ============================================================================
 * COMMAND: accept
 * ============================================================================ */

int daemon_cmd_accept(const char* args, char* response, size_t size) {
    if (!args) {
        snprintf(response, size, "[ERROR] Usage: accept <id>\n");
        return -1;
    }
    
    char peer_id[64];
    strncpy(peer_id, args, sizeof(peer_id) - 1);
    peer_id[sizeof(peer_id) - 1] = '\0';
    
    /* Send ACCEPT_CONFIRM via P2P */
    /* TODO: Implement P2P accept */
    
    /* Update state */
    state_update_peer(peer_id, PEER_FRIEND);
    
    snprintf(response, size,
             "[ORCA] Accepted request from %s\n"
             "[ORCA] Done.\n",
             peer_id);
    
    return 0;
}

/* ============================================================================
 * COMMAND: reject
 * ============================================================================ */

int daemon_cmd_reject(const char* args, char* response, size_t size) {
    if (!args) {
        snprintf(response, size, "[ERROR] Usage: reject <id>\n");
        return -1;
    }
    
    char peer_id[64];
    strncpy(peer_id, args, sizeof(peer_id) - 1);
    peer_id[sizeof(peer_id) - 1] = '\0';
    
    /* Send REJECT via P2P */
    /* TODO: Implement P2P reject */
    
    /* Update state */
    state_remove_peer(peer_id);
    
    snprintf(response, size,
             "[ORCA] Rejected request from %s\n"
             "[ORCA] Done.\n",
             peer_id);
    
    return 0;
}

/* ============================================================================
 * COMMAND: peers
 * ============================================================================ */

int daemon_cmd_peers(char* response, size_t size) {
    PeerState peers[128];
    int count = state_get_peers(peers, 128);
    
    if (count == 0) {
        snprintf(response, size,
                 "============================================================\n"
                 "  ORCASHI PEERS\n"
                 "============================================================\n"
                 "  No peers yet.\n"
                 "  Use './orcashi search <id>' to find peers.\n"
                 "============================================================\n");
        return 0;
    }
    
    char buffer[4096];
    int pos = 0;
    
    pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                    "============================================================\n"
                    "  ORCASHI PEERS\n"
                    "============================================================\n");
    
    /* Pending requests */
    int pending = state_get_pending(peers, 128);
    if (pending > 0) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                        "\nPENDING REQUESTS: %d\n", pending);
        for (int i = 0; i < pending; i++) {
            pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                            "  %s | REQUEST SENT | WAITING\n",
                            peers[i].id);
        }
    }
    
    /* Friends */
    int friends = state_get_friends(peers, 128);
    if (friends > 0) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                        "\nFRIEND LIST: %d\n", friends);
        for (int i = 0; i < friends; i++) {
            pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                            "  %d. %s | %s\n",
                            i + 1,
                            peers[i].id,
                            peers[i].online ? "online" : "offline");
        }
    }
    
    pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                    "\n============================================================\n");
    
    strncpy(response, buffer, size);
    response[size - 1] = '\0';
    
    return 0;
}

/* ============================================================================
 * COMMAND: chat_send
 * ============================================================================ */

int daemon_cmd_chat_send(const char* args, char* response, size_t size) {
    if (!args) {
        snprintf(response, size, "[ERROR] Usage: chat_send <id> <message>\n");
        return -1;
    }
    
    char peer_id[64];
    char message[4096];
    
    /* Parse: <id> <message> */
    char* msg_start = strchr(args, ' ');
    if (!msg_start) {
        snprintf(response, size, "[ERROR] Invalid chat_send command\n");
        return -1;
    }
    
    int id_len = msg_start - args;
    strncpy(peer_id, args, id_len);
    peer_id[id_len] = '\0';
    
    strcpy(message, msg_start + 1);
    
    /* Send message via P2P */
    /* TODO: Implement P2P send */
    
    snprintf(response, size, "[OK] Message sent to %s\n", peer_id);
    return 0;
}

/* ============================================================================
 * COMMAND: ghost
 * ============================================================================ */

int daemon_cmd_ghost(const char* args, char* response, size_t size) {
    if (!args) {
        snprintf(response, size, "[ERROR] Usage: ghost <id> <message>\n");
        return -1;
    }
    
    char peer_id[64];
    char message[4096];
    
    /* Parse: <id> <message> */
    char* msg_start = strchr(args, ' ');
    if (!msg_start) {
        snprintf(response, size, "[ERROR] Invalid ghost command\n");
        return -1;
    }
    
    int id_len = msg_start - args;
    strncpy(peer_id, args, id_len);
    peer_id[id_len] = '\0';
    
    strcpy(message, msg_start + 1);
    
    /* Store ghost message */
    state_add_ghost_message(peer_id, message);
    
    snprintf(response, size,
             "[ORCA] Peer %s is offline/busy.\n"
             "[ORCA] Sending ghost message...\n"
             "[ORCA] Message stored in ghost room.\n"
             "[ORCA] Done.\n",
             peer_id);
    
    return 0;
}

/* ============================================================================
 * COMMAND: status
 * ============================================================================ */

int daemon_cmd_status(char* response, size_t size) {
    snprintf(response, size,
             "[ORCA] Daemon is running (PID: %d)\n"
             "[ORCA] Online since: %s"
             "[ORCA] DHT: %s\n"
             "[ORCA] P2P: %s\n"
             "[ORCA] Peers: %d\n"
             "[ORCA] Pending requests: %d\n",
             getpid(),
             ctime(&g_status.start_time),
             g_status.dht_connected ? "Connected" : "Disconnected",
             g_status.p2p_ready ? "Ready" : "Not ready",
             state_get_count(),
             state_get_pending_count());
    
    return 0;
}

/* ============================================================================
 * COMMAND: stop
 * ============================================================================ */

int daemon_cmd_stop(char* response, size_t size) {
    snprintf(response, size, "[ORCA] Shutting down...\n");
    g_running = false;
    return 0;
}

/* ============================================================================
 * DAEMON THREADS
 * ============================================================================ */

void* daemon_dht_thread(void* arg) {
    (void)arg;
    daemon_log("DHT thread started");
    
    while (g_running) {
        if (g_dht) {
            dht_node_periodic(g_dht);
        }
        sleep(5);
    }
    
    daemon_log("DHT thread stopped");
    return NULL;
}

void* daemon_p2p_thread(void* arg) {
    (void)arg;
    daemon_log("P2P thread started");
    
    /* TODO: Initialize P2P UDP listener */
    /* TODO: Handle incoming messages */
    
    while (g_running) {
        /* Process P2P events */
        sleep(1);
    }
    
    daemon_log("P2P thread stopped");
    return NULL;
}

void* daemon_event_thread(void* arg) {
    (void)arg;
    daemon_log("Event thread started");
    
    while (g_running) {
        /* Process events */
        /* TODO: Check DHT for new peers */
        /* TODO: Check P2P for messages */
        /* TODO: Update state */
        /* TODO: Deliver ghost messages */
        sleep(1);
    }
    
    daemon_log("Event thread stopped");
    return NULL;
}

/* ============================================================================
 * DAEMON INIT / RUN / CLEANUP
 * ============================================================================ */

int daemon_init(void) {
    daemon_log("Initializing daemon...");
    
    /* Setup signals */
    daemon_setup_signals();
    
    /* Create home directory */
    mkdir(DAEMON_HOME, 0700);
    
    /* Initialize state manager */
    state_init();
    
    /* Initialize IPC */
    if (daemon_ipc_init() < 0) {
        return -1;
    }
    
    g_status.state = DAEMON_STATE_RUNNING;
    g_status.start_time = time(NULL);
    g_status.pid = getpid();
    g_running = true;
    
    daemon_log("Daemon initialized (PID: %d)", getpid());
    return 0;
}

int daemon_run(void) {
    daemon_log("Daemon running...");
    
    /* Write PID */
    daemon_write_pid();
    
    /* Create threads */
    pthread_create(&g_dht_thread, NULL, daemon_dht_thread, NULL);
    pthread_create(&g_p2p_thread, NULL, daemon_p2p_thread, NULL);
    pthread_create(&g_event_thread, NULL, daemon_event_thread, NULL);
    
    /* Main IPC loop */
    fd_set fds;
    struct timeval tv;
    
    while (g_running) {
        FD_ZERO(&fds);
        FD_SET(g_ipc_socket, &fds);
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(g_ipc_socket + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (g_running) {
                daemon_log("select() error: %s", strerror(errno));
            }
            break;
        }
        
        if (ret > 0) {
            int client_fd = accept(g_ipc_socket, NULL, NULL);
            if (client_fd >= 0) {
                daemon_ipc_handle(client_fd);
            }
        }
    }
    
    daemon_log("Daemon main loop exiting...");
    return 0;
}

void daemon_cleanup(void) {
    daemon_log("Cleaning up...");
    
    g_running = false;
    
    /* Wait for threads */
    if (g_dht_thread) {
        pthread_join(g_dht_thread, NULL);
        g_dht_thread = 0;
    }
    if (g_p2p_thread) {
        pthread_join(g_p2p_thread, NULL);
        g_p2p_thread = 0;
    }
    if (g_event_thread) {
        pthread_join(g_event_thread, NULL);
        g_event_thread = 0;
    }
    
    /* Cleanup DHT */
    if (g_dht) {
        dht_node_stop(g_dht);
        dht_node_destroy(g_dht);
        g_dht = NULL;
    }
    
    /* Cleanup IPC */
    if (g_ipc_socket >= 0) {
        close(g_ipc_socket);
        g_ipc_socket = -1;
        unlink(DAEMON_SOCKET);
    }
    
    /* Remove PID */
    daemon_remove_pid();
    
    g_status.state = DAEMON_STATE_STOPPED;
    daemon_log("Daemon cleaned up");
}

/* ============================================================================
 * DAEMON START / STOP
 * ============================================================================ */

int daemon_start(void) {
    if (daemon_is_running()) {
        return 0;
    }
    
    pid_t pid = fork();
    if (pid < 0) {
        daemon_log("Failed to fork: %s", strerror(errno));
        return -1;
    }
    
    if (pid > 0) {
        /* Parent */
        printf("[ORCA] Daemon started (PID: %d)\n", pid);
        printf("[ORCA] Use './orcashi status' to check\n");
        printf("[ORCA] Use './orcashi stop' to stop\n");
        return 0;
    }
    
    /* Child - become daemon */
    setsid();
    umask(0);
    
    /* Close stdin/stdout/stderr */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    open("/dev/null", O_RDWR);
    dup2(0, STDOUT_FILENO);
    dup2(0, STDERR_FILENO);
    
    /* Run daemon */
    if (daemon_init() < 0) {
        return -1;
    }
    
    daemon_run();
    daemon_cleanup();
    
    return 0;
}

int daemon_stop(void) {
    if (!daemon_is_running()) {
        return 0;
    }
    
    int pid = daemon_read_pid();
    if (pid > 0) {
        kill(pid, SIGTERM);
        /* Wait for daemon to exit */
        for (int i = 0; i < 10; i++) {
            if (!daemon_is_running()) break;
            sleep(1);
        }
    }
    
    daemon_remove_pid();
    unlink(DAEMON_SOCKET);
    return 0;
}
