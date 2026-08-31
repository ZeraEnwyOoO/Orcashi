 #include "daemon.h"
#include "state_manager.h"
#include "p2p_manager.h"
#include "dht_node.h"
#include "mixed_id.h"
#include "orca_identity.h"
#include "event_loop.h"
#include "logger.h"
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

#define DAEMON_DEBUG 1

#if DAEMON_DEBUG
#define DLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[DAEMON] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define DLOG(fmt, ...) ((void)0)
#endif

static DaemonStatus g_status = {0};
static int g_ipc_socket = -1;
static DHTNode* g_dht = NULL;
static bool g_running = false;
static pthread_t g_dht_thread = 0;
static pthread_t g_p2p_thread = 0;
static pthread_t g_event_thread = 0;
static pthread_t g_ipc_thread = 0;

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

void daemon_signal_handler(int sig) {
    (void)sig;
    daemon_log("Received signal %d, shutting down...", sig);
    g_running = false;
}

int daemon_setup_signals(void) {
    signal(SIGINT, daemon_signal_handler);
    signal(SIGTERM, daemon_signal_handler);
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

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
    
    if (listen(g_ipc_socket, 10) < 0) {
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
    
    char response[8192];
    response[0] = '\0';
    
    int ret = daemon_handle_command(buffer, response, sizeof(response));
    if (ret == 0 && strlen(response) == 0) {
        snprintf(response, sizeof(response), "OK\n");
    } else if (ret < 0) {
        if (strlen(response) == 0) {
            snprintf(response, sizeof(response), "ERROR: Command failed\n");
        }
    }
    
    daemon_ipc_send_response(client_fd, response);
    close(client_fd);
}

void* daemon_ipc_thread(void* arg) {
    (void)arg;
    
    daemon_log("IPC thread started");
    
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
    
    daemon_log("IPC thread stopped");
    return NULL;
}

int daemon_handle_command(const char* cmd, char* response, size_t response_size) {
    if (!cmd || !response) return -1;
    
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
        snprintf(response, response_size, "ERROR: Unknown command: %s\n", cmd_name);
        return -1;
    }
}

int daemon_cmd_identity(char* response, size_t size) {
    OrcaIdentity identity;
    if (orca_identity_load(&identity, NULL) < 0) {
        snprintf(response, size, "ERROR: No identity found\n");
        return -1;
    }
    
    char mixed_id[64];
    mixed_id_encode(identity.id, "0.0.0.0", 9000, mixed_id, sizeof(mixed_id));
    
    snprintf(response, size,
             "ID        : %s\n"
             "Name      : %s\n"
             "Mode      : %s\n"
             "Created   : %s"
             "Mixed ID  : %s\n",
             identity.id,
             identity.name,
             identity.mode == ORCA_IDENTITY_MODE_SECURE ? "SECURE" : "NORMAL",
             ctime(&identity.created_at),
             mixed_id);
    
    return 0;
}

int daemon_cmd_listen(char* response, size_t size) {
    if (g_dht) {
        snprintf(response, size, "DHT already announced\n");
        return 0;
    }
    
    OrcaIdentity identity;
    if (orca_identity_load(&identity, NULL) < 0) {
        snprintf(response, size, "ERROR: No identity found. Register first.\n");
        return -1;
    }
    
    g_dht = dht_node_create();
    if (!g_dht) {
        snprintf(response, size, "ERROR: Failed to create DHT node\n");
        return -1;
    }
    
    if (dht_node_start(g_dht, DHT_PORT) < 0) {
        snprintf(response, size, "ERROR: Failed to start DHT node\n");
        dht_node_destroy(g_dht);
        g_dht = NULL;
        return -1;
    }
    
    if (identity.mode == ORCA_IDENTITY_MODE_SECURE) {
        dht_node_announce_secure(g_dht, identity.id, P2P_PORT,
                                 identity.public_key, identity.signature);
    } else {
        dht_node_announce(g_dht, identity.id, P2P_PORT);
    }
    
    g_status.dht_connected = true;
    g_status.p2p_ready = true;
    
    p2p_init();
    
    snprintf(response, size,
             "DHT announced ID %s on port %d\n"
             "P2P listening on UDP port %d\n"
             "Daemon is ready\n",
             identity.id, P2P_PORT, P2P_PORT);
    
    return 0;
}

int daemon_cmd_search(const char* args, char* response, size_t size) {
    if (!args) {
        snprintf(response, size, "ERROR: Usage: search <id>\n");
        return -1;
    }
    
    if (!g_dht) {
        snprintf(response, size, "ERROR: Daemon not listening. Use 'listen' first.\n");
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
                 "Found peer %s\n"
                 "  IP  : %s\n"
                 "  Port: %d\n"
                 "  Status: ONLINE\n",
                 peer_id, dht_ip, dht_port);
        
        state_set_ip(peer_id, dht_ip);
        state_set_port(peer_id, dht_port);
        state_set_online(peer_id, true);
    } else {
        snprintf(response, size,
                 "Peer %s not found\n"
                 "  Status: OFFLINE\n",
                 peer_id);
        
        state_set_online(peer_id, false);
    }
    
    return 0;
}

int daemon_cmd_add(const char* args, char* response, size_t size) {
    if (!args) {
        snprintf(response, size, "ERROR: Usage: add <id>\n");
        return -1;
    }
    
    char peer_id[64];
    strncpy(peer_id, args, sizeof(peer_id) - 1);
    peer_id[sizeof(peer_id) - 1] = '\0';
    
    Peer* peer = state_get_peer(peer_id);
    if (!peer) {
        state_add_peer(peer_id);
        peer = state_get_peer(peer_id);
    }
    
    if (!peer) {
        snprintf(response, size, "ERROR: Failed to add peer\n");
        return -1;
    }
    
    if (peer->state == PEER_FRIEND) {
        snprintf(response, size, "Already friends with %s\n", peer_id);
        return 0;
    }
    
    state_update_peer(peer_id, PEER_REQUEST_SENT);
    
    if (strlen(peer->ip) > 0 && peer->port > 0) {
        int ret = p2p_connect(peer_id);
        if (ret == 0) {
            snprintf(response, size,
                     "Request sent to %s\n"
                     "Connection established\n",
                     peer_id);
            return 0;
        }
    }
    
    snprintf(response, size,
             "Request sent to %s\n"
             "Waiting for peer to come online\n",
             peer_id);
    
    return 0;
}

int daemon_cmd_accept(const char* args, char* response, size_t size) {
    if (!args) {
        snprintf(response, size, "ERROR: Usage: accept <id>\n");
        return -1;
    }
    
    char peer_id[64];
    strncpy(peer_id, args, sizeof(peer_id) - 1);
    peer_id[sizeof(peer_id) - 1] = '\0';
    
    Peer* peer = state_get_peer(peer_id);
    if (!peer) {
        snprintf(response, size, "ERROR: Peer %s not found\n", peer_id);
        return -1;
    }
    
    if (peer->state != PEER_REQUEST_RECEIVED) {
        snprintf(response, size, "ERROR: No pending request from %s\n", peer_id);
        return -1;
    }
    
    state_update_peer(peer_id, PEER_FRIEND);
    
    if (strlen(peer->ip) > 0 && peer->port > 0) {
        p2p_accept(peer_id);
    }
    
    int ghost_count = state_deliver_ghost_messages(peer_id);
    
    snprintf(response, size,
             "Accepted request from %s\n"
             "Delivered %d ghost messages\n",
             peer_id, ghost_count);
    
    return 0;
}

int daemon_cmd_reject(const char* args, char* response, size_t size) {
    if (!args) {
        snprintf(response, size, "ERROR: Usage: reject <id>\n");
        return -1;
    }
    
    char peer_id[64];
    strncpy(peer_id, args, sizeof(peer_id) - 1);
    peer_id[sizeof(peer_id) - 1] = '\0';
    
    Peer* peer = state_get_peer(peer_id);
    if (!peer) {
        snprintf(response, size, "ERROR: Peer %s not found\n", peer_id);
        return -1;
    }
    
    if (peer->state != PEER_REQUEST_RECEIVED) {
        snprintf(response, size, "ERROR: No pending request from %s\n", peer_id);
        return -1;
    }
    
    state_remove_peer(peer_id);
    
    snprintf(response, size, "Rejected request from %s\n", peer_id);
    return 0;
}

int daemon_cmd_peers(char* response, size_t size) {
    PeerState peers[128];
    int count = state_get_peers(peers, 128);
    
    if (count == 0) {
        snprintf(response, size, "No peers\n");
        return 0;
    }
    
    char buffer[4096];
    int pos = 0;
    
    pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                    "PEERS (%d):\n", count);
    
    for (int i = 0; i < count; i++) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                        "  %s | %s | %s:%d\n",
                        peers[i].id,
                        state_to_string(peers[i].state),
                        peers[i].ip,
                        peers[i].port);
    }
    
    strncpy(response, buffer, size);
    response[size - 1] = '\0';
    
    return 0;
}

int daemon_cmd_chat_send(const char* args, char* response, size_t size) {
    if (!args) {
        snprintf(response, size, "ERROR: Usage: chat_send <id> <message>\n");
        return -1;
    }
    
    char peer_id[64];
    char message[4096];
    
    char* msg_start = strchr(args, ' ');
    if (!msg_start) {
        snprintf(response, size, "ERROR: Invalid chat_send command\n");
        return -1;
    }
    
    int id_len = msg_start - args;
    strncpy(peer_id, args, id_len);
    peer_id[id_len] = '\0';
    
    strcpy(message, msg_start + 1);
    
    if (!p2p_is_connected(peer_id)) {
        snprintf(response, size, "ERROR: Peer %s is not connected\n", peer_id);
        return -1;
    }
    
    int ret = p2p_send(peer_id, message);
    if (ret == 0) {
        state_add_message(peer_id, message);
        snprintf(response, size, "Message sent to %s\n", peer_id);
    } else {
        snprintf(response, size, "ERROR: Failed to send message to %s\n", peer_id);
    }
    
    return 0;
}

int daemon_cmd_ghost(const char* args, char* response, size_t size) {
    if (!args) {
        snprintf(response, size, "ERROR: Usage: ghost <id> <message>\n");
        return -1;
    }
    
    char peer_id[64];
    char message[4096];
    
    char* msg_start = strchr(args, ' ');
    if (!msg_start) {
        snprintf(response, size, "ERROR: Invalid ghost command\n");
        return -1;
    }
    
    int id_len = msg_start - args;
    strncpy(peer_id, args, id_len);
    peer_id[id_len] = '\0';
    
    strcpy(message, msg_start + 1);
    
    state_add_ghost_message(peer_id, message);
    
    snprintf(response, size,
             "Ghost message stored for %s\n"
             "Will be delivered when peer comes online\n",
             peer_id);
    
    return 0;
}

int daemon_cmd_status(char* response, size_t size) {
    snprintf(response, size,
             "Daemon running (PID: %d)\n"
             "Uptime: %ld seconds\n"
             "DHT: %s\n"
             "P2P: %s\n"
             "Peers: %d\n",
             getpid(),
             (long)(time(NULL) - g_status.start_time),
             g_status.dht_connected ? "Connected" : "Disconnected",
             g_status.p2p_ready ? "Ready" : "Not ready",
             state_get_count());
    
    return 0;
}

int daemon_cmd_stop(char* response, size_t size) {
    snprintf(response, size, "Shutting down...\n");
    g_running = false;
    return 0;
}

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
    
    while (g_running) {
        fd_set fds;
        struct timeval tv;
        
        FD_ZERO(&fds);
        if (g_p2p_socket >= 0) {
            FD_SET(g_p2p_socket, &fds);
        }
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int max_fd = g_p2p_socket;
        if (max_fd < 0) {
            sleep(1);
            continue;
        }
        
        int ret = select(max_fd + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (g_running) {
                daemon_log("P2P select error: %s", strerror(errno));
            }
            break;
        }
        
        if (ret > 0 && g_p2p_socket >= 0 && FD_ISSET(g_p2p_socket, &fds)) {
            char buffer[4096];
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);
            
            int n = recvfrom(g_p2p_socket, buffer, sizeof(buffer) - 1, 0,
                             (struct sockaddr*)&from, &from_len);
            
            if (n > 0) {
                buffer[n] = '\0';
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
                int port = ntohs(from.sin_port);
                
                daemon_log("Received %d bytes from %s:%d", n, ip, port);
                
                Event event = event_create(EVENT_MESSAGE_RECEIVED, ip);
                strcpy(event.ip, ip);
                event.port = port;
                strcpy(event.message, buffer);
                event_queue_push(&event);
            }
        }
    }
    
    daemon_log("P2P thread stopped");
    return NULL;
}

void* daemon_event_thread(void* arg) {
    (void)arg;
    daemon_log("Event thread started");
    
    while (g_running) {
        Event event;
        int ret = event_queue_pop(&event, 100);
        if (ret == 0) {
            event_process(&event);
            event_free(&event);
        }
        
        state_save();
    }
    
    daemon_log("Event thread stopped");
    return NULL;
}

int daemon_init(void) {
    daemon_log("Initializing daemon...");
    
    daemon_setup_signals();
    
    mkdir(DAEMON_HOME, 0700);
    
    logger_init(DAEMON_LOG_FILE);
    logger_set_level(LOG_LEVEL_INFO);
    
    state_init();
    
    orca_init_crypto();
    orca_identity_storage_init();
    
    p2p_init();
    
    event_loop_init();
    
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
    
    daemon_write_pid();
    
    pthread_create(&g_dht_thread, NULL, daemon_dht_thread, NULL);
    pthread_create(&g_p2p_thread, NULL, daemon_p2p_thread, NULL);
    pthread_create(&g_event_thread, NULL, daemon_event_thread, NULL);
    pthread_create(&g_ipc_thread, NULL, daemon_ipc_thread, NULL);
    
    while (g_running) {
        sleep(1);
    }
    
    daemon_log("Daemon main loop exiting...");
    return 0;
}

void daemon_cleanup(void) {
    daemon_log("Cleaning up...");
    
    g_running = false;
    
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
    if (g_ipc_thread) {
        pthread_join(g_ipc_thread, NULL);
        g_ipc_thread = 0;
    }
    
    if (g_dht) {
        dht_node_stop(g_dht);
        dht_node_destroy(g_dht);
        g_dht = NULL;
    }
    
    p2p_cleanup();
    state_save();
    event_loop_stop();
    logger_close();
    
    if (g_ipc_socket >= 0) {
        close(g_ipc_socket);
        g_ipc_socket = -1;
        unlink(DAEMON_SOCKET);
    }
    
    daemon_remove_pid();
    
    g_status.state = DAEMON_STATE_STOPPED;
    daemon_log("Daemon cleaned up");
}

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
        printf("Daemon started (PID: %d)\n", pid);
        printf("Use './orcashi status' to check\n");
        printf("Use './orcashi stop' to stop\n");
        return 0;
    }
    
    setsid();
    umask(0);
    
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    open("/dev/null", O_RDWR);
    dup2(0, STDOUT_FILENO);
    dup2(0, STDERR_FILENO);
    
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
        for (int i = 0; i < 10; i++) {
            if (!daemon_is_running()) break;
            sleep(1);
        }
    }
    
    daemon_remove_pid();
    unlink(DAEMON_SOCKET);
    return 0;
}
