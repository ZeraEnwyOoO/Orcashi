 #ifndef DAEMON_H
#define DAEMON_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

#define DAEMON_NAME "orcashi"
#define DAEMON_HOME "/tmp/.orcashi/"
#define DAEMON_PID_FILE "/tmp/.orcashi/daemon.pid"
#define DAEMON_SOCKET "/tmp/.orcashi/socket"
#define DAEMON_LOG_FILE "/tmp/.orcashi/daemon.log"

#define DHT_PORT 33446
#define P2P_PORT 9000

typedef enum {
    DAEMON_STATE_STOPPED = 0,
    DAEMON_STATE_RUNNING = 1,
    DAEMON_STATE_STOPPING = 2
} DaemonState;

typedef struct {
    DaemonState state;
    int pid;
    int socket_fd;
    time_t start_time;
    time_t last_activity;
    bool dht_connected;
    bool p2p_ready;
    int peer_count;
    int pending_requests;
} DaemonStatus;

int daemon_start(void);
int daemon_stop(void);
bool daemon_is_running(void);
DaemonStatus daemon_get_status(void);

int daemon_run(void);
int daemon_init(void);
void daemon_cleanup(void);

int daemon_ipc_init(void);
void daemon_ipc_handle(int client_fd);
void daemon_ipc_send_response(int client_fd, const char* response);

int daemon_handle_command(const char* cmd, char* response, size_t response_size);

int daemon_cmd_identity(char* response, size_t size);
int daemon_cmd_listen(char* response, size_t size);
int daemon_cmd_search(const char* args, char* response, size_t size);
int daemon_cmd_add(const char* args, char* response, size_t size);
int daemon_cmd_accept(const char* args, char* response, size_t size);
int daemon_cmd_reject(const char* args, char* response, size_t size);
int daemon_cmd_peers(char* response, size_t size);
int daemon_cmd_chat_send(const char* args, char* response, size_t size);
int daemon_cmd_ghost(const char* args, char* response, size_t size);
int daemon_cmd_status(char* response, size_t size);
int daemon_cmd_stop(char* response, size_t size);

int daemon_write_pid(void);
int daemon_read_pid(void);
void daemon_remove_pid(void);
void daemon_log(const char* format, ...);

void* daemon_dht_thread(void* arg);
void* daemon_p2p_thread(void* arg);
void* daemon_event_thread(void* arg);
void* daemon_ipc_thread(void* arg);

void daemon_signal_handler(int sig);
int daemon_setup_signals(void);

#endif
