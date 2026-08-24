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

/* ============================================================================
 * DAEMON CONFIGURATION
 * ============================================================================ */

#define DAEMON_NAME "orcashi"
#define DAEMON_HOME "/tmp/.orcashi/"
#define DAEMON_PID_FILE "/tmp/.orcashi/daemon.pid"
#define DAEMON_SOCKET "/tmp/.orcashi/socket"
#define DAEMON_LOG_FILE "/tmp/.orcashi/daemon.log"

/* DHT Port */
#define DHT_PORT 33446

/* P2P UDP Port */
#define P2P_PORT 9000

/* ============================================================================
 * DAEMON STATE
 * ============================================================================ */

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

/* ============================================================================
 * DAEMON LIFECYCLE
 * ============================================================================ */

/* Start daemon (fork to background) */
int daemon_start(void);

/* Stop daemon */
int daemon_stop(void);

/* Check if daemon is running */
bool daemon_is_running(void);

/* Get daemon status */
DaemonStatus daemon_get_status(void);

/* ============================================================================
 * DAEMON MAIN LOOP
 * ============================================================================ */

/* Main daemon event loop (called in child process) */
int daemon_run(void);

/* Initialize daemon */
int daemon_init(void);

/* Cleanup daemon */
void daemon_cleanup(void);

/* ============================================================================
 * DAEMON IPC (Unix Socket)
 * ============================================================================ */

/* Initialize IPC socket */
int daemon_ipc_init(void);

/* Handle IPC connection */
void daemon_ipc_handle(int client_fd);

/* Send response to CLI */
void daemon_ipc_send_response(int client_fd, const char* response);

/* ============================================================================
 * DAEMON COMMAND HANDLERS
 * ============================================================================ */

/* Handle command from CLI */
int daemon_handle_command(const char* cmd, char* response, size_t response_size);

/* Individual command handlers */
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

/* ============================================================================
 * DAEMON UTILITIES
 * ============================================================================ */

/* Write PID file */
int daemon_write_pid(void);

/* Read PID file */
int daemon_read_pid(void);

/* Remove PID file */
void daemon_remove_pid(void);

/* Write log message */
void daemon_log(const char* format, ...);

/* ============================================================================
 * DAEMON THREADS
 * ============================================================================ */

/* DHT thread */
void* daemon_dht_thread(void* arg);

/* P2P listener thread */
void* daemon_p2p_thread(void* arg);

/* Event processor thread */
void* daemon_event_thread(void* arg);

/* ============================================================================
 * DAEMON SIGNAL HANDLERS
 * ============================================================================ */

/* Signal handler for daemon */
void daemon_signal_handler(int sig);

/* Setup signal handlers */
int daemon_setup_signals(void);

#endif /* DAEMON_H */
