#ifndef PARALLEL_RUNNER_H
#define PARALLEL_RUNNER_H

#include <stdbool.h>
#include <pthread.h>
#include <time.h>
#include "strategy_selector.h"
#include "p2p_manager.h"

/* ============================================================================
 * CONNECTION RESULT
 * ============================================================================ */

typedef struct {
    StrategyType strategy;
    bool success;
    int socket_fd;
    char peer_ip[INET_ADDRSTRLEN];
    int peer_port;
    int error_code;
    char error_msg[256];
    time_t start_time;
    time_t end_time;
    int elapsed_ms;
} ConnectionResult;

/* ============================================================================
 * TASK CONTEXT
 * ============================================================================ */

typedef struct {
    StrategyType strategy;
    P2PPeer* peer;
    ConnectionResult* result;
    int timeout_ms;
    bool cancelled;
    pthread_t thread;
    pthread_mutex_t mutex;
} TaskContext;

/* ============================================================================
 * PARALLEL RUNNER FUNCTIONS
 * ============================================================================ */

/* Run strategies in parallel */
int parallel_run(const StrategyList* strategies, P2PPeer* peer, ConnectionResult* result);

/* Run a single strategy */
int parallel_run_single(StrategyType strategy, P2PPeer* peer, ConnectionResult* result);

/* Cancel all running tasks */
void parallel_cancel_all(void);

/* ============================================================================
 * TASK MANAGEMENT
 * ============================================================================ */

/* Create a task for a strategy */
TaskContext* task_create(StrategyType strategy, P2PPeer* peer, int timeout_ms);

/* Start a task */
int task_start(TaskContext* task);

/* Wait for a task to complete */
int task_wait(TaskContext* task, ConnectionResult* result);

/* Cancel a task */
void task_cancel(TaskContext* task);

/* Free a task */
void task_free(TaskContext* task);

/* ============================================================================
 * STRATEGY EXECUTORS
 * ============================================================================ */

/* Execute a specific strategy */
int execute_ipv6_direct(P2PPeer* peer, ConnectionResult* result);
int execute_upnp(P2PPeer* peer, ConnectionResult* result);
int execute_udp_punch(P2PPeer* peer, ConnectionResult* result);
int execute_ttl_punch(P2PPeer* peer, ConnectionResult* result);
int execute_simultaneous_open(P2PPeer* peer, ConnectionResult* result);
int execute_port_prediction(P2PPeer* peer, ConnectionResult* result);
int execute_tcp_punch(P2PPeer* peer, ConnectionResult* result);
int execute_friend_relay(P2PPeer* peer, ConnectionResult* result);
int execute_turn_relay(P2PPeer* peer, ConnectionResult* result);
int execute_manual_port(P2PPeer* peer, ConnectionResult* result);

/* ============================================================================
 * DEBUG
 * ============================================================================ */

void parallel_debug_print(const ConnectionResult* result);
const char* parallel_result_status(ConnectionResult* result);

#endif /* PARALLEL_RUNNER_H */
