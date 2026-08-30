#include "parallel_runner.h"
#include "punch.h"
#include "ttl_punch.h"
#include "simultaneous_open.h"
#include "friend_relay.h"
#include "turn_client.h"
#include "upnp_client.h"
#include "port_prediction.h"
#include "nat_classifier.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define PARALLEL_DEBUG 1

#if PARALLEL_DEBUG
#define PLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[PARALLEL] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define PLOG(fmt, ...) ((void)0)
#endif

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================ */

static TaskContext* g_tasks[MAX_STRATEGIES];
static int g_task_count = 0;
static pthread_mutex_t g_task_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_cancelled = false;

/* ============================================================================
 * RESULT STATUS
 * ============================================================================ */

const char* parallel_result_status(ConnectionResult* result) {
    if (!result) return "NULL";
    return result->success ? "SUCCESS" : "FAILED";
}

/* ============================================================================
 * STRATEGY EXECUTORS
 * ============================================================================ */

int execute_ipv6_direct(P2PPeer* peer, ConnectionResult* result) {
    PLOG("Executing IPv6 Direct for %s", peer->id);
    
    if (!peer->has_ipv6 || strlen(peer->ipv6) == 0) {
        result->error_code = -1;
        strcpy(result->error_msg, "IPv6 not available");
        return -1;
    }
    
    /* Create IPv6 socket */
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        result->error_code = errno;
        snprintf(result->error_msg, sizeof(result->error_msg), 
                 "socket failed: %s", strerror(errno));
        return -1;
    }
    
    /* Set timeout */
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    /* Connect to peer via IPv6 */
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(peer->port);
    inet_pton(AF_INET6, peer->ipv6, &addr.sin6_addr);
    
    /* Send test packet */
    const char* test = "ORCA_IPV6_TEST";
    ssize_t sent = sendto(sock, test, strlen(test), 0,
                          (struct sockaddr*)&addr, sizeof(addr));
    if (sent < 0) {
        close(sock);
        result->error_code = errno;
        snprintf(result->error_msg, sizeof(result->error_msg), 
                 "sendto failed: %s", strerror(errno));
        return -1;
    }
    
    /* Wait for response */
    char buffer[256];
    struct sockaddr_in6 from;
    socklen_t from_len = sizeof(from);
    int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                     (struct sockaddr*)&from, &from_len);
    
    if (n > 0 && strcmp(buffer, "ORCA_IPV6_RESPONSE") == 0) {
        result->success = true;
        result->socket_fd = sock;
        inet_ntop(AF_INET6, &from.sin6_addr, result->peer_ip, sizeof(result->peer_ip));
        result->peer_port = ntohs(from.sin6_port);
        PLOG("✅ IPv6 Direct success for %s", peer->id);
        return 0;
    }
    
    close(sock);
    result->error_code = -1;
    strcpy(result->error_msg, "No IPv6 response");
    return -1;
}

int execute_upnp(P2PPeer* peer, ConnectionResult* result) {
    PLOG("Executing UPnP for %s", peer->id);
    
    int port = upnp_add_port_mapping(peer->port);
    if (port > 0) {
        result->success = true;
        result->socket_fd = -1;
        strcpy(result->peer_ip, peer->ip);
        result->peer_port = port;
        PLOG("✅ UPnP success for %s (port %d)", peer->id, port);
        return 0;
    }
    
    result->error_code = -1;
    strcpy(result->error_msg, "UPnP mapping failed");
    return -1;
}

int execute_udp_punch(P2PPeer* peer, ConnectionResult* result) {
    PLOG("Executing UDP Punch for %s", peer->id);
    
    PunchState p;
    if (punch_init(&p, PUNCH_PORT) < 0) {
        result->error_code = -1;
        strcpy(result->error_msg, "Failed to init punch");
        return -1;
    }
    
    int ret = punch_try_connect(&p, peer->ip, peer->port);
    if (ret == 0) {
        result->success = true;
        result->socket_fd = p.udp_socket;
        strcpy(result->peer_ip, p.peer_ip);
        result->peer_port = p.peer_port;
        PLOG("✅ UDP Punch success for %s", peer->id);
        return 0;
    }
    
    punch_close(&p);
    result->error_code = -1;
    strcpy(result->error_msg, "UDP punch failed");
    return -1;
}

int execute_ttl_punch(P2PPeer* peer, ConnectionResult* result) {
    PLOG("Executing TTL Punch for %s", peer->id);
    
    PunchState p;
    if (punch_init(&p, PUNCH_PORT + 1) < 0) {
        result->error_code = -1;
        strcpy(result->error_msg, "Failed to init TTL punch");
        return -1;
    }
    
    int ret = punch_try_ttl(&p, peer->ip, peer->port);
    if (ret == 0) {
        result->success = true;
        result->socket_fd = p.udp_socket;
        strcpy(result->peer_ip, p.peer_ip);
        result->peer_port = p.peer_port;
        PLOG("✅ TTL Punch success for %s", peer->id);
        return 0;
    }
    
    punch_close(&p);
    result->error_code = -1;
    strcpy(result->error_msg, "TTL punch failed");
    return -1;
}

int execute_simultaneous_open(P2PPeer* peer, ConnectionResult* result) {
    PLOG("Executing Simultaneous Open for %s", peer->id);
    
    PunchState p;
    if (punch_init(&p, PUNCH_PORT + 2) < 0) {
        result->error_code = -1;
        strcpy(result->error_msg, "Failed to init simultaneous open");
        return -1;
    }
    
    int ret = punch_try_simultaneous(&p, peer->ip, peer->port);
    if (ret == 0) {
        result->success = true;
        result->socket_fd = p.udp_socket;
        strcpy(result->peer_ip, p.peer_ip);
        result->peer_port = p.peer_port;
        PLOG("✅ Simultaneous Open success for %s", peer->id);
        return 0;
    }
    
    punch_close(&p);
    result->error_code = -1;
    strcpy(result->error_msg, "Simultaneous open failed");
    return -1;
}

int execute_port_prediction(P2PPeer* peer, ConnectionResult* result) {
    PLOG("Executing Port Prediction for %s", peer->id);
    
    PunchState p;
    if (punch_init(&p, PUNCH_PORT + 3) < 0) {
        result->error_code = -1;
        strcpy(result->error_msg, "Failed to init port prediction");
        return -1;
    }
    
    int ret = punch_try_port_prediction(&p, peer->ip, peer->port);
    if (ret == 0) {
        result->success = true;
        result->socket_fd = p.udp_socket;
        strcpy(result->peer_ip, p.peer_ip);
        result->peer_port = p.peer_port;
        PLOG("✅ Port Prediction success for %s", peer->id);
        return 0;
    }
    
    punch_close(&p);
    result->error_code = -1;
    strcpy(result->error_msg, "Port prediction failed");
    return -1;
}

int execute_tcp_punch(P2PPeer* peer, ConnectionResult* result) {
    PLOG("Executing TCP Punch for %s (not fully implemented)", peer->id);
    
    result->error_code = -1;
    strcpy(result->error_msg, "TCP punch not implemented yet");
    return -1;
}

int execute_friend_relay(P2PPeer* peer, ConnectionResult* result) {
    PLOG("Executing Friend Relay for %s", peer->id);
    
    /* TODO: Implement friend relay */
    result->error_code = -1;
    strcpy(result->error_msg, "Friend relay not implemented yet");
    return -1;
}

int execute_turn_relay(P2PPeer* peer, ConnectionResult* result) {
    PLOG("Executing TURN Relay for %s", peer->id);
    
    /* TODO: Implement TURN relay */
    result->error_code = -1;
    strcpy(result->error_msg, "TURN relay not implemented yet");
    return -1;
}

int execute_manual_port(P2PPeer* peer, ConnectionResult* result) {
    PLOG("Executing Manual Port for %s", peer->id);
    
    result->error_code = -1;
    strcpy(result->error_msg, "Manual port not implemented yet");
    return -1;
}

/* ============================================================================
 * EXECUTOR MAP
 * ============================================================================ */

typedef struct {
    StrategyType type;
    int (*executor)(P2PPeer*, ConnectionResult*);
} ExecutorMap;

static ExecutorMap g_executors[] = {
    {STRATEGY_IPV6_DIRECT, execute_ipv6_direct},
    {STRATEGY_UPNP, execute_upnp},
    {STRATEGY_UDP_PUNCH, execute_udp_punch},
    {STRATEGY_TTL_PUNCH, execute_ttl_punch},
    {STRATEGY_SIMULTANEOUS_OPEN, execute_simultaneous_open},
    {STRATEGY_PORT_PREDICTION, execute_port_prediction},
    {STRATEGY_TCP_PUNCH, execute_tcp_punch},
    {STRATEGY_FRIEND_RELAY, execute_friend_relay},
    {STRATEGY_TURN_RELAY, execute_turn_relay},
    {STRATEGY_MANUAL_PORT, execute_manual_port}
};

#define EXECUTOR_COUNT (sizeof(g_executors) / sizeof(ExecutorMap))

static int (*get_executor(StrategyType type))(P2PPeer*, ConnectionResult*) {
    for (int i = 0; i < EXECUTOR_COUNT; i++) {
        if (g_executors[i].type == type) {
            return g_executors[i].executor;
        }
    }
    return NULL;
}

/* ============================================================================
 * TASK MANAGEMENT
 * ============================================================================ */

static void* task_thread(void* arg) {
    TaskContext* task = (TaskContext*)arg;
    if (!task) return NULL;
    
    PLOG("Task started for strategy: %s", strategy_name(task->strategy));
    
    task->result->start_time = time(NULL);
    task->result->strategy = task->strategy;
    
    int (*executor)(P2PPeer*, ConnectionResult*) = get_executor(task->strategy);
    if (executor) {
        int ret = executor(task->peer, task->result);
        task->result->success = (ret == 0);
    } else {
        task->result->success = false;
        strcpy(task->result->error_msg, "No executor found");
    }
    
    task->result->end_time = time(NULL);
    task->result->elapsed_ms = (int)((task->result->end_time - task->result->start_time) * 1000);
    
    PLOG("Task finished for strategy: %s (%s, %dms)",
         strategy_name(task->strategy),
         task->result->success ? "SUCCESS" : "FAILED",
         task->result->elapsed_ms);
    
    return NULL;
}

TaskContext* task_create(StrategyType strategy, P2PPeer* peer, int timeout_ms) {
    TaskContext* task = calloc(1, sizeof(TaskContext));
    if (!task) return NULL;
    
    task->strategy = strategy;
    task->peer = peer;
    task->timeout_ms = timeout_ms;
    task->cancelled = false;
    task->result = calloc(1, sizeof(ConnectionResult));
    pthread_mutex_init(&task->mutex, NULL);
    
    return task;
}

int task_start(TaskContext* task) {
    if (!task) return -1;
    
    pthread_mutex_lock(&g_task_mutex);
    g_tasks[g_task_count++] = task;
    pthread_mutex_unlock(&g_task_mutex);
    
    return pthread_create(&task->thread, NULL, task_thread, task);
}

int task_wait(TaskContext* task, ConnectionResult* result) {
    if (!task || !result) return -1;
    
    pthread_join(task->thread, NULL);
    memcpy(result, task->result, sizeof(ConnectionResult));
    
    return result->success ? 0 : -1;
}

void task_cancel(TaskContext* task) {
    if (!task) return;
    
    pthread_mutex_lock(&task->mutex);
    task->cancelled = true;
    pthread_mutex_unlock(&task->mutex);
    
    /* TODO: Cancel the thread properly */
}

void task_free(TaskContext* task) {
    if (!task) return;
    
    free(task->result);
    pthread_mutex_destroy(&task->mutex);
    free(task);
}

/* ============================================================================
 * PARALLEL RUN
 * ============================================================================ */

int parallel_run(const StrategyList* strategies, P2PPeer* peer, ConnectionResult* result) {
    if (!strategies || !peer || !result) return -1;
    
    PLOG("Starting parallel run with %d strategies", strategies->count);
    
    if (strategies->count == 0) {
        PLOG("No strategies to run");
        return -1;
    }
    
    g_cancelled = false;
    
    /* Create and start tasks */
    TaskContext* tasks[MAX_STRATEGIES];
    int task_count = 0;
    
    for (int i = 0; i < strategies->count && i < MAX_STRATEGIES; i++) {
        StrategyType type = strategies->strategies[i];
        StrategyInfo info = strategy_get_info(type);
        
        TaskContext* task = task_create(type, peer, info.max_wait_ms);
        if (!task) continue;
        
        if (task_start(task) == 0) {
            tasks[task_count++] = task;
            PLOG("Started task %d: %s", i, strategy_name(type));
        } else {
            task_free(task);
        }
    }
    
    if (task_count == 0) {
        PLOG("No tasks started");
        return -1;
    }
    
    /* Wait for any task to complete */
    int completed = 0;
    int success_index = -1;
    
    while (completed < task_count && success_index < 0 && !g_cancelled) {
        for (int i = 0; i < task_count; i++) {
            if (!tasks[i]) continue;
            
            /* Check if task is done */
            if (tasks[i]->result->success || tasks[i]->result->error_code != 0) {
                completed++;
                if (tasks[i]->result->success) {
                    success_index = i;
                }
                break;
            }
        }
        
        if (success_index < 0) {
            usleep(100000); /* 100ms */
        }
    }
    
    /* Cancel all other tasks */
    for (int i = 0; i < task_count; i++) {
        if (i != success_index && tasks[i]) {
            task_cancel(tasks[i]);
        }
    }
    
    /* Wait for all tasks to finish */
    for (int i = 0; i < task_count; i++) {
        if (tasks[i]) {
            pthread_join(tasks[i]->thread, NULL);
        }
    }
    
    /* Get result */
    if (success_index >= 0 && tasks[success_index]) {
        memcpy(result, tasks[success_index]->result, sizeof(ConnectionResult));
        PLOG("✅ Parallel run success with strategy: %s", strategy_name(result->strategy));
        
        /* Free all tasks */
        for (int i = 0; i < task_count; i++) {
            if (tasks[i]) task_free(tasks[i]);
        }
        return 0;
    }
    
    /* All failed - return best result */
    if (task_count > 0 && tasks[0]) {
        memcpy(result, tasks[0]->result, sizeof(ConnectionResult));
    }
    
    PLOG("❌ Parallel run failed");
    for (int i = 0; i < task_count; i++) {
        if (tasks[i]) task_free(tasks[i]);
    }
    return -1;
}

int parallel_run_single(StrategyType strategy, P2PPeer* peer, ConnectionResult* result) {
    StrategyList list;
    list.count = 1;
    list.strategies[0] = strategy;
    return parallel_run(&list, peer, result);
}

void parallel_cancel_all(void) {
    g_cancelled = true;
}

/* ============================================================================
 * DEBUG
 * ============================================================================ */

void parallel_debug_print(const ConnectionResult* result) {
    if (!result) {
        printf("Result is NULL\n");
        return;
    }
    
    printf("\n=== CONNECTION RESULT ===\n");
    printf("Strategy: %s\n", strategy_name(result->strategy));
    printf("Success: %s\n", result->success ? "YES" : "NO");
    printf("Socket FD: %d\n", result->socket_fd);
    printf("Peer: %s:%d\n", result->peer_ip, result->peer_port);
    printf("Error Code: %d\n", result->error_code);
    printf("Error Message: %s\n", result->error_msg);
    printf("Start Time: %s", ctime(&result->start_time));
    printf("End Time: %s", ctime(&result->end_time));
    printf("Elapsed: %d ms\n", result->elapsed_ms);
    printf("==========================\n");
}

/* ============================================================================
 * TEST FUNCTION
 * ============================================================================ */

#ifdef PARALLEL_TEST

int main() {
    printf("=== Parallel Runner Test ===\n");
    
    P2PPeer peer;
    memset(&peer, 0, sizeof(peer));
    strcpy(peer.id, "test_peer");
    strcpy(peer.ip, "127.0.0.1");
    peer.port = 9000;
    peer.has_ipv6 = true;
    strcpy(peer.ipv6, "::1");
    
    StrategyList list;
    list.count = 3;
    list.strategies[0] = STRATEGY_IPV6_DIRECT;
    list.strategies[1] = STRATEGY_UDP_PUNCH;
    list.strategies[2] = STRATEGY_TTL_PUNCH;
    
    ConnectionResult result;
    memset(&result, 0, sizeof(result));
    
    int ret = parallel_run(&list, &peer, &result);
    printf("\nParallel run result: %d\n", ret);
    parallel_debug_print(&result);
    
    return 0;
}

#endif /* PARALLEL_TEST */
