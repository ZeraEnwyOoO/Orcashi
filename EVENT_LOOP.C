#include "event_loop.h"
#include "state_manager.h"
#include "p2p_manager.h"
#include "dht_node.h"
#include "mixed_id.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>

#define EVENT_QUEUE_SIZE 1024
#define EVENT_LOOP_DEBUG 1

#if EVENT_LOOP_DEBUG
#define ELOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[EVENT] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define ELOG(fmt, ...) ((void)0)
#endif

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================ */

static Event g_event_queue[EVENT_QUEUE_SIZE];
static int g_queue_head = 0;
static int g_queue_tail = 0;
static int g_queue_count = 0;
static pthread_mutex_t g_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_queue_cond = PTHREAD_COND_INITIALIZER;
static bool g_running = false;
static pthread_t g_event_thread = 0;

/* ============================================================================
 * EVENT QUEUE
 * ============================================================================ */

int event_queue_push(const Event* event) {
    if (!event) return -1;
    
    pthread_mutex_lock(&g_queue_mutex);
    
    if (g_queue_count >= EVENT_QUEUE_SIZE) {
        ELOG("Queue full, dropping event");
        pthread_mutex_unlock(&g_queue_mutex);
        return -1;
    }
    
    g_event_queue[g_queue_tail] = *event;
    g_queue_tail = (g_queue_tail + 1) % EVENT_QUEUE_SIZE;
    g_queue_count++;
    
    pthread_cond_signal(&g_queue_cond);
    pthread_mutex_unlock(&g_queue_mutex);
    
    return 0;
}

int event_queue_pop(Event* event, int timeout_ms) {
    if (!event) return -1;
    
    pthread_mutex_lock(&g_queue_mutex);
    
    while (g_queue_count == 0 && g_running) {
        if (timeout_ms > 0) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += timeout_ms / 1000;
            ts.tv_nsec += (timeout_ms % 1000) * 1000000;
            if (ts.tv_nsec >= 1000000000) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000;
            }
            int ret = pthread_cond_timedwait(&g_queue_cond, &g_queue_mutex, &ts);
            if (ret == ETIMEDOUT) {
                pthread_mutex_unlock(&g_queue_mutex);
                return -1;
            }
        } else {
            pthread_cond_wait(&g_queue_cond, &g_queue_mutex);
        }
    }
    
    if (g_queue_count == 0) {
        pthread_mutex_unlock(&g_queue_mutex);
        return -1;
    }
    
    *event = g_event_queue[g_queue_head];
    g_queue_head = (g_queue_head + 1) % EVENT_QUEUE_SIZE;
    g_queue_count--;
    
    pthread_mutex_unlock(&g_queue_mutex);
    return 0;
}

bool event_queue_has_events(void) {
    pthread_mutex_lock(&g_queue_mutex);
    bool has = g_queue_count > 0;
    pthread_mutex_unlock(&g_queue_mutex);
    return has;
}

int event_queue_size(void) {
    pthread_mutex_lock(&g_queue_mutex);
    int size = g_queue_count;
    pthread_mutex_unlock(&g_queue_mutex);
    return size;
}

/* ============================================================================
 * EVENT HANDLERS
 * ============================================================================ */

const char* event_type_to_string(EventType type) {
    switch (type) {
        case EVENT_ADD_REQUEST: return "ADD_REQUEST";
        case EVENT_ACCEPT_CONFIRM: return "ACCEPT_CONFIRM";
        case EVENT_REJECT_CONFIRM: return "REJECT_CONFIRM";
        case EVENT_MESSAGE_RECEIVED: return "MESSAGE_RECEIVED";
        case EVENT_PEER_ONLINE: return "PEER_ONLINE";
        case EVENT_PEER_OFFLINE: return "PEER_OFFLINE";
        case EVENT_GHOST_DELIVERED: return "GHOST_DELIVERED";
        case EVENT_STATUS_UPDATE: return "STATUS_UPDATE";
        case EVENT_DHT_FOUND: return "DHT_FOUND";
        case EVENT_DHT_NOT_FOUND: return "DHT_NOT_FOUND";
        case EVENT_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

Event event_create(EventType type, const char* peer_id) {
    Event event;
    memset(&event, 0, sizeof(event));
    event.type = type;
    event.timestamp = time(NULL);
    if (peer_id) {
        strncpy(event.peer_id, peer_id, sizeof(event.peer_id) - 1);
        event.peer_id[sizeof(event.peer_id) - 1] = '\0';
    }
    return event;
}

void event_copy(Event* dest, const Event* src) {
    if (!dest || !src) return;
    *dest = *src;
}

void event_free(Event* event) {
    if (!event) return;
    if (event->data) {
        free(event->data);
        event->data = NULL;
    }
    memset(event, 0, sizeof(Event));
}

/* ============================================================================
 * EVENT HANDLERS
 * ============================================================================ */

int event_handle_add_request(const Event* event) {
    if (!event) return -1;
    
    ELOG("Handling ADD_REQUEST from %s", event->from_id);
    
    /* Update state */
    state_update_peer(event->from_id, PEER_REQUEST_RECEIVED);
    state_set_ip(event->from_id, event->ip);
    state_set_port(event->from_id, event->port);
    
    /* Notify CLI */
    event_notify_cli("[ORCA] Friend request from %s (%s:%d)\n",
                     event->from_id, event->ip, event->port);
    event_notify_cli("[ORCA] Use './orcashi accept %s' to accept\n",
                     event->from_id);
    event_notify_cli("[ORCA] Use './orcashi reject %s' to reject\n",
                     event->from_id);
    
    return 0;
}

int event_handle_accept_confirm(const Event* event) {
    if (!event) return -1;
    
    ELOG("Handling ACCEPT_CONFIRM from %s", event->from_id);
    
    /* Update state */
    state_update_peer(event->from_id, PEER_FRIEND);
    state_set_online(event->from_id, true);
    state_set_ip(event->from_id, event->ip);
    state_set_port(event->from_id, event->port);
    
    /* Deliver ghost messages */
    int ghost_count = state_deliver_ghost_messages(event->from_id);
    if (ghost_count > 0) {
        ELOG("Delivered %d ghost messages to %s", ghost_count, event->from_id);
        event_notify_cli("[ORCA] Delivered %d ghost messages to %s\n",
                         ghost_count, event->from_id);
    }
    
    /* Notify CLI */
    event_notify_cli("[ORCA] %s accepted your request!\n", event->from_id);
    event_notify_cli("[ORCA] Friendship with %s is now accepted.\n", event->from_id);
    event_notify_cli("[ORCA] Use './orcashi chat %s' to start chatting.\n", event->from_id);
    
    return 0;
}

int event_handle_reject_confirm(const Event* event) {
    if (!event) return -1;
    
    ELOG("Handling REJECT_CONFIRM from %s", event->from_id);
    
    /* Update state */
    state_remove_peer(event->from_id);
    
    /* Notify CLI */
    event_notify_cli("[ORCA] %s rejected your request.\n", event->from_id);
    
    return 0;
}

int event_handle_message_received(const Event* event) {
    if (!event) return -1;
    
    ELOG("Message from %s: %s", event->from_id, event->message);
    
    /* Update state */
    state_set_online(event->from_id, true);
    state_update_last_seen(event->from_id);
    
    /* Store message */
    state_add_message(event->from_id, event->message);
    
    /* Notify CLI (if chat is active) */
    event_notify_cli("[%s] %s\n", event->from_id, event->message);
    
    return 0;
}

int event_handle_peer_online(const Event* event) {
    if (!event) return -1;
    
    ELOG("Peer %s is online", event->peer_id);
    
    /* Update state */
    state_set_online(event->peer_id, true);
    state_set_ip(event->peer_id, event->ip);
    state_set_port(event->peer_id, event->port);
    
    /* Deliver ghost messages */
    int ghost_count = state_deliver_ghost_messages(event->peer_id);
    if (ghost_count > 0) {
        ELOG("Delivered %d ghost messages to %s", ghost_count, event->peer_id);
        event_notify_cli("[ORCA] Delivered %d ghost messages to %s\n",
                         ghost_count, event->peer_id);
    }
    
    /* Notify CLI */
    event_notify_cli("[ORCA] %s is now online!\n", event->peer_id);
    
    return 0;
}

int event_handle_peer_offline(const Event* event) {
    if (!event) return -1;
    
    ELOG("Peer %s is offline", event->peer_id);
    
    /* Update state */
    state_set_online(event->peer_id, false);
    
    /* Notify CLI */
    event_notify_cli("[ORCA] %s went offline.\n", event->peer_id);
    
    return 0;
}

int event_handle_ghost_delivered(const Event* event) {
    if (!event) return -1;
    
    ELOG("Ghost message delivered to %s", event->to_id);
    
    /* Notify CLI */
    event_notify_cli("[ORCA] Ghost message delivered to %s\n", event->to_id);
    
    return 0;
}

int event_handle_status_update(const Event* event) {
    if (!event) return -1;
    
    ELOG("Status update for %s", event->peer_id);
    
    /* Update state */
    if (strlen(event->ip) > 0) {
        state_set_ip(event->peer_id, event->ip);
    }
    if (event->port > 0) {
        state_set_port(event->peer_id, event->port);
    }
    if (event->is_secure) {
        state_set_secure(event->peer_id, true);
    }
    
    return 0;
}

int event_handle_dht_found(const Event* event) {
    if (!event) return -1;
    
    ELOG("DHT found peer %s at %s:%d", event->peer_id, event->ip, event->port);
    
    /* Update state */
    state_set_ip(event->peer_id, event->ip);
    state_set_port(event->peer_id, event->port);
    state_set_online(event->peer_id, true);
    
    return 0;
}

int event_handle_dht_not_found(const Event* event) {
    if (!event) return -1;
    
    ELOG("DHT did not find peer %s", event->peer_id);
    
    /* Update state */
    state_set_online(event->peer_id, false);
    
    return 0;
}

int event_handle_error(const Event* event) {
    if (!event) return -1;
    
    ELOG("Error: %s", event->message);
    
    /* Notify CLI */
    event_notify_cli("[ERROR] %s\n", event->message);
    
    return 0;
}

/* ============================================================================
 * EVENT PROCESSOR
 * ============================================================================ */

int event_process(const Event* event) {
    if (!event) return -1;
    
    ELOG("Processing event: %s", event_type_to_string(event->type));
    
    switch (event->type) {
        case EVENT_ADD_REQUEST:
            return event_handle_add_request(event);
        case EVENT_ACCEPT_CONFIRM:
            return event_handle_accept_confirm(event);
        case EVENT_REJECT_CONFIRM:
            return event_handle_reject_confirm(event);
        case EVENT_MESSAGE_RECEIVED:
            return event_handle_message_received(event);
        case EVENT_PEER_ONLINE:
            return event_handle_peer_online(event);
        case EVENT_PEER_OFFLINE:
            return event_handle_peer_offline(event);
        case EVENT_GHOST_DELIVERED:
            return event_handle_ghost_delivered(event);
        case EVENT_STATUS_UPDATE:
            return event_handle_status_update(event);
        case EVENT_DHT_FOUND:
            return event_handle_dht_found(event);
        case EVENT_DHT_NOT_FOUND:
            return event_handle_dht_not_found(event);
        case EVENT_ERROR:
            return event_handle_error(event);
        default:
            ELOG("Unknown event type: %d", event->type);
            return -1;
    }
}

/* ============================================================================
 * EVENT NOTIFICATIONS
 * ============================================================================ */

void event_notify_cli(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    fflush(stdout);
    va_end(args);
}

void event_notify_p2p(const Event* event) {
    (void)event;
    /* TODO: Notify P2P manager about event */
}

void event_notify_dht(const Event* event) {
    (void)event;
    /* TODO: Notify DHT about event */
}

/* ============================================================================
 * EVENT LOOP
 * ============================================================================ */

int event_loop_init(void) {
    ELOG("Initializing event loop");
    g_running = true;
    return 0;
}

void* event_loop_run(void* arg) {
    (void)arg;
    
    ELOG("Event loop started");
    
    while (g_running) {
        Event event;
        int ret = event_queue_pop(&event, 1000);
        if (ret == 0) {
            event_process(&event);
            event_free(&event);
        }
        
        /* Periodic tasks */
        /* TODO: Check DHT, P2P, etc. */
    }
    
    ELOG("Event loop stopped");
    return NULL;
}

void event_loop_stop(void) {
    ELOG("Stopping event loop");
    g_running = false;
    pthread_cond_broadcast(&g_queue_cond);
    
    if (g_event_thread) {
        pthread_join(g_event_thread, NULL);
        g_event_thread = 0;
    }
}

/* ============================================================================
 * EXTERNAL EVENT TRIGGERS
 * ============================================================================ */

/* These functions are called from DHT, P2P, etc. to push events */

int event_trigger_add_request(const char* from_id, const char* ip, int port) {
    Event event = event_create(EVENT_ADD_REQUEST, from_id);
    strcpy(event.from_id, from_id);
    strcpy(event.ip, ip);
    event.port = port;
    return event_queue_push(&event);
}

int event_trigger_accept_confirm(const char* from_id, const char* ip, int port) {
    Event event = event_create(EVENT_ACCEPT_CONFIRM, from_id);
    strcpy(event.from_id, from_id);
    strcpy(event.ip, ip);
    event.port = port;
    return event_queue_push(&event);
}

int event_trigger_message_received(const char* from_id, const char* message) {
    Event event = event_create(EVENT_MESSAGE_RECEIVED, from_id);
    strcpy(event.from_id, from_id);
    strcpy(event.message, message);
    return event_queue_push(&event);
}

int event_trigger_peer_online(const char* peer_id, const char* ip, int port) {
    Event event = event_create(EVENT_PEER_ONLINE, peer_id);
    strcpy(event.ip, ip);
    event.port = port;
    return event_queue_push(&event);
}

int event_trigger_peer_offline(const char* peer_id) {
    Event event = event_create(EVENT_PEER_OFFLINE, peer_id);
    return event_queue_push(&event);
}
