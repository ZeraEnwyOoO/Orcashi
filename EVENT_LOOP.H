#ifndef EVENT_LOOP_H
#define EVENT_LOOP_H

#include <stdbool.h>
#include <time.h>
#include "state_manager.h"

/* ============================================================================
 * EVENT TYPES
 * ============================================================================ */

typedef enum {
    EVENT_NONE = 0,
    EVENT_ADD_REQUEST,        /* Peer sent ADD_REQUEST */
    EVENT_ACCEPT_CONFIRM,     /* Peer accepted request */
    EVENT_REJECT_CONFIRM,     /* Peer rejected request */
    EVENT_MESSAGE_RECEIVED,   /* New message from peer */
    EVENT_PEER_ONLINE,        /* Peer came online */
    EVENT_PEER_OFFLINE,       /* Peer went offline */
    EVENT_GHOST_DELIVERED,    /* Ghost message delivered */
    EVENT_STATUS_UPDATE,      /* Peer status changed */
    EVENT_DHT_FOUND,          /* DHT found peer */
    EVENT_DHT_NOT_FOUND,      /* DHT didn't find peer */
    EVENT_ERROR               /* Error occurred */
} EventType;

/* ============================================================================
 * EVENT STRUCTURE
 * ============================================================================ */

typedef struct {
    EventType type;
    char peer_id[64];
    char from_id[64];
    char to_id[64];
    char message[4096];
    char ip[INET_ADDRSTRLEN];
    int port;
    time_t timestamp;
    bool is_secure;
    void* data;  /* Extra data */
    size_t data_len;
} Event;

/* ============================================================================
 * EVENT LOOP FUNCTIONS
 * ============================================================================ */

/* Initialize event loop */
int event_loop_init(void);

/* Start event loop (runs in thread) */
void* event_loop_run(void* arg);

/* Stop event loop */
void event_loop_stop(void);

/* ============================================================================
 * EVENT QUEUE
 * ============================================================================ */

/* Push event to queue (async) */
int event_queue_push(const Event* event);

/* Pop event from queue (blocking) */
int event_queue_pop(Event* event, int timeout_ms);

/* Check if queue has events */
bool event_queue_has_events(void);

/* Get queue size */
int event_queue_size(void);

/* ============================================================================
 * EVENT HANDLERS
 * ============================================================================ */

/* Process a single event */
int event_process(const Event* event);

/* Individual event handlers */
int event_handle_add_request(const Event* event);
int event_handle_accept_confirm(const Event* event);
int event_handle_reject_confirm(const Event* event);
int event_handle_message_received(const Event* event);
int event_handle_peer_online(const Event* event);
int event_handle_peer_offline(const Event* event);
int event_handle_ghost_delivered(const Event* event);
int event_handle_status_update(const Event* event);
int event_handle_dht_found(const Event* event);
int event_handle_dht_not_found(const Event* event);
int event_handle_error(const Event* event);

/* ============================================================================
 * EVENT NOTIFICATIONS
 * ============================================================================ */

/* Notify CLI about event */
void event_notify_cli(const char* format, ...);

/* Notify P2P about event */
void event_notify_p2p(const Event* event);

/* Notify DHT about event */
void event_notify_dht(const Event* event);

/* ============================================================================
 * EVENT UTILITIES
 * ============================================================================ */

/* Convert event type to string */
const char* event_type_to_string(EventType type);

/* Create event */
Event event_create(EventType type, const char* peer_id);

/* Copy event */
void event_copy(Event* dest, const Event* src);

/* Free event data */
void event_free(Event* event);

#endif /* EVENT_LOOP_H */
