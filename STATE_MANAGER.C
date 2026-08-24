#include "state_manager.h"
#include "event_loop.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>

#define STATE_FILE "/tmp/.orcashi/state.json"
#define MAX_PEERS 256
#define MAX_GHOST_MESSAGES 1024
#define MAX_MESSAGES 4096

#define STATE_DEBUG 1

#if STATE_DEBUG
#define SLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[STATE] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define SLOG(fmt, ...) ((void)0)
#endif

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================ */

static Peer g_peers[MAX_PEERS];
static int g_peer_count = 0;

static GhostMessage g_ghost_messages[MAX_GHOST_MESSAGES];
static int g_ghost_count = 0;

static char g_messages[MAX_MESSAGES][4096];
static int g_message_count = 0;

static pthread_mutex_t g_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_initialized = false;

/* ============================================================================
 * UTILITY
 * ============================================================================ */

const char* state_to_string(PeerState state) {
    switch (state) {
        case PEER_UNKNOWN: return "unknown";
        case PEER_REQUEST_SENT: return "request_sent";
        case PEER_REQUEST_RECEIVED: return "request_received";
        case PEER_FRIEND: return "friend";
        case PEER_ONLINE: return "online";
        case PEER_OFFLINE: return "offline";
        case PEER_BUSY: return "busy";
        case PEER_GHOST: return "ghost";
        default: return "unknown";
    }
}

static void normalize_id(const char* input, char* output, size_t size) {
    if (!input || !output || size == 0) return;
    
    size_t i = 0, j = 0;
    size_t len = strlen(input);
    
    for (i = 0; i < len && j < size - 1; i++) {
        if (input[i] != '<' && input[i] != '>') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

static bool is_same_id(const char* id1, const char* id2) {
    if (!id1 || !id2) return false;
    
    char n1[64], n2[64];
    normalize_id(id1, n1, sizeof(n1));
    normalize_id(id2, n2, sizeof(n2));
    
    return strcmp(n1, n2) == 0;
}

/* ============================================================================
 * INIT / LOAD / SAVE
 * ============================================================================ */

int state_init(void) {
    pthread_mutex_lock(&g_state_mutex);
    
    if (g_initialized) {
        pthread_mutex_unlock(&g_state_mutex);
        return 0;
    }
    
    SLOG("Initializing state manager");
    
    memset(g_peers, 0, sizeof(g_peers));
    g_peer_count = 0;
    memset(g_ghost_messages, 0, sizeof(g_ghost_messages));
    g_ghost_count = 0;
    memset(g_messages, 0, sizeof(g_messages));
    g_message_count = 0;
    
    g_initialized = true;
    
    pthread_mutex_unlock(&g_state_mutex);
    
    /* Load from disk */
    state_load();
    
    return 0;
}

int state_save(void) {
    pthread_mutex_lock(&g_state_mutex);
    
    SLOG("Saving state...");
    
    FILE* f = fopen(STATE_FILE, "w");
    if (!f) {
        SLOG("Failed to save state: %s", strerror(errno));
        pthread_mutex_unlock(&g_state_mutex);
        return -1;
    }
    
    fprintf(f, "{\n");
    fprintf(f, "  \"version\": 1,\n");
    fprintf(f, "  \"peers\": [\n");
    
    for (int i = 0; i < g_peer_count; i++) {
        Peer* p = &g_peers[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": \"%s\",\n", p->id);
        fprintf(f, "      \"state\": %d,\n", p->state);
        fprintf(f, "      \"online\": %s,\n", p->online ? "true" : "false");
        fprintf(f, "      \"busy\": %s,\n", p->busy ? "true" : "false");
        fprintf(f, "      \"ip\": \"%s\",\n", p->ip);
        fprintf(f, "      \"port\": %d,\n", p->port);
        fprintf(f, "      \"last_seen\": %ld,\n", (long)p->last_seen);
        fprintf(f, "      \"created_at\": %ld,\n", (long)p->created_at);
        fprintf(f, "      \"friend_since\": %ld,\n", (long)p->friend_since);
        fprintf(f, "      \"pending_messages\": %d,\n", p->pending_messages);
        fprintf(f, "      \"ghost_count\": %d\n", p->ghost_count);
        fprintf(f, "    }");
        if (i < g_peer_count - 1) fprintf(f, ",");
        fprintf(f, "\n");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    
    SLOG("State saved (%d peers)", g_peer_count);
    
    pthread_mutex_unlock(&g_state_mutex);
    return 0;
}

int state_load(void) {
    pthread_mutex_lock(&g_state_mutex);
    
    SLOG("Loading state...");
    
    FILE* f = fopen(STATE_FILE, "r");
    if (!f) {
        SLOG("No state file found, starting fresh");
        pthread_mutex_unlock(&g_state_mutex);
        return 0;
    }
    
    char line[4096];
    Peer peer;
    bool in_peer = false;
    int loaded = 0;
    
    memset(&peer, 0, sizeof(peer));
    
    while (fgets(line, sizeof(line), f)) {
        if (strlen(line) <= 1) continue;
        
        if (strstr(line, "{") != NULL) {
            memset(&peer, 0, sizeof(peer));
            in_peer = true;
            continue;
        }
        
        if (!in_peer) continue;
        
        char id[64], ip[64];
        int state = 0, online = 0, busy = 0, port = 0;
        long last_seen = 0, created_at = 0, friend_since = 0;
        int pending_messages = 0, ghost_count = 0;
        
        if (sscanf(line, " \"id\": \"%63[^\"]\"", id) == 1) {
            strcpy(peer.id, id);
        }
        if (sscanf(line, " \"state\": %d", &state) == 1) {
            peer.state = state;
        }
        if (sscanf(line, " \"online\": %d", &online) == 1) {
            peer.online = online;
        }
        if (sscanf(line, " \"busy\": %d", &busy) == 1) {
            peer.busy = busy;
        }
        if (sscanf(line, " \"ip\": \"%63[^\"]\"", ip) == 1) {
            strcpy(peer.ip, ip);
        }
        if (sscanf(line, " \"port\": %d", &port) == 1) {
            peer.port = port;
        }
        if (sscanf(line, " \"last_seen\": %ld", &last_seen) == 1) {
            peer.last_seen = last_seen;
        }
        if (sscanf(line, " \"created_at\": %ld", &created_at) == 1) {
            peer.created_at = created_at;
        }
        if (sscanf(line, " \"friend_since\": %ld", &friend_since) == 1) {
            peer.friend_since = friend_since;
        }
        if (sscanf(line, " \"pending_messages\": %d", &pending_messages) == 1) {
            peer.pending_messages = pending_messages;
        }
        if (sscanf(line, " \"ghost_count\": %d", &ghost_count) == 1) {
            peer.ghost_count = ghost_count;
        }
        
        if (strstr(line, "}") != NULL) {
            if (strlen(peer.id) > 0 && g_peer_count < MAX_PEERS) {
                g_peers[g_peer_count++] = peer;
                loaded++;
            }
            in_peer = false;
            memset(&peer, 0, sizeof(peer));
        }
    }
    
    fclose(f);
    
    SLOG("Loaded %d peers", loaded);
    
    pthread_mutex_unlock(&g_state_mutex);
    return g_peer_count;
}

/* ============================================================================
 * PEER OPERATIONS
 * ============================================================================ */

int state_add_peer(const char* id) {
    if (!id) return -1;
    
    char norm_id[64];
    normalize_id(id, norm_id, sizeof(norm_id));
    if (strlen(norm_id) == 0) return -1;
    
    pthread_mutex_lock(&g_state_mutex);
    
    /* Check if exists */
    for (int i = 0; i < g_peer_count; i++) {
        if (is_same_id(g_peers[i].id, norm_id)) {
            pthread_mutex_unlock(&g_state_mutex);
            return 0;
        }
    }
    
    if (g_peer_count >= MAX_PEERS) {
        pthread_mutex_unlock(&g_state_mutex);
        return -1;
    }
    
    Peer* p = &g_peers[g_peer_count++];
    strcpy(p->id, norm_id);
    p->state = PEER_UNKNOWN;
    p->online = false;
    p->busy = false;
    p->is_secure = false;
    p->port = 0;
    p->created_at = time(NULL);
    p->last_seen = time(NULL);
    p->pending_messages = 0;
    p->ghost_count = 0;
    strcpy(p->ip, "");
    strcpy(p->public_key, "");
    strcpy(p->name, "");
    
    SLOG("Added peer %s", norm_id);
    
    pthread_mutex_unlock(&g_state_mutex);
    return 0;
}

int state_update_peer(const char* id, PeerState state) {
    if (!id) return -1;
    
    char norm_id[64];
    normalize_id(id, norm_id, sizeof(norm_id));
    if (strlen(norm_id) == 0) return -1;
    
    pthread_mutex_lock(&g_state_mutex);
    
    for (int i = 0; i < g_peer_count; i++) {
        if (is_same_id(g_peers[i].id, norm_id)) {
            g_peers[i].state = state;
            g_peers[i].last_seen = time(NULL);
            
            if (state == PEER_FRIEND) {
                g_peers[i].friend_since = time(NULL);
            }
            
            SLOG("Updated peer %s to state %s", norm_id, state_to_string(state));
            pthread_mutex_unlock(&g_state_mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&g_state_mutex);
    return -1;
}

int state_remove_peer(const char* id) {
    if (!id) return -1;
    
    char norm_id[64];
    normalize_id(id, norm_id, sizeof(norm_id));
    if (strlen(norm_id) == 0) return -1;
    
    pthread_mutex_lock(&g_state_mutex);
    
    for (int i = 0; i < g_peer_count; i++) {
        if (is_same_id(g_peers[i].id, norm_id)) {
            for (int j = i; j < g_peer_count - 1; j++) {
                g_peers[j] = g_peers[j + 1];
            }
            g_peer_count--;
            SLOG("Removed peer %s", norm_id);
            pthread_mutex_unlock(&g_state_mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&g_state_mutex);
    return -1;
}

Peer* state_get_peer(const char* id) {
    if (!id) return NULL;
    
    char norm_id[64];
    normalize_id(id, norm_id, sizeof(norm_id));
    if (strlen(norm_id) == 0) return NULL;
    
    pthread_mutex_lock(&g_state_mutex);
    
    for (int i = 0; i < g_peer_count; i++) {
        if (is_same_id(g_peers[i].id, norm_id)) {
            pthread_mutex_unlock(&g_state_mutex);
            return &g_peers[i];
        }
    }
    
    pthread_mutex_unlock(&g_state_mutex);
    return NULL;
}

int state_get_peers(Peer* out, int max) {
    if (!out || max <= 0) return 0;
    
    pthread_mutex_lock(&g_state_mutex);
    
    int count = 0;
    for (int i = 0; i < g_peer_count && count < max; i++) {
        out[count++] = g_peers[i];
    }
    
    pthread_mutex_unlock(&g_state_mutex);
    return count;
}

int state_get_count(void) {
    pthread_mutex_lock(&g_state_mutex);
    int count = g_peer_count;
    pthread_mutex_unlock(&g_state_mutex);
    return count;
}

/* ============================================================================
 * PEER QUERIES
 * ============================================================================ */

bool state_is_online(const char* id) {
    Peer* p = state_get_peer(id);
    return p && p->online;
}

bool state_is_friend(const char* id) {
    Peer* p = state_get_peer(id);
    return p && p->state == PEER_FRIEND;
}

bool state_is_busy(const char* id) {
    Peer* p = state_get_peer(id);
    return p && p->busy;
}

PeerState state_get_state(const char* id) {
    Peer* p = state_get_peer(id);
    return p ? p->state : PEER_UNKNOWN;
}

/* ============================================================================
 * PEER FIELD UPDATES
 * ============================================================================ */

int state_set_online(const char* id, bool online) {
    Peer* p = state_get_peer(id);
    if (!p) return -1;
    
    pthread_mutex_lock(&g_state_mutex);
    p->online = online;
    p->last_seen = time(NULL);
    pthread_mutex_unlock(&g_state_mutex);
    return 0;
}

int state_set_busy(const char* id, bool busy) {
    Peer* p = state_get_peer(id);
    if (!p) return -1;
    
    pthread_mutex_lock(&g_state_mutex);
    p->busy = busy;
    pthread_mutex_unlock(&g_state_mutex);
    return 0;
}

int state_set_ip(const char* id, const char* ip) {
    if (!id || !ip) return -1;
    
    Peer* p = state_get_peer(id);
    if (!p) return -1;
    
    pthread_mutex_lock(&g_state_mutex);
    strcpy(p->ip, ip);
    pthread_mutex_unlock(&g_state_mutex);
    return 0;
}

int state_set_port(const char* id, int port) {
    Peer* p = state_get_peer(id);
    if (!p) return -1;
    
    pthread_mutex_lock(&g_state_mutex);
    p->port = port;
    pthread_mutex_unlock(&g_state_mutex);
    return 0;
}

int state_set_secure(const char* id, bool secure) {
    Peer* p = state_get_peer(id);
    if (!p) return -1;
    
    pthread_mutex_lock(&g_state_mutex);
    p->is_secure = secure;
    pthread_mutex_unlock(&g_state_mutex);
    return 0;
}

int state_set_name(const char* id, const char* name) {
    if (!id || !name) return -1;
    
    Peer* p = state_get_peer(id);
    if (!p) return -1;
    
    pthread_mutex_lock(&g_state_mutex);
    strcpy(p->name, name);
    pthread_mutex_unlock(&g_state_mutex);
    return 0;
}

int state_set_public_key(const char* id, const char* pubkey) {
    if (!id || !pubkey) return -1;
    
    Peer* p = state_get_peer(id);
    if (!p) return -1;
    
    pthread_mutex_lock(&g_state_mutex);
    strcpy(p->public_key, pubkey);
    pthread_mutex_unlock(&g_state_mutex);
    return 0;
}

int state_update_last_seen(const char* id) {
    Peer* p = state_get_peer(id);
    if (!p) return -1;
    
    pthread_mutex_lock(&g_state_mutex);
    p->last_seen = time(NULL);
    pthread_mutex_unlock(&g_state_mutex);
    return 0;
}

/* ============================================================================
 * PENDING REQUESTS
 * ============================================================================ */

int state_get_pending(Peer* out, int max) {
    if (!out || max <= 0) return 0;
    
    pthread_mutex_lock(&g_state_mutex);
    
    int count = 0;
    for (int i = 0; i < g_peer_count && count < max; i++) {
        if (g_peers[i].state == PEER_REQUEST_SENT ||
            g_peers[i].state == PEER_REQUEST_RECEIVED) {
            out[count++] = g_peers[i];
        }
    }
    
    pthread_mutex_unlock(&g_state_mutex);
    return count;
}

int state_get_pending_count(void) {
    pthread_mutex_lock(&g_state_mutex);
    
    int count = 0;
    for (int i = 0; i < g_peer_count; i++) {
        if (g_peers[i].state == PEER_REQUEST_SENT ||
            g_peers[i].state == PEER_REQUEST_RECEIVED) {
            count++;
        }
    }
    
    pthread_mutex_unlock(&g_state_mutex);
    return count;
}

bool state_has_pending_request(const char* id) {
    Peer* p = state_get_peer(id);
    if (!p) return false;
    return p->state == PEER_REQUEST_SENT || p->state == PEER_REQUEST_RECEIVED;
}

/* ============================================================================
 * FRIEND LIST
 * ============================================================================ */

int state_get_friends(Peer* out, int max) {
    if (!out || max <= 0) return 0;
    
    pthread_mutex_lock(&g_state_mutex);
    
    int count = 0;
    for (int i = 0; i < g_peer_count && count < max; i++) {
        if (g_peers[i].state == PEER_FRIEND) {
            out[count++] = g_peers[i];
        }
    }
    
    pthread_mutex_unlock(&g_state_mutex);
    return count;
}

int state_get_friend_count(void) {
    pthread_mutex_lock(&g_state_mutex);
    
    int count = 0;
    for (int i = 0; i < g_peer_count; i++) {
        if (g_peers[i].state == PEER_FRIEND) {
            count++;
        }
    }
    
    pthread_mutex_unlock(&g_state_mutex);
    return count;
}

/* ============================================================================
 * GHOST MESSAGES
 * ============================================================================ */

int state_add_ghost_message(const char* to_id, const char* message) {
    if (!to_id || !message) return -1;
    
    char norm_id[64];
    normalize_id(to_id, norm_id, sizeof(norm_id));
    if (strlen(norm_id) == 0) return -1;
    
    pthread_mutex_lock(&g_state_mutex);
    
    if (g_ghost_count >= MAX_GHOST_MESSAGES) {
        pthread_mutex_unlock(&g_state_mutex);
        return -1;
    }
    
    GhostMessage* gm = &g_ghost_messages[g_ghost_count++];
    
    /* Generate message ID */
    snprintf(gm->id, sizeof(gm->id), "ghost_%ld_%d", time(NULL), rand() % 10000);
    strcpy(gm->to_id, norm_id);
    strcpy(gm->message, message);
    gm->timestamp = time(NULL);
    gm->delivered = false;
    gm->delivered_at = 0;
    gm->retry_count = 0;
    
    /* Update peer ghost count */
    for (int i = 0; i < g_peer_count; i++) {
        if (is_same_id(g_peers[i].id, norm_id)) {
            g_peers[i].ghost_count++;
            break;
        }
    }
    
    SLOG("Added ghost message to %s: %s", norm_id, message);
    
    pthread_mutex_unlock(&g_state_mutex);
    return 0;
}

int state_get_ghost_messages(const char* to_id, GhostMessage* out, int max) {
    if (!to_id || !out || max <= 0) return 0;
    
    char norm_id[64];
    normalize_id(to_id, norm_id, sizeof(norm_id));
    if (strlen(norm_id) == 0) return 0;
    
    pthread_mutex_lock(&g_state_mutex);
    
    int count = 0;
    for (int i = 0; i < g_ghost_count && count < max; i++) {
        if (is_same_id(g_ghost_messages[i].to_id, norm_id) &&
            !g_ghost_messages[i].delivered) {
            out[count++] = g_ghost_messages[i];
        }
    }
    
    pthread_mutex_unlock(&g_state_mutex);
    return count;
}

int state_deliver_ghost_messages(const char* to_id) {
    if (!to_id) return 0;
    
    char norm_id[64];
    normalize_id(to_id, norm_id, sizeof(norm_id));
    if (strlen(norm_id) == 0) return 0;
    
    pthread_mutex_lock(&g_state_mutex);
    
    int delivered = 0;
    for (int i = 0; i < g_ghost_count; i++) {
        if (is_same_id(g_ghost_messages[i].to_id, norm_id) &&
            !g_ghost_messages[i].delivered) {
            
            /* Mark as delivered */
            g_ghost_messages[i].delivered = true;
            g_ghost_messages[i].delivered_at = time(NULL);
            delivered++;
            
            /* Trigger event */
            Event event = event_create(EVENT_GHOST_DELIVERED, norm_id);
            strcpy(event.from_id, g_ghost_messages[i].from_id);
            strcpy(event.message, g_ghost_messages[i].message);
            event_queue_push(&event);
            
            SLOG("Delivered ghost message to %s: %s", norm_id, g_ghost_messages[i].message);
        }
    }
    
    /* Update peer ghost count */
    for (int i = 0; i < g_peer_count; i++) {
        if (is_same_id(g_peers[i].id, norm_id)) {
            g_peers[i].ghost_count -= delivered;
            if (g_peers[i].ghost_count < 0) g_peers[i].ghost_count = 0;
            break;
        }
    }
    
    pthread_mutex_unlock(&g_state_mutex);
    return delivered;
}

int state_get_ghost_count(const char* to_id) {
    if (!to_id) return 0;
    
    char norm_id[64];
    normalize_id(to_id, norm_id, sizeof(norm_id));
    if (strlen(norm_id) == 0) return 0;
    
    pthread_mutex_lock(&g_state_mutex);
    
    int count = 0;
    for (int i = 0; i < g_ghost_count; i++) {
        if (is_same_id(g_ghost_messages[i].to_id, norm_id) &&
            !g_ghost_messages[i].delivered) {
            count++;
        }
    }
    
    pthread_mutex_unlock(&g_state_mutex);
    return count;
}

bool state_has_ghost_messages(const char* to_id) {
    return state_get_ghost_count(to_id) > 0;
}

/* ============================================================================
 * MESSAGES
 * ============================================================================ */

int state_add_message(const char* from_id, const char* message) {
    if (!from_id || !message) return -1;
    
    pthread_mutex_lock(&g_state_mutex);
    
    if (g_message_count >= MAX_MESSAGES) {
        pthread_mutex_unlock(&g_state_mutex);
        return -1;
    }
    
    snprintf(g_messages[g_message_count], sizeof(g_messages[0]), 
             "%s|%s", from_id, message);
    g_message_count++;
    
    pthread_mutex_unlock(&g_state_mutex);
    return 0;
}

int state_get_messages(const char* peer_id, char* out[], int max) {
    (void)peer_id;
    (void)out;
    (void)max;
    /* TODO: Implement message retrieval */
    return 0;
}

int state_clear_messages(const char* peer_id) {
    (void)peer_id;
    /* TODO: Implement message clearing */
    return 0;
}

/* ============================================================================
 * DEBUG
 * ============================================================================ */

void state_debug_print(void) {
    pthread_mutex_lock(&g_state_mutex);
    
    printf("\n=== STATE MANAGER DEBUG ===\n");
    printf("Peers: %d\n", g_peer_count);
    for (int i = 0; i < g_peer_count; i++) {
        Peer* p = &g_peers[i];
        printf("  [%d] %s | state=%s | online=%d | ip=%s | port=%d\n",
               i, p->id, state_to_string(p->state), p->online, p->ip, p->port);
    }
    printf("Ghost messages: %d\n", g_ghost_count);
    printf("Messages: %d\n", g_message_count);
    printf("===========================\n");
    
    pthread_mutex_unlock(&g_state_mutex);
}
