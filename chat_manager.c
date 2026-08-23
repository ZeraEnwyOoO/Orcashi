 #include "chat_manager.h"
#include "orcashi.h"
#include "peer_list.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define CHAT_DEBUG 1

#if CHAT_DEBUG
#define CLOG(fmt, ...) \
    do { \
        fprintf(stderr, "[CHAT] " fmt "\n", ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define CLOG(fmt, ...) ((void)0)
#endif

static ORCASHI* g_orcashi = NULL;
static PeerList* g_peer_list = NULL;
static ChatSession g_session;
static bool g_initialized = false;

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

int chat_manager_init(ORCASHI* orcashi, PeerList* peer_list) {
    if (!orcashi || !peer_list) {
        CLOG("chat_manager_init: NULL parameter");
        return -1;
    }
    
    g_orcashi = orcashi;
    g_peer_list = peer_list;
    g_initialized = true;
    memset(&g_session, 0, sizeof(g_session));
    
    CLOG("chat_manager_init: initialized");
    return 0;
}

void chat_manager_cleanup(void) {
    g_initialized = false;
    g_orcashi = NULL;
    g_peer_list = NULL;
    CLOG("chat_manager_cleanup: cleaned up");
}

/* ============================================================================
 * Helper: Check peer online status
 * ============================================================================ */

static bool is_peer_online(const char* peer_id) {
    if (!g_orcashi || !peer_id) return false;
    
    DiscoveryPeerInfo p;
    if (discovery_find_peer(g_orcashi->discovery, peer_id, &p)) {
        return p.online;
    }
    
    /* Check registry */
    RegistryPeer reg_peer;
    if (registry_get_peer(g_orcashi->registry, peer_id, &reg_peer)) {
        return reg_peer.online;
    }
    
    return false;
}

/* ============================================================================
 * Helper: Connect to peer
 * ============================================================================ */

static int connect_to_peer(const char* peer_id) {
    if (!g_orcashi || !peer_id) return -1;
    
    RegistryPeer reg_peer;
    if (!registry_get_peer(g_orcashi->registry, peer_id, &reg_peer)) {
        CLOG("connect_to_peer: peer %s not in registry", peer_id);
        return -1;
    }
    
    if (strlen(reg_peer.ip) == 0 || strcmp(reg_peer.ip, "0.0.0.0") == 0) {
        CLOG("connect_to_peer: peer %s has no IP", peer_id);
        return -1;
    }
    
    CLOG("connect_to_peer: connecting to %s at %s:%s", 
         peer_id, reg_peer.ip, reg_peer.port);
    
    if (orcashi_join_room(g_orcashi, reg_peer.ip, atoi(reg_peer.port))) {
        CLOG("connect_to_peer: connected to %s", peer_id);
        return 0;
    }
    
    CLOG("connect_to_peer: failed to connect to %s", peer_id);
    return -1;
}

/* ============================================================================
 * Chat Session
 * ============================================================================ */

int chat_start(const char* peer_id) {
    if (!g_initialized || !peer_id) {
        CLOG("chat_start: not initialized or NULL peer_id");
        return -1;
    }
    
    char norm_id[64];
    if (!peer_list_normalize_id(peer_id, norm_id, sizeof(norm_id))) {
        CLOG("chat_start: invalid peer ID: %s", peer_id);
        return -1;
    }
    
    /* Check if peer is accepted */
    if (!peer_list_is_accepted(g_peer_list, norm_id)) {
        CLOG("chat_start: peer %s not accepted yet", norm_id);
        printf("\n[ERROR] Peer %s is not accepted yet.\n", norm_id);
        printf("[ORCA] Use './orcashi add %s' first.\n", norm_id);
        return -1;
    }
    
    /* Check if peer is online */
    bool online = is_peer_online(norm_id);
    
    /* Create session */
    memset(&g_session, 0, sizeof(g_session));
    strcpy(g_session.peer_id, norm_id);
    g_session.is_online = online;
    g_session.peer_list = g_peer_list;
    g_session.orcashi = g_orcashi;
    g_session.running = true;
    
    /* Get pending count */
    g_session.pending_count = peer_list_get_pending_count(g_peer_list, norm_id);
    
    /* Display header */
    printf("\n");
    printf("============================================================\n");
    printf("  ORCASHI CHAT\n");
    printf("============================================================\n");
    printf("  Peer: %s\n", norm_id);
    printf("  Status: %s\n", online ? "ONLINE" : "OFFLINE");
    if (g_session.pending_count > 0) {
        printf("  Pending messages: %d\n", g_session.pending_count);
    }
    printf("============================================================\n");
    printf("  Type /exit to quit\n");
    printf("  Type /status to check connection\n");
    printf("============================================================\n");
    printf("\n");
    
    /* If online, try to connect */
    if (online) {
        printf("[CHAT] Peer is online. Connecting...\n");
        if (connect_to_peer(norm_id) == 0) {
            g_session.is_online = true;
            printf("[CHAT] Connected! Secure channel: %s\n",
                   orcashi_session_established(g_orcashi) ? "ENABLED" : "DISABLED");
            
            /* Deliver pending messages */
            if (g_session.pending_count > 0) {
                printf("[CHAT] Delivering %d pending messages...\n", g_session.pending_count);
                chat_deliver_pending(norm_id);
            }
        } else {
            g_session.is_online = false;
            printf("[CHAT] Could not connect. Messages will be queued.\n");
        }
    } else {
        printf("[CHAT] Peer is offline. Messages will be queued.\n");
    }
    printf("\n");
    
    /* Interactive chat loop */
    char input[4096];
    char msg[4096];
    fd_set fds;
    struct timeval tv;
    
    while (g_session.running) {
        /* Check for incoming messages */
        if (g_session.is_online && orcashi_is_connected(g_orcashi)) {
            while (orcashi_receive_message(g_orcashi, msg, sizeof(msg), 1)) {
                if (plug_ecdh_complete(g_orcashi->plug)) {
                    printf("[%s] (secure) %s\n", norm_id, msg);
                } else {
                    printf("[%s] %s\n", norm_id, msg);
                }
                fflush(stdout);
            }
        }
        
        /* Check for peer status change */
        if (!g_session.is_online && is_peer_online(norm_id)) {
            printf("\n[CHAT] Peer %s is now ONLINE!\n", norm_id);
            printf("[CHAT] Connecting...\n");
            if (connect_to_peer(norm_id) == 0) {
                g_session.is_online = true;
                printf("[CHAT] Connected! Delivering pending messages...\n");
                chat_deliver_pending(norm_id);
            } else {
                printf("[CHAT] Failed to connect.\n");
            }
            printf("\n");
        }
        
        /* Input handling */
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        
        int ret = select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
        if (ret > 0) {
            if (!fgets(input, sizeof(input), stdin)) break;
            input[strcspn(input, "\n")] = '\0';
            
            if (strcmp(input, "/exit") == 0) {
                break;
            }
            
            if (strcmp(input, "/status") == 0) {
                printf("[CHAT] Peer: %s\n", norm_id);
                printf("[CHAT] Status: %s\n", g_session.is_online ? "ONLINE" : "OFFLINE");
                printf("[CHAT] Connected: %s\n", orcashi_is_connected(g_orcashi) ? "YES" : "NO");
                printf("[CHAT] Secure: %s\n", orcashi_session_established(g_orcashi) ? "YES" : "NO");
                printf("[CHAT] Pending messages: %d\n", 
                       peer_list_get_pending_count(g_peer_list, norm_id));
                continue;
            }
            
            if (strcmp(input, "/deliver") == 0) {
                printf("[CHAT] Delivering pending messages...\n");
                chat_deliver_pending(norm_id);
                continue;
            }
            
            if (strlen(input) > 0) {
                /* Send message */
                if (g_session.is_online && orcashi_is_connected(g_orcashi)) {
                    if (orcashi_send_message(g_orcashi, input)) {
                        printf("[you] %s\n", input);
                    } else {
                        printf("[CHAT] Failed to send. Queueing message.\n");
                        peer_list_queue_message(g_peer_list, norm_id, input, true);
                        printf("[QUEUED] Message saved locally.\n");
                    }
                } else {
                    /* Queue message */
                    peer_list_queue_message(g_peer_list, norm_id, input, true);
                    printf("[QUEUED] Peer is offline. Message saved locally.\n");
                }
            }
        }
    }
    
    printf("\n[CHAT] Session ended.\n");
    orcashi_disconnect(g_orcashi);
    return 0;
}

/* ============================================================================
 * Chat Send/Receive
 * ============================================================================ */

int chat_send_message(const char* peer_id, const char* msg) {
    if (!g_initialized || !peer_id || !msg) return -1;
    
    /* Try to send directly if online */
    if (g_session.is_online && orcashi_is_connected(g_orcashi)) {
        if (orcashi_send_message(g_orcashi, msg)) {
            return 0;
        }
    }
    
    /* Queue message */
    return peer_list_queue_message(g_peer_list, peer_id, msg, true);
}

int chat_receive_messages(const char* peer_id) {
    if (!g_initialized || !peer_id) return -1;
    
    if (!g_session.is_online || !orcashi_is_connected(g_orcashi)) {
        return 0;
    }
    
    char msg[4096];
    int count = 0;
    while (orcashi_receive_message(g_orcashi, msg, sizeof(msg), 1)) {
        printf("[%s] %s\n", peer_id, msg);
        count++;
    }
    return count;
}

/* ============================================================================
 * Auto-Delivery
 * ============================================================================ */

int chat_deliver_pending(const char* peer_id) {
    if (!g_initialized || !peer_id) return -1;
    if (!g_peer_list) return -1;
    
    QueuedMessage msgs[64];
    int count = peer_list_get_pending_messages(g_peer_list, peer_id, msgs, 64);
    
    if (count == 0) {
        CLOG("chat_deliver_pending: no pending messages for %s", peer_id);
        return 0;
    }
    
    CLOG("chat_deliver_pending: delivering %d messages to %s", count, peer_id);
    
    /* Connect if not connected */
    if (!orcashi_is_connected(g_orcashi)) {
        if (connect_to_peer(peer_id) != 0) {
            CLOG("chat_deliver_pending: cannot connect to %s", peer_id);
            return -1;
        }
    }
    
    int delivered = 0;
    for (int i = 0; i < count; i++) {
        if (orcashi_send_message(g_orcashi, msgs[i].payload)) {
            peer_list_mark_message_delivered(g_peer_list, msgs[i].msg_id);
            printf("[CHAT] Message %d delivered\n", i + 1);
            delivered++;
        } else {
            peer_list_mark_message_failed(g_peer_list, msgs[i].msg_id);
            printf("[CHAT] Message %d failed to deliver\n", i + 1);
        }
    }
    
    CLOG("chat_deliver_pending: delivered %d/%d messages", delivered, count);
    return delivered;
}

int chat_deliver_all_pending(void) {
    if (!g_initialized) return -1;
    
    QueuedMessage msgs[256];
    int count = peer_list_get_all_pending_messages(g_peer_list, msgs, 256);
    
    if (count == 0) {
        CLOG("chat_deliver_all_pending: no pending messages");
        return 0;
    }
    
    CLOG("chat_deliver_all_pending: delivering %d messages", count);
    
    /* Group by recipient */
    int delivered = 0;
    for (int i = 0; i < count; i++) {
        if (is_peer_online(msgs[i].to_id)) {
            if (connect_to_peer(msgs[i].to_id) == 0) {
                if (orcashi_send_message(g_orcashi, msgs[i].payload)) {
                    peer_list_mark_message_delivered(g_peer_list, msgs[i].msg_id);
                    delivered++;
                }
                orcashi_disconnect(g_orcashi);
            }
        }
    }
    
    CLOG("chat_deliver_all_pending: delivered %d messages", delivered);
    return delivered;
}

bool chat_has_pending(const char* peer_id) {
    if (!g_initialized || !peer_id) return false;
    return peer_list_has_pending_messages(g_peer_list, peer_id);
}

/* ============================================================================
 * Status
 * ============================================================================ */

int chat_get_status(const char* peer_id, char* status_out, size_t size) {
    if (!g_initialized || !peer_id || !status_out) return -1;
    
    if (is_peer_online(peer_id)) {
        snprintf(status_out, size, "online");
    } else {
        snprintf(status_out, size, "offline");
    }
    return 0;
}

int chat_get_pending_count(const char* peer_id) {
    if (!g_initialized || !peer_id) return 0;
    return peer_list_get_pending_count(g_peer_list, peer_id);
}
