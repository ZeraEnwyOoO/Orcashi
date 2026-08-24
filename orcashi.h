 #ifndef ORCASHI_H
#define ORCASHI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* ============================================================================
 * VERSION
 * ============================================================================ */

#define ORCASHI_VERSION "5.0.0"
#define ORCASHI_NAME "Orcashi"
#define ORCASHI_HOME "/tmp/.orcashi/"

/* ============================================================================
 * PORTS
 * ============================================================================ */

#define ORCASHI_P2P_PORT 9000
#define ORCASHI_DHT_PORT 33446
#define ORCASHI_PUNCH_PORT 33445

/* ============================================================================
 * INCLUDES - All V5 Components
 * ============================================================================ */

/* CLI Layer */
#include "commands.h"

/* Daemon Layer */
#include "daemon.h"
#include "event_loop.h"

/* Core Layer (HEART) */
#include "state_manager.h"

/* P2P Layer */
#include "p2p_manager.h"
#include "punch.h"

/* Crypto Layer */
#include "orca_identity.h"
#include "orca_crypto.h"
#include "ecdh.h"
#include "aes_gcm.h"

/* DHT Layer */
#include "dht_node.h"
#include "dht.h"

/* Utilities */
#include "mixed_id.h"
#include "logger.h"

/* ============================================================================
 * MAIN ORCASHI STRUCTURE
 * ============================================================================ */

typedef struct {
    /* Identity */
    char id[64];
    char name[128];
    bool has_identity;
    bool is_secure;
    
    /* Network */
    char local_ip[INET_ADDRSTRLEN];
    char public_ip[INET_ADDRSTRLEN];
    int p2p_port;
    int dht_port;
    
    /* State */
    bool initialized;
    bool daemon_running;
    bool is_listening;
    time_t start_time;
    
    /* Callbacks */
    void (*on_peer_found)(const char* id, const char* ip, int port);
    void (*on_message_received)(const char* from, const char* msg);
    void (*on_status_change)(const char* status);
    void (*on_call_received)(const char* from, int room);
    
} Orcashi;

/* ============================================================================
 * LIFECYCLE FUNCTIONS
 * ============================================================================ */

/* Initialize Orcashi */
int orcashi_init(Orcashi* orcashi);

/* Initialize with custom config */
int orcashi_init_with_config(Orcashi* orcashi, const char* config_path);

/* Cleanup Orcashi */
void orcashi_cleanup(Orcashi* orcashi);

/* ============================================================================
 * DAEMON FUNCTIONS
 * ============================================================================ */

/* Start background daemon */
int orcashi_start_daemon(Orcashi* orcashi);

/* Stop background daemon */
int orcashi_stop_daemon(Orcashi* orcashi);

/* Check if daemon is running */
bool orcashi_is_daemon_running(Orcashi* orcashi);

/* ============================================================================
 * IDENTITY FUNCTIONS
 * ============================================================================ */

/* Register identity */
int orcashi_register_identity(Orcashi* orcashi, const char* passcode);

/* Load identity */
int orcashi_load_identity(Orcashi* orcashi, const char* passcode);

/* Show identity info */
void orcashi_print_identity(Orcashi* orcashi);

/* ============================================================================
 * PEER FUNCTIONS
 * ============================================================================ */

/* Search for peer */
int orcashi_search_peer(Orcashi* orcashi, const char* peer_id);

/* Add peer (send friend request) */
int orcashi_add_peer(Orcashi* orcashi, const char* peer_id);

/* Accept peer request */
int orcashi_accept_peer(Orcashi* orcashi, const char* peer_id);

/* Reject peer request */
int orcashi_reject_peer(Orcashi* orcashi, const char* peer_id);

/* Remove peer */
int orcashi_remove_peer(Orcashi* orcashi, const char* peer_id);

/* List peers */
void orcashi_list_peers(Orcashi* orcashi);

/* ============================================================================
 * CHAT FUNCTIONS
 * ============================================================================ */

/* Start chat with peer */
int orcashi_chat_start(Orcashi* orcashi, const char* peer_id);

/* Send message in chat */
int orcashi_chat_send(Orcashi* orcashi, const char* peer_id, const char* message);

/* Send ghost message */
int orcashi_ghost_send(Orcashi* orcashi, const char* peer_id, const char* message);

/* ============================================================================
 * VOICE CALL FUNCTIONS (Ghost Call)
 * ============================================================================ */

/* Start voice call */
int orcashi_call_start(Orcashi* orcashi, const char* peer_id);

/* Answer voice call */
int orcashi_call_answer(Orcashi* orcashi, const char* caller_id, int room);

/* Check if call is active */
bool orcashi_call_is_active(Orcashi* orcashi);

/* ============================================================================
 * NOTE FUNCTIONS (Orcanote)
 * ============================================================================ */

/* Add note to time capsule */
int orcashi_note_add(Orcashi* orcashi, const char* content);

/* View all notes */
void orcashi_note_view(Orcashi* orcashi);

/* Find note by hash */
int orcashi_note_find(Orcashi* orcashi, const char* hash);

/* ============================================================================
 * MIXED ID FUNCTIONS
 * ============================================================================ */

/* Get Mixed ID for current identity */
int orcashi_get_mixed_id(Orcashi* orcashi, char* out, size_t size);

/* Connect via Mixed ID */
int orcashi_connect_mixed_id(Orcashi* orcashi, const char* mixed_id);

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

/* Get local IP */
char* orcashi_get_local_ip(void);

/* Get public IP */
char* orcashi_get_public_ip(void);

/* Generate ID */
char* orcashi_generate_id(void);

/* Bytes to hex */
char* orcashi_bytes_to_hex(const unsigned char* bytes, int len);

/* ============================================================================
 * CALLBACK SETTERS
 * ============================================================================ */

void orcashi_set_on_peer_found(Orcashi* orcashi, 
                                void (*callback)(const char*, const char*, int));

void orcashi_set_on_message_received(Orcashi* orcashi,
                                      void (*callback)(const char*, const char*));

void orcashi_set_on_status_change(Orcashi* orcashi,
                                   void (*callback)(const char*));

void orcashi_set_on_call_received(Orcashi* orcashi,
                                   void (*callback)(const char*, int));

/* ============================================================================
 * DEBUG FUNCTIONS
 * ============================================================================ */

void orcashi_debug_print(Orcashi* orcashi);
void orcashi_debug_dump_state(Orcashi* orcashi);

#endif /* ORCASHI_H */
