 #ifndef PLUG_H
#define PLUG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <stdbool.h>

/* ============================================================================
 * SECURE MESSAGE TYPES
 * ============================================================================ */

typedef enum {
    PLUG_MSG_TYPE_PLAIN = 0,
    PLUG_MSG_TYPE_SECURE = 1,
    PLUG_MSG_TYPE_HANDSHAKE = 2,
    PLUG_MSG_TYPE_ECDH_INIT = 3,
    PLUG_MSG_TYPE_ECDH_RESPONSE = 4
} PlugMessageType;

/* ============================================================================
 * TCP PLUG STRUCT - PHASE 4
 * ============================================================================ */

typedef struct {
    /* Socket */
    int plug_socket;
    int client_socket;
    bool connected;
    bool running;
    char peer_ip[INET_ADDRSTRLEN];
    char peer_id[64];
    
    /* Threads */
    pthread_t receive_thread;
    pthread_t send_thread;
    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_cond;
    
    /* Queues */
    char** message_queue;
    char** send_queue;
    int message_count;
    int send_count;
    int queue_capacity;
    
    /* ===== LEGACY SECURITY ===== */
    bool secure_mode;
    char aes_key_hex[65];      /* AES-256 key as hex */
    char nonce_hex[25];        /* Current nonce */
    bool handshake_complete;
    char peer_public_key_hex[65];
    char handshake_buffer[1024];
    
    /* ===== PHASE 4: ECDH + AES-GCM SECURE SESSION ===== */
    bool ecdh_initiated;
    bool ecdh_complete;
    unsigned char ecdh_public_key[32];
    unsigned char ecdh_private_key[32];
    unsigned char ecdh_shared_secret[32];
    unsigned char aes_key[32];         /* AES-256-GCM key */
    unsigned char nonce[12];           /* 12-byte nonce for GCM */
    uint64_t nonce_counter;            /* Counter for nonce generation */
    char peer_ecdh_public_key_hex[65];
    
} TCPPlug;

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

TCPPlug* plug_create(void);
void plug_destroy(TCPPlug* plug);

/* ============================================================================
 * SERVER / CLIENT
 * ============================================================================ */

bool plug_create_server(TCPPlug* plug, int port);
bool plug_connect_client(TCPPlug* plug, const char* target_ip, int port);

/* ============================================================================
 * LEGACY MESSAGING
 * ============================================================================ */

bool plug_send_message(TCPPlug* plug, const char* msg);
bool plug_send_secure_message(TCPPlug* plug, const char* msg, const char* key_hex);
bool plug_receive_message(TCPPlug* plug, char* msg, int msg_size, int timeout_ms);

/* ============================================================================
 * LEGACY HANDSHAKE (RSA-based)
 * ============================================================================ */

bool plug_start_handshake(TCPPlug* plug, const char* public_key_hex);
bool plug_complete_handshake(TCPPlug* plug, const char* peer_public_key_hex);
bool plug_handshake_complete(TCPPlug* plug);

/* ============================================================================
 * PHASE 4: ECDH + AES-GCM SECURE SESSION
 * ============================================================================ */

/* Initiate ECDH handshake (call after connection established) */
bool plug_initiate_ecdh(TCPPlug* plug);

/* Respond to ECDH_INIT (called automatically from receive loop) */
bool plug_respond_ecdh(TCPPlug* plug, const char* peer_pubkey_hex);

/* Complete ECDH handshake after receiving ECDH_RESPONSE */
bool plug_complete_ecdh(TCPPlug* plug, const char* peer_pubkey_hex);

/* Check if ECDH secure channel is established */
bool plug_ecdh_complete(TCPPlug* plug);

/* Send secure message (encrypted with AES-GCM) */
bool plug_send_secure(TCPPlug* plug, const char* msg);

/* Receive secure message (decrypts if SECURE: format) */
bool plug_receive_secure(TCPPlug* plug, char* msg, int msg_size);

/* Check if connection is in secure mode */
bool plug_is_secure(TCPPlug* plug);

/* ============================================================================
 * CONNECTION MANAGEMENT
 * ============================================================================ */

bool plug_is_connected(TCPPlug* plug);
const char* plug_get_peer_ip(TCPPlug* plug);
int plug_get_socket(TCPPlug* plug);
void plug_close_connection(TCPPlug* plug);

#endif
