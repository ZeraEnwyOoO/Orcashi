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

// ===== Secure message type =====
typedef enum {
    PLUG_MSG_TYPE_PLAIN = 0,
    PLUG_MSG_TYPE_SECURE = 1,
    PLUG_MSG_TYPE_HANDSHAKE = 2
} PlugMessageType;

typedef struct {
    int plug_socket;
    int client_socket;
    bool connected;
    bool running;
    char peer_ip[INET_ADDRSTRLEN];
    char peer_id[64];
    
    // ===== Threads =====
    pthread_t receive_thread;
    pthread_t send_thread;
    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_cond;
    
    // ===== Queues =====
    char** message_queue;
    char** send_queue;
    int message_count;
    int send_count;
    int queue_capacity;
    
    // ===== Security =====
    bool secure_mode;
    char aes_key_hex[65];      // AES-256 key as hex
    char nonce_hex[25];        // Current nonce
    bool handshake_complete;
    char peer_public_key_hex[65];
    char handshake_buffer[1024];
    
} TCPPlug;

// ===== Lifecycle =====
TCPPlug* plug_create(void);
void plug_destroy(TCPPlug* plug);

// ===== Server/Client =====
bool plug_create_server(TCPPlug* plug, int port);
bool plug_connect_client(TCPPlug* plug, const char* target_ip, int port);

// ===== Messaging =====
bool plug_send_message(TCPPlug* plug, const char* msg);
bool plug_send_secure_message(TCPPlug* plug, const char* msg, const char* key_hex);
bool plug_receive_message(TCPPlug* plug, char* msg, int msg_size, int timeout_ms);

// ===== Secure Handshake =====
bool plug_start_handshake(TCPPlug* plug, const char* public_key_hex);
bool plug_complete_handshake(TCPPlug* plug, const char* peer_public_key_hex);
bool plug_handshake_complete(TCPPlug* plug);
bool plug_is_secure(TCPPlug* plug);

// ===== Connection =====
bool plug_is_connected(TCPPlug* plug);
const char* plug_get_peer_ip(TCPPlug* plug);
int plug_get_socket(TCPPlug* plug);
void plug_close_connection(TCPPlug* plug);

#endif
