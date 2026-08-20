 // plug.c - Full version with ECDH + AES-GCM secure session support
#define _POSIX_C_SOURCE 200809L

#include "plug.h"
#include "aes_gcm.h"
#include "orca_crypto.h"
#include "ecdh.h"
#include <unistd.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#define QUEUE_INITIAL_SIZE 100
#define BUFFER_SIZE 16384
#define HANDSHAKE_TIMEOUT 30

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

static void* receive_loop(void* arg);
static void* send_loop(void* arg);
static bool plug_parse_handshake(TCPPlug* plug, const char* msg);

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

TCPPlug* plug_create(void) {
    TCPPlug* plug = (TCPPlug*)calloc(1, sizeof(TCPPlug));
    if (!plug) return NULL;
    
    plug->plug_socket = -1;
    plug->client_socket = -1;
    plug->connected = false;
    plug->running = false;
    plug->queue_capacity = QUEUE_INITIAL_SIZE;
    plug->secure_mode = false;
    plug->handshake_complete = false;
    plug->ecdh_initiated = false;
    plug->ecdh_complete = false;
    plug->nonce_counter = 0;
    
    plug->message_queue = (char**)calloc(QUEUE_INITIAL_SIZE, sizeof(char*));
    plug->send_queue = (char**)calloc(QUEUE_INITIAL_SIZE, sizeof(char*));
    
    pthread_mutex_init(&plug->queue_mutex, NULL);
    pthread_cond_init(&plug->queue_cond, NULL);
    
    return plug;
}

void plug_destroy(TCPPlug* plug) {
    if (!plug) return;
    
    plug_close_connection(plug);
    
    if (plug->message_queue) {
        for (int i = 0; i < plug->message_count; i++) {
            if (plug->message_queue[i]) free(plug->message_queue[i]);
        }
        free(plug->message_queue);
    }
    
    if (plug->send_queue) {
        for (int i = 0; i < plug->send_count; i++) {
            if (plug->send_queue[i]) free(plug->send_queue[i]);
        }
        free(plug->send_queue);
    }
    
    /* Zeroize sensitive data */
    memset(plug->ecdh_shared_secret, 0, 32);
    memset(plug->aes_key, 0, 32);
    memset(plug->ecdh_private_key, 0, 32);
    memset(plug->ecdh_public_key, 0, 32);
    memset(plug->peer_ecdh_public_key_hex, 0, 65);
    
    pthread_mutex_destroy(&plug->queue_mutex);
    pthread_cond_destroy(&plug->queue_cond);
    
    free(plug);
}

/* ============================================================================
 * SERVER / CLIENT
 * ============================================================================ */

bool plug_create_server(TCPPlug* plug, int port) {
    if (!plug) return false;
    
    plug->plug_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (plug->plug_socket < 0) {
        fprintf(stderr, "[ERROR] Failed to create socket!\n");
        return false;
    }
    
    int opt = 1;
    setsockopt(plug->plug_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(plug->plug_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[ERROR] Failed to bind to port %d!\n", port);
        close(plug->plug_socket);
        return false;
    }
    
    if (listen(plug->plug_socket, 5) < 0) {
        fprintf(stderr, "[ERROR] Failed to listen!\n");
        close(plug->plug_socket);
        return false;
    }
    
    printf("[ORCA] TCP Plug ready on port %d\n", port);
    printf("[ORCA] Waiting for connection...\n");
    fflush(stdout);
    
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    plug->client_socket = accept(plug->plug_socket, (struct sockaddr*)&client_addr, &addr_len);
    
    if (plug->client_socket < 0) {
        fprintf(stderr, "[ERROR] Failed to accept connection!\n");
        close(plug->plug_socket);
        return false;
    }
    
    inet_ntop(AF_INET, &client_addr.sin_addr, plug->peer_ip, INET_ADDRSTRLEN);
    strcpy(plug->peer_id, plug->peer_ip);
    plug->connected = true;
    plug->running = true;
    
    int flag = 1;
    setsockopt(plug->client_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
    printf("[ORCA] Client connected from %s!\n", plug->peer_ip);
    fflush(stdout);
    
    pthread_create(&plug->receive_thread, NULL, receive_loop, plug);
    pthread_create(&plug->send_thread, NULL, send_loop, plug);
    
    return true;
}

bool plug_connect_client(TCPPlug* plug, const char* target_ip, int port) {
    if (!plug) return false;
    
    plug->client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (plug->client_socket < 0) {
        fprintf(stderr, "[ERROR] Failed to create socket!\n");
        return false;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &addr.sin_addr);
    
    if (connect(plug->client_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[ERROR] Failed to connect to %s:%d!\n", target_ip, port);
        close(plug->client_socket);
        return false;
    }
    
    strcpy(plug->peer_ip, target_ip);
    strcpy(plug->peer_id, target_ip);
    plug->connected = true;
    plug->running = true;
    
    int flag = 1;
    setsockopt(plug->client_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
    printf("[ORCA] Connected to %s:%d!\n", target_ip, port);
    fflush(stdout);
    
    pthread_create(&plug->receive_thread, NULL, receive_loop, plug);
    pthread_create(&plug->send_thread, NULL, send_loop, plug);
    
    return true;
}

/* ============================================================================
 * ECDH SECURE HANDSHAKE - Initiator
 * ============================================================================ */

bool plug_initiate_ecdh(TCPPlug* plug) {
    if (!plug || !plug->connected) return false;
    
    /* Reset secure state */
    plug->ecdh_complete = false;
    plug->secure_mode = false;
    plug->ecdh_initiated = false;
    plug->nonce_counter = 0;
    memset(plug->aes_key, 0, 32);
    memset(plug->ecdh_shared_secret, 0, 32);
    
    /* Generate ephemeral X25519 keypair */
    OrcaECDHKeypair keypair;
    if (orca_ecdh_generate_keypair(&keypair) < 0) {
        fprintf(stderr, "[PLUG] Failed to generate ECDH keypair\n");
        return false;
    }
    
    memcpy(plug->ecdh_public_key, keypair.public_key, 32);
    memcpy(plug->ecdh_private_key, keypair.private_key, 32);
    
    char pubkey_hex[65];
    if (orca_bytes_to_hex(keypair.public_key, 32, pubkey_hex) == NULL) {
        fprintf(stderr, "[PLUG] Failed to convert public key to hex\n");
        return false;
    }
    
    char msg[128];
    snprintf(msg, sizeof(msg), "ECDH_INIT:%s", pubkey_hex);
    
    if (!plug_send_message(plug, msg)) {
        return false;
    }
    
    plug->ecdh_initiated = true;
    printf("[PLUG] ECDH initiated\n");
    return true;
}

/* ============================================================================
 * ECDH SECURE HANDSHAKE - Responder
 * ============================================================================ */

bool plug_respond_ecdh(TCPPlug* plug, const char* peer_pubkey_hex) {
    if (!plug || !plug->connected || !peer_pubkey_hex) return false;
    
    /* Validate hex length (64 chars for 32 bytes) */
    if (strlen(peer_pubkey_hex) != 64) {
        fprintf(stderr, "[PLUG] Invalid peer public key length: %zu\n", strlen(peer_pubkey_hex));
        return false;
    }
    
    /* Validate hex characters */
    for (size_t i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)peer_pubkey_hex[i])) {
            fprintf(stderr, "[PLUG] Invalid hex character in peer public key\n");
            return false;
        }
    }
    
    strncpy(plug->peer_ecdh_public_key_hex, peer_pubkey_hex, 64);
    plug->peer_ecdh_public_key_hex[64] = '\0';
    
    /* Generate ephemeral X25519 keypair */
    OrcaECDHKeypair keypair;
    if (orca_ecdh_generate_keypair(&keypair) < 0) {
        fprintf(stderr, "[PLUG] Failed to generate ECDH keypair for response\n");
        return false;
    }
    
    memcpy(plug->ecdh_public_key, keypair.public_key, 32);
    memcpy(plug->ecdh_private_key, keypair.private_key, 32);
    
    /* Convert peer public key from hex to bytes */
    unsigned char peer_pubkey[32];
    if (orca_hex_to_bytes(peer_pubkey_hex, peer_pubkey, 32) < 0) {
        fprintf(stderr, "[PLUG] Failed to parse peer public key hex\n");
        return false;
    }
    
    /* Compute shared secret */
    if (orca_ecdh_compute_shared_secret(keypair.private_key, peer_pubkey,
                                        plug->ecdh_shared_secret) < 0) {
        fprintf(stderr, "[PLUG] Failed to compute shared secret\n");
        return false;
    }
    
    /* Derive AES-256-GCM key from shared secret */
    if (orca_aes_gcm_derive_key_from_shared_secret(plug->ecdh_shared_secret, NULL, 0,
                                                   (const unsigned char*)"orcashi-chat", 12,
                                                   plug->aes_key) < 0) {
        fprintf(stderr, "[PLUG] Failed to derive AES key\n");
        return false;
    }
    
    /* Send response with our public key */
    char pubkey_hex[65];
    if (orca_bytes_to_hex(keypair.public_key, 32, pubkey_hex) == NULL) {
        fprintf(stderr, "[PLUG] Failed to convert public key to hex\n");
        return false;
    }
    
    char msg[128];
    snprintf(msg, sizeof(msg), "ECDH_RESPONSE:%s", pubkey_hex);
    
    if (!plug_send_message(plug, msg)) {
        return false;
    }
    
    /* Secure channel is now established (responder) */
    memset(plug->nonce, 0, 12);
    plug->nonce_counter = 0;
    plug->ecdh_complete = true;
    plug->secure_mode = true;
    plug->ecdh_initiated = false;
    
    printf("[PLUG] ECDH secure channel established (responder)\n");
    return true;
}

/* ============================================================================
 * ECDH SECURE HANDSHAKE - Complete (Initiator receives response)
 * ============================================================================ */

bool plug_complete_ecdh(TCPPlug* plug, const char* peer_pubkey_hex) {
    if (!plug || !plug->connected || !peer_pubkey_hex) return false;
    
    if (!plug->ecdh_initiated) {
        fprintf(stderr, "[PLUG] Complete called but not initiated - REJECTED\n");
        return false;
    }
    
    /* Validate hex length (64 chars for 32 bytes) */
    if (strlen(peer_pubkey_hex) != 64) {
        fprintf(stderr, "[PLUG] Invalid peer public key length: %zu\n", strlen(peer_pubkey_hex));
        return false;
    }
    
    /* Validate hex characters */
    for (size_t i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)peer_pubkey_hex[i])) {
            fprintf(stderr, "[PLUG] Invalid hex character in peer public key\n");
            return false;
        }
    }
    
    strncpy(plug->peer_ecdh_public_key_hex, peer_pubkey_hex, 64);
    plug->peer_ecdh_public_key_hex[64] = '\0';
    
    /* Convert peer public key from hex to bytes */
    unsigned char peer_pubkey[32];
    if (orca_hex_to_bytes(peer_pubkey_hex, peer_pubkey, 32) < 0) {
        fprintf(stderr, "[PLUG] Failed to parse peer public key hex\n");
        return false;
    }
    
    /* Compute shared secret using our private key and peer's public key */
    if (orca_ecdh_compute_shared_secret(plug->ecdh_private_key, peer_pubkey,
                                        plug->ecdh_shared_secret) < 0) {
        fprintf(stderr, "[PLUG] Failed to compute shared secret\n");
        return false;
    }
    
    /* Derive AES-256-GCM key from shared secret */
    if (orca_aes_gcm_derive_key_from_shared_secret(plug->ecdh_shared_secret, NULL, 0,
                                                   (const unsigned char*)"orcashi-chat", 12,
                                                   plug->aes_key) < 0) {
        fprintf(stderr, "[PLUG] Failed to derive AES key\n");
        return false;
    }
    
    /* Secure channel is now established (initiator) */
    memset(plug->nonce, 0, 12);
    plug->nonce_counter = 0;
    plug->ecdh_complete = true;
    plug->secure_mode = true;
    plug->ecdh_initiated = false;
    
    printf("[PLUG] ECDH secure channel established (initiator)\n");
    return true;
}

bool plug_ecdh_complete(TCPPlug* plug) {
    return plug && plug->ecdh_complete && plug->secure_mode;
}

/* ============================================================================
 * SECURE MESSAGING - SEND (FIXED: Raw AES Key)
 * ============================================================================ */

bool plug_send_secure(TCPPlug* plug, const char* msg) {
    if (!plug || !plug->connected || !plug->ecdh_complete || !plug->secure_mode) {
        return false;
    }
    
    /* Increment nonce counter (must never repeat) */
    plug->nonce_counter++;
    
    /* Build 12-byte nonce: 8-byte counter (big-endian) + 4 zero bytes */
    unsigned char nonce[12];
    memset(nonce, 0, 12);
    for (int i = 0; i < 8; i++) {
        nonce[11 - i] = (plug->nonce_counter >> (i * 8)) & 0xFF;
    }
    
    /* Encrypt with AES-256-GCM using raw key directly */
    unsigned char tag[16];
    unsigned char* ciphertext = NULL;
    size_t ciphertext_len = 0;
    
    if (orca_aes_gcm_encrypt((const unsigned char*)msg, strlen(msg),
                             plug->aes_key, nonce, tag,
                             &ciphertext, &ciphertext_len) < 0) {
        fprintf(stderr, "[PLUG] Failed to encrypt message\n");
        return false;
    }
    
    /* Format: SECURE:<nonce_hex>:<tag_hex>:<ciphertext_b64>\n */
    char nonce_hex[25];
    char tag_hex[33];
    char* ciphertext_b64 = orca_base64_encode(ciphertext, ciphertext_len);
    
    orca_bytes_to_hex(nonce, 12, nonce_hex);
    orca_bytes_to_hex(tag, 16, tag_hex);
    
    char secure_msg[8192];
    snprintf(secure_msg, sizeof(secure_msg), "SECURE:%s:%s:%s\n",
             nonce_hex, tag_hex, ciphertext_b64);
    
    free(ciphertext);
    free(ciphertext_b64);
    
    /* Queue the message */
    pthread_mutex_lock(&plug->queue_mutex);
    if (plug->send_count >= plug->queue_capacity) {
        pthread_mutex_unlock(&plug->queue_mutex);
        return false;
    }
    
    char* msg_copy = strdup(secure_msg);
    if (!msg_copy) {
        pthread_mutex_unlock(&plug->queue_mutex);
        return false;
    }
    
    plug->send_queue[plug->send_count++] = msg_copy;
    pthread_cond_signal(&plug->queue_cond);
    pthread_mutex_unlock(&plug->queue_mutex);
    
    return true;
}

/* ============================================================================
 * SECURE MESSAGING - RECEIVE (FIXED: Raw AES Key)
 * ============================================================================ */

bool plug_receive_secure(TCPPlug* plug, char* msg, int msg_size) {
    if (!plug || !plug->ecdh_complete || !plug->secure_mode) {
        return false;
    }
    
    char raw_msg[8192];
    if (!plug_receive_message(plug, raw_msg, sizeof(raw_msg), 0)) {
        return false;
    }
    
    /* Skip handshake messages (should not happen after secure established) */
    if (strstr(raw_msg, "ECDH_INIT") != NULL ||
        strstr(raw_msg, "ECDH_RESPONSE") != NULL ||
        strstr(raw_msg, "HANDSHAKE") != NULL) {
        return false;
    }
    
    /* Check for SECURE: prefix */
    char* secure_start = strstr(raw_msg, "SECURE:");
    if (!secure_start) {
        /* Plaintext message - return as-is (legacy support) */
        strncpy(msg, raw_msg, msg_size - 1);
        msg[msg_size - 1] = '\0';
        return true;
    }
    
    /* Remove trailing newline if present */
    char* newline = strchr(secure_start, '\n');
    if (newline) {
        *newline = '\0';
    }
    
    /* Parse SECURE:<nonce>:<tag>:<ciphertext> */
    char* nonce_start = secure_start + 7;  /* Skip "SECURE:" */
    char* tag_start = strchr(nonce_start, ':');
    if (!tag_start) {
        strncpy(msg, raw_msg, msg_size - 1);
        msg[msg_size - 1] = '\0';
        return true;
    }
    tag_start++;
    
    char* cipher_start = strchr(tag_start, ':');
    if (!cipher_start) {
        strncpy(msg, raw_msg, msg_size - 1);
        msg[msg_size - 1] = '\0';
        return true;
    }
    cipher_start++;
    
    char nonce_hex[25];
    char tag_hex[33];
    
    size_t nonce_len = tag_start - nonce_start - 1;
    if (nonce_len >= sizeof(nonce_hex)) {
        fprintf(stderr, "[PLUG] Invalid nonce length\n");
        return false;
    }
    strncpy(nonce_hex, nonce_start, nonce_len);
    nonce_hex[nonce_len] = '\0';
    
    size_t tag_len = cipher_start - tag_start - 1;
    if (tag_len >= sizeof(tag_hex)) {
        fprintf(stderr, "[PLUG] Invalid tag length\n");
        return false;
    }
    strncpy(tag_hex, tag_start, tag_len);
    tag_hex[tag_len] = '\0';
    
    /* ===== FIX: Convert hex to raw bytes, use raw key directly ===== */
    unsigned char nonce[12];
    unsigned char tag[16];
    
    if (orca_hex_to_bytes(nonce_hex, nonce, 12) < 0) {
        fprintf(stderr, "[PLUG] Invalid nonce hex\n");
        return false;
    }
    
    if (orca_hex_to_bytes(tag_hex, tag, 16) < 0) {
        fprintf(stderr, "[PLUG] Invalid tag hex\n");
        return false;
    }
    
    int ciphertext_len;
    unsigned char* ciphertext = orca_base64_decode(cipher_start, &ciphertext_len);
    if (!ciphertext) {
        fprintf(stderr, "[PLUG] Failed to decode ciphertext\n");
        return false;
    }
    
    unsigned char* plaintext;
    size_t plaintext_len;
    
    /* ===== Use raw key directly, not hex string ===== */
    int result = orca_aes_gcm_decrypt(ciphertext, ciphertext_len,
                                      plug->aes_key, nonce, tag,
                                      &plaintext, &plaintext_len);
    free(ciphertext);
    
    if (result < 0) {
        fprintf(stderr, "[PLUG] Failed to decrypt secure message\n");
        return false;
    }
    
    strncpy(msg, (char*)plaintext, msg_size - 1);
    msg[msg_size - 1] = '\0';
    free(plaintext);
    
    return true;
}

bool plug_is_secure(TCPPlug* plug) {
    return plug && plug->secure_mode && plug->ecdh_complete;
}

/* ============================================================================
 * PLAINTEXT MESSAGING (Control/Handshake)
 * ============================================================================ */

bool plug_send_message(TCPPlug* plug, const char* msg) {
    if (!plug || !plug->connected) return false;
    
    size_t len = strlen(msg);
    size_t total_len = len + 2;
    char* msg_with_newline = (char*)malloc(total_len);
    if (!msg_with_newline) {
        return false;
    }
    
    snprintf(msg_with_newline, total_len, "%s\n", msg);
    
    pthread_mutex_lock(&plug->queue_mutex);
    if (plug->send_count >= plug->queue_capacity) {
        pthread_mutex_unlock(&plug->queue_mutex);
        free(msg_with_newline);
        return false;
    }
    
    plug->send_queue[plug->send_count++] = msg_with_newline;
    pthread_cond_signal(&plug->queue_cond);
    pthread_mutex_unlock(&plug->queue_mutex);
    
    return true;
}

/* Legacy secure message (deprecated - kept for API compatibility) */
bool plug_send_secure_message(TCPPlug* plug, const char* msg, const char* key_hex) {
    (void)key_hex;  /* Ignored - use plug->aes_key instead */
    if (plug_ecdh_complete(plug)) {
        return plug_send_secure(plug, msg);
    }
    return plug_send_message(plug, msg);
}

bool plug_receive_message(TCPPlug* plug, char* msg, int msg_size, int timeout_ms) {
    if (!plug) return false;
    
    pthread_mutex_lock(&plug->queue_mutex);
    
    if (plug->message_count == 0) {
        if (timeout_ms > 0) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += timeout_ms / 1000;
            ts.tv_nsec += (timeout_ms % 1000) * 1000000;
            if (ts.tv_nsec >= 1000000000) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000;
            }
            pthread_cond_timedwait(&plug->queue_cond, &plug->queue_mutex, &ts);
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += 5000000;
            if (ts.tv_nsec >= 1000000000) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000;
            }
            pthread_cond_timedwait(&plug->queue_cond, &plug->queue_mutex, &ts);
        }
    }
    
    if (plug->message_count == 0) {
        pthread_mutex_unlock(&plug->queue_mutex);
        return false;
    }
    
    char* msg_ptr = plug->message_queue[0];
    strncpy(msg, msg_ptr, msg_size - 1);
    msg[msg_size - 1] = '\0';
    free(msg_ptr);
    
    for (int i = 0; i < plug->message_count - 1; i++) {
        plug->message_queue[i] = plug->message_queue[i + 1];
    }
    plug->message_count--;
    
    pthread_mutex_unlock(&plug->queue_mutex);
    return true;
}

/* ============================================================================
 * LEGACY HANDSHAKE (Deprecated - kept for API compatibility)
 * ============================================================================ */

bool plug_start_handshake(TCPPlug* plug, const char* public_key_hex) {
    (void)public_key_hex;
    /* Legacy - not used with new ECDH */
    if (!plug || !plug->connected) return false;
    return plug_initiate_ecdh(plug);
}

bool plug_complete_handshake(TCPPlug* plug, const char* peer_public_key_hex) {
    if (!plug || !plug->connected || !peer_public_key_hex) return false;
    return plug_complete_ecdh(plug, peer_public_key_hex);
}

bool plug_handshake_complete(TCPPlug* plug) {
    return plug_ecdh_complete(plug);
}

/* ============================================================================
 * RECEIVE LOOP
 * ============================================================================ */

static void* receive_loop(void* arg) {
    TCPPlug* plug = (TCPPlug*)arg;
    char buffer[BUFFER_SIZE];
    char* accumulated = (char*)calloc(1, BUFFER_SIZE * 4);
    if (!accumulated) {
        return NULL;
    }
    int acc_len = 0;
    fd_set fds;
    struct timeval tv;
    
    while (plug->running && plug->connected) {
        FD_ZERO(&fds);
        FD_SET(plug->client_socket, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 5000;
        
        int ret = select(plug->client_socket + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) break;
        if (ret == 0) continue;
        
        int n = recv(plug->client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (n <= 0) {
            plug->connected = false;
            break;
        }
        
        buffer[n] = '\0';
        
        if (acc_len + n < BUFFER_SIZE * 4) {
            memcpy(accumulated + acc_len, buffer, n);
            acc_len += n;
        }
        
        char* pos = accumulated;
        char* newline;
        while ((newline = strchr(pos, '\n')) != NULL) {
            *newline = '\0';
            if (strlen(pos) > 0) {
                char* msg = (char*)malloc(strlen(pos) + 1);
                if (msg) {
                    strcpy(msg, pos);
                    
                    bool is_handshake = plug_parse_handshake(plug, msg);
                    
                    if (!is_handshake) {
                        pthread_mutex_lock(&plug->queue_mutex);
                        if (plug->message_count < plug->queue_capacity) {
                            plug->message_queue[plug->message_count++] = msg;
                        } else {
                            free(msg);
                        }
                        pthread_cond_signal(&plug->queue_cond);
                        pthread_mutex_unlock(&plug->queue_mutex);
                    } else {
                        free(msg);
                    }
                }
            }
            pos = newline + 1;
        }
        
        if (pos > accumulated) {
            acc_len = strlen(pos);
            memmove(accumulated, pos, acc_len + 1);
        }
    }
    
    free(accumulated);
    return NULL;
}

/* ============================================================================
 * SEND LOOP
 * ============================================================================ */

static void* send_loop(void* arg) {
    TCPPlug* plug = (TCPPlug*)arg;
    
    while (plug->running && plug->connected) {
        char* msg = NULL;
        
        pthread_mutex_lock(&plug->queue_mutex);
        while (plug->send_count == 0 && plug->running) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += 1000000;
            if (ts.tv_nsec >= 1000000000) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000;
            }
            pthread_cond_timedwait(&plug->queue_cond, &plug->queue_mutex, &ts);
        }
        
        if (!plug->running) {
            pthread_mutex_unlock(&plug->queue_mutex);
            break;
        }
        
        if (plug->send_count > 0) {
            msg = plug->send_queue[0];
            for (int i = 0; i < plug->send_count - 1; i++) {
                plug->send_queue[i] = plug->send_queue[i + 1];
            }
            plug->send_count--;
        }
        pthread_mutex_unlock(&plug->queue_mutex);
        
        if (msg) {
            send(plug->client_socket, msg, strlen(msg), MSG_NOSIGNAL);
            free(msg);
        }
    }
    
    return NULL;
}

/* ============================================================================
 * HANDSHAKE PARSER
 * ============================================================================ */

static bool plug_parse_handshake(TCPPlug* plug, const char* msg) {
    /* ECDH_INIT:<pubkey> - Received by responder */
    if (strncmp(msg, "ECDH_INIT:", 10) == 0) {
        const char* pubkey = msg + 10;
        plug_respond_ecdh(plug, pubkey);
        return true;
    }
    
    /* ECDH_RESPONSE:<pubkey> - Received by initiator */
    if (strncmp(msg, "ECDH_RESPONSE:", 14) == 0) {
        const char* pubkey = msg + 14;
        
        /* ===== FIX: Only initiator can complete ===== */
        if (!plug->ecdh_initiated) {
            printf("[PLUG] Ignoring ECDH_RESPONSE - not initiator\n");
            return true;
        }
        
        plug_complete_ecdh(plug, pubkey);
        return true;
    }
    
    /* Legacy HANDSHAKE messages - ignored (deprecated) */
    if (strncmp(msg, "HANDSHAKE:", 10) == 0) {
        return true;
    }
    if (strncmp(msg, "HANDSHAKE_RESPONSE:", 19) == 0) {
        return true;
    }
    if (strcmp(msg, "HANDSHAKE_OK") == 0) {
        return true;
    }
    
    return false;
}

/* ============================================================================
 * CONNECTION MANAGEMENT
 * ============================================================================ */

bool plug_is_connected(TCPPlug* plug) {
    return plug && plug->connected;
}

const char* plug_get_peer_ip(TCPPlug* plug) {
    return plug ? plug->peer_ip : NULL;
}

int plug_get_socket(TCPPlug* plug) {
    return plug ? plug->client_socket : -1;
}

void plug_close_connection(TCPPlug* plug) {
    if (!plug) return;
    
    plug->running = false;
    plug->connected = false;
    plug->handshake_complete = false;
    plug->secure_mode = false;
    plug->ecdh_initiated = false;
    plug->ecdh_complete = false;
    
    /* Zeroize sensitive data */
    memset(plug->ecdh_shared_secret, 0, 32);
    memset(plug->aes_key, 0, 32);
    memset(plug->ecdh_private_key, 0, 32);
    memset(plug->ecdh_public_key, 0, 32);
    plug->nonce_counter = 0;
    
    if (plug->client_socket >= 0) {
        close(plug->client_socket);
        plug->client_socket = -1;
    }
    if (plug->plug_socket >= 0) {
        close(plug->plug_socket);
        plug->plug_socket = -1;
    }
    
    pthread_cond_broadcast(&plug->queue_cond);
    
    if (plug->receive_thread) {
        pthread_join(plug->receive_thread, NULL);
        plug->receive_thread = 0;
    }
    if (plug->send_thread) {
        pthread_join(plug->send_thread, NULL);
        plug->send_thread = 0;
    }
}
