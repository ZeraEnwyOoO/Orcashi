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

#define QUEUE_INITIAL_SIZE 100
#define BUFFER_SIZE 16384
#define HANDSHAKE_TIMEOUT 30

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
    
    memset(plug->ecdh_shared_secret, 0, 32);
    memset(plug->aes_key, 0, 32);
    memset(plug->ecdh_private_key, 0, 32);
    
    pthread_mutex_destroy(&plug->queue_mutex);
    pthread_cond_destroy(&plug->queue_cond);
    
    free(plug);
}

/* ============================================================================
 * SERVER
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

/* ============================================================================
 * CLIENT
 * ============================================================================ */

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
 * ECDH SECURE HANDSHAKE
 * ============================================================================ */

bool plug_initiate_ecdh(TCPPlug* plug) {
    if (!plug || !plug->connected) return false;
    
    OrcaECDHKeypair keypair;
    if (orca_ecdh_generate_keypair(&keypair) < 0) {
        fprintf(stderr, "[PLUG] Failed to generate ECDH keypair\n");
        return false;
    }
    
    memcpy(plug->ecdh_public_key, keypair.public_key, 32);
    memcpy(plug->ecdh_private_key, keypair.private_key, 32);
    
    char pubkey_hex[65];
    orca_bytes_to_hex(keypair.public_key, 32, pubkey_hex);
    
    char msg[128];
    snprintf(msg, sizeof(msg), "ECDH_INIT:%s", pubkey_hex);
    
    if (!plug_send_message(plug, msg)) {
        return false;
    }
    
    plug->ecdh_initiated = true;
    printf("[PLUG] ECDH initiated\n");
    return true;
}

bool plug_respond_ecdh(TCPPlug* plug, const char* peer_pubkey_hex) {
    if (!plug || !plug->connected) return false;
    
    strcpy(plug->peer_ecdh_public_key_hex, peer_pubkey_hex);
    
    OrcaECDHKeypair keypair;
    if (orca_ecdh_generate_keypair(&keypair) < 0) {
        fprintf(stderr, "[PLUG] Failed to generate ECDH keypair for response\n");
        return false;
    }
    
    memcpy(plug->ecdh_public_key, keypair.public_key, 32);
    memcpy(plug->ecdh_private_key, keypair.private_key, 32);
    
    unsigned char peer_pubkey[32];
    if (orca_hex_to_bytes(peer_pubkey_hex, peer_pubkey, 32) < 0) {
        return false;
    }
    
    if (orca_ecdh_compute_shared_secret(keypair.private_key, peer_pubkey,
                                        plug->ecdh_shared_secret) < 0) {
        fprintf(stderr, "[PLUG] Failed to compute shared secret\n");
        return false;
    }
    
    if (orca_aes_gcm_derive_key_from_shared_secret(plug->ecdh_shared_secret, NULL, 0,
                                                   (const unsigned char*)"orcashi-chat", 12,
                                                   plug->aes_key) < 0) {
        fprintf(stderr, "[PLUG] Failed to derive AES key\n");
        return false;
    }
    
    char pubkey_hex[65];
    orca_bytes_to_hex(keypair.public_key, 32, pubkey_hex);
    
    char msg[128];
    snprintf(msg, sizeof(msg), "ECDH_RESPONSE:%s", pubkey_hex);
    
    if (!plug_send_message(plug, msg)) {
        return false;
    }
    
    memset(plug->nonce, 0, 12);
    plug->nonce_counter = 0;
    plug->ecdh_complete = true;
    plug->secure_mode = true;
    
    printf("[PLUG] ECDH secure channel established (responder)\n");
    return true;
}

bool plug_complete_ecdh(TCPPlug* plug, const char* peer_pubkey_hex) {
    if (!plug || !plug->connected) return false;
    
    strcpy(plug->peer_ecdh_public_key_hex, peer_pubkey_hex);
    
    unsigned char peer_pubkey[32];
    if (orca_hex_to_bytes(peer_pubkey_hex, peer_pubkey, 32) < 0) {
        return false;
    }
    
    if (orca_ecdh_compute_shared_secret(plug->ecdh_private_key, peer_pubkey,
                                        plug->ecdh_shared_secret) < 0) {
        fprintf(stderr, "[PLUG] Failed to compute shared secret\n");
        return false;
    }
    
    if (orca_aes_gcm_derive_key_from_shared_secret(plug->ecdh_shared_secret, NULL, 0,
                                                   (const unsigned char*)"orcashi-chat", 12,
                                                   plug->aes_key) < 0) {
        fprintf(stderr, "[PLUG] Failed to derive AES key\n");
        return false;
    }
    
    memset(plug->nonce, 0, 12);
    plug->nonce_counter = 0;
    plug->ecdh_complete = true;
    plug->secure_mode = true;
    
    printf("[PLUG] ECDH secure channel established (initiator)\n");
    return true;
}

bool plug_ecdh_complete(TCPPlug* plug) {
    return plug && plug->ecdh_complete && plug->secure_mode;
}

/* ============================================================================
 * SECURE MESSAGING
 * ============================================================================ */

bool plug_send_secure(TCPPlug* plug, const char* msg) {
    if (!plug || !plug->connected || !plug->ecdh_complete) {
        return false;
    }
    
    plug->nonce_counter++;
    
    unsigned char nonce[12];
    memset(nonce, 0, 12);
    for (int i = 0; i < 8; i++) {
        nonce[11 - i] = (plug->nonce_counter >> (i * 8)) & 0xFF;
    }
    
    unsigned char tag[16];
    unsigned char* ciphertext = NULL;
    size_t ciphertext_len = 0;
    
    if (orca_aes_gcm_encrypt((const unsigned char*)msg, strlen(msg),
                             plug->aes_key, nonce, tag,
                             &ciphertext, &ciphertext_len) < 0) {
        fprintf(stderr, "[PLUG] Failed to encrypt message\n");
        return false;
    }
    
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
    
    if (!plug->connected) return false;
    
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
 * RECEIVE SECURE MESSAGE - FIXED: Skip handshake messages
 * ============================================================================ */

bool plug_receive_secure(TCPPlug* plug, char* msg, int msg_size) {
    if (!plug || !plug->ecdh_complete) {
        return false;
    }
    
    char raw_msg[8192];
    if (!plug_receive_message(plug, raw_msg, sizeof(raw_msg), 0)) {
        return false;
    }
    
    /* ===== FIX: Skip handshake messages ===== */
    if (strncmp(raw_msg, "ECDH_INIT:", 10) == 0 ||
        strncmp(raw_msg, "ECDH_RESPONSE:", 14) == 0 ||
        strncmp(raw_msg, "HANDSHAKE:", 10) == 0 ||
        strncmp(raw_msg, "HANDSHAKE_RESPONSE:", 19) == 0 ||
        strcmp(raw_msg, "HANDSHAKE_OK") == 0) {
        return false;  /* Don't return handshake messages to chat */
    }
    
    char* secure_start = strstr(raw_msg, "SECURE:");
    if (!secure_start) {
        strncpy(msg, raw_msg, msg_size - 1);
        msg[msg_size - 1] = '\0';
        return true;
    }
    
    char* newline = strchr(secure_start, '\n');
    if (newline) {
        *newline = '\0';
    }
    
    char* nonce_start = secure_start + 7;
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
    strncpy(nonce_hex, nonce_start, tag_start - nonce_start - 1);
    nonce_hex[tag_start - nonce_start - 1] = '\0';
    strncpy(tag_hex, tag_start, cipher_start - tag_start - 1);
    tag_hex[cipher_start - tag_start - 1] = '\0';
    
    char* plaintext = NULL;
    if (orca_aes_gcm_decrypt_string(cipher_start, nonce_hex, tag_hex,
                                    (char*)plug->aes_key, &plaintext) < 0) {
        fprintf(stderr, "[PLUG] Failed to decrypt secure message\n");
        return false;
    }
    
    strncpy(msg, plaintext, msg_size - 1);
    msg[msg_size - 1] = '\0';
    free(plaintext);
    
    return true;
}

/* ============================================================================
 * MESSAGING
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

bool plug_send_secure_message(TCPPlug* plug, const char* msg, const char* key_hex) {
    if (!plug || !plug->connected || !key_hex) return false;
    
    char nonce_hex[25];
    char tag_hex[33];
    char* ciphertext_b64 = NULL;
    
    if (orca_aes_gcm_encrypt_string(msg, key_hex, nonce_hex, tag_hex, &ciphertext_b64) < 0) {
        return false;
    }
    
    char secure_msg[BUFFER_SIZE];
    snprintf(secure_msg, sizeof(secure_msg), "SECURE:%s:%s:%s\n",
             nonce_hex, tag_hex, ciphertext_b64);
    free(ciphertext_b64);
    
    return plug_send_message(plug, secure_msg);
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
 * LEGACY HANDSHAKE
 * ============================================================================ */

static bool plug_parse_handshake(TCPPlug* plug, const char* msg) {
    if (strncmp(msg, "HANDSHAKE:", 10) == 0) {
        const char* pub_key = msg + 10;
        strcpy(plug->peer_public_key_hex, pub_key);
        
        char response[256];
        snprintf(response, sizeof(response), "HANDSHAKE_RESPONSE:%s", pub_key);
        plug_send_message(plug, response);
        
        plug_complete_handshake(plug, pub_key);
        return true;
    }
    
    if (strncmp(msg, "HANDSHAKE_RESPONSE:", 19) == 0) {
        const char* pub_key = msg + 19;
        plug_complete_handshake(plug, pub_key);
        return true;
    }
    
    if (strcmp(msg, "HANDSHAKE_OK") == 0) {
        plug->handshake_complete = true;
        plug->secure_mode = true;
        return true;
    }
    
    if (strncmp(msg, "ECDH_INIT:", 10) == 0) {
        const char* pubkey = msg + 10;
        plug_respond_ecdh(plug, pubkey);
        return true;
    }
    
    if (strncmp(msg, "ECDH_RESPONSE:", 14) == 0) {
        const char* pubkey = msg + 14;
        plug_complete_ecdh(plug, pubkey);
        return true;
    }
    
    return false;
}

bool plug_start_handshake(TCPPlug* plug, const char* public_key_hex) {
    if (!plug || !plug->connected) return false;
    
    char handshake[256];
    snprintf(handshake, sizeof(handshake), "HANDSHAKE:%s", public_key_hex);
    
    return plug_send_message(plug, handshake);
}

bool plug_complete_handshake(TCPPlug* plug, const char* peer_public_key_hex) {
    if (!plug || !plug->connected) return false;
    
    strcpy(plug->peer_public_key_hex, peer_public_key_hex);
    
    char combined[65];
    strcpy(combined, peer_public_key_hex);
    strcat(combined, "shared-secret");
    
    unsigned char hash[32];
    orca_hash_string(combined, hash);
    orca_bytes_to_hex(hash, 32, plug->aes_key_hex);
    
    plug->secure_mode = true;
    plug->handshake_complete = true;
    
    plug_send_message(plug, "HANDSHAKE_OK");
    
    printf("[PLUG] Legacy handshake complete!\n");
    return true;
}

bool plug_handshake_complete(TCPPlug* plug) {
    return plug && plug->handshake_complete && plug->secure_mode;
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
    
    memset(plug->ecdh_shared_secret, 0, 32);
    memset(plug->aes_key, 0, 32);
    memset(plug->ecdh_private_key, 0, 32);
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
