 #define _POSIX_C_SOURCE 200809L

#include "plug.h"
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
#define BUFFER_SIZE 4096

static void* receive_loop(void* arg);
static void* send_loop(void* arg);

TCPPlug* plug_create(void) {
    TCPPlug* plug = (TCPPlug*)calloc(1, sizeof(TCPPlug));
    if (!plug) return NULL;
    
    plug->plug_socket = -1;
    plug->client_socket = -1;
    plug->connected = false;
    plug->running = false;
    plug->queue_capacity = QUEUE_INITIAL_SIZE;
    
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
    
    pthread_mutex_destroy(&plug->queue_mutex);
    pthread_cond_destroy(&plug->queue_cond);
    
    free(plug);
}

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
    
    printf("[ORCA] Client connected from %s!\n", plug->peer_ip);
    
    int flag = 1;
    setsockopt(plug->client_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
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
    
    printf("[ORCA] Connected to %s:%d!\n", target_ip, port);
    
    int flag = 1;
    setsockopt(plug->client_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
    pthread_create(&plug->receive_thread, NULL, receive_loop, plug);
    pthread_create(&plug->send_thread, NULL, send_loop, plug);
    
    return true;
}

static void* receive_loop(void* arg) {
    TCPPlug* plug = (TCPPlug*)arg;
    char buffer[BUFFER_SIZE];
    char* accumulated = (char*)calloc(1, BUFFER_SIZE * 2);
    int acc_len = 0;
    fd_set fds;
    struct timeval tv;
    
    while (plug->running && plug->connected) {
        FD_ZERO(&fds);
        FD_SET(plug->client_socket, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(plug->client_socket + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) break;
        if (ret == 0) continue;
        
        int n = recv(plug->client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (n <= 0) {
            plug->connected = false;
            break;
        }
        
        buffer[n] = '\0';
        
        if (acc_len + n < BUFFER_SIZE * 2) {
            memcpy(accumulated + acc_len, buffer, n);
            acc_len += n;
        }
        
        char* pos = accumulated;
        char* newline;
        while ((newline = strchr(pos, '\n')) != NULL) {
            *newline = '\0';
            if (strlen(pos) > 0) {
                char* msg = (char*)malloc(strlen(pos) + 1);
                strcpy(msg, pos);
                
                pthread_mutex_lock(&plug->queue_mutex);
                if (plug->message_count < plug->queue_capacity) {
                    plug->message_queue[plug->message_count++] = msg;
                } else {
                    free(msg);
                }
                pthread_cond_signal(&plug->queue_cond);
                pthread_mutex_unlock(&plug->queue_mutex);
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

static void* send_loop(void* arg) {
    TCPPlug* plug = (TCPPlug*)arg;
    
    while (plug->running && plug->connected) {
        char* msg = NULL;
        
        pthread_mutex_lock(&plug->queue_mutex);
        while (plug->send_count == 0 && plug->running) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 1;
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

bool plug_send_message(TCPPlug* plug, const char* msg) {
    if (!plug || !plug->connected) return false;
    
    pthread_mutex_lock(&plug->queue_mutex);
    if (plug->send_count >= plug->queue_capacity) {
        pthread_mutex_unlock(&plug->queue_mutex);
        return false;
    }
    
    char* msg_copy = (char*)malloc(strlen(msg) + 2);
    sprintf(msg_copy, "%s\n", msg);
    plug->send_queue[plug->send_count++] = msg_copy;
    pthread_cond_signal(&plug->queue_cond);
    pthread_mutex_unlock(&plug->queue_mutex);
    
    return true;
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
            pthread_cond_wait(&plug->queue_cond, &plug->queue_mutex);
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
