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
    addr.sin_family
