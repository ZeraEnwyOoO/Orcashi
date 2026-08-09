 // plug.h - TCP Plug in C
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

typedef struct {
    int plug_socket;
    int client_socket;
    bool connected;
    bool running;
    char peer_ip[INET_ADDRSTRLEN];
    char peer_id[64];
    
    pthread_t receive_thread;
    pthread_t send_thread;
    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_cond;
    
    char** message_queue;
    char** send_queue;
    int message_count;
    int send_count;
    int queue_capacity;
} TCPPlug;

// Functions
TCPPlug* plug_create(void);
void plug_destroy(TCPPlug* plug);

bool plug_create_server(TCPPlug* plug, int port);
bool plug_connect_client(TCPPlug* plug, const char* target_ip, int port);

bool plug_send_message(TCPPlug* plug, const char* msg);
bool plug_receive_message(TCPPlug* plug, char* msg, int msg_size, int timeout_ms);

bool plug_is_connected(TCPPlug* plug);
const char* plug_get_peer_ip(TCPPlug* plug);

void plug_close_connection(TCPPlug* plug);

#endif
