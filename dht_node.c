 // dht_node.c - Fixed version (remove unused function)
#include "dht_node.h"
#include "dht.h"
#include "bootstrap.h"
#include "orca_identity.h"
#include "orca_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define DHT_BUF_SIZE 4096
#define DHT_LOOKUP_TIMEOUT 20

struct DHTNode {
    int udp_socket;
    int port;
    bool running;
    pthread_t thread;
    pthread_mutex_t mutex;
    
    unsigned char my_dht_id[20];
    char my_orcashi_id[64];
    int my_port;
    bool announced;
    bool secure_mode;
    char public_key[ORCA_PUBKEY_LEN];
    char signature[ORCA_SIG_LEN];
    
    char lookup_id[64];
    char lookup_ip[INET_ADDRSTRLEN];
    int lookup_port;
    char lookup_public_key[ORCA_PUBKEY_LEN];
    char lookup_signature[ORCA_SIG_LEN];
    bool lookup_done;
    bool lookup_secure;
    time_t lookup_start;
    int lookup_timeout;
    bool bootstrap_done;
};

static void* dht_node_thread(void* arg);
static void dht_node_callback(void* closure, int event,
                              const unsigned char* info_hash,
                              const void* data, size_t data_len);

DHTNode* dht_node_create(void) {
    DHTNode* node = (DHTNode*)calloc(1, sizeof(DHTNode));
    if (!node) return NULL;
    
    node->udp_socket = -1;
    node->port = DHT_NODE_PORT;
    node->running = false;
    node->announced = false;
    node->lookup_done = false;
    node->lookup_timeout = DHT_LOOKUP_TIMEOUT;
    node->bootstrap_done = false;
    node->secure_mode = false;
    
    pthread_mutex_init(&node->mutex, NULL);
    
    return node;
}

void dht_node_destroy(DHTNode* node) {
    if (!node) return;
    
    dht_node_stop(node);
    
    if (node->udp_socket >= 0) {
        close(node->udp_socket);
        node->udp_socket = -1;
    }
    
    pthread_mutex_destroy(&node->mutex);
    free(node);
}

int dht_node_start(DHTNode* node, int port) {
    if (!node) return -1;
    
    node->port = port;
    
    node->udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (node->udp_socket < 0) {
        fprintf(stderr, "[DHT] Failed to create UDP socket: %s\n", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    setsockopt(node->udp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(node->udp_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[DHT] Failed to bind UDP socket: %s\n", strerror(errno));
        close(node->udp_socket);
        node->udp_socket = -1;
        return -1;
    }
    
    char seed[64];
    snprintf(seed, sizeof(seed), "Orcashi-v4-%d-%lld", getpid(), (long long)time(NULL));
    dht_hash(node->my_dht_id, 20, seed, strlen(seed), NULL, 0, NULL, 0);
    
    if (dht_init(node->udp_socket, -1, node->my_dht_id, NULL) < 0) {
        fprintf(stderr, "[DHT] Failed to init DHT: %s\n", strerror(errno));
        close(node->udp_socket);
        node->udp_socket = -1;
        return -1;
    }
    
    bootstrap_connect_dht(node->udp_socket);
    
    node->running = true;
    pthread_create(&node->thread, NULL, dht_node_thread, node);
    
    printf("[DHT] Started on port %d\n", port);
    return 0;
}

void dht_node_stop(DHTNode* node) {
    if (!node || !node->running) return;
    
    node->running = false;
    
    if (node->thread) {
        pthread_join(node->thread, NULL);
        node->thread = 0;
    }
    
    dht_uninit();
    printf("[DHT] Stopped\n");
}

static void* dht_node_thread(void* arg) {
    DHTNode* node = (DHTNode*)arg;
    char buffer[DHT_BUF_SIZE];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    fd_set fds;
    struct timeval tv;
    time_t tosleep;
    
    printf("[DHT] Thread started\n");
    
    while (node->running) {
        FD_ZERO(&fds);
        FD_SET(node->udp_socket, &fds);
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(node->udp_socket + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            break;
        }
        
        if (ret > 0) {
            int n = recvfrom(node->udp_socket, buffer, sizeof(buffer) - 1, 0,
                            (struct sockaddr*)&from, &from_len);
            if (n > 0) {
                buffer[n] = '\0';
                dht_periodic(buffer, n, (struct sockaddr*)&from, from_len,
                            &tosleep, dht_node_callback, node);
            }
        }
        
        dht_periodic(NULL, 0, NULL, 0, &tosleep, dht_node_callback, node);
    }
    
    printf("[DHT] Thread stopped\n");
    return NULL;
}

static void dht_node_callback(void* closure, int event,
                              const unsigned char* info_hash,
                              const void* data, size_t data_len) {
    DHTNode* node = (DHTNode*)closure;
    (void)info_hash;
    
    if (event == DHT_EVENT_VALUES || event == DHT_EVENT_VALUES6) {
        const unsigned char* peer_data = (const unsigned char*)data;
        char ip[INET_ADDRSTRLEN];
        int port;
        
        if (data_len >= 6) {
            sprintf(ip, "%d.%d.%d.%d", 
                    peer_data[0], peer_data[1], peer_data[2], peer_data[3]);
            port = (peer_data[4] << 8) | peer_data[5];
            
            pthread_mutex_lock(&node->mutex);
            if (!node->lookup_done) {
                strcpy(node->lookup_ip, ip);
                node->lookup_port = port;
                node->lookup_done = true;
                printf("[DHT] Found peer: %s:%d\n", ip, port);
            }
            pthread_mutex_unlock(&node->mutex);
        }
    }
}

int dht_node_announce(DHTNode* node, const char* id, int port) {
    if (!node) return -1;
    
    unsigned char dht_id[20];
    dht_hash(dht_id, 20, id, strlen(id), NULL, 0, NULL, 0);
    
    pthread_mutex_lock(&node->mutex);
    strcpy(node->my_orcashi_id, id);
    node->my_port = port;
    node->announced = true;
    node->secure_mode = false;
    pthread_mutex_unlock(&node->mutex);
    
    printf("[DHT] Announcing %s at port %d...\n", id, port);
    return dht_search(dht_id, port, AF_INET, dht_node_callback, node);
}

int dht_node_announce_secure(DHTNode* node, const char* id, int port,
                             const char* public_key, const char* signature) {
    if (!node) return -1;
    
    char data_to_verify[512];
    snprintf(data_to_verify, sizeof(data_to_verify), "%s:%d:%s", id, port, public_key);
    
    if (!orca_rsa_verify_string(data_to_verify, signature, public_key)) {
        printf("[DHT] Invalid signature for secure announce\n");
        return -1;
    }
    
    unsigned char dht_id[20];
    dht_hash(dht_id, 20, id, strlen(id), NULL, 0, NULL, 0);
    
    pthread_mutex_lock(&node->mutex);
    strcpy(node->my_orcashi_id, id);
    node->my_port = port;
    node->announced = true;
    node->secure_mode = true;
    strcpy(node->public_key, public_key);
    strcpy(node->signature, signature);
    pthread_mutex_unlock(&node->mutex);
    
    printf("[DHT] Secure announce: %s at port %d\n", id, port);
    
    return dht_search(dht_id, port, AF_INET, dht_node_callback, node);
}

int dht_node_lookup(DHTNode* node, const char* id, int timeout_sec,
                    char* ip_out, int* port_out) {
    if (!node || !ip_out || !port_out) return 0;
    
    unsigned char dht_id[20];
    dht_hash(dht_id, 20, id, strlen(id), NULL, 0, NULL, 0);
    
    pthread_mutex_lock(&node->mutex);
    strcpy(node->lookup_id, id);
    node->lookup_done = false;
    node->lookup_secure = false;
    node->lookup_start = time(NULL);
    node->lookup_timeout = timeout_sec;
    pthread_mutex_unlock(&node->mutex);
    
    printf("[DHT] Looking up %s...\n", id);
    
    int ret = dht_search(dht_id, 0, AF_INET, dht_node_callback, node);
    if (ret < 0) {
        printf("[DHT] Search failed\n");
        return 0;
    }
    
    time_t start = time(NULL);
    while (time(NULL) - start < timeout_sec) {
        pthread_mutex_lock(&node->mutex);
        if (node->lookup_done) {
            strcpy(ip_out, node->lookup_ip);
            *port_out = node->lookup_port;
            pthread_mutex_unlock(&node->mutex);
            return 1;
        }
        pthread_mutex_unlock(&node->mutex);
        sleep(1);
    }
    
    printf("[DHT] Lookup timeout for %s\n", id);
    return 0;
}

int dht_node_lookup_secure(DHTNode* node, const char* id, int timeout_sec,
                           char* ip_out, int* port_out,
                           char* public_key_out, char* signature_out) {
    if (!node || !ip_out || !port_out || !public_key_out || !signature_out) return 0;
    
    unsigned char dht_id[20];
    dht_hash(dht_id, 20, id, strlen(id), NULL, 0, NULL, 0);
    
    pthread_mutex_lock(&node->mutex);
    strcpy(node->lookup_id, id);
    node->lookup_done = false;
    node->lookup_secure = true;
    node->lookup_start = time(NULL);
    node->lookup_timeout = timeout_sec;
    memset(node->lookup_public_key, 0, ORCA_PUBKEY_LEN);
    memset(node->lookup_signature, 0, ORCA_SIG_LEN);
    pthread_mutex_unlock(&node->mutex);
    
    printf("[DHT] Secure lookup for %s...\n", id);
    
    int ret = dht_search(dht_id, 0, AF_INET, dht_node_callback, node);
    if (ret < 0) {
        printf("[DHT] Search failed\n");
        return 0;
    }
    
    time_t start = time(NULL);
    while (time(NULL) - start < timeout_sec) {
        pthread_mutex_lock(&node->mutex);
        if (node->lookup_done) {
            strcpy(ip_out, node->lookup_ip);
            *port_out = node->lookup_port;
            strcpy(public_key_out, node->lookup_public_key);
            strcpy(signature_out, node->lookup_signature);
            pthread_mutex_unlock(&node->mutex);
            return 1;
        }
        pthread_mutex_unlock(&node->mutex);
        sleep(1);
    }
    
    printf("[DHT] Secure lookup timeout for %s\n", id);
    return 0;
}

void dht_node_periodic(DHTNode* node) {
    if (!node) return;
    
    time_t tosleep;
    dht_periodic(NULL, 0, NULL, 0, &tosleep, dht_node_callback, node);
}

bool dht_node_is_running(DHTNode* node) {
    return node && node->running;
}

int dht_node_get_port(DHTNode* node) {
    return node ? node->port : -1;
}
