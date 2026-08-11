 #ifndef ENDPOINT_H
#define ENDPOINT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

#define MAX_ENDPOINTS 1024

typedef struct {
    char id[64];
    char ip[INET_ADDRSTRLEN];
    int port;
    time_t last_update;
    bool verified;
    char public_key_hash[128];
} EndpointInfo;

typedef struct {
    EndpointInfo endpoints[MAX_ENDPOINTS];
    int endpoint_count;
    pthread_mutex_t mutex;
    int heartbeat_interval;
} EndpointRegistry;

EndpointRegistry* endpoint_registry_create(void);
void endpoint_registry_destroy(EndpointRegistry* er);

void endpoint_register(EndpointRegistry* er, const char* id, const char* ip, int port);
bool endpoint_get(EndpointRegistry* er, const char* id, EndpointInfo* out_info);
void endpoint_update(EndpointRegistry* er, const char* id, const char* ip, int port);
void endpoint_remove(EndpointRegistry* er, const char* id);
int endpoint_get_all(EndpointRegistry* er, EndpointInfo* infos, int max);
void endpoint_cleanup_stale(EndpointRegistry* er, int max_age_seconds);
void endpoint_set_heartbeat(EndpointRegistry* er, int seconds);

#endif
