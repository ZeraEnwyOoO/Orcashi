 #include "endpoint.h"

EndpointRegistry* endpoint_registry_create(void) {
    EndpointRegistry* er = (EndpointRegistry*)calloc(1, sizeof(EndpointRegistry));
    if (!er) return NULL;
    
    er->endpoint_count = 0;
    er->heartbeat_interval = 30;
    
    pthread_mutex_init(&er->mutex, NULL);
    
    return er;
}

void endpoint_registry_destroy(EndpointRegistry* er) {
    if (!er) return;
    
    pthread_mutex_destroy(&er->mutex);
    free(er);
}

void endpoint_register(EndpointRegistry* er, const char* id, const char* ip, int port) {
    if (!er) return;
    
    pthread_mutex_lock(&er->mutex);
    
    for (int i = 0; i < er->endpoint_count; i++) {
        if (strcmp(er->endpoints[i].id, id) == 0) {
            strcpy(er->endpoints[i].ip, ip);
            er->endpoints[i].port = port;
            er->endpoints[i].last_update = time(NULL);
            er->endpoints[i].verified = false;
            pthread_mutex_unlock(&er->mutex);
            return;
        }
    }
    
    if (er->endpoint_count < MAX_ENDPOINTS) {
        EndpointInfo* info = &er->endpoints[er->endpoint_count++];
        strcpy(info->id, id);
        strcpy(info->ip, ip);
        info->port = port;
        info->last_update = time(NULL);
        info->verified = false;
        memset(info->public_key_hash, 0, sizeof(info->public_key_hash));
    }
    
    pthread_mutex_unlock(&er->mutex);
}

bool endpoint_get(EndpointRegistry* er, const char* id, EndpointInfo* out_info) {
    if (!er || !out_info) return false;
    
    pthread_mutex_lock(&er->mutex);
    
    for (int i = 0; i < er->endpoint_count; i++) {
        if (strcmp(er->endpoints[i].id, id) == 0) {
            *out_info = er->endpoints[i];
            pthread_mutex_unlock(&er->mutex);
            return true;
        }
    }
    
    pthread_mutex_unlock(&er->mutex);
    return false;
}

void endpoint_update(EndpointRegistry* er, const char* id, const char* ip, int port) {
    if (!er) return;
    
    pthread_mutex_lock(&er->mutex);
    
    for (int i = 0; i < er->endpoint_count; i++) {
        if (strcmp(er->endpoints[i].id, id) == 0) {
            strcpy(er->endpoints[i].ip, ip);
            er->endpoints[i].port = port;
            er->endpoints[i].last_update = time(NULL);
            break;
        }
    }
    
    pthread_mutex_unlock(&er->mutex);
}

void endpoint_remove(EndpointRegistry* er, const char* id) {
    if (!er) return;
    
    pthread_mutex_lock(&er->mutex);
    
    for (int i = 0; i < er->endpoint_count; i++) {
        if (strcmp(er->endpoints[i].id, id) == 0) {
            for (int j = i; j < er->endpoint_count - 1; j++) {
                er->endpoints[j] = er->endpoints[j + 1];
            }
            er->endpoint_count--;
            break;
        }
    }
    
    pthread_mutex_unlock(&er->mutex);
}

int endpoint_get_all(EndpointRegistry* er, EndpointInfo* infos, int max) {
    if (!er || !infos) return 0;
    
    pthread_mutex_lock(&er->mutex);
    
    int count = 0;
    for (int i = 0; i < er->endpoint_count && count < max; i++) {
        infos[count++] = er->endpoints[i];
    }
    
    pthread_mutex_unlock(&er->mutex);
    return count;
}

void endpoint_cleanup_stale(EndpointRegistry* er, int max_age_seconds) {
    if (!er) return;
    
    time_t now = time(NULL);
    
    pthread_mutex_lock(&er->mutex);
    
    int i = 0;
    while (i < er->endpoint_count) {
        if (now - er->endpoints[i].last_update > max_age_seconds) {
            for (int j = i; j < er->endpoint_count - 1; j++) {
                er->endpoints[j] = er->endpoints[j + 1];
            }
            er->endpoint_count--;
        } else {
            i++;
        }
    }
    
    pthread_mutex_unlock(&er->mutex);
}

void endpoint_set_heartbeat(EndpointRegistry* er, int seconds) {
    if (er) {
        er->heartbeat_interval = seconds;
    }
}
