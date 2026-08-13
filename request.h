 #ifndef REQUEST_H
#define REQUEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#define MAX_REQUESTS 1024

typedef struct {
    char from_id[64];
    char to_id[64];
    char status[16];
    time_t timestamp;
} Request;

typedef struct {
    Request requests[MAX_REQUESTS];
    int request_count;
    char request_file[512];
} RequestManager;

RequestManager* request_manager_create(void);
void request_manager_destroy(RequestManager* rm);
bool request_send(RequestManager* rm, const char* from_id, const char* to_id);
int request_get_pending(RequestManager* rm, const char* to_id, Request* out, int max);
bool request_accept(RequestManager* rm, const char* from_id, const char* to_id);
bool request_reject(RequestManager* rm, const char* from_id, const char* to_id);
bool request_exists(RequestManager* rm, const char* from_id, const char* to_id);
void request_save(RequestManager* rm);
void request_load(RequestManager* rm);

// ===== Helper: Remove < and > from ID =====
void strip_brackets(const char* input, char* output, size_t out_size);

#endif
