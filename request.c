 // request.c
#include "request.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define REQUEST_FILE "/tmp/.orcashi/requests.json"

// ===== JSON Escape Function =====
static void json_escape(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return;
    
    size_t i = 0, j = 0;
    size_t len = strlen(input);
    
    for (i = 0; i < len && j < out_size - 6; i++) {
        char c = input[i];
        switch (c) {
            case '"':  output[j++] = '\\'; output[j++] = '"'; break;
            case '\\': output[j++] = '\\'; output[j++] = '\\'; break;
            case '\b': output[j++] = '\\'; output[j++] = 'b'; break;
            case '\f': output[j++] = '\\'; output[j++] = 'f'; break;
            case '\n': output[j++] = '\\'; output[j++] = 'n'; break;
            case '\r': output[j++] = '\\'; output[j++] = 'r'; break;
            case '\t': output[j++] = '\\'; output[j++] = 't'; break;
            default:
                if (c < 0x20) {
                    snprintf(output + j, out_size - j, "\\u%04x", c);
                    j += 6;
                } else {
                    output[j++] = c;
                }
                break;
        }
    }
    output[j] = '\0';
}

void strip_brackets(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return;
    
    size_t i = 0, j = 0;
    size_t len = strlen(input);
    
    for (i = 0; i < len && j < out_size - 1; i++) {
        if (input[i] != '<' && input[i] != '>') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

RequestManager* request_manager_create(void) {
    RequestManager* rm = (RequestManager*)calloc(1, sizeof(RequestManager));
    if (!rm) return NULL;
    
    strcpy(rm->request_file, REQUEST_FILE);
    mkdir("/tmp/.orcashi/", 0700);
    request_load(rm);
    
    return rm;
}

void request_manager_destroy(RequestManager* rm) {
    if (rm) {
        request_save(rm);
        free(rm);
    }
}

bool request_send(RequestManager* rm, const char* from_id, const char* to_id) {
    if (!rm) return false;
    
    if (request_exists(rm, from_id, to_id)) {
        printf("[ORCA] Request already sent to %s\n", to_id);
        return false;
    }
    
    if (rm->request_count >= MAX_REQUESTS) return false;
    
    Request* req = &rm->requests[rm->request_count++];
    strcpy(req->from_id, from_id);
    strcpy(req->to_id, to_id);
    strcpy(req->status, "pending");
    req->timestamp = time(NULL);
    
    request_save(rm);
    printf("[ORCA] Request sent to %s!\n", to_id);
    return true;
}

int request_get_pending(RequestManager* rm, const char* to_id, Request* out, int max) {
    if (!rm || !out) return 0;
    
    char nt[64];
    strip_brackets(to_id, nt, sizeof(nt));
    
    int count = 0;
    for (int i = 0; i < rm->request_count && count < max; i++) {
        char rnt[64];
        strip_brackets(rm->requests[i].to_id, rnt, sizeof(rnt));
        
        if (strcmp(rnt, nt) == 0 &&
            strcmp(rm->requests[i].status, "pending") == 0) {
            out[count++] = rm->requests[i];
        }
    }
    
    return count;
}

bool request_accept(RequestManager* rm, const char* from_id, const char* to_id) {
    if (!rm) return false;
    
    char nf[64], nt[64];
    strip_brackets(from_id, nf, sizeof(nf));
    strip_brackets(to_id, nt, sizeof(nt));
    
    for (int i = 0; i < rm->request_count; i++) {
        char rnf[64], rnt[64];
        strip_brackets(rm->requests[i].from_id, rnf, sizeof(rnf));
        strip_brackets(rm->requests[i].to_id, rnt, sizeof(rnt));
        
        if (strcmp(rnf, nf) == 0 && strcmp(rnt, nt) == 0 &&
            strcmp(rm->requests[i].status, "pending") == 0) {
            strcpy(rm->requests[i].status, "accepted");
            request_save(rm);
            printf("[ORCA] Accepted request from %s!\n", from_id);
            return true;
        }
    }
    
    return false;
}

bool request_reject(RequestManager* rm, const char* from_id, const char* to_id) {
    if (!rm) return false;
    
    char nf[64], nt[64];
    strip_brackets(from_id, nf, sizeof(nf));
    strip_brackets(to_id, nt, sizeof(nt));
    
    for (int i = 0; i < rm->request_count; i++) {
        char rnf[64], rnt[64];
        strip_brackets(rm->requests[i].from_id, rnf, sizeof(rnf));
        strip_brackets(rm->requests[i].to_id, rnt, sizeof(rnt));
        
        if (strcmp(rnf, nf) == 0 && strcmp(rnt, nt) == 0 &&
            strcmp(rm->requests[i].status, "pending") == 0) {
            strcpy(rm->requests[i].status, "rejected");
            request_save(rm);
            printf("[ORCA] Rejected request from %s\n", from_id);
            return true;
        }
    }
    
    return false;
}

bool request_exists(RequestManager* rm, const char* from_id, const char* to_id) {
    if (!rm) return false;
    
    char nf[64], nt[64];
    strip_brackets(from_id, nf, sizeof(nf));
    strip_brackets(to_id, nt, sizeof(nt));
    
    for (int i = 0; i < rm->request_count; i++) {
        char rnf[64], rnt[64];
        strip_brackets(rm->requests[i].from_id, rnf, sizeof(rnf));
        strip_brackets(rm->requests[i].to_id, rnt, sizeof(rnt));
        
        if (strcmp(rnf, nf) == 0 && strcmp(rnt, nt) == 0 &&
            strcmp(rm->requests[i].status, "pending") == 0) {
            return true;
        }
    }
    
    return false;
}

// ===== FIXED: request_save with JSON escaping =====
void request_save(RequestManager* rm) {
    if (!rm) return;
    
    FILE* f = fopen(rm->request_file, "w");
    if (!f) return;
    
    char escaped_from[512], escaped_to[512], escaped_status[64];
    
    fprintf(f, "{\n  \"requests\": [\n");
    
    for (int i = 0; i < rm->request_count; i++) {
        if (i > 0) fprintf(f, ",\n");
        Request* r = &rm->requests[i];
        
        json_escape(r->from_id, escaped_from, sizeof(escaped_from));
        json_escape(r->to_id, escaped_to, sizeof(escaped_to));
        json_escape(r->status, escaped_status, sizeof(escaped_status));
        
        fprintf(f, "    {\n");
        fprintf(f, "      \"from_id\": \"%s\",\n", escaped_from);
        fprintf(f, "      \"to_id\": \"%s\",\n", escaped_to);
        fprintf(f, "      \"status\": \"%s\",\n", escaped_status);
        fprintf(f, "      \"timestamp\": %ld\n", (long)r->timestamp);
        fprintf(f, "    }");
    }
    
    fprintf(f, "\n  ]\n}\n");
    fclose(f);
}

// ===== FIXED: request_load with proper JSON parsing =====
void request_load(RequestManager* rm) {
    if (!rm) return;
    
    FILE* f = fopen(rm->request_file, "r");
    if (!f) return;
    
    char line[2048];
    Request req;
    bool in_request = false;
    int brace_depth = 0;
    
    while (fgets(line, sizeof(line), f)) {
        char* p = line;
        
        // Count braces to handle nested objects properly
        for (char* c = line; *c; c++) {
            if (*c == '{') brace_depth++;
            if (*c == '}') brace_depth--;
        }
        
        // Parse "from_id"
        char* from_start = strstr(line, "\"from_id\":");
        if (from_start) {
            char* start = strchr(from_start, '"');
            if (start) {
                start++;
                char* end = strchr(start, '"');
                if (end) {
                    int len = end - start;
                    if (len < (int)sizeof(req.from_id)) {
                        strncpy(req.from_id, start, len);
                        req.from_id[len] = '\0';
                        in_request = true;
                    }
                }
            }
        }
        
        // Parse "to_id"
        char* to_start = strstr(line, "\"to_id\":");
        if (to_start) {
            char* start = strchr(to_start, '"');
            if (start) {
                start++;
                char* end = strchr(start, '"');
                if (end) {
                    int len = end - start;
                    if (len < (int)sizeof(req.to_id)) {
                        strncpy(req.to_id, start, len);
                        req.to_id[len] = '\0';
                    }
                }
            }
        }
        
        // Parse "status"
        char* status_start = strstr(line, "\"status\":");
        if (status_start) {
            char* start = strchr(status_start, '"');
            if (start) {
                start++;
                char* end = strchr(start, '"');
                if (end) {
                    int len = end - start;
                    if (len < (int)sizeof(req.status)) {
                        strncpy(req.status, start, len);
                        req.status[len] = '\0';
                    }
                }
            }
        }
        
        // Parse "timestamp"
        char* ts_start = strstr(line, "\"timestamp\":");
        if (ts_start) {
            char* start = ts_start + 12;
            while (*start == ' ' || *start == '\t') start++;
            req.timestamp = atol(start);
        }
        
        // End of request object
        if (in_request && brace_depth == 0 && strchr(line, '}') != NULL) {
            if (strlen(req.from_id) > 0 && rm->request_count < MAX_REQUESTS) {
                rm->requests[rm->request_count++] = req;
                memset(&req, 0, sizeof(req));
                in_request = false;
            }
        }
    }
    
    fclose(f);
}
