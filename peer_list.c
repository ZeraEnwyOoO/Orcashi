// peer_list.c - Persistent accepted-peer list management
#include "peer_list.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#define PEER_LIST_DEBUG 1

#if PEER_LIST_DEBUG
#define PLOG(fmt, ...) \
    do { \
        fprintf(stderr, "[PEER_LIST DEBUG] " fmt "\n", ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define PLOG(fmt, ...) ((void)0)
#endif

/* ============================================================================
 * Static Helpers
 * ============================================================================ */

static int ensure_directory(const char* path) {
    char dir[512];
    strncpy(dir, path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';
    
    char* last_slash = strrchr(dir, '/');
    if (last_slash) {
        *last_slash = '\0';
    }
    
    struct stat st;
    if (stat(dir, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        PLOG("ensure_directory: %s exists but is not a directory", dir);
        return -1;
    }
    
    if (mkdir(dir, 0700) != 0) {
        PLOG("ensure_directory: failed to create %s: %s", dir, strerror(errno));
        return -1;
    }
    
    PLOG("ensure_directory: created %s", dir);
    return 0;
}

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

static void strip_brackets(const char* input, char* output, size_t out_size) {
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

static int ids_match(const char* id1, const char* id2) {
    if (!id1 || !id2) return 0;
    
    char n1[64], n2[64];
    strip_brackets(id1, n1, sizeof(n1));
    strip_brackets(id2, n2, sizeof(n2));
    
    return strcmp(n1, n2) == 0;
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

PeerList* peer_list_create(void) {
    PeerList* pl = (PeerList*)calloc(1, sizeof(PeerList));
    if (!pl) {
        PLOG("peer_list_create: malloc failed");
        return NULL;
    }
    
    strcpy(pl->file_path, "/tmp/.orcashi/registry.json");
    pl->count = 0;
    pl->dirty = false;
    
    PLOG("peer_list_create: created, path=%s", pl->file_path);
    return pl;
}

void peer_list_destroy(PeerList* pl) {
    if (!pl) return;
    
    PLOG("peer_list_destroy: count=%d, dirty=%d", pl->count, pl->dirty);
    
    /* Do NOT save on destroy - persistence must be explicit */
    free(pl);
}

/* ============================================================================
 * Load
 * ============================================================================ */

int peer_list_load(PeerList* pl) {
    if (!pl) return -1;
    
    PLOG("peer_list_load: loading from %s", pl->file_path);
    
    /* Reset state */
    pl->count = 0;
    pl->dirty = false;
    
    FILE* f = fopen(pl->file_path, "r");
    if (!f) {
        PLOG("peer_list_load: no file found, starting fresh");
        return 0;
    }
    
    char line[8192];
    PeerListEntry entry;
    bool in_peer = false;
    int loaded = 0;
    
    while (fgets(line, sizeof(line), f)) {
        /* Parse ID */
        if (strstr(line, "\"id\":\"") != NULL) {
            char* start = strstr(line, "\"id\":\"") + 6;
            char* end = strchr(start, '"');
            if (end) {
                int len = end - start;
                if (len < (int)sizeof(entry.id)) {
                    strncpy(entry.id, start, len);
                    entry.id[len] = '\0';
                    in_peer = true;
                }
            }
        }
        
        /* Parse IP */
        if (in_peer && strstr(line, "\"ip\":\"") != NULL) {
            char* start = strstr(line, "\"ip\":\"") + 6;
            char* end = strchr(start, '"');
            if (end) {
                int len = end - start;
                if (len < (int)sizeof(entry.ip)) {
                    strncpy(entry.ip, start, len);
                    entry.ip[len] = '\0';
                }
            }
        }
        
        /* Parse Port */
        if (in_peer && strstr(line, "\"port\":\"") != NULL) {
            char* start = strstr(line, "\"port\":\"") + 8;
            char* end = strchr(start, '"');
            if (end) {
                int len = end - start;
                if (len < (int)sizeof(entry.port)) {
                    strncpy(entry.port, start, len);
                    entry.port[len] = '\0';
                }
            }
        }
        
        /* Parse Online */
        if (in_peer && strstr(line, "\"online\":") != NULL) {
            char* start = strstr(line, "\"online\":") + 9;
            entry.online = (strstr(start, "true") != NULL);
        }
        
        /* Parse Status */
        if (in_peer && strstr(line, "\"status\":\"") != NULL) {
            char* start = strstr(line, "\"status\":\"") + 10;
            char* end = strchr(start, '"');
            if (end) {
                int len = end - start;
                if (len < (int)sizeof(entry.status)) {
                    strncpy(entry.status, start, len);
                    entry.status[len] = '\0';
                }
            }
        }
        
        /* Parse Last Seen */
        if (in_peer && strstr(line, "\"last_seen\":") != NULL) {
            char* start = strstr(line, "\"last_seen\":") + 12;
            entry.last_seen = atol(start);
        }
        
        /* Parse Mode */
        if (in_peer && strstr(line, "\"mode\":") != NULL) {
            char* start = strstr(line, "\"mode\":") + 7;
            entry.mode = atoi(start);
        }
        
        /* Parse Name */
        if (in_peer && strstr(line, "\"name\":\"") != NULL) {
            char* start = strstr(line, "\"name\":\"") + 8;
            char* end = strchr(start, '"');
            if (end) {
                int len = end - start;
                if (len < (int)sizeof(entry.name)) {
                    strncpy(entry.name, start, len);
                    entry.name[len] = '\0';
                }
            }
        }
        
        /* Parse Public Key */
        if (in_peer && strstr(line, "\"public_key\":\"") != NULL) {
            char* start = strstr(line, "\"public_key\":\"") + 14;
            char* end = strchr(start, '"');
            if (end) {
                int len = end - start;
                if (len < (int)sizeof(entry.public_key)) {
                    strncpy(entry.public_key, start, len);
                    entry.public_key[len] = '\0';
                }
            }
        }
        
        /* Parse Signature */
        if (in_peer && strstr(line, "\"signature\":\"") != NULL) {
            char* start = strstr(line, "\"signature\":\"") + 13;
            char* end = strchr(start, '"');
            if (end) {
                int len = end - start;
                if (len < (int)sizeof(entry.signature)) {
                    strncpy(entry.signature, start, len);
                    entry.signature[len] = '\0';
                }
            }
        }
        
        /* Parse Salt Hex */
        if (in_peer && strstr(line, "\"salt_hex\":\"") != NULL) {
            char* start = strstr(line, "\"salt_hex\":\"") + 12;
            char* end = strchr(start, '"');
            if (end) {
                int len = end - start;
                if (len < (int)sizeof(entry.salt_hex)) {
                    strncpy(entry.salt_hex, start, len);
                    entry.salt_hex[len] = '\0';
                }
            }
        }
        
        /* Parse Created At */
        if (in_peer && strstr(line, "\"created_at\":") != NULL) {
            char* start = strstr(line, "\"created_at\":") + 13;
            entry.created_at = atol(start);
        }
        
        /* Parse Verified */
        if (in_peer && strstr(line, "\"verified\":") != NULL) {
            char* start = strstr(line, "\"verified\":") + 11;
            entry.verified = (strstr(start, "true") != NULL);
        }
        
        /* End of peer */
        if (in_peer && strchr(line, '}') != NULL) {
            if (strlen(entry.id) > 0 && pl->count < MAX_PEER_LIST) {
                pl->peers[pl->count++] = entry;
                loaded++;
                PLOG("peer_list_load: loaded peer %s", entry.id);
                memset(&entry, 0, sizeof(entry));
                in_peer = false;
            }
        }
    }
    
    fclose(f);
    PLOG("peer_list_load: loaded %d peers, total count=%d", loaded, pl->count);
    return pl->count;
}

/* ============================================================================
 * Save - Atomic write using temporary file
 * ============================================================================ */

int peer_list_save(PeerList* pl) {
    if (!pl) return -1;
    
    PLOG("peer_list_save: saving %d peers to %s", pl->count, pl->file_path);
    
    /* Ensure directory exists */
    if (ensure_directory(pl->file_path) < 0) {
        PLOG("peer_list_save: failed to create directory");
        return -1;
    }
    
    /* Write to temporary file first */
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", pl->file_path);
    
    FILE* f = fopen(tmp_path, "w");
    if (!f) {
        PLOG("peer_list_save: failed to open temp file: %s", strerror(errno));
        return -1;
    }
    
    fprintf(f, "{\n  \"peers\": [\n");
    
    for (int i = 0; i < pl->count; i++) {
        if (i > 0) fprintf(f, ",\n");
        PeerListEntry* p = &pl->peers[i];
        
        char escaped_id[128], escaped_ip[64], escaped_port[32];
        char escaped_status[32], escaped_name[256];
        char escaped_pubkey[8192], escaped_sig[1024], escaped_salt[64];
        
        json_escape(p->id, escaped_id, sizeof(escaped_id));
        json_escape(p->ip, escaped_ip, sizeof(escaped_ip));
        json_escape(p->port, escaped_port, sizeof(escaped_port));
        json_escape(p->status, escaped_status, sizeof(escaped_status));
        json_escape(p->name, escaped_name, sizeof(escaped_name));
        json_escape(p->public_key, escaped_pubkey, sizeof(escaped_pubkey));
        json_escape(p->signature, escaped_sig, sizeof(escaped_sig));
        json_escape(p->salt_hex, escaped_salt, sizeof(escaped_salt));
        
        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": \"%s\",\n", escaped_id);
        fprintf(f, "      \"ip\": \"%s\",\n", escaped_ip);
        fprintf(f, "      \"port\": \"%s\",\n", escaped_port);
        fprintf(f, "      \"online\": %s,\n", p->online ? "true" : "false");
        fprintf(f, "      \"status\": \"%s\",\n", escaped_status);
        fprintf(f, "      \"last_seen\": %ld,\n", (long)p->last_seen);
        fprintf(f, "      \"mode\": %d,\n", p->mode);
        fprintf(f, "      \"created_at\": %ld,\n", (long)p->created_at);
        fprintf(f, "      \"verified\": %s,\n", p->verified ? "true" : "false");
        fprintf(f, "      \"name\": \"%s\",\n", escaped_name);
        fprintf(f, "      \"public_key\": \"%s\",\n", escaped_pubkey);
        fprintf(f, "      \"signature\": \"%s\",\n", escaped_sig);
        fprintf(f, "      \"salt_hex\": \"%s\"\n", escaped_salt);
        fprintf(f, "    }");
    }
    
    fprintf(f, "\n  ]\n}\n");
    
    if (fclose(f) != 0) {
        PLOG("peer_list_save: failed to close temp file: %s", strerror(errno));
        unlink(tmp_path);
        return -1;
    }
    
    /* Atomic rename */
    if (rename(tmp_path, pl->file_path) != 0) {
        PLOG("peer_list_save: failed to rename temp file: %s", strerror(errno));
        unlink(tmp_path);
        return -1;
    }
    
    pl->dirty = false;
    PLOG("peer_list_save: saved successfully");
    return 0;
}

/* ============================================================================
 * Query
 * ============================================================================ */

int peer_list_get_count(PeerList* pl) {
    return pl ? pl->count : 0;
}

PeerListEntry* peer_list_get(PeerList* pl, int index) {
    if (!pl || index < 0 || index >= pl->count) return NULL;
    return &pl->peers[index];
}

PeerListEntry* peer_list_find(PeerList* pl, const char* id) {
    if (!pl || !id) return NULL;
    
    for (int i = 0; i < pl->count; i++) {
        if (ids_match(pl->peers[i].id, id)) {
            return &pl->peers[i];
        }
    }
    return NULL;
}

/* ============================================================================
 * Modify
 * ============================================================================ */

int peer_list_add(PeerList* pl, const RegistryPeer* peer) {
    if (!pl || !peer) return -1;
    
    /* Check if already exists */
    PeerListEntry* existing = peer_list_find(pl, peer->id);
    if (existing) {
        PLOG("peer_list_add: peer %s already exists, updating", peer->id);
        memcpy(existing, peer, sizeof(PeerListEntry));
        existing->last_seen = time(NULL);
        pl->dirty = true;
        return 0;
    }
    
    if (pl->count >= MAX_PEER_LIST) {
        PLOG("peer_list_add: list full, cannot add %s", peer->id);
        return -1;
    }
    
    memcpy(&pl->peers[pl->count++], peer, sizeof(PeerListEntry));
    pl->dirty = true;
    PLOG("peer_list_add: added peer %s at %s:%s (count=%d)", 
         peer->id, peer->ip, peer->port, pl->count);
    return 0;
}

int peer_list_remove(PeerList* pl, const char* id) {
    if (!pl || !id) return -1;
    
    for (int i = 0; i < pl->count; i++) {
        if (ids_match(pl->peers[i].id, id)) {
            for (int j = i; j < pl->count - 1; j++) {
                pl->peers[j] = pl->peers[j + 1];
            }
            pl->count--;
            pl->dirty = true;
            PLOG("peer_list_remove: removed peer %s (count=%d)", id, pl->count);
            return 0;
        }
    }
    
    PLOG("peer_list_remove: peer %s not found", id);
    return -1;
}

void peer_list_clear(PeerList* pl) {
    if (!pl) return;
    pl->count = 0;
    pl->dirty = true;
    PLOG("peer_list_clear: cleared all peers");
}

void peer_list_mark_dirty(PeerList* pl) {
    if (pl) {
        pl->dirty = true;
        PLOG("peer_list_mark_dirty: marked dirty");
    }
}

bool peer_list_is_dirty(PeerList* pl) {
    return pl ? pl->dirty : false;
}
