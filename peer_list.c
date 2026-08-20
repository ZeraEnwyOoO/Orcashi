 #include "peer_list.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>

#define PEER_LIST_DEBUG 1

#if PEER_LIST_DEBUG
#define PLOG(fmt, ...) \
    do { \
        fprintf(stderr, "[PEER_LIST] " fmt "\n", ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define PLOG(fmt, ...) ((void)0)
#endif

#define PEER_LIST_DEFAULT_PATH "/tmp/.orcashi/registry.json"

/* ============================================================================
 * ID Normalization (Single Source of Truth)
 * ============================================================================ */

bool peer_list_normalize_id(const char* input, char* output, size_t output_size) {
    if (!input || !output || output_size == 0) {
        return false;
    }
    
    size_t i = 0, j = 0;
    size_t len = strlen(input);
    
    /* Strip angle brackets */
    for (i = 0; i < len && j < output_size - 1; i++) {
        if (input[i] != '<' && input[i] != '>') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
    
    /* Validate: must not be empty */
    if (j == 0) {
        return false;
    }
    
    /* Validate: must contain only digits */
    for (i = 0; i < j; i++) {
        if (!isdigit((unsigned char)output[i])) {
            return false;
        }
    }
    
    return true;
}

static bool peer_list_is_same_id(const char* id1, const char* id2) {
    if (!id1 || !id2) return false;
    
    char n1[PEER_LIST_MAX_ID_LEN];
    char n2[PEER_LIST_MAX_ID_LEN];
    
    if (!peer_list_normalize_id(id1, n1, sizeof(n1))) return false;
    if (!peer_list_normalize_id(id2, n2, sizeof(n2))) return false;
    
    return strcmp(n1, n2) == 0;
}

/* ============================================================================
 * Directory Helper
 * ============================================================================ */

static int ensure_directory(const char* path) {
    if (!path) return -1;
    
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

/* ============================================================================
 * JSON Escape/Unescape
 * ============================================================================ */

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

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

PeerList* peer_list_create(void) {
    PeerList* pl = (PeerList*)calloc(1, sizeof(PeerList));
    if (!pl) {
        PLOG("peer_list_create: calloc failed");
        return NULL;
    }
    
    strcpy(pl->file_path, PEER_LIST_DEFAULT_PATH);
    pl->count = 0;
    pl->dirty = false;
    
    if (pthread_mutex_init(&pl->mutex, NULL) != 0) {
        PLOG("peer_list_create: pthread_mutex_init failed");
        free(pl);
        return NULL;
    }
    
    PLOG("peer_list_create: created, path=%s", pl->file_path);
    return pl;
}

void peer_list_destroy(PeerList* pl) {
    if (!pl) return;
    
    PLOG("peer_list_destroy: count=%d, dirty=%d", pl->count, pl->dirty);
    
    /* Do NOT auto-save on destroy - persistence must be explicit */
    pthread_mutex_destroy(&pl->mutex);
    free(pl);
}

/* ============================================================================
 * Load
 * ============================================================================ */

int peer_list_load(PeerList* pl) {
    if (!pl) return -1;
    
    pthread_mutex_lock(&pl->mutex);
    
    PLOG("peer_list_load: loading from %s", pl->file_path);
    
    /* Reset state */
    pl->count = 0;
    pl->dirty = false;
    
    FILE* f = fopen(pl->file_path, "r");
    if (!f) {
        PLOG("peer_list_load: no file found, starting fresh");
        pthread_mutex_unlock(&pl->mutex);
        return 0;
    }
    
    char line[8192];
    PeerListEntry entry;
    bool in_peer = false;
    int loaded = 0;
    
    /* Initialize entry */
    memset(&entry, 0, sizeof(entry));
    
    while (fgets(line, sizeof(line), f)) {
        /* Skip empty lines */
        if (strlen(line) <= 1) continue;
        
        /* Check for beginning of peer object */
        if (strstr(line, "{") != NULL) {
            memset(&entry, 0, sizeof(entry));
            in_peer = true;
            continue;
        }
        
        /* Check for end of peer object */
        if (in_peer && strstr(line, "}") != NULL) {
            if (strlen(entry.id) > 0 && pl->count < PEER_LIST_MAX_PEERS) {
                pl->peers[pl->count++] = entry;
                loaded++;
                PLOG("peer_list_load: loaded peer %s (status=%s)", 
                     entry.id, entry.status);
            }
            in_peer = false;
            memset(&entry, 0, sizeof(entry));
            continue;
        }
        
        if (!in_peer) continue;
        
        /* Parse ID */
        if (strstr(line, "\"id\":") != NULL) {
            char* start = strstr(line, "\"id\":");
            if (start) {
                start = strchr(start, '"');
                if (start) {
                    start++;
                    char* end = strchr(start, '"');
                    if (end) {
                        int len = end - start;
                        if (len > 0 && len < (int)sizeof(entry.id)) {
                            strncpy(entry.id, start, len);
                            entry.id[len] = '\0';
                        }
                    }
                }
            }
        }
        
        /* Parse IP */
        if (strstr(line, "\"ip\":") != NULL) {
            char* start = strstr(line, "\"ip\":");
            if (start) {
                start = strchr(start, '"');
                if (start) {
                    start++;
                    char* end = strchr(start, '"');
                    if (end) {
                        int len = end - start;
                        if (len > 0 && len < (int)sizeof(entry.ip)) {
                            strncpy(entry.ip, start, len);
                            entry.ip[len] = '\0';
                        }
                    }
                }
            }
        }
        
        /* Parse Port */
        if (strstr(line, "\"port\":") != NULL) {
            char* start = strstr(line, "\"port\":");
            if (start) {
                start = strchr(start, '"');
                if (start) {
                    start++;
                    char* end = strchr(start, '"');
                    if (end) {
                        int len = end - start;
                        if (len > 0 && len < (int)sizeof(entry.port)) {
                            strncpy(entry.port, start, len);
                            entry.port[len] = '\0';
                        }
                    }
                }
            }
        }
        
        /* Parse Online */
        if (strstr(line, "\"online\":") != NULL) {
            char* start = strstr(line, "\"online\":");
            if (start) {
                start += 9;
                while (*start == ' ' || *start == '\t') start++;
                entry.online = (strstr(start, "true") != NULL);
            }
        }
        
        /* Parse Status */
        if (strstr(line, "\"status\":") != NULL) {
            char* start = strstr(line, "\"status\":");
            if (start) {
                start = strchr(start, '"');
                if (start) {
                    start++;
                    char* end = strchr(start, '"');
                    if (end) {
                        int len = end - start;
                        if (len > 0 && len < (int)sizeof(entry.status)) {
                            strncpy(entry.status, start, len);
                            entry.status[len] = '\0';
                        }
                    }
                }
            }
        }
        
        /* Parse Last Seen */
        if (strstr(line, "\"last_seen\":") != NULL) {
            char* start = strstr(line, "\"last_seen\":");
            if (start) {
                start += 12;
                while (*start == ' ' || *start == '\t') start++;
                entry.last_seen = atol(start);
            }
        }
        
        /* Parse Mode */
        if (strstr(line, "\"mode\":") != NULL) {
            char* start = strstr(line, "\"mode\":");
            if (start) {
                start += 7;
                while (*start == ' ' || *start == '\t') start++;
                entry.mode = atoi(start);
            }
        }
        
        /* Parse Name */
        if (strstr(line, "\"name\":") != NULL) {
            char* start = strstr(line, "\"name\":");
            if (start) {
                start = strchr(start, '"');
                if (start) {
                    start++;
                    char* end = strchr(start, '"');
                    if (end) {
                        int len = end - start;
                        if (len > 0 && len < (int)sizeof(entry.name)) {
                            strncpy(entry.name, start, len);
                            entry.name[len] = '\0';
                        }
                    }
                }
            }
        }
        
        /* Parse Public Key */
        if (strstr(line, "\"public_key\":") != NULL) {
            char* start = strstr(line, "\"public_key\":");
            if (start) {
                start = strchr(start, '"');
                if (start) {
                    start++;
                    char* end = strchr(start, '"');
                    if (end) {
                        int len = end - start;
                        if (len > 0 && len < (int)sizeof(entry.public_key)) {
                            strncpy(entry.public_key, start, len);
                            entry.public_key[len] = '\0';
                        }
                    }
                }
            }
        }
        
        /* Parse Signature */
        if (strstr(line, "\"signature\":") != NULL) {
            char* start = strstr(line, "\"signature\":");
            if (start) {
                start = strchr(start, '"');
                if (start) {
                    start++;
                    char* end = strchr(start, '"');
                    if (end) {
                        int len = end - start;
                        if (len > 0 && len < (int)sizeof(entry.signature)) {
                            strncpy(entry.signature, start, len);
                            entry.signature[len] = '\0';
                        }
                    }
                }
            }
        }
        
        /* Parse Salt Hex */
        if (strstr(line, "\"salt_hex\":") != NULL) {
            char* start = strstr(line, "\"salt_hex\":");
            if (start) {
                start = strchr(start, '"');
                if (start) {
                    start++;
                    char* end = strchr(start, '"');
                    if (end) {
                        int len = end - start;
                        if (len > 0 && len < (int)sizeof(entry.salt_hex)) {
                            strncpy(entry.salt_hex, start, len);
                            entry.salt_hex[len] = '\0';
                        }
                    }
                }
            }
        }
        
        /* Parse Created At */
        if (strstr(line, "\"created_at\":") != NULL) {
            char* start = strstr(line, "\"created_at\":");
            if (start) {
                start += 13;
                while (*start == ' ' || *start == '\t') start++;
                entry.created_at = atol(start);
            }
        }
        
        /* Parse Verified */
        if (strstr(line, "\"verified\":") != NULL) {
            char* start = strstr(line, "\"verified\":");
            if (start) {
                start += 11;
                while (*start == ' ' || *start == '\t') start++;
                entry.verified = (strstr(start, "true") != NULL);
            }
        }
    }
    
    fclose(f);
    
    PLOG("peer_list_load: loaded %d peers, total count=%d", loaded, pl->count);
    
    pthread_mutex_unlock(&pl->mutex);
    return pl->count;
}

/* ============================================================================
 * Save - Atomic write using temporary file
 * ============================================================================ */

int peer_list_save(PeerList* pl) {
    if (!pl) return -1;
    
    pthread_mutex_lock(&pl->mutex);
    
    PLOG("peer_list_save: saving %d peers to %s", pl->count, pl->file_path);
    
    /* Ensure directory exists */
    if (ensure_directory(pl->file_path) < 0) {
        PLOG("peer_list_save: failed to create directory");
        pthread_mutex_unlock(&pl->mutex);
        return -1;
    }
    
    /* Write to temporary file first */
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", pl->file_path);
    
    FILE* f = fopen(tmp_path, "w");
    if (!f) {
        PLOG("peer_list_save: failed to open temp file: %s", strerror(errno));
        pthread_mutex_unlock(&pl->mutex);
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
        pthread_mutex_unlock(&pl->mutex);
        return -1;
    }
    
    /* Atomic rename */
    if (rename(tmp_path, pl->file_path) != 0) {
        PLOG("peer_list_save: failed to rename temp file: %s", strerror(errno));
        unlink(tmp_path);
        pthread_mutex_unlock(&pl->mutex);
        return -1;
    }
    
    pl->dirty = false;
    PLOG("peer_list_save: saved successfully");
    
    pthread_mutex_unlock(&pl->mutex);
    return 0;
}

/* ============================================================================
 * Query
 * ============================================================================ */

int peer_list_get_count(PeerList* pl) {
    if (!pl) return 0;
    pthread_mutex_lock(&pl->mutex);
    int count = pl->count;
    pthread_mutex_unlock(&pl->mutex);
    return count;
}

PeerListEntry* peer_list_get(PeerList* pl, int index) {
    if (!pl) return NULL;
    pthread_mutex_lock(&pl->mutex);
    if (index < 0 || index >= pl->count) {
        pthread_mutex_unlock(&pl->mutex);
        return NULL;
    }
    PeerListEntry* entry = &pl->peers[index];
    pthread_mutex_unlock(&pl->mutex);
    return entry;
}

PeerListEntry* peer_list_find(PeerList* pl, const char* id) {
    if (!pl || !id) return NULL;
    
    char norm_id[PEER_LIST_MAX_ID_LEN];
    if (!peer_list_normalize_id(id, norm_id, sizeof(norm_id))) {
        return NULL;
    }
    
    pthread_mutex_lock(&pl->mutex);
    
    for (int i = 0; i < pl->count; i++) {
        char existing_norm[PEER_LIST_MAX_ID_LEN];
        if (!peer_list_normalize_id(pl->peers[i].id, existing_norm, 
                                    sizeof(existing_norm))) {
            continue;
        }
        
        if (strcmp(existing_norm, norm_id) == 0) {
            pthread_mutex_unlock(&pl->mutex);
            return &pl->peers[i];
        }
    }
    
    pthread_mutex_unlock(&pl->mutex);
    return NULL;
}

/* ============================================================================
 * Modify
 * ============================================================================ */

int peer_list_add(PeerList* pl, const RegistryPeer* peer) {
    if (!pl || !peer) return -1;
    
    char norm_id[PEER_LIST_MAX_ID_LEN];
    if (!peer_list_normalize_id(peer->id, norm_id, sizeof(norm_id))) {
        PLOG("peer_list_add: invalid id '%s'", peer->id);
        return -1;
    }
    
    pthread_mutex_lock(&pl->mutex);
    
    /* Check if already exists */
    for (int i = 0; i < pl->count; i++) {
        char existing_norm[PEER_LIST_MAX_ID_LEN];
        if (!peer_list_normalize_id(pl->peers[i].id, existing_norm, 
                                    sizeof(existing_norm))) {
            continue;
        }
        
        if (strcmp(existing_norm, norm_id) == 0) {
            /* Update existing entry */
            PeerListEntry* entry = &pl->peers[i];
            strncpy(entry->ip, peer->ip, sizeof(entry->ip) - 1);
            entry->ip[sizeof(entry->ip) - 1] = '\0';
            
            strncpy(entry->port, peer->port, sizeof(entry->port) - 1);
            entry->port[sizeof(entry->port) - 1] = '\0';
            
            entry->online = peer->online;
            
            strncpy(entry->status, peer->status, sizeof(entry->status) - 1);
            entry->status[sizeof(entry->status) - 1] = '\0';
            
            entry->last_seen = time(NULL);
            entry->mode = peer->mode;
            
            strncpy(entry->name, peer->name, sizeof(entry->name) - 1);
            entry->name[sizeof(entry->name) - 1] = '\0';
            
            strncpy(entry->public_key, peer->public_key, 
                    sizeof(entry->public_key) - 1);
            entry->public_key[sizeof(entry->public_key) - 1] = '\0';
            
            strncpy(entry->signature, peer->signature, 
                    sizeof(entry->signature) - 1);
            entry->signature[sizeof(entry->signature) - 1] = '\0';
            
            entry->verified = peer->verified;
            entry->created_at = peer->created_at;
            
            pl->dirty = true;
            PLOG("peer_list_add: updated peer %s", peer->id);
            pthread_mutex_unlock(&pl->mutex);
            return 0;
        }
    }
    
    /* Add new entry */
    if (pl->count >= PEER_LIST_MAX_PEERS) {
        PLOG("peer_list_add: list full");
        pthread_mutex_unlock(&pl->mutex);
        return -1;
    }
    
    PeerListEntry* entry = &pl->peers[pl->count++];
    
    strncpy(entry->id, peer->id, sizeof(entry->id) - 1);
    entry->id[sizeof(entry->id) - 1] = '\0';
    
    strncpy(entry->ip, peer->ip, sizeof(entry->ip) - 1);
    entry->ip[sizeof(entry->ip) - 1] = '\0';
    
    strncpy(entry->port, peer->port, sizeof(entry->port) - 1);
    entry->port[sizeof(entry->port) - 1] = '\0';
    
    entry->online = peer->online;
    
    strncpy(entry->status, peer->status, sizeof(entry->status) - 1);
    entry->status[sizeof(entry->status) - 1] = '\0';
    
    entry->last_seen = time(NULL);
    entry->mode = peer->mode;
    
    strncpy(entry->name, peer->name, sizeof(entry->name) - 1);
    entry->name[sizeof(entry->name) - 1] = '\0';
    
    strncpy(entry->public_key, peer->public_key, 
            sizeof(entry->public_key) - 1);
    entry->public_key[sizeof(entry->public_key) - 1] = '\0';
    
    strncpy(entry->signature, peer->signature, 
            sizeof(entry->signature) - 1);
    entry->signature[sizeof(entry->signature) - 1] = '\0';
    
    entry->verified = peer->verified;
    entry->created_at = peer->created_at;
    
    pl->dirty = true;
    PLOG("peer_list_add: added peer %s (count=%d)", peer->id, pl->count);
    
    pthread_mutex_unlock(&pl->mutex);
    return 0;
}

int peer_list_add_entry(PeerList* pl, const PeerListEntry* entry) {
    if (!pl || !entry) return -1;
    
    char norm_id[PEER_LIST_MAX_ID_LEN];
    if (!peer_list_normalize_id(entry->id, norm_id, sizeof(norm_id))) {
        PLOG("peer_list_add_entry: invalid id '%s'", entry->id);
        return -1;
    }
    
    pthread_mutex_lock(&pl->mutex);
    
    /* Check if already exists */
    for (int i = 0; i < pl->count; i++) {
        char existing_norm[PEER_LIST_MAX_ID_LEN];
        if (!peer_list_normalize_id(pl->peers[i].id, existing_norm, 
                                    sizeof(existing_norm))) {
            continue;
        }
        
        if (strcmp(existing_norm, norm_id) == 0) {
            pl->peers[i] = *entry;
            pl->dirty = true;
            PLOG("peer_list_add_entry: updated peer %s", entry->id);
            pthread_mutex_unlock(&pl->mutex);
            return 0;
        }
    }
    
    if (pl->count >= PEER_LIST_MAX_PEERS) {
        PLOG("peer_list_add_entry: list full");
        pthread_mutex_unlock(&pl->mutex);
        return -1;
    }
    
    pl->peers[pl->count++] = *entry;
    pl->dirty = true;
    PLOG("peer_list_add_entry: added peer %s (count=%d)", entry->id, pl->count);
    
    pthread_mutex_unlock(&pl->mutex);
    return 0;
}

int peer_list_update(PeerList* pl, const char* id, const RegistryPeer* peer) {
    if (!pl || !id || !peer) return -1;
    
    char norm_id[PEER_LIST_MAX_ID_LEN];
    if (!peer_list_normalize_id(id, norm_id, sizeof(norm_id))) {
        PLOG("peer_list_update: invalid id '%s'", id);
        return -1;
    }
    
    pthread_mutex_lock(&pl->mutex);
    
    for (int i = 0; i < pl->count; i++) {
        char existing_norm[PEER_LIST_MAX_ID_LEN];
        if (!peer_list_normalize_id(pl->peers[i].id, existing_norm, 
                                    sizeof(existing_norm))) {
            continue;
        }
        
        if (strcmp(existing_norm, norm_id) == 0) {
            PeerListEntry* entry = &pl->peers[i];
            strncpy(entry->ip, peer->ip, sizeof(entry->ip) - 1);
            entry->ip[sizeof(entry->ip) - 1] = '\0';
            
            strncpy(entry->port, peer->port, sizeof(entry->port) - 1);
            entry->port[sizeof(entry->port) - 1] = '\0';
            
            entry->online = peer->online;
            
            strncpy(entry->status, peer->status, sizeof(entry->status) - 1);
            entry->status[sizeof(entry->status) - 1] = '\0';
            
            entry->last_seen = time(NULL);
            entry->mode = peer->mode;
            
            strncpy(entry->name, peer->name, sizeof(entry->name) - 1);
            entry->name[sizeof(entry->name) - 1] = '\0';
            
            strncpy(entry->public_key, peer->public_key, 
                    sizeof(entry->public_key) - 1);
            entry->public_key[sizeof(entry->public_key) - 1] = '\0';
            
            entry->verified = peer->verified;
            entry->created_at = peer->created_at;
            
            pl->dirty = true;
            PLOG("peer_list_update: updated peer %s", id);
            pthread_mutex_unlock(&pl->mutex);
            return 0;
        }
    }
    
    PLOG("peer_list_update: peer %s not found", id);
    pthread_mutex_unlock(&pl->mutex);
    return -1;
}

int peer_list_remove(PeerList* pl, const char* id) {
    if (!pl || !id) return -1;
    
    char norm_id[PEER_LIST_MAX_ID_LEN];
    if (!peer_list_normalize_id(id, norm_id, sizeof(norm_id))) {
        PLOG("peer_list_remove: invalid id '%s'", id);
        return -1;
    }
    
    pthread_mutex_lock(&pl->mutex);
    
    for (int i = 0; i < pl->count; i++) {
        char existing_norm[PEER_LIST_MAX_ID_LEN];
        if (!peer_list_normalize_id(pl->peers[i].id, existing_norm, 
                                    sizeof(existing_norm))) {
            continue;
        }
        
        if (strcmp(existing_norm, norm_id) == 0) {
            /* Shift remaining entries */
            for (int j = i; j < pl->count - 1; j++) {
                pl->peers[j] = pl->peers[j + 1];
            }
            pl->count--;
            pl->dirty = true;
            PLOG("peer_list_remove: removed peer %s (count=%d)", id, pl->count);
            pthread_mutex_unlock(&pl->mutex);
            return 0;
        }
    }
    
    PLOG("peer_list_remove: peer %s not found", id);
    pthread_mutex_unlock(&pl->mutex);
    return -1;
}

void peer_list_clear(PeerList* pl) {
    if (!pl) return;
    pthread_mutex_lock(&pl->mutex);
    pl->count = 0;
    pl->dirty = true;
    PLOG("peer_list_clear: cleared all peers");
    pthread_mutex_unlock(&pl->mutex);
}

/* ============================================================================
 * Sync with Registry
 * ============================================================================ */

int peer_list_sync_to_registry(PeerList* pl, Registry* reg) {
    if (!pl || !reg) return -1;
    
    pthread_mutex_lock(&pl->mutex);
    
    int synced = 0;
    for (int i = 0; i < pl->count; i++) {
        PeerListEntry* entry = &pl->peers[i];
        
        /* Skip entries with empty or invalid IDs */
        if (strlen(entry->id) == 0) continue;
        
        /* Register in registry */
        if (registry_register_peer(reg, entry->id, entry->ip, entry->port)) {
            /* Update status to match persistent state */
            if (strlen(entry->status) > 0) {
                registry_update_status(reg, entry->id, entry->status);
            }
            synced++;
            PLOG("peer_list_sync_to_registry: synced peer %s (status=%s)", 
                 entry->id, entry->status);
        }
    }
    
    PLOG("peer_list_sync_to_registry: synced %d peers", synced);
    
    pthread_mutex_unlock(&pl->mutex);
    return synced;
}

int peer_list_sync_from_registry(PeerList* pl, Registry* reg) {
    if (!pl || !reg) return -1;
    
    RegistryPeer peers[PEER_LIST_MAX_PEERS];
    int count = registry_get_all_peers(reg, peers, PEER_LIST_MAX_PEERS);
    
    if (count <= 0) {
        PLOG("peer_list_sync_from_registry: no peers in registry");
        return 0;
    }
    
    pthread_mutex_lock(&pl->mutex);
    
    int synced = 0;
    for (int i = 0; i < count; i++) {
        /* Check if already exists */
        int found = -1;
        for (int j = 0; j < pl->count; j++) {
            if (peer_list_is_same_id(pl->peers[j].id, peers[i].id)) {
                found = j;
                break;
            }
        }
        
        if (found >= 0) {
            /* Update existing */
            PeerListEntry* entry = &pl->peers[found];
            strncpy(entry->ip, peers[i].ip, sizeof(entry->ip) - 1);
            entry->ip[sizeof(entry->ip) - 1] = '\0';
            
            strncpy(entry->port, peers[i].port, sizeof(entry->port) - 1);
            entry->port[sizeof(entry->port) - 1] = '\0';
            
            entry->online = peers[i].online;
            
            strncpy(entry->status, peers[i].status, sizeof(entry->status) - 1);
            entry->status[sizeof(entry->status) - 1] = '\0';
            
            entry->last_seen = peers[i].last_seen;
            entry->mode = peers[i].mode;
            
            strncpy(entry->name, peers[i].name, sizeof(entry->name) - 1);
            entry->name[sizeof(entry->name) - 1] = '\0';
            
            strncpy(entry->public_key, peers[i].public_key, 
                    sizeof(entry->public_key) - 1);
            entry->public_key[sizeof(entry->public_key) - 1] = '\0';
            
            entry->verified = peers[i].verified;
            entry->created_at = peers[i].created_at;
            
            synced++;
        } else if (pl->count < PEER_LIST_MAX_PEERS) {
            /* Add new */
            PeerListEntry* entry = &pl->peers[pl->count++];
            
            strncpy(entry->id, peers[i].id, sizeof(entry->id) - 1);
            entry->id[sizeof(entry->id) - 1] = '\0';
            
            strncpy(entry->ip, peers[i].ip, sizeof(entry->ip) - 1);
            entry->ip[sizeof(entry->ip) - 1] = '\0';
            
            strncpy(entry->port, peers[i].port, sizeof(entry->port) - 1);
            entry->port[sizeof(entry->port) - 1] = '\0';
            
            entry->online = peers[i].online;
            
            strncpy(entry->status, peers[i].status, sizeof(entry->status) - 1);
            entry->status[sizeof(entry->status) - 1] = '\0';
            
            entry->last_seen = peers[i].last_seen;
            entry->mode = peers[i].mode;
            
            strncpy(entry->name, peers[i].name, sizeof(entry->name) - 1);
            entry->name[sizeof(entry->name) - 1] = '\0';
            
            strncpy(entry->public_key, peers[i].public_key, 
                    sizeof(entry->public_key) - 1);
            entry->public_key[sizeof(entry->public_key) - 1] = '\0';
            
            entry->verified = peers[i].verified;
            entry->created_at = peers[i].created_at;
            
            synced++;
        }
    }
    
    if (synced > 0) {
        pl->dirty = true;
    }
    
    PLOG("peer_list_sync_from_registry: synced %d peers from registry", synced);
    
    pthread_mutex_unlock(&pl->mutex);
    return synced;
}

/* ============================================================================
 * Utility
 * ============================================================================ */

void peer_list_mark_dirty(PeerList* pl) {
    if (pl) {
        pthread_mutex_lock(&pl->mutex);
        pl->dirty = true;
        pthread_mutex_unlock(&pl->mutex);
        PLOG("peer_list_mark_dirty: marked dirty");
    }
}

bool peer_list_is_dirty(PeerList* pl) {
    if (!pl) return false;
    pthread_mutex_lock(&pl->mutex);
    bool dirty = pl->dirty;
    pthread_mutex_unlock(&pl->mutex);
    return dirty;
}
