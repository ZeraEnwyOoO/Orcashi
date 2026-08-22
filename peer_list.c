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

#define PEER_LIST_DEFAULT_PATH "/tmp/.orcashi/"

/* ============================================================================
 * ID Normalization
 * ============================================================================ */

bool peer_list_normalize_id(const char* input, char* output, size_t output_size) {
    if (!input || !output || output_size == 0) return false;
    
    size_t i = 0, j = 0;
    size_t len = strlen(input);
    
    for (i = 0; i < len && j < output_size - 1; i++) {
        if (input[i] != '<' && input[i] != '>') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
    
    if (j == 0) return false;
    
    for (i = 0; i < j; i++) {
        if (!isdigit((unsigned char)output[i])) return false;
    }
    
    return true;
}

static bool peer_list_is_same_id(const char* id1, const char* id2) {
    if (!id1 || !id2) return false;
    char n1[64], n2[64];
    if (!peer_list_normalize_id(id1, n1, sizeof(n1))) return false;
    if (!peer_list_normalize_id(id2, n2, sizeof(n2))) return false;
    return strcmp(n1, n2) == 0;
}

/* ============================================================================
 * Directory Helper
 * ============================================================================ */

static int ensure_directory(const char* path) {
    if (!path) return -1;
    
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        return -1;
    }
    
    if (mkdir(path, 0700) != 0) {
        PLOG("ensure_directory: failed to create %s: %s", path, strerror(errno));
        return -1;
    }
    
    PLOG("ensure_directory: created %s", path);
    return 0;
}

/* ============================================================================
 * JSON Escape
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
 * Generate Message ID
 * ============================================================================ */

static void generate_msg_id(char* id_out, size_t size) {
    time_t now = time(NULL);
    snprintf(id_out, size, "msg_%ld_%d", (long)now, rand() % 10000);
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
    
    strcpy(pl->data_dir, PEER_LIST_DEFAULT_PATH);
    pl->peer_count = 0;
    pl->msg_count = 0;
    pl->dirty = false;
    
    if (pthread_mutex_init(&pl->mutex, NULL) != 0) {
        PLOG("peer_list_create: pthread_mutex_init failed");
        free(pl);
        return NULL;
    }
    
    ensure_directory(pl->data_dir);
    
    PLOG("peer_list_create: created, dir=%s", pl->data_dir);
    return pl;
}

void peer_list_destroy(PeerList* pl) {
    if (!pl) return;
    
    PLOG("peer_list_destroy: peers=%d, msgs=%d, dirty=%d", 
         pl->peer_count, pl->msg_count, pl->dirty);
    
    pthread_mutex_destroy(&pl->mutex);
    free(pl);
}

/* ============================================================================
 * Peer Operations
 * ============================================================================ */

int peer_list_add_peer(PeerList* pl, const RegistryPeer* peer) {
    if (!pl || !peer) return -1;
    
    char norm_id[64];
    if (!peer_list_normalize_id(peer->id, norm_id, sizeof(norm_id))) {
        PLOG("peer_list_add: invalid id '%s'", peer->id);
        return -1;
    }
    
    pthread_mutex_lock(&pl->mutex);
    
    /* Check if already exists */
    for (int i = 0; i < pl->peer_count; i++) {
        if (peer_list_is_same_id(pl->peers[i].id, peer->id)) {
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
            strncpy(entry->public_key, peer->public_key, sizeof(entry->public_key) - 1);
            entry->public_key[sizeof(entry->public_key) - 1] = '\0';
            strncpy(entry->signature, peer->signature, sizeof(entry->signature) - 1);
            entry->signature[sizeof(entry->signature) - 1] = '\0';
            entry->verified = peer->verified;
            entry->created_at = peer->created_at;
            pl->dirty = true;
            PLOG("peer_list_add: updated peer %s", peer->id);
            pthread_mutex_unlock(&pl->mutex);
            return 0;
        }
    }
    
    if (pl->peer_count >= PEER_LIST_MAX_PEERS) {
        PLOG("peer_list_add: list full");
        pthread_mutex_unlock(&pl->mutex);
        return -1;
    }
    
    PeerListEntry* entry = &pl->peers[pl->peer_count++];
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
    strncpy(entry->public_key, peer->public_key, sizeof(entry->public_key) - 1);
    entry->public_key[sizeof(entry->public_key) - 1] = '\0';
    strncpy(entry->signature, peer->signature, sizeof(entry->signature) - 1);
    entry->signature[sizeof(entry->signature) - 1] = '\0';
    entry->verified = peer->verified;
    entry->created_at = peer->created_at;
    pl->dirty = true;
    
    PLOG("peer_list_add: added peer %s (count=%d)", peer->id, pl->peer_count);
    pthread_mutex_unlock(&pl->mutex);
    return 0;
}

int peer_list_update_peer(PeerList* pl, const char* id, const RegistryPeer* peer) {
    if (!pl || !id || !peer) return -1;
    pthread_mutex_lock(&pl->mutex);
    
    for (int i = 0; i < pl->peer_count; i++) {
        if (peer_list_is_same_id(pl->peers[i].id, id)) {
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
            strncpy(entry->public_key, peer->public_key, sizeof(entry->public_key) - 1);
            entry->public_key[sizeof(entry->public_key) - 1] = '\0';
            strncpy(entry->signature, peer->signature, sizeof(entry->signature) - 1);
            entry->signature[sizeof(entry->signature) - 1] = '\0';
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

int peer_list_remove_peer(PeerList* pl, const char* id) {
    if (!pl || !id) return -1;
    
    pthread_mutex_lock(&pl->mutex);
    
    for (int i = 0; i < pl->peer_count; i++) {
        if (peer_list_is_same_id(pl->peers[i].id, id)) {
            for (int j = i; j < pl->peer_count - 1; j++) {
                pl->peers[j] = pl->peers[j + 1];
            }
            pl->peer_count--;
            pl->dirty = true;
            PLOG("peer_list_remove: removed peer %s (count=%d)", id, pl->peer_count);
            pthread_mutex_unlock(&pl->mutex);
            return 0;
        }
    }
    
    PLOG("peer_list_remove: peer %s not found", id);
    pthread_mutex_unlock(&pl->mutex);
    return -1;
}

PeerListEntry* peer_list_find_peer(PeerList* pl, const char* id) {
    if (!pl || !id) return NULL;
    
    pthread_mutex_lock(&pl->mutex);
    for (int i = 0; i < pl->peer_count; i++) {
        if (peer_list_is_same_id(pl->peers[i].id, id)) {
            pthread_mutex_unlock(&pl->mutex);
            return &pl->peers[i];
        }
    }
    pthread_mutex_unlock(&pl->mutex);
    return NULL;
}

int peer_list_get_accepted_peers(PeerList* pl, PeerListEntry* out, int max) {
    if (!pl || !out || max <= 0) return 0;
    
    pthread_mutex_lock(&pl->mutex);
    
    int count = 0;
    for (int i = 0; i < pl->peer_count && count < max; i++) {
        if (strcmp(pl->peers[i].status, "accepted") == 0) {
            out[count++] = pl->peers[i];
        }
    }
    
    pthread_mutex_unlock(&pl->mutex);
    return count;
}

bool peer_list_is_accepted(PeerList* pl, const char* id) {
    if (!pl || !id) return false;
    
    pthread_mutex_lock(&pl->mutex);
    for (int i = 0; i < pl->peer_count; i++) {
        if (peer_list_is_same_id(pl->peers[i].id, id) &&
            strcmp(pl->peers[i].status, "accepted") == 0) {
            pthread_mutex_unlock(&pl->mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&pl->mutex);
    return false;
}

/* ============================================================================
 * Message Queue Operations
 * ============================================================================ */

int peer_list_queue_message(PeerList* pl, const char* to_id, 
                            const char* payload, bool encrypted) {
    if (!pl || !to_id || !payload) return -1;
    
    pthread_mutex_lock(&pl->mutex);
    
    if (pl->msg_count >= PEER_LIST_MAX_MSGS) {
        PLOG("peer_list_queue_message: queue full");
        pthread_mutex_unlock(&pl->mutex);
        return -1;
    }
    
    QueuedMessage* msg = &pl->messages[pl->msg_count++];
    generate_msg_id(msg->msg_id, sizeof(msg->msg_id));
    strncpy(msg->to_id, to_id, sizeof(msg->to_id) - 1);
    msg->to_id[sizeof(msg->to_id) - 1] = '\0';
    strncpy(msg->payload, payload, sizeof(msg->payload) - 1);
    msg->payload[sizeof(msg->payload) - 1] = '\0';
    msg->timestamp = time(NULL);
    msg->status = MSG_STATUS_PENDING;
    msg->encrypted = encrypted;
    msg->retry_count = 0;
    msg->delivered_at = 0;
    
    PLOG("peer_list_queue_message: queued message %s for %s", msg->msg_id, to_id);
    
    pthread_mutex_unlock(&pl->mutex);
    return 0;
}

int peer_list_get_pending_messages(PeerList* pl, const char* to_id,
                                   QueuedMessage* out, int max) {
    if (!pl || !out || max <= 0) return 0;
    
    pthread_mutex_lock(&pl->mutex);
    
    int count = 0;
    for (int i = 0; i < pl->msg_count && count < max; i++) {
        if (strcmp(pl->messages[i].to_id, to_id) == 0 &&
            pl->messages[i].status == MSG_STATUS_PENDING) {
            out[count++] = pl->messages[i];
        }
    }
    
    pthread_mutex_unlock(&pl->mutex);
    return count;
}

int peer_list_get_all_pending_messages(PeerList* pl, QueuedMessage* out, int max) {
    if (!pl || !out || max <= 0) return 0;
    
    pthread_mutex_lock(&pl->mutex);
    
    int count = 0;
    for (int i = 0; i < pl->msg_count && count < max; i++) {
        if (pl->messages[i].status == MSG_STATUS_PENDING) {
            out[count++] = pl->messages[i];
        }
    }
    
    pthread_mutex_unlock(&pl->mutex);
    return count;
}

int peer_list_mark_message_delivered(PeerList* pl, const char* msg_id) {
    if (!pl || !msg_id) return -1;
    
    pthread_mutex_lock(&pl->mutex);
    
    for (int i = 0; i < pl->msg_count; i++) {
        if (strcmp(pl->messages[i].msg_id, msg_id) == 0) {
            pl->messages[i].status = MSG_STATUS_DELIVERED;
            pl->messages[i].delivered_at = time(NULL);
            PLOG("peer_list_mark_message_delivered: %s", msg_id);
            pthread_mutex_unlock(&pl->mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&pl->mutex);
    return -1;
}

int peer_list_mark_message_sent(PeerList* pl, const char* msg_id) {
    if (!pl || !msg_id) return -1;
    
    pthread_mutex_lock(&pl->mutex);
    
    for (int i = 0; i < pl->msg_count; i++) {
        if (strcmp(pl->messages[i].msg_id, msg_id) == 0) {
            pl->messages[i].status = MSG_STATUS_SENT;
            PLOG("peer_list_mark_message_sent: %s", msg_id);
            pthread_mutex_unlock(&pl->mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&pl->mutex);
    return -1;
}

int peer_list_mark_message_failed(PeerList* pl, const char* msg_id) {
    if (!pl || !msg_id) return -1;
    
    pthread_mutex_lock(&pl->mutex);
    
    for (int i = 0; i < pl->msg_count; i++) {
        if (strcmp(pl->messages[i].msg_id, msg_id) == 0) {
            pl->messages[i].status = MSG_STATUS_FAILED;
            pl->messages[i].retry_count++;
            PLOG("peer_list_mark_message_failed: %s (retry %d)", 
                 msg_id, pl->messages[i].retry_count);
            pthread_mutex_unlock(&pl->mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&pl->mutex);
    return -1;
}

int peer_list_get_pending_count(PeerList* pl, const char* to_id) {
    if (!pl || !to_id) return 0;
    
    pthread_mutex_lock(&pl->mutex);
    
    int count = 0;
    for (int i = 0; i < pl->msg_count; i++) {
        if (strcmp(pl->messages[i].to_id, to_id) == 0 &&
            pl->messages[i].status == MSG_STATUS_PENDING) {
            count++;
        }
    }
    
    pthread_mutex_unlock(&pl->mutex);
    return count;
}

bool peer_list_has_pending_messages(PeerList* pl, const char* to_id) {
    if (!pl || !to_id) return false;
    
    pthread_mutex_lock(&pl->mutex);
    
    for (int i = 0; i < pl->msg_count; i++) {
        if (strcmp(pl->messages[i].to_id, to_id) == 0 &&
            pl->messages[i].status == MSG_STATUS_PENDING) {
            pthread_mutex_unlock(&pl->mutex);
            return true;
        }
    }
    
    pthread_mutex_unlock(&pl->mutex);
    return false;
}

/* ============================================================================
 * Load / Save - Using sscanf() NO BUFFER MODIFICATION!
 * ============================================================================ */

int peer_list_load(PeerList* pl) {
    if (!pl) return -1;
    
    pthread_mutex_lock(&pl->mutex);
    
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/peers.json", pl->data_dir);
    
    PLOG("peer_list_load: loading from %s", file_path);
    
    pl->peer_count = 0;
    pl->dirty = false;
    
    FILE* f = fopen(file_path, "r");
    if (!f) {
        PLOG("peer_list_load: no file found, starting fresh");
        pthread_mutex_unlock(&pl->mutex);
        return 0;
    }
    
    char line[8192];
    PeerListEntry entry;
    bool in_peer = false;
    int loaded = 0;
    
    memset(&entry, 0, sizeof(entry));
    
    while (fgets(line, sizeof(line), f)) {
        if (strlen(line) <= 1) continue;
        
        /* Check for beginning of peer object */
        if (strstr(line, "{") != NULL) {
            memset(&entry, 0, sizeof(entry));
            in_peer = true;
            continue;
        }
        
        if (!in_peer) continue;
        
        /* ===== USING sscanf() - NO BUFFER MODIFICATION! ===== */
        char id[64], status[16], ip[16], port[16];
        char name[128], pubkey[4096], sig[512], salt[33];
        int mode = 0, online = 0, verified = 0;
        long last_seen = 0, created_at = 0;
        
        if (sscanf(line, " \"id\": \"%63[^\"]\"", id) == 1) {
            strcpy(entry.id, id);
        }
        if (sscanf(line, " \"status\": \"%15[^\"]\"", status) == 1) {
            strcpy(entry.status, status);
        }
        if (sscanf(line, " \"ip\": \"%15[^\"]\"", ip) == 1) {
            strcpy(entry.ip, ip);
        }
        if (sscanf(line, " \"port\": \"%15[^\"]\"", port) == 1) {
            strcpy(entry.port, port);
        }
        if (sscanf(line, " \"online\": %d", &online) == 1) {
            entry.online = online;
        }
        if (sscanf(line, " \"mode\": %d", &mode) == 1) {
            entry.mode = mode;
        }
        if (sscanf(line, " \"verified\": %d", &verified) == 1) {
            entry.verified = verified;
        }
        if (sscanf(line, " \"last_seen\": %ld", &last_seen) == 1) {
            entry.last_seen = last_seen;
        }
        if (sscanf(line, " \"created_at\": %ld", &created_at) == 1) {
            entry.created_at = created_at;
        }
        if (sscanf(line, " \"name\": \"%127[^\"]\"", name) == 1) {
            strcpy(entry.name, name);
        }
        
        /* Check for end of peer object */
        if (strstr(line, "}") != NULL) {
            if (strlen(entry.id) > 0 && pl->peer_count < PEER_LIST_MAX_PEERS) {
                pl->peers[pl->peer_count++] = entry;
                loaded++;
                PLOG("peer_list_load: loaded peer %s (status=%s)", 
                     entry.id, entry.status);
            }
            in_peer = false;
            memset(&entry, 0, sizeof(entry));
        }
    }
    
    fclose(f);
    
    PLOG("peer_list_load: loaded %d peers, total count=%d", loaded, pl->peer_count);
    
    pthread_mutex_unlock(&pl->mutex);
    return pl->peer_count;
}

int peer_list_save(PeerList* pl) {
    if (!pl) return -1;
    
    pthread_mutex_lock(&pl->mutex);
    
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/peers.json", pl->data_dir);
    
    PLOG("peer_list_save: saving %d peers to %s", pl->peer_count, file_path);
    
    ensure_directory(pl->data_dir);
    
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s/peers.json.tmp", pl->data_dir);
    
    FILE* f = fopen(tmp_path, "w");
    if (!f) {
        PLOG("peer_list_save: failed to open temp file: %s", strerror(errno));
        pthread_mutex_unlock(&pl->mutex);
        return -1;
    }
    
    fprintf(f, "{\n  \"peers\": [\n");
    
    for (int i = 0; i < pl->peer_count; i++) {
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
        fprintf(f, "      \"name\": \"%s\"\n", escaped_name);
        fprintf(f, "    }");
    }
    
    fprintf(f, "\n  ]\n}\n");
    
    if (fclose(f) != 0) {
        PLOG("peer_list_save: failed to close temp file: %s", strerror(errno));
        unlink(tmp_path);
        pthread_mutex_unlock(&pl->mutex);
        return -1;
    }
    
    if (rename(tmp_path, file_path) != 0) {
        PLOG("peer_list_save: failed to rename: %s", strerror(errno));
        unlink(tmp_path);
        pthread_mutex_unlock(&pl->mutex);
        return -1;
    }
    
    pl->dirty = false;
    PLOG("peer_list_save: saved successfully");
    
    pthread_mutex_unlock(&pl->mutex);
    return 0;
}

int peer_list_load_messages(PeerList* pl) {
    if (!pl) return -1;
    
    pthread_mutex_lock(&pl->mutex);
    
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/messages.json", pl->data_dir);
    
    PLOG("peer_list_load_messages: loading from %s", file_path);
    
    pl->msg_count = 0;
    
    FILE* f = fopen(file_path, "r");
    if (!f) {
        PLOG("peer_list_load_messages: no file found, starting fresh");
        pthread_mutex_unlock(&pl->mutex);
        return 0;
    }
    
    char line[8192];
    QueuedMessage msg;
    bool in_msg = false;
    int loaded = 0;
    
    memset(&msg, 0, sizeof(msg));
    
    while (fgets(line, sizeof(line), f)) {
        if (strlen(line) <= 1) continue;
        
        if (strstr(line, "{") != NULL) {
            memset(&msg, 0, sizeof(msg));
            in_msg = true;
            continue;
        }
        
        if (!in_msg) continue;
        
        /* Parse with sscanf() */
        char msg_id[64], from_id[64], to_id[64];
        char payload[4096];
        int status = 0, encrypted = 0;
        long timestamp = 0, delivered_at = 0;
        
        if (sscanf(line, " \"msg_id\": \"%63[^\"]\"", msg_id) == 1) {
            strcpy(msg.msg_id, msg_id);
        }
        if (sscanf(line, " \"from_id\": \"%63[^\"]\"", from_id) == 1) {
            strcpy(msg.from_id, from_id);
        }
        if (sscanf(line, " \"to_id\": \"%63[^\"]\"", to_id) == 1) {
            strcpy(msg.to_id, to_id);
        }
        if (sscanf(line, " \"payload\": \"%4095[^\"]\"", payload) == 1) {
            strcpy(msg.payload, payload);
        }
        if (sscanf(line, " \"status\": %d", &status) == 1) {
            msg.status = status;
        }
        if (sscanf(line, " \"encrypted\": %d", &encrypted) == 1) {
            msg.encrypted = encrypted;
        }
        if (sscanf(line, " \"timestamp\": %ld", &timestamp) == 1) {
            msg.timestamp = timestamp;
        }
        if (sscanf(line, " \"delivered_at\": %ld", &delivered_at) == 1) {
            msg.delivered_at = delivered_at;
        }
        
        if (strstr(line, "}") != NULL) {
            if (strlen(msg.msg_id) > 0 && pl->msg_count < PEER_LIST_MAX_MSGS) {
                pl->messages[pl->msg_count++] = msg;
                loaded++;
            }
            in_msg = false;
            memset(&msg, 0, sizeof(msg));
        }
    }
    
    fclose(f);
    
    PLOG("peer_list_load_messages: loaded %d messages", loaded);
    pthread_mutex_unlock(&pl->mutex);
    return pl->msg_count;
}

int peer_list_save_messages(PeerList* pl) {
    if (!pl) return -1;
    
    pthread_mutex_lock(&pl->mutex);
    
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/messages.json", pl->data_dir);
    
    PLOG("peer_list_save_messages: saving %d messages", pl->msg_count);
    
    ensure_directory(pl->data_dir);
    
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s/messages.json.tmp", pl->data_dir);
    
    FILE* f = fopen(tmp_path, "w");
    if (!f) {
        PLOG("peer_list_save_messages: failed to open temp file");
        pthread_mutex_unlock(&pl->mutex);
        return -1;
    }
    
    fprintf(f, "{\n  \"messages\": [\n");
    
    for (int i = 0; i < pl->msg_count; i++) {
        if (i > 0) fprintf(f, ",\n");
        QueuedMessage* m = &pl->messages[i];
        
        char escaped_payload[8192];
        json_escape(m->payload, escaped_payload, sizeof(escaped_payload));
        
        fprintf(f, "    {\n");
        fprintf(f, "      \"msg_id\": \"%s\",\n", m->msg_id);
        fprintf(f, "      \"from_id\": \"%s\",\n", m->from_id);
        fprintf(f, "      \"to_id\": \"%s\",\n", m->to_id);
        fprintf(f, "      \"payload\": \"%s\",\n", escaped_payload);
        fprintf(f, "      \"timestamp\": %ld,\n", (long)m->timestamp);
        fprintf(f, "      \"status\": %d,\n", m->status);
        fprintf(f, "      \"encrypted\": %d,\n", m->encrypted ? 1 : 0);
        fprintf(f, "      \"delivered_at\": %ld,\n", (long)m->delivered_at);
        fprintf(f, "      \"retry_count\": %d\n", m->retry_count);
        fprintf(f, "    }");
    }
    
    fprintf(f, "\n  ]\n}\n");
    
    if (fclose(f) != 0) {
        unlink(tmp_path);
        pthread_mutex_unlock(&pl->mutex);
        return -1;
    }
    
    if (rename(tmp_path, file_path) != 0) {
        unlink(tmp_path);
        pthread_mutex_unlock(&pl->mutex);
        return -1;
    }
    
    PLOG("peer_list_save_messages: saved successfully");
    pthread_mutex_unlock(&pl->mutex);
    return 0;
}

/* ============================================================================
 * Sync with Registry
 * ============================================================================ */

int peer_list_sync_to_registry(PeerList* pl, Registry* reg) {
    if (!pl || !reg) return -1;
    
    pthread_mutex_lock(&pl->mutex);
    
    int synced = 0;
    for (int i = 0; i < pl->peer_count; i++) {
        PeerListEntry* entry = &pl->peers[i];
        if (strlen(entry->id) == 0) continue;
        
        RegistryPeer peer;
        memset(&peer, 0, sizeof(peer));
        strcpy(peer.id, entry->id);
        strcpy(peer.ip, entry->ip);
        strcpy(peer.port, entry->port);
        peer.online = entry->online;
        strcpy(peer.status, entry->status);
        peer.mode = entry->mode;
        strcpy(peer.name, entry->name);
        strcpy(peer.public_key, entry->public_key);
        strcpy(peer.signature, entry->signature);
        peer.verified = entry->verified;
        peer.created_at = entry->created_at;
        
        if (registry_register_peer(reg, entry->id, entry->ip, entry->port)) {
            registry_update_status(reg, entry->id, entry->status);
            synced++;
            PLOG("peer_list_sync_to_registry: synced peer %s", entry->id);
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
        for (int j = 0; j < pl->peer_count; j++) {
            if (peer_list_is_same_id(pl->peers[j].id, peers[i].id)) {
                found = j;
                break;
            }
        }
        
        if (found >= 0) {
            PeerListEntry* entry = &pl->peers[found];
            strcpy(entry->ip, peers[i].ip);
            strcpy(entry->port, peers[i].port);
            entry->online = peers[i].online;
            strcpy(entry->status, peers[i].status);
            entry->last_seen = peers[i].last_seen;
            entry->mode = peers[i].mode;
            strcpy(entry->name, peers[i].name);
            strcpy(entry->public_key, peers[i].public_key);
            strcpy(entry->signature, peers[i].signature);
            entry->verified = peers[i].verified;
            entry->created_at = peers[i].created_at;
            synced++;
        } else if (pl->peer_count < PEER_LIST_MAX_PEERS) {
            PeerListEntry* entry = &pl->peers[pl->peer_count++];
            strcpy(entry->id, peers[i].id);
            strcpy(entry->ip, peers[i].ip);
            strcpy(entry->port, peers[i].port);
            entry->online = peers[i].online;
            strcpy(entry->status, peers[i].status);
            entry->last_seen = peers[i].last_seen;
            entry->mode = peers[i].mode;
            strcpy(entry->name, peers[i].name);
            strcpy(entry->public_key, peers[i].public_key);
            strcpy(entry->signature, peers[i].signature);
            entry->verified = peers[i].verified;
            entry->created_at = peers[i].created_at;
            synced++;
        }
    }
    
    if (synced > 0) pl->dirty = true;
    
    PLOG("peer_list_sync_from_registry: synced %d peers", synced);
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

void peer_list_clear(PeerList* pl) {
    if (!pl) return;
    pthread_mutex_lock(&pl->mutex);
    pl->peer_count = 0;
    pl->msg_count = 0;
    pl->dirty = true;
    PLOG("peer_list_clear: cleared all data");
    pthread_mutex_unlock(&pl->mutex);
}
