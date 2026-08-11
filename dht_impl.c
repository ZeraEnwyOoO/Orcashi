 #include "dht_impl.h"
#include "dht.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <pthread.h>

#ifdef __linux__
#include <sys/random.h>
#endif

#define MAX_BLACKLIST 64

typedef struct {
    struct sockaddr_storage addr;
    int addrlen;
    time_t added_at;
} BlacklistEntry;

static BlacklistEntry blacklist[MAX_BLACKLIST];
static int blacklist_count = 0;
static pthread_mutex_t blacklist_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================================
 * Blacklist Functions
 * ============================================================================ */

int dht_blacklisted(const struct sockaddr *sa, int salen)
{
    return dht_blacklist_check(sa, salen);
}

void dht_blacklist_add(const struct sockaddr *sa, int salen)
{
    if (!sa || salen <= 0) return;
    
    pthread_mutex_lock(&blacklist_mutex);
    
    // Check if already in blacklist
    for (int i = 0; i < blacklist_count; i++) {
        if (blacklist[i].addrlen == salen &&
            memcmp(&blacklist[i].addr, sa, salen) == 0) {
            blacklist[i].added_at = time(NULL);
            pthread_mutex_unlock(&blacklist_mutex);
            return;
        }
    }
    
    // Add new entry (replace oldest if full)
    if (blacklist_count < MAX_BLACKLIST) {
        int idx = blacklist_count++;
        memcpy(&blacklist[idx].addr, sa, salen);
        blacklist[idx].addrlen = salen;
        blacklist[idx].added_at = time(NULL);
    } else {
        // Replace oldest entry
        int oldest = 0;
        for (int i = 1; i < MAX_BLACKLIST; i++) {
            if (blacklist[i].added_at < blacklist[oldest].added_at) {
                oldest = i;
            }
        }
        memcpy(&blacklist[oldest].addr, sa, salen);
        blacklist[oldest].addrlen = salen;
        blacklist[oldest].added_at = time(NULL);
    }
    
    pthread_mutex_unlock(&blacklist_mutex);
}

int dht_blacklist_check(const struct sockaddr *sa, int salen)
{
    if (!sa || salen <= 0) return 0;
    
    pthread_mutex_lock(&blacklist_mutex);
    
    for (int i = 0; i < blacklist_count; i++) {
        if (blacklist[i].addrlen == salen &&
            memcmp(&blacklist[i].addr, sa, salen) == 0) {
            pthread_mutex_unlock(&blacklist_mutex);
            return 1;
        }
    }
    
    pthread_mutex_unlock(&blacklist_mutex);
    return 0;
}

void dht_blacklist_clear(void)
{
    pthread_mutex_lock(&blacklist_mutex);
    blacklist_count = 0;
    memset(blacklist, 0, sizeof(blacklist));
    pthread_mutex_unlock(&blacklist_mutex);
}

/* ============================================================================
 * Random Bytes
 * ============================================================================ */

static int random_seeded = 0;

int dht_random_bytes(void *buf, size_t size)
{
    if (!buf || size == 0) return -1;
    
    unsigned char *bytes = (unsigned char*)buf;
    
#ifdef __linux__
    // Use getrandom() on Linux for better randomness
    if (getrandom(buf, size, 0) == (ssize_t)size) {
        return 0;
    }
#endif
    
    // Fallback: use rand()
    if (!random_seeded) {
        srand(time(NULL) ^ getpid() ^ (unsigned long)pthread_self());
        random_seeded = 1;
    }
    
    for (size_t i = 0; i < size; i++) {
        bytes[i] = rand() & 0xFF;
    }
    
    return 0;
}

/* ============================================================================
 * Hash Function
 * ============================================================================ */

void dht_hash(void *hash_return, int hash_size,
              const void *v1, int len1,
              const void *v2, int len2,
              const void *v3, int len3)
{
    if (!hash_return || hash_size <= 0) return;
    
    unsigned char *hash = (unsigned char*)hash_return;
    
    // FNV-1a 64-bit offset basis
    unsigned long long h = 0x811c9dc5c8f5e5ddULL;
    
#define FNV_HASH_DATA(data, len) \
    if (data && len > 0) { \
        const unsigned char *ptr = (const unsigned char*)data; \
        for (int i = 0; i < len; i++) { \
            h ^= ptr[i]; \
            h *= 0x01000193ULL; \
            h ^= h >> 32; \
        } \
    }
    
    FNV_HASH_DATA(v1, len1);
    FNV_HASH_DATA(v2, len2);
    FNV_HASH_DATA(v3, len3);
    
#undef FNV_HASH_DATA
    
    // Copy hash to output
    for (int i = 0; i < hash_size && i < 20; i++) {
        hash[i] = (h >> (i * 8)) & 0xFF;
    }
    
    // Pad remaining bytes with zeros
    for (int i = 20; i < hash_size; i++) {
        hash[i] = 0;
    }
}

/* ============================================================================
 * UDP Send Function
 * ============================================================================ */

int dht_sendto(int sockfd, const void *buf, int len, int flags,
               const struct sockaddr *to, int tolen)
{
    if (sockfd < 0 || !buf || len <= 0 || !to || tolen <= 0) {
        errno = EINVAL;
        return -1;
    }
    
    ssize_t sent = sendto(sockfd, buf, len, flags, to, tolen);
    
    if (sent < 0) {
        // Don't log EAGAIN/EWOULDBLOCK - they're normal
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            fprintf(stderr, "[DHT] sendto failed: %s\n", strerror(errno));
        }
        return -1;
    }
    
    return (int)sent;
}

/* ============================================================================
 * Debug Output
 * ============================================================================ */

FILE *dht_debug = NULL;

void dht_debug_enable(const char *filename)
{
    if (filename) {
        dht_debug = fopen(filename, "a");
        if (!dht_debug) {
            fprintf(stderr, "[DHT] Failed to open debug file: %s\n", filename);
        }
    } else {
        dht_debug = stderr;
    }
}

void dht_debug_disable(void)
{
    if (dht_debug && dht_debug != stderr) {
        fclose(dht_debug);
    }
    dht_debug = NULL;
}

/* ============================================================================
 * Additional Utility Functions
 * ============================================================================ */

int dht_compare_ids(const unsigned char *id1, const unsigned char *id2)
{
    return memcmp(id1, id2, 20);
}

void dht_id_to_string(const unsigned char *id, char *buf, int buflen)
{
    if (!id || !buf || buflen < 41) return;
    
    for (int i = 0; i < 20; i++) {
        snprintf(buf + (i * 2), buflen - (i * 2), "%02x", id[i]);
    }
    buf[40] = '\0';
}
