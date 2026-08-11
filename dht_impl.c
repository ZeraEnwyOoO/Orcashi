 
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

int dht_blacklisted(const struct sockaddr *sa, int salen)
{
    return dht_blacklist_check(sa, salen);
}

void dht_blacklist_add(const struct sockaddr *sa, int salen)
{
    if (!sa || salen <= 0) return;
    pthread_mutex_lock(&blacklist_mutex);
    for (int i = 0; i < blacklist_count; i++) {
        if (blacklist[i].addrlen == salen &&
            memcmp(&blacklist[i].addr, sa, salen) == 0) {
            blacklist[i].added_at = time(NULL);
            pthread_mutex_unlock(&blacklist_mutex);
            return;
        }
    }
    if (blacklist_count < MAX_BLACKLIST) {
        int idx = blacklist_count++;
        memcpy(&blacklist[idx].addr, sa, salen);
        blacklist[idx].addrlen = salen;
        blacklist[idx].added_at = time(NULL);
    } else {
        int oldest = 0;
        for (int i = 1; i < MAX_BLACKLIST; i++) {
            if (blacklist[i].added_at < blacklist[oldest].added_at)
                oldest = i;
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

static int random_seeded = 0;

int dht_random_bytes(void *buf, size_t size)
{
    if (!buf || size == 0) return -1;
    unsigned char *bytes = (unsigned char*)buf;
#ifdef __linux__
    if (getrandom(buf, size, 0) == (ssize_t)size) return 0;
#endif
    if (!random_seeded) {
        srand(time(NULL) ^ getpid() ^ (unsigned long)pthread_self());
        random_seeded = 1;
    }
    for (size_t i = 0; i < size; i++)
        bytes[i] = rand() & 0xFF;
    return 0;
}

void dht_hash(void *hash_return, int hash_size,
              const void *v1, int len1,
              const void *v2, int len2,
              const void *v3, int len3)
{
    if (!hash_return || hash_size <= 0) return;
    unsigned char *hash = (unsigned char*)hash_return;
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
    for (int i = 0; i < hash_size && i < 20; i++)
        hash[i] = (h >> (i * 8)) & 0xFF;
    for (int i = 20; i < hash_size; i++)
        hash[i] = 0;
}

int dht_sendto(int sockfd, const void *buf, int len, int flags,
               const struct sockaddr *to, int tolen)
{
    if (sockfd < 0 || !buf || len <= 0 || !to || tolen <= 0) {
        errno = EINVAL;
        return -1;
    }
    ssize_t sent = sendto(sockfd, buf, len, flags, to, tolen);
    return (int)sent;
}
 
