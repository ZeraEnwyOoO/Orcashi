 #define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "dht.h"

static FILE* dht_log_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int debug_enabled = 1;

void dht_set_log_file(const char* filename) {
    pthread_mutex_lock(&log_mutex);
    if (dht_log_file) fclose(dht_log_file);
    dht_log_file = NULL;
    if (filename) {
        dht_log_file = fopen(filename, "a");
        if (dht_log_file) {
            time_t now = time(NULL);
            fprintf(dht_log_file, "\n=== DHT LOG STARTED at %s", ctime(&now));
            fflush(dht_log_file);
        }
    }
    pthread_mutex_unlock(&log_mutex);
}

void dht_set_debug(int enabled) {
    debug_enabled = enabled;
}

int dht_blacklisted(const struct sockaddr *sa, int salen) {
    (void)sa; (void)salen;
    return 0;
}

int dht_random_bytes(void *buf, size_t size) {
    int result = RAND_bytes((unsigned char*)buf, (int)size);
    if (result == 1) return 0;
    unsigned char* b = (unsigned char*)buf;
    srand(time(NULL) ^ getpid());
    for (size_t i = 0; i < size; i++) b[i] = rand() & 0xFF;
    return -1;
}

void dht_hash(void *hash_return, int hash_size,
              const void *data1, int len1,
              const void *data2, int len2,
              const void *data3, int len3) {
    unsigned char hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(hash_return, 0, hash_size); return; }
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data1, len1);
    if (data2 && len2 > 0) EVP_DigestUpdate(ctx, data2, len2);
    if (data3 && len3 > 0) EVP_DigestUpdate(ctx, data3, len3);
    unsigned int len = 32;
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    int copy_size = (hash_size < 32) ? hash_size : 32;
    memcpy(hash_return, hash, copy_size);
}

// ===== REAL dht_sendto =====
int dht_sendto(int sockfd, const void *buf, int len, int flags,
               const struct sockaddr *dest_addr, int addrlen) {
    if (!buf || len <= 0) return -1;
    
    // Log for debugging
    if (debug_enabled) {
        char ip[INET_ADDRSTRLEN];
        int port = 0;
        if (dest_addr->sa_family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)dest_addr;
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            port = ntohs(sin->sin_port);
        }
        fprintf(stderr, "[DHT] Sending %d bytes to %s:%d\n", len, ip, port);
    }
    
    ssize_t sent = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    if (sent < 0) {
        fprintf(stderr, "[DHT] sendto failed: %s\n", strerror(errno));
        return -1;
    }
    return (int)sent;
}
