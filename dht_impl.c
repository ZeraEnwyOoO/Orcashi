 // dht_impl.c - Real DHT Implementation for jech/dht
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <pthread.h>

// ===== DEBUG LOGGING =====
static FILE* dht_log_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void dht_set_log_file(const char* filename) {
    if (dht_log_file) fclose(dht_log_file);
    if (filename) {
        dht_log_file = fopen(filename, "a");
        if (dht_log_file) {
            time_t now = time(NULL);
            fprintf(dht_log_file, "\n=== DHT LOG STARTED at %s", ctime(&now));
            fflush(dht_log_file);
        }
    }
}

static void dht_log(const char* level, const char* format, ...) {
    if (!dht_log_file) return;
    
    pthread_mutex_lock(&log_mutex);
    
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(dht_log_file, "[%s] [%s] ", time_buf, level);
    
    va_list args;
    va_start(args, format);
    vfprintf(dht_log_file, format, args);
    va_end(args);
    
    fprintf(dht_log_file, "\n");
    fflush(dht_log_file);
    
    pthread_mutex_unlock(&log_mutex);
}

// ===== REQUIRED FUNCTIONS FOR jech/dht =====

int dht_blacklisted(const struct sockaddr *sa, int salen) {
    // Blacklist logic - អាចបន្ថែម IP blacklist ប្រសិនបើចង់
    dht_log("DEBUG", "dht_blacklisted called for family %d", sa->sa_family);
    return 0;  // 0 = not blacklisted
}

int dht_random_bytes(void *buf, size_t size) {
    // ប្រើ OpenSSL RAND_bytes សម្រាប់ random សុវត្ថិភាព
    int result = RAND_bytes(buf, size);
    
    if (result == 1) {
        dht_log("DEBUG", "dht_random_bytes: generated %zu secure random bytes", size);
        return 0;  // Success
    } else {
        dht_log("ERROR", "dht_random_bytes: RAND_bytes failed! Using fallback");
        
        // Fallback: ប្រើ /dev/urandom
        FILE* f = fopen("/dev/urandom", "r");
        if (f) {
            size_t n = fread(buf, 1, size, f);
            fclose(f);
            if (n == size) {
                dht_log("DEBUG", "dht_random_bytes: fallback /dev/urandom succeeded");
                return 0;
            }
        }
        
        // Last resort: ប្រើ time + rand
        dht_log("WARNING", "dht_random_bytes: using weak random fallback");
        unsigned char* b = (unsigned char*)buf;
        srand(time(NULL) ^ getpid());
        for (size_t i = 0; i < size; i++) {
            b[i] = rand() & 0xFF;
        }
        return -1;
    }
}

void dht_hash(void *hash_return, int hash_size,
              const void *data1, int len1,
              const void *data2, int len2,
              const void *data3, int len3) {
    dht_log("DEBUG", "dht_hash: computing SHA256 hash (size=%d, len1=%d, len2=%d, len3=%d)",
            hash_size, len1, len2, len3);
    
    unsigned char hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        dht_log("ERROR", "dht_hash: EVP_MD_CTX_new failed!");
        memset(hash_return, 0, hash_size);
        return;
    }
    
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data1, len1);
    if (data2 && len2 > 0) {
        EVP_DigestUpdate(ctx, data2, len2);
    }
    if (data3 && len3 > 0) {
        EVP_DigestUpdate(ctx, data3, len3);
    }
    
    unsigned int len = 32;
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    
    int copy_size = (hash_size < 32) ? hash_size : 32;
    memcpy(hash_return, hash, copy_size);
    
    dht_log("DEBUG", "dht_hash: hash computed successfully (copied %d bytes)", copy_size);
}

// ===== REAL UDP SEND =====

int dht_sendto(int sockfd, const void *buf, int len, int flags,
               const struct sockaddr *dest_addr, int addrlen) {
    char ip_str[INET6_ADDRSTRLEN];
    int port = 0;
    
    if (dest_addr->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)dest_addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
        port = ntohs(sin->sin_port);
    } else if (dest_addr->sa_family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)dest_addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
        port = ntohs(sin6->sin6_port);
    } else {
        snprintf(ip_str, sizeof(ip_str), "unknown(%d)", dest_addr->sa_family);
    }
    
    dht_log("INFO", "dht_sendto: sending %d bytes to %s:%d (socket %d)", 
            len, ip_str, port, sockfd);
    
    // REAL sendto() call
    ssize_t sent = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    
    if (sent < 0) {
        dht_log("ERROR", "dht_sendto: sendto failed! errno=%d (%s)", 
                errno, strerror(errno));
        return -1;
    }
    
    if (sent != len) {
        dht_log("WARNING", "dht_sendto: partial send! %zd/%d bytes sent", sent, len);
    } else {
        dht_log("DEBUG", "dht_sendto: successfully sent %zd bytes", sent);
    }
    
    return (int)sent;
}
