// dht_impl.c - DHT Implementation Helper for ORCASHI (Pure C)
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
#include <sys/select.h>
#include <fcntl.h>

#include "dht.h"
#include "dht_impl.h"

// ===== DEBUG LOGGING =====
static FILE* dht_log_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int debug_enabled = 1;
static int dht_initialized = 0;

// ===== DHT State =====
static int dht_socket = -1;
static int dht_socket6 = -1;
static unsigned char dht_myid[20];
static char dht_myid_hex[41];

// ===== Log Functions =====

void dht_set_log_file(const char* filename) {
    pthread_mutex_lock(&log_mutex);
    if (dht_log_file) {
        fclose(dht_log_file);
        dht_log_file = NULL;
    }
    
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

static void dht_log(const char* level, const char* format, ...) {
    if (!dht_log_file && debug_enabled) {
        fprintf(stderr, "[DHT] [%s] ", level);
        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        fprintf(stderr, "\n");
        fflush(stderr);
        return;
    }
    
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

// ===== REQUIRED FUNCTIONS FOR dht.c =====

/**
 * dht_blacklisted - Check if address is blacklisted
 * Returns: 1 if blacklisted, 0 if not
 */
int dht_blacklisted(const struct sockaddr *sa, int salen) {
    // No blacklist by default
    (void)sa;
    (void)salen;
    return 0;
}

/**
 * dht_random_bytes - Generate cryptographically secure random bytes
 * Returns: 0 on success, -1 on failure
 */
int dht_random_bytes(void *buf, size_t size) {
    if (!buf || size == 0) return -1;
    
    // Try OpenSSL RAND_bytes first
    int result = RAND_bytes((unsigned char*)buf, (int)size);
    if (result == 1) {
        dht_log("DEBUG", "dht_random_bytes: generated %zu secure bytes", size);
        return 0;
    }
    
    // Fallback: /dev/urandom
    dht_log("WARNING", "dht_random_bytes: RAND_bytes failed, trying /dev/urandom");
    FILE* f = fopen("/dev/urandom", "r");
    if (f) {
        size_t n = fread(buf, 1, size, f);
        fclose(f);
        if (n == size) {
            dht_log("DEBUG", "dht_random_bytes: /dev/urandom succeeded");
            return 0;
        }
    }
    
    // Last resort: use rand() with time seed
    dht_log("WARNING", "dht_random_bytes: using weak random fallback");
    unsigned char* b = (unsigned char*)buf;
    srand(time(NULL) ^ getpid() ^ (unsigned long)buf);
    for (size_t i = 0; i < size; i++) {
        b[i] = rand() & 0xFF;
    }
    return -1;
}

/**
 * dht_hash - Compute SHA256 hash (or fallback)
 */
void dht_hash(void *hash_return, int hash_size,
              const void *data1, int len1,
              const void *data2, int len2,
              const void *data3, int len3) {
    if (!hash_return || hash_size <= 0) return;
    
    unsigned char hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    
    if (!ctx) {
        // Fallback: simple XOR hash
        dht_log("WARNING", "dht_hash: EVP_MD_CTX_new failed, using XOR fallback");
        unsigned char* h = (unsigned char*)hash_return;
        memset(h, 0, hash_size);
        
        const unsigned char* d1 = (const unsigned char*)data1;
        for (int i = 0; i < len1 && i < hash_size; i++) {
            h[i] ^= d1[i];
        }
        if (data2 && len2 > 0) {
            const unsigned char* d2 = (const unsigned char*)data2;
            for (int i = 0; i < len2 && i < hash_size; i++) {
                h[i] ^= d2[i];
            }
        }
        if (data3 && len3 > 0) {
            const unsigned char* d3 = (const unsigned char*)data3;
            for (int i = 0; i < len3 && i < hash_size; i++) {
                h[i] ^= d3[i];
            }
        }
        return;
    }
    
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

/**
 * dht_sendto - Send UDP packet (REAL)
 * Returns: number of bytes sent, -1 on error
 */
int dht_sendto(int sockfd, const void *buf, int len, int flags,
               const struct sockaddr *dest_addr, int addrlen) {
    if (!buf || len <= 0 || !dest_addr) return -1;
    
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
        strcpy(ip_str, "unknown");
    }
    
    dht_log("DEBUG", "dht_sendto: sending %d bytes to %s:%d (fd=%d)", 
            len, ip_str, port, sockfd);
    
    // REAL sendto call
    ssize_t sent = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    
    if (sent < 0) {
        dht_log("ERROR", "dht_sendto: sendto failed! errno=%d (%s)", 
                errno, strerror(errno));
        return -1;
    }
    
    if (sent != len) {
        dht_log("WARNING", "dht_sendto: partial send! %zd/%d bytes", sent, len);
    } else {
        dht_log("DEBUG", "dht_sendto: successfully sent %zd bytes", sent);
    }
    
    return (int)sent;
}

// ===== DHT Initialization Helper =====

int dht_init_helper(int port, const unsigned char* id) {
    if (dht_initialized) {
        dht_log("WARNING", "dht_init_helper: already initialized");
        return 1;
    }
    
    dht_log("INFO", "dht_init_helper: initializing DHT on port %d", port);
    
    // Set ID
    if (id) {
        memcpy(dht_myid, id, 20);
    } else {
        dht_random_bytes(dht_myid, 20);
    }
    
    // Convert to hex
    for (int i = 0; i < 20; i++) {
        sprintf(dht_myid_hex + (i * 2), "%02x", dht_myid[i]);
    }
    dht_myid_hex[40] = '\0';
    
    dht_log("INFO", "dht_init_helper: node ID = %s", dht_myid_hex);
    
    // Create socket
    dht_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (dht_socket < 0) {
        dht_log("ERROR", "dht_init_helper: failed to create socket! %s", strerror(errno));
        return -1;
    }
    
    // Set SO_REUSEADDR
    int opt = 1;
    if (setsockopt(dht_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        dht_log("WARNING", "dht_init_helper: setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
    }
    
    // Bind to port
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(dht_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        dht_log("ERROR", "dht_init_helper: failed to bind to port %d! %s", port, strerror(errno));
        close(dht_socket);
        dht_socket = -1;
        return -1;
    }
    
    dht_log("INFO", "dht_init_helper: socket bound to port %d", port);
    
    // Initialize DHT
    int result = dht_init(dht_socket, -1, dht_myid, NULL);
    if (result < 0) {
        dht_log("ERROR", "dht_init_helper: dht_init failed! result=%d", result);
        close(dht_socket);
        dht_socket = -1;
        return -1;
    }
    
    dht_initialized = 1;
    dht_log("INFO", "dht_init_helper: DHT initialized successfully");
    
    return 0;
}

void dht_shutdown_helper(void) {
    if (!dht_initialized) {
        return;
    }
    
    dht_log("INFO", "dht_shutdown_helper: shutting down DHT");
    
    dht_initialized = 0;
    dht_uninit();
    
    if (dht_socket >= 0) {
        close(dht_socket);
        dht_socket = -1;
    }
    
    dht_log("INFO", "dht_shutdown_helper: DHT shutdown complete");
}

int dht_get_socket(void) {
    return dht_socket;
}

const char* dht_get_node_id(void) {
    return dht_myid_hex;
}

int dht_is_initialized(void) {
    return dht_initialized;
}

// ===== DHT Operation Helpers =====

int dht_store_peer(const char* id, int port) {
    if (!dht_initialized) {
        dht_log("ERROR", "dht_store_peer: DHT not initialized");
        return -1;
    }
    
    if (!id) {
        dht_log("ERROR", "dht_store_peer: id is NULL");
        return -1;
    }
    
    unsigned char info_hash[20];
    // Use first 20 bytes of id as info_hash
    size_t id_len = strlen(id);
    memset(info_hash, 0, 20);
    memcpy(info_hash, id, (id_len > 20) ? 20 : id_len);
    
    dht_log("INFO", "dht_store_peer: storing %s on port %d", id, port);
    
    int result = dht_search(info_hash, port, AF_INET, NULL, NULL);
    if (result < 0) {
        dht_log("ERROR", "dht_store_peer: dht_search failed! result=%d", result);
        return -1;
    }
    
    dht_log("INFO", "dht_store_peer: search started, waiting for confirmation...");
    return 0;
}

int dht_lookup_peer(const char* id, char* result, int result_size) {
    if (!dht_initialized) {
        dht_log("ERROR", "dht_lookup_peer: DHT not initialized");
        return -1;
    }
    
    if (!id || !result) {
        dht_log("ERROR", "dht_lookup_peer: invalid parameters");
        return -1;
    }
    
    unsigned char info_hash[20];
    size_t id_len = strlen(id);
    memset(info_hash, 0, 20);
    memcpy(info_hash, id, (id_len > 20) ? 20 : id_len);
    
    dht_log("INFO", "dht_lookup_peer: looking up %s", id);
    
    int result_code = dht_search(info_hash, 0, AF_INET, NULL, NULL);
    if (result_code < 0) {
        dht_log("ERROR", "dht_lookup_peer: dht_search failed! result=%d", result_code);
        return -1;
    }
    
    dht_log("INFO", "dht_lookup_peer: search started, waiting for results...");
    // In real implementation, this would wait for callback
    // For now, return a placeholder
    snprintf(result, result_size, "127.0.0.1:9000");
    return 0;
}

// ===== Bootstrap Helper =====

int dht_add_bootstrap_node(const char* host, int port) {
    if (!dht_initialized) {
        dht_log("ERROR", "dht_add_bootstrap_node: DHT not initialized");
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    // Try numeric IP first
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        // DNS lookup
        struct hostent* he = gethostbyname(host);
        if (!he) {
            dht_log("ERROR", "dht_add_bootstrap_node: failed to resolve %s", host);
            return -1;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    
    dht_log("INFO", "dht_add_bootstrap_node: pinging %s:%d", host, port);
    int result = dht_ping_node((struct sockaddr*)&addr, sizeof(addr));
    
    if (result < 0) {
        dht_log("WARNING", "dht_add_bootstrap_node: ping failed for %s", host);
    } else {
        dht_log("INFO", "dht_add_bootstrap_node: ping succeeded for %s", host);
    }
    
    return result;
}

void dht_auto_bootstrap(void) {
    if (!dht_initialized) {
        dht_log("ERROR", "dht_auto_bootstrap: DHT not initialized");
        return;
    }
    
    const char* bootstrap_nodes[] = {
        "router.bittorrent.com",
        "dht.transmissionbt.com",
        "router.utorrent.com",
        "dht.aelitis.com",
        "bootstrap.jami.net",
        "dht.libtorrent.org"
    };
    
    dht_log("INFO", "dht_auto_bootstrap: starting bootstrap...");
    
    for (int i = 0; i < 6; i++) {
        dht_add_bootstrap_node(bootstrap_nodes[i], 6881);
        usleep(100000);  // 100ms delay between pings
    }
    
    dht_log("INFO", "dht_auto_bootstrap: bootstrap complete");
}

// ===== Statistics =====

void dht_print_stats(void) {
    if (!dht_initialized) {
        printf("[DHT] Not initialized\n");
        return;
    }
    
    int good = 0, dubious = 0, cached = 0, incoming = 0;
    int total = dht_nodes(AF_INET, &good, &dubious, &cached, &incoming);
    
    printf("\n[DHT] Statistics:\n");
    printf("  Total nodes:   %d\n", total);
    printf("  Good nodes:    %d\n", good);
    printf("  Dubious nodes: %d\n", dubious);
    printf("  Cached nodes:  %d\n", cached);
    printf("  Incoming:      %d\n", incoming);
    printf("  Node ID:       %s\n", dht_myid_hex);
    printf("\n");
}

void dht_dump_table(void) {
    if (!dht_initialized) {
        printf("[DHT] Not initialized\n");
        return;
    }
    dht_dump_tables(stdout);
}
