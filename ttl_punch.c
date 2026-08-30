#include "ttl_punch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define TTL_DEBUG 1

#if TTL_DEBUG
#define TLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[TTL] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define TLOG(fmt, ...) ((void)0)
#endif

/* ============================================================================
 * TTL PUNCH IMPLEMENTATION
 * ============================================================================ */

int ttl_punch_with_ttl(const char* target_ip, int target_port, int ttl, char* peer_ip, int* peer_port) {
    if (!target_ip || !peer_ip || !peer_port) return -1;
    
    TLOG("TTL punch to %s:%d with TTL=%d", target_ip, target_port, ttl);
    
    /* Create UDP socket with TTL option */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        TLOG("Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    /* Set TTL */
    if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        TLOG("Failed to set TTL: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    /* Set timeout */
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    /* Setup target address */
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &target.sin_addr);
    
    /* Send TTL probe packet */
    const char* msg = "ORCA_TTL_PROBE";
    ssize_t sent = sendto(sock, msg, strlen(msg), 0,
                          (struct sockaddr*)&target, sizeof(target));
    
    if (sent < 0) {
        TLOG("Failed to send TTL probe: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    /* Wait for response */
    char buffer[256];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    
    int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                     (struct sockaddr*)&from, &from_len);
    
    close(sock);
    
    if (n > 0) {
        buffer[n] = '\0';
        TLOG("Received response: %s", buffer);
        
        if (strcmp(buffer, "ORCA_TTL_RESPONSE") == 0) {
            inet_ntop(AF_INET, &from.sin_addr, peer_ip, INET_ADDRSTRLEN);
            *peer_port = ntohs(from.sin_port);
            TLOG("✅ TTL punch successful with TTL=%d", ttl);
            return 0;
        }
    }
    
    TLOG("No response for TTL=%d", ttl);
    return -1;
}

int ttl_punch(const char* target_ip, int target_port, char* peer_ip, int* peer_port) {
    if (!target_ip || !peer_ip || !peer_port) return -1;
    
    TLOG("TTL punch to %s:%d", target_ip, target_port);
    
    /* Try default TTL first */
    if (ttl_punch_with_ttl(target_ip, target_port, TTL_DEFAULT, peer_ip, peer_port) == 0) {
        return 0;
    }
    
    /* Try all TTL values */
    return ttl_punch_scan(target_ip, target_port, peer_ip, peer_port);
}

int ttl_punch_scan(const char* target_ip, int target_port, char* peer_ip, int* peer_port) {
    if (!target_ip || !peer_ip || !peer_port) return -1;
    
    TLOG("TTL scan to %s:%d (TTL %d-%d)", target_ip, target_port, TTL_MIN, TTL_MAX);
    
    for (int ttl = TTL_MIN; ttl <= TTL_MAX; ttl++) {
        if (ttl_punch_with_ttl(target_ip, target_port, ttl, peer_ip, peer_port) == 0) {
            TLOG("✅ TTL scan successful with TTL=%d", ttl);
            return 0;
        }
        usleep(50000); /* 50ms between attempts */
    }
    
    TLOG("❌ TTL scan failed for all TTL values");
    return -1;
}

/* ============================================================================
 * TTL UTILITIES
 * ============================================================================ */

bool ttl_punch_supported(void) {
    /* Check if TTL socket option is supported */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    
    int ttl = 1;
    int ret = setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    close(sock);
    
    return (ret == 0);
}

int ttl_get_best_ttl(void) {
    /* Determine best TTL value for current network */
    /* Try to find TTL that reaches gateway but not beyond */
    
    for (int ttl = 1; ttl <= 10; ttl++) {
        /* Send ping with TTL to gateway */
        /* If gateway responds with ICMP Time Exceeded, this TTL is good */
        /* For now, return default */
    }
    
    return TTL_DEFAULT;
}

/* ============================================================================
 * TEST FUNCTION
 * ============================================================================ */

#ifdef TTL_TEST

int main() {
    printf("=== TTL Punch Test ===\n");
    
    printf("TTL supported: %s\n", ttl_punch_supported() ? "YES" : "NO");
    printf("Best TTL: %d\n", ttl_get_best_ttl());
    
    char peer_ip[INET_ADDRSTRLEN];
    int peer_port;
    
    /* Test with localhost (won't work, just for demo) */
    int ret = ttl_punch("127.0.0.1", 9000, peer_ip, &peer_port);
    printf("TTL punch result: %d\n", ret);
    
    if (ret == 0) {
        printf("Peer: %s:%d\n", peer_ip, peer_port);
    }
    
    return 0;
}

#endif /* TTL_TEST */
