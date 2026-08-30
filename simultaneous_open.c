#include "simultaneous_open.h"
#include "punch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define SIM_DEBUG 1

#if SIM_DEBUG
#define SLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[SIM] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define SLOG(fmt, ...) ((void)0)
#endif

/* ============================================================================
 * SIMULTANEOUS OPEN IMPLEMENTATION
 * ============================================================================ */

int simultaneous_open_punch(void* punch_state, const char* target_ip, int target_port) {
    PunchState* p = (PunchState*)punch_state;
    if (!p || !target_ip) return -1;
    
    SLOG("Simultaneous open punch to %s:%d", target_ip, target_port);
    
    /* Get synchronization time */
    time_t sync_time = simultaneous_get_sync_time();
    SLOG("Sync time: %ld", (long)sync_time);
    
    /* Send punch packets with timing */
    const char* msg = "ORCA_SIM_PUNCH";
    
    for (int i = 0; i < SIM_OPEN_RETRY; i++) {
        /* Send punch */
        struct sockaddr_in target;
        memset(&target, 0, sizeof(target));
        target.sin_family = AF_INET;
        target.sin_port = htons(target_port);
        inet_pton(AF_INET, target_ip, &target.sin_addr);
        
        sendto(p->udp_socket, msg, strlen(msg), 0,
               (struct sockaddr*)&target, sizeof(target));
        
        /* Listen for response */
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        char buffer[256];
        
        struct timeval tv;
        tv.tv_sec = SIM_OPEN_TIMEOUT;
        tv.tv_usec = 0;
        setsockopt(p->udp_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        int n = recvfrom(p->udp_socket, buffer, sizeof(buffer) - 1, 0,
                         (struct sockaddr*)&from, &from_len);
        
        if (n > 0) {
            buffer[n] = '\0';
            if (strcmp(buffer, "ORCA_SIM_RESPONSE") == 0) {
                char peer_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &from.sin_addr, peer_ip, sizeof(peer_ip));
                int peer_port = ntohs(from.sin_port);
                SLOG("✅ Simultaneous open successful! Peer at %s:%d", peer_ip, peer_port);
                return 0;
            }
        }
        
        /* Exponential backoff */
        int backoff = SIM_OPEN_BACKOFF * (1 << i);
        SLOG("Retry %d, backoff %dms", i+1, backoff);
        usleep(backoff * 1000);
    }
    
    SLOG("❌ Simultaneous open failed");
    return -1;
}

int simultaneous_open_sync(const char* target_ip, int target_port, 
                           time_t sync_time, char* peer_ip, int* peer_port) {
    if (!target_ip || !peer_ip || !peer_port) return -1;
    
    SLOG("Synchronized simultaneous open to %s:%d at %ld", 
         target_ip, target_port, (long)sync_time);
    
    /* Wait until sync time */
    time_t now = time(NULL);
    if (now < sync_time) {
        struct timespec ts;
        ts.tv_sec = sync_time - now;
        ts.tv_nsec = 0;
        nanosleep(&ts, NULL);
    }
    
    /* Create socket */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        SLOG("Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    /* Set timeout */
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    /* Setup target */
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &target.sin_addr);
    
    /* Send at exact sync time */
    const char* msg = "ORCA_SIM_SYNC";
    sendto(sock, msg, strlen(msg), 0,
           (struct sockaddr*)&target, sizeof(target));
    
    /* Listen for response */
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    char buffer[256];
    
    int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                     (struct sockaddr*)&from, &from_len);
    
    close(sock);
    
    if (n > 0 && strcmp(buffer, "ORCA_SIM_SYNC_RESPONSE") == 0) {
        inet_ntop(AF_INET, &from.sin_addr, peer_ip, INET_ADDRSTRLEN);
        *peer_port = ntohs(from.sin_port);
        SLOG("✅ Synchronized open successful!");
        return 0;
    }
    
    SLOG("❌ Synchronized open failed");
    return -1;
}

/* ============================================================================
 * SIMULTANEOUS OPEN UTILITIES
 * ============================================================================ */

bool simultaneous_open_supported(void) {
    /* Check if simultaneous open is supported */
    /* Most systems support this */
    return true;
}

time_t simultaneous_get_sync_time(void) {
    /* Get synchronization time (current time + 5 seconds) */
    time_t now = time(NULL);
    return now + 5;
}

/* ============================================================================
 * TEST FUNCTION
 * ============================================================================ */

#ifdef SIM_TEST

int main() {
    printf("=== Simultaneous Open Test ===\n");
    
    printf("Supported: %s\n", simultaneous_open_supported() ? "YES" : "NO");
    
    time_t sync = simultaneous_get_sync_time();
    printf("Sync time: %s", ctime(&sync));
    
    char peer_ip[INET_ADDRSTRLEN];
    int peer_port;
    
    int ret = simultaneous_open_sync("127.0.0.1", 9000, sync, peer_ip, &peer_port);
    printf("Result: %d\n", ret);
    
    return 0;
}

#endif /* SIM_TEST */
