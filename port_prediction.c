 #include "port_prediction.h"
#include "punch.h"
#include "orca_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>

#define PREDICT_DEBUG 1

#if PREDICT_DEBUG
#define PLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[PREDICT] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define PLOG(fmt, ...) ((void)0)
#endif

static int g_probe_socket = -1;
static int g_probe_port = 0;

int port_predictor_init(PortPredictor* pred, const char* target_ip, int target_port) {
    if (!pred || !target_ip) {
        return -1;
    }
    
    memset(pred, 0, sizeof(PortPredictor));
    strcpy(pred->target_ip, target_ip);
    pred->target_port = target_port;
    pred->count = 0;
    pred->pattern_detected = 0;
    pred->confidence = 0;
    pred->predicted_port = -1;
    pred->best_ttl = 5;
    pred->last_prediction = 0;
    
    PLOG("Port predictor initialized for %s:%d", target_ip, target_port);
    return 0;
}

int port_predictor_add_observation(PortPredictor* pred, int observed_port) {
    if (!pred || pred->count >= PORT_PREDICT_SAMPLES) {
        return -1;
    }
    
    if (observed_port < PORT_PREDICT_MIN_PORT || observed_port > PORT_PREDICT_MAX_PORT) {
        PLOG("Invalid port observation: %d", observed_port);
        return -1;
    }
    
    PortObservation* obs = &pred->observations[pred->count];
    obs->port = observed_port;
    obs->observed_at = time(NULL);
    obs->sequence_num = pred->count;
    obs->confirmed = 0;
    pred->count++;
    
    PLOG("Added observation %d: port %d", pred->count, observed_port);
    return 0;
}

int port_predictor_open_probe_socket(int* port_out) {
    if (g_probe_socket >= 0) {
        if (port_out) *port_out = g_probe_port;
        return g_probe_socket;
    }
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        PLOG("Failed to create probe socket: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    
    for (int port = PORT_PREDICT_PROBE_PORT; port < PORT_PREDICT_PROBE_PORT + 20; port++) {
        addr.sin_port = htons(port);
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            g_probe_socket = sock;
            g_probe_port = port;
            if (port_out) *port_out = port;
            PLOG("Probe socket bound to port %d", port);
            return sock;
        }
    }
    
    close(sock);
    PLOG("Failed to bind probe socket");
    return -1;
}

void port_predictor_close_probe_socket(void) {
    if (g_probe_socket >= 0) {
        close(g_probe_socket);
        g_probe_socket = -1;
        g_probe_port = 0;
    }
}

static int port_predictor_probe_port(const char* target_ip, int target_port, int* observed_port) {
    int sock = port_predictor_open_probe_socket(NULL);
    if (sock < 0) {
        return -1;
    }
    
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &target.sin_addr);
    
    char probe_msg[32];
    snprintf(probe_msg, sizeof(probe_msg), "ORCA_PROBE_%d", (int)time(NULL));
    
    ssize_t sent = sendto(sock, probe_msg, strlen(probe_msg), 0,
                          (struct sockaddr*)&target, sizeof(target));
    
    if (sent < 0) {
        PLOG("Failed to send probe: %s", strerror(errno));
        return -1;
    }
    
    char buffer[256];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    
    int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                     (struct sockaddr*)&from, &from_len);
    
    if (n > 0) {
        buffer[n] = '\0';
        if (strstr(buffer, "ORCA_PROBE_RESPONSE") != NULL) {
            int ext_port = ntohs(from.sin_port);
            if (observed_port) {
                *observed_port = ext_port;
            }
            PLOG("Probe response from port %d", ext_port);
            return ext_port;
        }
    }
    
    return -1;
}

static int port_predictor_probe_with_ttl(const char* target_ip, int target_port, int ttl, int* observed_port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        close(sock);
        return -1;
    }
    
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &target.sin_addr);
    
    char probe_msg[32];
    snprintf(probe_msg, sizeof(probe_msg), "ORCA_TTL_PROBE_%d", ttl);
    
    sendto(sock, probe_msg, strlen(probe_msg), 0,
           (struct sockaddr*)&target, sizeof(target));
    
    char buffer[256];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    
    int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                     (struct sockaddr*)&from, &from_len);
    
    close(sock);
    
    if (n > 0) {
        buffer[n] = '\0';
        if (strstr(buffer, "ORCA_TTL_RESPONSE") != NULL) {
            int ext_port = ntohs(from.sin_port);
            if (observed_port) {
                *observed_port = ext_port;
            }
            PLOG("TTL probe response from port %d (TTL=%d)", ext_port, ttl);
            return ext_port;
        }
    }
    
    return -1;
}

int port_analyze_pattern(PortPredictor* pred) {
    if (!pred || pred->count < 3) {
        PLOG("Not enough observations for pattern analysis (have %d, need 3)", 
             pred ? pred->count : 0);
        return -1;
    }
    
    int ports[PORT_PREDICT_SAMPLES];
    for (int i = 0; i < pred->count; i++) {
        ports[i] = pred->observations[i].port;
    }
    
    int diffs[PORT_PREDICT_SAMPLES - 1];
    for (int i = 0; i < pred->count - 1; i++) {
        diffs[i] = ports[i + 1] - ports[i];
    }
    
    int consistent = 1;
    int first_diff = diffs[0];
    for (int i = 1; i < pred->count - 1; i++) {
        if (diffs[i] != first_diff) {
            consistent = 0;
            break;
        }
    }
    
    if (consistent && first_diff > 0 && first_diff < 20) {
        pred->pattern_detected = 1;
        pred->pattern_offset = first_diff;
        pred->confidence = 80;
        pred->predicted_port = ports[pred->count - 1] + first_diff;
        PLOG("Detected sequential pattern: offset %d", first_diff);
        return 0;
    }
    
    int even_count = 0;
    int odd_count = 0;
    for (int i = 0; i < pred->count; i++) {
        if (ports[i] % 2 == 0) {
            even_count++;
        } else {
            odd_count++;
        }
    }
    
    if (even_count > odd_count * 2) {
        pred->pattern_detected = 1;
        pred->confidence = 60;
        pred->predicted_port = (ports[pred->count - 1] & ~1) + 2;
        PLOG("Detected even port pattern");
        return 0;
    }
    
    if (odd_count > even_count * 2) {
        pred->pattern_detected = 1;
        pred->confidence = 60;
        pred->predicted_port = (ports[pred->count - 1] | 1) + 2;
        PLOG("Detected odd port pattern");
        return 0;
    }
    
    if (pred->count >= 4) {
        int sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0;
        for (int i = 0; i < pred->count; i++) {
            sum_x += i;
            sum_y += ports[i];
            sum_xy += i * ports[i];
            sum_x2 += i * i;
        }
        
        int n = pred->count;
        float slope = (n * sum_xy - sum_x * sum_y) / (float)(n * sum_x2 - sum_x * sum_x);
        float intercept = (sum_y - slope * sum_x) / n;
        
        if (slope > 0.5 && slope < 10) {
            pred->pattern_detected = 1;
            pred->confidence = 50;
            pred->predicted_port = (int)(slope * n + intercept);
            
            if (pred->predicted_port < PORT_PREDICT_MIN_PORT) {
                pred->predicted_port = PORT_PREDICT_MIN_PORT;
            }
            if (pred->predicted_port > PORT_PREDICT_MAX_PORT) {
                pred->predicted_port = PORT_PREDICT_MAX_PORT;
            }
            
            PLOG("Linear regression: slope %.2f, predicted %d", slope, pred->predicted_port);
            return 0;
        }
    }
    
    pred->pattern_detected = 0;
    pred->confidence = 10;
    pred->predicted_port = ports[pred->count - 1] + (rand() % 5) + 1;
    
    if (pred->predicted_port > PORT_PREDICT_MAX_PORT) {
        pred->predicted_port = PORT_PREDICT_MAX_PORT;
    }
    
    PLOG("No pattern detected, using random prediction: %d", pred->predicted_port);
    return -1;
}

int port_predictor_predict(PortPredictor* pred) {
    if (!pred) {
        return -1;
    }
    
    if (pred->count < 3) {
        PLOG("Not enough observations (have %d, need 3)", pred->count);
        return -1;
    }
    
    int result = port_analyze_pattern(pred);
    if (result < 0) {
        PLOG("Pattern analysis failed, using range prediction");
        int base = pred->observations[pred->count - 1].port;
        pred->predicted_port = base + (rand() % 5) + 1;
        if (pred->predicted_port > PORT_PREDICT_MAX_PORT) {
            pred->predicted_port = PORT_PREDICT_MAX_PORT;
        }
        pred->confidence = 20;
        return pred->predicted_port;
    }
    
    pred->last_prediction = time(NULL);
    PLOG("Predicted port: %d (confidence: %d%%)", 
         pred->predicted_port, pred->confidence);
    return pred->predicted_port;
}

int port_predictor_punch(void* punch_state, const char* target_ip, int target_port) {
    PunchState* p = (PunchState*)punch_state;
    if (!p || !target_ip) {
        return -1;
    }
    
    PLOG("Port prediction punch to %s:%d", target_ip, target_port);
    
    PortPredictor pred;
    if (port_predictor_init(&pred, target_ip, target_port) < 0) {
        return -1;
    }
    
    for (int i = 0; i < 6; i++) {
        int observed_port = port_predictor_probe_port(target_ip, target_port, NULL);
        if (observed_port > 0) {
            port_predictor_add_observation(&pred, observed_port);
            usleep(200000);
        } else {
            int ttl = 1 + (i % 5);
            int ttl_port = port_predictor_probe_with_ttl(target_ip, target_port, ttl, NULL);
            if (ttl_port > 0) {
                port_predictor_add_observation(&pred, ttl_port);
            }
            usleep(100000);
        }
    }
    
    if (pred.count < 3) {
        PLOG("Not enough observations, using range scan");
        return port_predict_range(target_ip, target_port, p->peer_ip, &p->peer_port);
    }
    
    int predicted = port_predictor_predict(&pred);
    if (predicted < 0) {
        PLOG("Prediction failed, using range scan");
        return port_predict_range(target_ip, target_port, p->peer_ip, &p->peer_port);
    }
    
    PLOG("Attempting predicted port: %d", predicted);
    
    for (int attempt = 0; attempt < 3; attempt++) {
        if (punch_send(p, target_ip, predicted) == 0) {
            if (punch_listen(p, p->peer_ip, &p->peer_port) == 0) {
                p->punched = 1;
                PLOG("Success with predicted port %d (attempt %d)", predicted, attempt + 1);
                return 0;
            }
        }
        usleep(100000);
    }
    
    int range_start = predicted - PORT_PREDICT_RANGE;
    int range_end = predicted + PORT_PREDICT_RANGE;
    
    if (range_start < PORT_PREDICT_MIN_PORT) {
        range_start = PORT_PREDICT_MIN_PORT;
    }
    if (range_end > PORT_PREDICT_MAX_PORT) {
        range_end = PORT_PREDICT_MAX_PORT;
    }
    
    PLOG("Scanning range %d-%d", range_start, range_end);
    
    for (int port = range_start; port <= range_end; port++) {
        if (port == predicted) {
            continue;
        }
        
        for (int attempt = 0; attempt < 2; attempt++) {
            if (punch_send(p, target_ip, port) == 0) {
                if (punch_listen(p, p->peer_ip, &p->peer_port) == 0) {
                    p->punched = 1;
                    PLOG("Success with port %d in range", port);
                    return 0;
                }
            }
            usleep(50000);
        }
        
        if ((port - range_start) % 5 == 0) {
            usleep(50000);
        }
    }
    
    PLOG("Port prediction failed for %s:%d", target_ip, target_port);
    return -1;
}

int port_predict_range(const char* target_ip, int target_port, char* peer_ip, int* peer_port) {
    if (!target_ip || !peer_ip || !peer_port) {
        return -1;
    }
    
    PLOG("Port range scan for %s:%d", target_ip, target_port);
    
    int sock = port_predictor_open_probe_socket(NULL);
    if (sock < 0) {
        PLOG("Failed to open probe socket");
        return -1;
    }
    
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &target.sin_addr);
    
    int start_port = target_port - PORT_PREDICT_RANGE;
    int end_port = target_port + PORT_PREDICT_RANGE;
    
    if (start_port < PORT_PREDICT_MIN_PORT) {
        start_port = PORT_PREDICT_MIN_PORT;
    }
    if (end_port > PORT_PREDICT_MAX_PORT) {
        end_port = PORT_PREDICT_MAX_PORT;
    }
    
    PLOG("Scanning ports %d to %d", start_port, end_port);
    
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    for (int port = start_port; port <= end_port; port++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "ORCA_RANGE_%d", port);
        
        struct sockaddr_in peer_addr;
        memset(&peer_addr, 0, sizeof(peer_addr));
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons(port);
        inet_pton(AF_INET, target_ip, &peer_addr.sin_addr);
        
        sendto(sock, msg, strlen(msg), 0,
               (struct sockaddr*)&peer_addr, sizeof(peer_addr));
        
        char buffer[256];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        
        int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                         (struct sockaddr*)&from, &from_len);
        
        if (n > 0) {
            buffer[n] = '\0';
            if (strstr(buffer, "ORCA_RANGE_RESPONSE") != NULL) {
                inet_ntop(AF_INET, &from.sin_addr, peer_ip, INET_ADDRSTRLEN);
                *peer_port = ntohs(from.sin_port);
                PLOG("Found working port: %d", port);
                return 0;
            }
        }
        
        if ((port - start_port) % 5 == 0) {
            usleep(50000);
        }
    }
    
    PLOG("Port range scan failed for %s:%d", target_ip, target_port);
    return -1;
}

bool port_prediction_possible(PortPredictor* pred) {
    if (!pred) {
        return false;
    }
    
    return pred->pattern_detected && pred->confidence > 40 && pred->count >= 3;
}

void port_predictor_debug_print(PortPredictor* pred) {
    if (!pred) {
        printf("PortPredictor is NULL\n");
        return;
    }
    
    printf("\n=== PORT PREDICTOR DEBUG ===\n");
    printf("Target: %s:%d\n", pred->target_ip, pred->target_port);
    printf("Observations: %d\n", pred->count);
    printf("Pattern detected: %s\n", pred->pattern_detected ? "YES" : "NO");
    printf("Pattern offset: %d\n", pred->pattern_offset);
    printf("Predicted port: %d\n", pred->predicted_port);
    printf("Confidence: %d%%\n", pred->confidence);
    printf("Best TTL: %d\n", pred->best_ttl);
    printf("Last prediction: %s", ctime(&pred->last_prediction));
    
    printf("Observations:\n");
    for (int i = 0; i < pred->count; i++) {
        printf("  [%d] port=%d seq=%d confirmed=%d\n",
               i, pred->observations[i].port, 
               pred->observations[i].sequence_num,
               pred->observations[i].confirmed);
    }
    printf("==============================\n");
}
