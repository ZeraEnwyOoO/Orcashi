#include "port_prediction.h"
#include "punch.h"
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

#define PROBE_PORT_START 33445
#define PROBE_PORT_END 33455

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
    
    PLOG("Port predictor initialized for %s:%d", target_ip, target_port);
    return 0;
}

int port_predictor_add_observation(PortPredictor* pred, int observed_port) {
    if (!pred || pred->count >= PORT_PREDICT_SAMPLES) {
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

static int probe_port(const char* target_ip, int target_port, int* observed_port) {
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
    
    for (int port = PROBE_PORT_START; port <= PROBE_PORT_END; port++) {
        addr.sin_port = htons(port);
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            if (observed_port) {
                *observed_port = port;
            }
            break;
        }
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
    
    const char* probe = "ORCA_PORT_PROBE";
    sendto(sock, probe, strlen(probe), 0,
           (struct sockaddr*)&target, sizeof(target));
    
    char buffer[256];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    
    int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                     (struct sockaddr*)&from, &from_len);
    
    close(sock);
    
    if (n > 0) {
        buffer[n] = '\0';
        if (strstr(buffer, "ORCA_PORT_RESPONSE") != NULL) {
            int ext_port = ntohs(from.sin_port);
            PLOG("Probe response from port %d", ext_port);
            return ext_port;
        }
    }
    
    return -1;
}

int port_predictor_predict(PortPredictor* pred) {
    if (!pred || pred->count < 3) {
        PLOG("Not enough observations for prediction (have %d, need 3)", 
             pred ? pred->count : 0);
        return -1;
    }
    
    int result = port_analyze_pattern(pred);
    if (result < 0) {
        PLOG("No pattern detected, using range prediction");
        int base = pred->observations[pred->count - 1].port;
        pred->predicted_port = base + (rand() % 5) + 1;
        pred->confidence = 30;
        return pred->predicted_port;
    }
    
    pred->last_prediction = time(NULL);
    PLOG("Predicted port: %d (confidence: %d%%)", 
         pred->predicted_port, pred->confidence);
    return pred->predicted_port;
}

int port_analyze_pattern(PortPredictor* pred) {
    if (!pred || pred->count < 3) {
        return -1;
    }
    
    int ports[PORT_PREDICT_SAMPLES];
    for (int i = 0; i < pred->count; i++) {
        ports[i] = pred->observations[i].port;
    }
    
    /* Check for sequential pattern */
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
    
    /* Check for even/odd pattern */
    int even_count = 0;
    int odd_count = 0;
    for (int i = 0; i < pred->count; i++) {
        if (ports[i] % 2 == 0) {
            even_count++;
        } else {
            odd_count++;
        }
    }
    
    if (even_count > odd_count) {
        pred->pattern_detected = 1;
        pred->confidence = 60;
        pred->predicted_port = (ports[pred->count - 1] & ~1) + 2;
        PLOG("Detected even port pattern");
        return 0;
    }
    
    if (odd_count > even_count) {
        pred->pattern_detected = 1;
        pred->confidence = 60;
        pred->predicted_port = (ports[pred->count - 1] | 1) + 2;
        PLOG("Detected odd port pattern");
        return 0;
    }
    
    /* Check for linear regression */
    if (pred->count >= 5) {
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
            PLOG("Linear regression: slope %.2f, predicted %d", slope, pred->predicted_port);
            return 0;
        }
    }
    
    /* No pattern detected */
    pred->pattern_detected = 0;
    pred->confidence = 10;
    pred->predicted_port = ports[pred->count - 1] + (rand() % 10) + 1;
    PLOG("No pattern detected, random prediction: %d", pred->predicted_port);
    return -1;
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
    
    /* Collect observations */
    for (int i = 0; i < 5; i++) {
        int observed_port = probe_port(target_ip, target_port, NULL);
        if (observed_port > 0) {
            port_predictor_add_observation(&pred, observed_port);
        }
        usleep(200000);
    }
    
    if (pred.count < 3) {
        PLOG("Not enough observations, using range scan");
        return port_predict_range(target_ip, target_port, p->peer_ip, &p->peer_port);
    }
    
    /* Predict port */
    int predicted = port_predictor_predict(&pred);
    if (predicted < 0) {
        PLOG("Prediction failed, using range scan");
        return port_predict_range(target_ip, target_port, p->peer_ip, &p->peer_port);
    }
    
    PLOG("Attempting predicted port: %d", predicted);
    
    /* Try predicted port */
    if (punch_send(p, target_ip, predicted) == 0) {
        if (punch_listen(p, p->peer_ip, &p->peer_port) == 0) {
            p->punched = 1;
            PLOG("Success with predicted port %d", predicted);
            return 0;
        }
    }
    
    /* Try range around predicted port */
    int range_start = predicted - PORT_PREDICT_RANGE;
    int range_end = predicted + PORT_PREDICT_RANGE;
    
    if (range_start < 1024) {
        range_start = 1024;
    }
    if (range_end > 65535) {
        range_end = 65535;
    }
    
    PLOG("Scanning range %d-%d", range_start, range_end);
    
    for (int port = range_start; port <= range_end; port++) {
        if (port == predicted) {
            continue;
        }
        
        if (punch_send(p, target_ip, port) == 0) {
            if (punch_listen(p, p->peer_ip, &p->peer_port) == 0) {
                p->punched = 1;
                PLOG("Success with port %d in range", port);
                return 0;
            }
        }
        
        if ((port - range_start) % 5 == 0) {
            usleep(50000);
        }
    }
    
    PLOG("Port prediction failed");
    return -1;
}

int port_predict_range(const char* target_ip, int target_port, char* peer_ip, int* peer_port) {
    if (!target_ip || !peer_ip || !peer_port) {
        return -1;
    }
    
    PLOG("Port range scan for %s:%d", target_ip, target_port);
    
    PunchState p;
    if (punch_init(&p, PUNCH_PORT + 10) < 0) {
        PLOG("Failed to init punch for range scan");
        return -1;
    }
    
    int start_port = target_port - PORT_PREDICT_RANGE;
    int end_port = target_port + PORT_PREDICT_RANGE;
    
    if (start_port < 1024) {
        start_port = 1024;
    }
    if (end_port > 65535) {
        end_port = 65535;
    }
    
    PLOG("Scanning ports %d to %d", start_port, end_port);
    
    for (int port = start_port; port <= end_port; port++) {
        if (punch_send(&p, target_ip, port) == 0) {
            if (punch_listen(&p, peer_ip, peer_port) == 0) {
                PLOG("Found working port: %d", port);
                punch_close(&p);
                return 0;
            }
        }
        
        if ((port - start_port) % 10 == 0) {
            usleep(50000);
        }
    }
    
    punch_close(&p);
    PLOG("Port range scan failed");
    return -1;
}

bool port_prediction_possible(PortPredictor* pred) {
    if (!pred) {
        return 0;
    }
    
    return pred->pattern_detected && pred->confidence > 50;
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
    
    printf("Observations:\n");
    for (int i = 0; i < pred->count; i++) {
        printf("  [%d] port=%d seq=%d\n",
               i, pred->observations[i].port, pred->observations[i].sequence_num);
    }
    printf("==============================\n");
}

/* Test function */
#ifdef PREDICT_TEST

int main() {
    printf("=== Port Prediction Test ===\n");
    
    PortPredictor pred;
    port_predictor_init(&pred, "192.168.1.100", 9000);
    
    /* Simulate observations */
    int base = 50000;
    for (int i = 0; i < 8; i++) {
        port_predictor_add_observation(&pred, base + i * 2);
    }
    
    int predicted = port_predictor_predict(&pred);
    printf("Predicted port: %d\n", predicted);
    
    port_predictor_debug_print(&pred);
    
    return 0;
}

#endif
