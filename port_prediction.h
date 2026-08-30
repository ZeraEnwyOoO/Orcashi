 #ifndef PORT_PREDICTION_H
#define PORT_PREDICTION_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define PORT_PREDICT_SAMPLES 10
#define PORT_PREDICT_RANGE 10
#define PORT_PREDICT_MAX_RETRY 5
#define PORT_PREDICT_TIMEOUT 2
#define PORT_PREDICT_MIN_PORT 1024
#define PORT_PREDICT_MAX_PORT 65535
#define PORT_PREDICT_PROBE_PORT 33445

typedef struct {
    int port;
    time_t observed_at;
    int sequence_num;
    bool confirmed;
} PortObservation;

typedef struct {
    char target_ip[INET_ADDRSTRLEN];
    int target_port;
    PortObservation observations[PORT_PREDICT_SAMPLES];
    int count;
    int predicted_port;
    int pattern_offset;
    int pattern_detected;
    int confidence;
    time_t last_prediction;
    int best_ttl;
} PortPredictor;

int port_predictor_init(PortPredictor* pred, const char* target_ip, int target_port);
int port_predictor_add_observation(PortPredictor* pred, int observed_port);
int port_predictor_predict(PortPredictor* pred);
int port_predictor_punch(void* punch_state, const char* target_ip, int target_port);
int port_predict_range(const char* target_ip, int target_port, char* peer_ip, int* peer_port);
bool port_prediction_possible(PortPredictor* pred);
int port_analyze_pattern(PortPredictor* pred);
void port_predictor_debug_print(PortPredictor* pred);

#endif
