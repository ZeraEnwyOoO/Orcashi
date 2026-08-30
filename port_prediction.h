
#ifndef PORT_PREDICTION_H
#define PORT_PREDICTION_H

#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ============================================================================
 * PORT PREDICTION CONFIGURATION
 * ============================================================================ */

#define PORT_PREDICT_RANGE 10
#define PORT_PREDICT_MAX_RETRY 5
#define PORT_PREDICT_TIMEOUT 2

/* ============================================================================
 * PORT PREDICTION FUNCTIONS
 * ============================================================================ */

/* Punch using port prediction */
int port_prediction_punch(void* punch_state, const char* target_ip, int target_port);

/* Predict NAT port based on pattern */
int port_predict_nat_port(const char* target_ip, int target_port);

/* Try range of predicted ports */
int port_predict_range(const char* target_ip, int target_port, char* peer_ip, int* peer_port);

/* ============================================================================
 * PORT PREDICTION UTILITIES
 * ============================================================================ */

/* Check if port prediction is possible */
bool port_prediction_possible(void);

/* Analyze NAT port allocation pattern */
int port_analyze_pattern(const char* target_ip);

#endif /* PORT_PREDICTION_H */
