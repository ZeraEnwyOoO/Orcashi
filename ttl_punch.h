#ifndef TTL_PUNCH_H
#define TTL_PUNCH_H

#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ============================================================================
 * TTL PUNCH CONFIGURATION
 * ============================================================================ */

#define TTL_MIN 1
#define TTL_MAX 10
#define TTL_DEFAULT 5
#define TTL_RETRY_COUNT 3

/* ============================================================================
 * TTL PUNCH FUNCTIONS
 * ============================================================================ */

/* Punch using TTL manipulation */
int ttl_punch(const char* target_ip, int target_port, char* peer_ip, int* peer_port);

/* Punch with specific TTL value */
int ttl_punch_with_ttl(const char* target_ip, int target_port, int ttl, char* peer_ip, int* peer_port);

/* Try multiple TTL values */
int ttl_punch_scan(const char* target_ip, int target_port, char* peer_ip, int* peer_port);

/* ============================================================================
 * TTL UTILITIES
 * ============================================================================ */

/* Check if TTL punch is supported */
bool ttl_punch_supported(void);

/* Get best TTL value for current network */
int ttl_get_best_ttl(void);

#endif /* TTL_PUNCH_H */
