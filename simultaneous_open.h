
#ifndef SIMULTANEOUS_OPEN_H
#define SIMULTANEOUS_OPEN_H

#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

/* ============================================================================
 * SIMULTANEOUS OPEN CONFIGURATION
 * ============================================================================ */

#define SIM_OPEN_RETRY 5
#define SIM_OPEN_TIMEOUT 2
#define SIM_OPEN_BACKOFF 100  /* ms */

/* ============================================================================
 * SIMULTANEOUS OPEN FUNCTIONS
 * ============================================================================ */

/* Punch using simultaneous open technique */
int simultaneous_open_punch(void* punch_state, const char* target_ip, int target_port);

/* Synchronized punch with timestamp */
int simultaneous_open_sync(const char* target_ip, int target_port, 
                           time_t sync_time, char* peer_ip, int* peer_port);

/* ============================================================================
 * SIMULTANEOUS OPEN UTILITIES
 * ============================================================================ */

/* Check if simultaneous open is supported */
bool simultaneous_open_supported(void);

/* Get synchronization timestamp */
time_t simultaneous_get_sync_time(void);

#endif /* SIMULTANEOUS_OPEN_H */
