#ifndef NAT_CLASSIFIER_H
#define NAT_CLASSIFIER_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ============================================================================
 * NAT TYPES
 * ============================================================================ */

typedef enum {
    NAT_UNKNOWN = 0,
    NAT_FULL_CONE,
    NAT_RESTRICTED_CONE,
    NAT_PORT_RESTRICTED,
    NAT_SYMMETRIC
} NATType;

/* ============================================================================
 * NAT CLASSIFIER STATE
 * ============================================================================ */

typedef struct {
    NATType type;
    char external_ip[INET_ADDRSTRLEN];
    int external_port;
    bool detected;
    time_t detection_time;
    int confidence;          /* 0-100 */
    char detected_via[64];   /* "dht", "stun", "manual" */
} NATClassifierResult;

/* ============================================================================
 * NAT CLASSIFIER FUNCTIONS
 * ============================================================================ */

/* Detect NAT type using DHT (Tox-style) */
NATType nat_classify_via_dht(void* dht_node);

/* Detect NAT type using STUN (fallback) */
NATType nat_classify_via_stun(void);

/* Detect NAT type using UPnP */
NATType nat_classify_via_upnp(void);

/* ============================================================================
 * NAT DETECTION HELPERS
 * ============================================================================ */

/* Check if IPv6 is available */
bool nat_has_ipv6(void);

/* Check if UPnP is available */
bool nat_has_upnp(void);

/* Check if we're behind a firewall */
bool nat_is_firewalled(void);

/* ============================================================================
 * NAT TYPE STRINGS
 * ============================================================================ */

const char* nat_type_to_string(NATType type);

/* ============================================================================
 * DEBUG
 * ============================================================================ */

void nat_debug_print(NATClassifierResult* result);

#endif /* NAT_CLASSIFIER_H */
