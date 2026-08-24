#ifndef MIXED_ID_H
#define MIXED_ID_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ============================================================================
 * MIXED ID STRUCTURE
 * ============================================================================ */

/*
 * Mixed ID Format: <id>.<pair1>.<pair2>.<port>
 * 
 * Example: 255.49320.258.9000
 * 
 * Decode:
 *   id = 255
 *   pair1 = 49320 → (192 << 8) | 168 → 192.168
 *   pair2 = 258   → (1 << 8) | 2   → 1.2
 *   port = 9000
 * 
 * Result: ID=255, IP=192.168.1.2, Port=9000
 */

#define MIXED_ID_MAX_LEN 64
#define MIXED_ID_MAX_ID_LEN 16
#define MIXED_ID_MAX_IP_LEN INET_ADDRSTRLEN

/* ============================================================================
 * MIXED ID FUNCTIONS
 * ============================================================================ */

/* Encode ID + IP + Port → Mixed ID string */
int mixed_id_encode(const char* id, const char* ip, int port, char* out, size_t out_size);

/* Decode Mixed ID string → ID + IP + Port */
int mixed_id_decode(const char* mixed, char* id_out, char* ip_out, int* port_out);

/* ============================================================================
 * MIXED ID VALIDATION
 * ============================================================================ */

/* Check if string is a valid Mixed ID */
bool mixed_id_is_valid(const char* mixed);

/* Check if string is a normal ID (without dots) */
bool mixed_id_is_id(const char* input);

/* Check if string is an IP address */
bool mixed_id_is_ip(const char* input);

/* ============================================================================
 * MIXED ID UTILITIES
 * ============================================================================ */

/* Extract ID from Mixed ID */
int mixed_id_extract_id(const char* mixed, char* id_out, size_t size);

/* Extract IP from Mixed ID */
int mixed_id_extract_ip(const char* mixed, char* ip_out, size_t size);

/* Extract Port from Mixed ID */
int mixed_id_extract_port(const char* mixed, int* port_out);

/* ============================================================================
 * MIXED ID AUTO-DETECT
 * ============================================================================ */

/* Detect if input is Mixed ID, ID, or IP */
typedef enum {
    MIXED_TYPE_UNKNOWN = 0,
    MIXED_TYPE_ID,          /* "255" */
    MIXED_TYPE_IP,          /* "192.168.1.2" */
    MIXED_TYPE_MIXED,       /* "255.49320.258.9000" */
    MIXED_TYPE_MIXED_IP,    /* "49320.258.9000" (without ID) */
} MixedType;

MixedType mixed_id_detect_type(const char* input);

/* Auto-detect and parse */
int mixed_id_auto_parse(const char* input, char* id_out, char* ip_out, int* port_out);

/* ============================================================================
 * MIXED ID DISPLAY
 * ============================================================================ */

/* Generate human-readable description */
int mixed_id_describe(const char* mixed, char* desc, size_t size);

#endif /* MIXED_ID_H */
