#include "mixed_id.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#define MIXED_DEBUG 1

#if MIXED_DEBUG
#define MLOG(fmt, ...) \
    do { \
        fprintf(stderr, "[MIXED] " fmt "\n", ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define MLOG(fmt, ...) ((void)0)
#endif

/* ============================================================================
 * ENCODE / DECODE
 * ============================================================================ */

int mixed_id_encode(const char* id, const char* ip, int port, char* out, size_t out_size) {
    if (!id || !ip || !out || out_size == 0) return -1;
    
    /* Validate IP */
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        MLOG("Invalid IP: %s", ip);
        return -1;
    }
    
    /* Parse IP octets */
    int octets[4];
    if (sscanf(ip, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]) != 4) {
        MLOG("Failed to parse IP: %s", ip);
        return -1;
    }
    
    /* Parse ID (strip brackets if present) */
    char clean_id[64];
    size_t id_len = strlen(id);
    size_t j = 0;
    for (size_t i = 0; i < id_len && j < sizeof(clean_id) - 1; i++) {
        if (id[i] != '<' && id[i] != '>') {
            clean_id[j++] = id[i];
        }
    }
    clean_id[j] = '\0';
    
    int id_num = atoi(clean_id);
    if (id_num <= 0 || id_num > 999) {
        MLOG("Invalid ID: %s", id);
        return -1;
    }
    
    /* Encode */
    uint16_t pair1 = (octets[0] << 8) | octets[1];
    uint16_t pair2 = (octets[2] << 8) | octets[3];
    
    snprintf(out, out_size, "%d.%d.%d.%d", id_num, pair1, pair2, port);
    
    MLOG("Encoded: %s → %s", id, out);
    return 0;
}

int mixed_id_decode(const char* mixed, char* id_out, char* ip_out, int* port_out) {
    if (!mixed || !id_out || !ip_out || !port_out) return -1;
    
    int id_num, pair1, pair2, port;
    
    if (sscanf(mixed, "%d.%d.%d.%d", &id_num, &pair1, &pair2, &port) != 4) {
        MLOG("Failed to parse Mixed ID: %s", mixed);
        return -1;
    }
    
    /* Validate */
    if (id_num <= 0 || id_num > 999) {
        MLOG("Invalid ID in Mixed ID: %d", id_num);
        return -1;
    }
    
    if (port <= 0 || port > 65535) {
        MLOG("Invalid port in Mixed ID: %d", port);
        return -1;
    }
    
    /* Decode ID */
    snprintf(id_out, 16, "%d", id_num);
    
    /* Decode IP */
    int octet1 = pair1 >> 8;
    int octet2 = pair1 & 0xFF;
    int octet3 = pair2 >> 8;
    int octet4 = pair2 & 0xFF;
    
    snprintf(ip_out, INET_ADDRSTRLEN, "%d.%d.%d.%d", octet1, octet2, octet3, octet4);
    
    *port_out = port;
    
    MLOG("Decoded: %s → ID=%s, IP=%s, Port=%d", mixed, id_out, ip_out, port);
    return 0;
}

/* ============================================================================
 * VALIDATION
 * ============================================================================ */

bool mixed_id_is_valid(const char* mixed) {
    if (!mixed) return false;
    
    char id[64], ip[INET_ADDRSTRLEN];
    int port;
    
    if (mixed_id_decode(mixed, id, ip, &port) < 0) {
        return false;
    }
    
    /* Verify ID is 1-999 */
    int id_num = atoi(id);
    if (id_num <= 0 || id_num > 999) return false;
    
    /* Verify port is valid */
    if (port <= 0 || port > 65535) return false;
    
    /* Verify IP is valid */
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        return false;
    }
    
    return true;
}

bool mixed_id_is_id(const char* input) {
    if (!input) return false;
    
    /* Check if all digits */
    for (size_t i = 0; i < strlen(input); i++) {
        if (!isdigit(input[i])) return false;
    }
    
    int num = atoi(input);
    return num > 0 && num <= 999;
}

bool mixed_id_is_ip(const char* input) {
    if (!input) return false;
    
    struct sockaddr_in sa;
    return inet_pton(AF_INET, input, &sa.sin_addr) == 1;
}

/* ============================================================================
 * AUTO-DETECT
 * ============================================================================ */

MixedType mixed_id_detect_type(const char* input) {
    if (!input) return MIXED_TYPE_UNKNOWN;
    
    /* Check if it's a Mixed ID (4 parts with dots) */
    int dots = 0;
    for (size_t i = 0; i < strlen(input); i++) {
        if (input[i] == '.') dots++;
    }
    
    if (dots == 3) {
        /* Could be IP or Mixed ID */
        if (mixed_id_is_valid(input)) {
            return MIXED_TYPE_MIXED;
        }
        
        /* Check if it's an IP */
        if (mixed_id_is_ip(input)) {
            return MIXED_TYPE_IP;
        }
    }
    
    /* Check if it's an ID */
    if (mixed_id_is_id(input)) {
        return MIXED_TYPE_ID;
    }
    
    /* Check if it's an IP */
    if (mixed_id_is_ip(input)) {
        return MIXED_TYPE_IP;
    }
    
    return MIXED_TYPE_UNKNOWN;
}

int mixed_id_auto_parse(const char* input, char* id_out, char* ip_out, int* port_out) {
    if (!input || !id_out || !ip_out || !port_out) return -1;
    
    MixedType type = mixed_id_detect_type(input);
    
    switch (type) {
        case MIXED_TYPE_MIXED:
            return mixed_id_decode(input, id_out, ip_out, port_out);
            
        case MIXED_TYPE_ID:
            strcpy(id_out, input);
            strcpy(ip_out, "0.0.0.0");
            *port_out = 0;
            return 0;
            
        case MIXED_TYPE_IP:
            strcpy(id_out, "");
            strcpy(ip_out, input);
            *port_out = 9000;
            return 0;
            
        default:
            MLOG("Unknown input type: %s", input);
            return -1;
    }
}

/* ============================================================================
 * EXTRACT
 * ============================================================================ */

int mixed_id_extract_id(const char* mixed, char* id_out, size_t size) {
    if (!mixed || !id_out || size == 0) return -1;
    
    int id_num, pair1, pair2, port;
    if (sscanf(mixed, "%d.%d.%d.%d", &id_num, &pair1, &pair2, &port) != 4) {
        return -1;
    }
    
    snprintf(id_out, size, "%d", id_num);
    return 0;
}

int mixed_id_extract_ip(const char* mixed, char* ip_out, size_t size) {
    if (!mixed || !ip_out || size == 0) return -1;
    
    int id_num, pair1, pair2, port;
    if (sscanf(mixed, "%d.%d.%d.%d", &id_num, &pair1, &pair2, &port) != 4) {
        return -1;
    }
    
    int octet1 = pair1 >> 8;
    int octet2 = pair1 & 0xFF;
    int octet3 = pair2 >> 8;
    int octet4 = pair2 & 0xFF;
    
    snprintf(ip_out, size, "%d.%d.%d.%d", octet1, octet2, octet3, octet4);
    return 0;
}

int mixed_id_extract_port(const char* mixed, int* port_out) {
    if (!mixed || !port_out) return -1;
    
    int id_num, pair1, pair2, port;
    if (sscanf(mixed, "%d.%d.%d.%d", &id_num, &pair1, &pair2, &port) != 4) {
        return -1;
    }
    
    *port_out = port;
    return 0;
}

/* ============================================================================
 * DISPLAY
 * ============================================================================ */

int mixed_id_describe(const char* mixed, char* desc, size_t size) {
    if (!mixed || !desc || size == 0) return -1;
    
    char id[64], ip[INET_ADDRSTRLEN];
    int port;
    
    if (mixed_id_decode(mixed, id, ip, &port) < 0) {
        snprintf(desc, size, "Invalid Mixed ID: %s", mixed);
        return -1;
    }
    
    snprintf(desc, size, "ID: %s, IP: %s, Port: %d", id, ip, port);
    return 0;
}

/* ============================================================================
 * TEST
 * ============================================================================ */

#ifdef MIXED_ID_TEST

void mixed_id_test(void) {
    printf("\n=== MIXED ID TEST ===\n");
    
    /* Test encode */
    char mixed[64];
    mixed_id_encode("255", "192.168.1.2", 9000, mixed, sizeof(mixed));
    printf("Encode: 255 + 192.168.1.2:9000 → %s\n", mixed);
    
    /* Test decode */
    char id[64], ip[INET_ADDRSTRLEN];
    int port;
    mixed_id_decode(mixed, id, ip, &port);
    printf("Decode: %s → ID=%s, IP=%s, Port=%d\n", mixed, id, ip, port);
    
    /* Test validation */
    printf("Is valid? %s\n", mixed_id_is_valid(mixed) ? "YES" : "NO");
    printf("Is ID? %s\n", mixed_id_is_id("255") ? "YES" : "NO");
    printf("Is IP? %s\n", mixed_id_is_ip("192.168.1.2") ? "YES" : "NO");
    
    /* Test auto-detect */
    const char* tests[] = {"255", "192.168.1.2", "255.49320.258.9000", NULL};
    for (int i = 0; tests[i]; i++) {
        MixedType type = mixed_id_detect_type(tests[i]);
        printf("Auto-detect: %s → type=%d\n", tests[i], type);
    }
    
    printf("========================\n");
}

#endif /* MIXED_ID_TEST */
