 #ifndef NAT_CLASSIFIER_H
#define NAT_CLASSIFIER_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef enum {
    NAT_UNKNOWN = 0,
    NAT_FULL_CONE,
    NAT_RESTRICTED_CONE,
    NAT_PORT_RESTRICTED,
    NAT_SYMMETRIC
} NATType;

typedef struct {
    NATType type;
    char external_ip[INET_ADDRSTRLEN];
    int external_port;
    bool detected;
    time_t detection_time;
    int confidence;
    char detected_via[64];
} NATClassifierResult;

/* DHT-based NAT detection (Tox style) */
NATType nat_classify_via_dht(void* dht_node, const char* my_id);

/* STUN-based NAT detection (fallback) */
NATType nat_classify_via_stun(void);

/* UPnP-based NAT detection */
NATType nat_classify_via_upnp(void);

/* IPv6 detection */
bool nat_has_ipv6(void);

/* UPnP availability */
bool nat_has_upnp(void);

/* Firewall detection */
bool nat_is_firewalled(void);

const char* nat_type_to_string(NATType type);

void nat_debug_print(NATClassifierResult* result);

#endif
