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
    bool has_ipv6;
    bool has_upnp;
    bool is_firewalled;
    char local_ip[INET_ADDRSTRLEN];
    int local_port;
} NATClassifierResult;

NATType nat_classify_via_dht(void* dht_node, const char* my_id);
NATType nat_classify_via_stun(void);
NATType nat_classify_via_upnp(void);
NATType nat_classify_via_icmp(void);
NATType nat_classify_combined(NATClassifierResult* result);

bool nat_has_ipv6(void);
bool nat_has_upnp(void);
bool nat_is_firewalled(void);
bool nat_can_punch(void);
bool nat_is_symmetric(NATType type);

const char* nat_type_to_string(NATType type);
int nat_type_priority(NATType type);
void nat_debug_print(NATClassifierResult* result);

#endif
