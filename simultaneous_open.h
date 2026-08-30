 #ifndef STRATEGY_SELECTOR_H
#define STRATEGY_SELECTOR_H

#include <stdbool.h>
#include "nat_classifier.h"

typedef enum {
    STRATEGY_NONE = 0,
    STRATEGY_IPV6_DIRECT,
    STRATEGY_UPNP,
    STRATEGY_UDP_PUNCH,
    STRATEGY_TTL_PUNCH,
    STRATEGY_SIMULTANEOUS_OPEN,
    STRATEGY_PORT_PREDICTION,
    STRATEGY_TCP_PUNCH,
    STRATEGY_FRIEND_RELAY,
    STRATEGY_TURN_RELAY,
    STRATEGY_MANUAL_PORT
} StrategyType;

typedef struct {
    StrategyType type;
    const char* name;
    int priority;
    int max_wait_ms;
    bool requires_peer;
    bool requires_server;
} StrategyInfo;

typedef struct {
    NATType nat_type;
    bool has_ipv6;
    bool has_upnp;
    bool has_relay;
    bool is_relay;
    bool is_firewalled;
    char ip[INET_ADDRSTRLEN];
    int port;
    char ipv6[INET6_ADDRSTRLEN];
    int ipv6_port;
} PeerProfile;

#define MAX_STRATEGIES 16

typedef struct {
    StrategyType strategies[MAX_STRATEGIES];
    int count;
} StrategyList;

int strategy_filter(StrategyList* list, const PeerProfile* local, const PeerProfile* remote);
const char* strategy_name(StrategyType type);
StrategyInfo strategy_get_info(StrategyType type);
bool strategy_is_applicable(StrategyType type, const PeerProfile* local, const PeerProfile* remote);
int strategy_get_priority(StrategyType type);
void strategy_sort_by_priority(StrategyList* list);
void strategy_debug_print(const StrategyList* list);
const char* strategy_type_to_string(StrategyType type);

#endif
