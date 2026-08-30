#ifndef STRATEGY_SELECTOR_H
#define STRATEGY_SELECTOR_H

#include <stdbool.h>
#include "nat_classifier.h"

/* ============================================================================
 * STRATEGY TYPES
 * ============================================================================ */

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

/* ============================================================================
 * STRATEGY INFO
 * ============================================================================ */

typedef struct {
    StrategyType type;
    const char* name;
    int priority;           /* 1-10, lower = higher priority */
    int max_wait_ms;        /* Maximum time to wait for this strategy */
    bool requires_peer;     /* Does this need peer cooperation? */
    bool requires_server;   /* Does this need external server? */
} StrategyInfo;

/* ============================================================================
 * PEER PROFILE
 * ============================================================================ */

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

/* ============================================================================
 * STRATEGY LIST
 * ============================================================================ */

#define MAX_STRATEGIES 16

typedef struct {
    StrategyType strategies[MAX_STRATEGIES];
    int count;
} StrategyList;

/* ============================================================================
 * STRATEGY SELECTOR FUNCTIONS
 * ============================================================================ */

/* Filter strategies based on local and remote profiles */
int strategy_filter(StrategyList* list, const PeerProfile* local, const PeerProfile* remote);

/* Get strategy name */
const char* strategy_name(StrategyType type);

/* Get strategy info */
StrategyInfo strategy_get_info(StrategyType type);

/* Check if strategy is applicable */
bool strategy_is_applicable(StrategyType type, const PeerProfile* local, const PeerProfile* remote);

/* ============================================================================
 * STRATEGY PRIORITY
 * ============================================================================ */

/* Get strategy priority (1-10) */
int strategy_get_priority(StrategyType type);

/* Sort strategies by priority */
void strategy_sort_by_priority(StrategyList* list);

/* ============================================================================
 * DEBUG
 * ============================================================================ */

void strategy_debug_print(const StrategyList* list);
const char* strategy_type_to_string(StrategyType type);

#endif /* STRATEGY_SELECTOR_H */
