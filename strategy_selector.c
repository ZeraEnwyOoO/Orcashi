
#include "strategy_selector.h"
#include <stdio.h>
#include <string.h>

#define STRATEGY_DEBUG 1

#if STRATEGY_DEBUG
#define SLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[STRATEGY] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define SLOG(fmt, ...) ((void)0)
#endif

/* ============================================================================
 * STRATEGY INFO TABLE
 * ============================================================================ */

static StrategyInfo g_strategy_info[] = {
    {STRATEGY_NONE, "NONE", 99, 0, false, false},
    {STRATEGY_IPV6_DIRECT, "IPv6_DIRECT", 1, 2000, false, false},
    {STRATEGY_UPNP, "UPnP", 2, 3000, false, false},
    {STRATEGY_UDP_PUNCH, "UDP_PUNCH", 3, 5000, false, false},
    {STRATEGY_TTL_PUNCH, "TTL_PUNCH", 4, 3000, false, false},
    {STRATEGY_SIMULTANEOUS_OPEN, "SIMULTANEOUS_OPEN", 5, 4000, false, false},
    {STRATEGY_PORT_PREDICTION, "PORT_PREDICTION", 6, 5000, false, false},
    {STRATEGY_TCP_PUNCH, "TCP_PUNCH", 7, 8000, false, false},
    {STRATEGY_FRIEND_RELAY, "FRIEND_RELAY", 8, 5000, true, false},
    {STRATEGY_TURN_RELAY, "TURN_RELAY", 9, 6000, false, true},
    {STRATEGY_MANUAL_PORT, "MANUAL_PORT", 10, 60000, false, false}
};

#define STRATEGY_COUNT (sizeof(g_strategy_info) / sizeof(StrategyInfo))

/* ============================================================================
 * STRATEGY NAME
 * ============================================================================ */

const char* strategy_name(StrategyType type) {
    for (int i = 0; i < STRATEGY_COUNT; i++) {
        if (g_strategy_info[i].type == type) {
            return g_strategy_info[i].name;
        }
    }
    return "UNKNOWN";
}

const char* strategy_type_to_string(StrategyType type) {
    return strategy_name(type);
}

/* ============================================================================
 * STRATEGY INFO
 * ============================================================================ */

StrategyInfo strategy_get_info(StrategyType type) {
    for (int i = 0; i < STRATEGY_COUNT; i++) {
        if (g_strategy_info[i].type == type) {
            return g_strategy_info[i];
        }
    }
    return g_strategy_info[0]; /* NONE */
}

int strategy_get_priority(StrategyType type) {
    return strategy_get_info(type).priority;
}

/* ============================================================================
 * STRATEGY APPLICABILITY
 * ============================================================================ */

bool strategy_is_applicable(StrategyType type, const PeerProfile* local, const PeerProfile* remote) {
    if (!local || !remote) return false;
    
    switch (type) {
        case STRATEGY_IPV6_DIRECT:
            /* Both peers must have IPv6 */
            return local->has_ipv6 && remote->has_ipv6;
            
        case STRATEGY_UPNP:
            /* Local must have UPnP and peer must be reachable */
            return local->has_upnp && remote->has_upnp;
            
        case STRATEGY_UDP_PUNCH:
            /* UDP punch works for most NAT types except symmetric+symmetric */
            if (local->nat_type == NAT_SYMMETRIC && remote->nat_type == NAT_SYMMETRIC) {
                return false;
            }
            return true;
            
        case STRATEGY_TTL_PUNCH:
            /* TTL works for most NAT types */
            return true;
            
        case STRATEGY_SIMULTANEOUS_OPEN:
            /* Works for restricted NAT types */
            return (local->nat_type == NAT_RESTRICTED_CONE || 
                    local->nat_type == NAT_PORT_RESTRICTED ||
                    remote->nat_type == NAT_RESTRICTED_CONE ||
                    remote->nat_type == NAT_PORT_RESTRICTED);
            
        case STRATEGY_PORT_PREDICTION:
            /* Only useful for symmetric NAT */
            return (local->nat_type == NAT_SYMMETRIC || remote->nat_type == NAT_SYMMETRIC);
            
        case STRATEGY_TCP_PUNCH:
            /* Works for most NAT types except symmetric */
            if (local->nat_type == NAT_SYMMETRIC || remote->nat_type == NAT_SYMMETRIC) {
                return false;
            }
            return true;
            
        case STRATEGY_FRIEND_RELAY:
            /* Need at least one relay peer available */
            return (local->has_relay || remote->has_relay);
            
        case STRATEGY_TURN_RELAY:
            /* Always available if TURN server configured */
            return true;
            
        case STRATEGY_MANUAL_PORT:
            /* Always available as last resort */
            return true;
            
        default:
            return false;
    }
}

/* ============================================================================
 * STRATEGY FILTER
 * ============================================================================ */

int strategy_filter(StrategyList* list, const PeerProfile* local, const PeerProfile* remote) {
    if (!list || !local || !remote) return -1;
    
    SLOG("Filtering strategies for local NAT: %s, remote NAT: %s",
         nat_type_to_string(local->nat_type), nat_type_to_string(remote->nat_type));
    
    list->count = 0;
    
    /* Try all strategies in priority order */
    for (int priority = 1; priority <= 10; priority++) {
        for (int i = 1; i < STRATEGY_COUNT; i++) {
            StrategyType type = g_strategy_info[i].type;
            if (g_strategy_info[i].priority == priority) {
                if (strategy_is_applicable(type, local, remote)) {
                    list->strategies[list->count++] = type;
                    SLOG("  Added: %s (priority %d)", strategy_name(type), priority);
                } else {
                    SLOG("  Skipped: %s (not applicable)", strategy_name(type));
                }
            }
        }
    }
    
    SLOG("Selected %d strategies", list->count);
    return list->count;
}

/* ============================================================================
 * STRATEGY SORT
 * ============================================================================ */

void strategy_sort_by_priority(StrategyList* list) {
    if (!list || list->count <= 1) return;
    
    /* Simple bubble sort by priority */
    for (int i = 0; i < list->count - 1; i++) {
        for (int j = 0; j < list->count - i - 1; j++) {
            int p1 = strategy_get_priority(list->strategies[j]);
            int p2 = strategy_get_priority(list->strategies[j + 1]);
            if (p1 > p2) {
                StrategyType temp = list->strategies[j];
                list->strategies[j] = list->strategies[j + 1];
                list->strategies[j + 1] = temp;
            }
        }
    }
}

/* ============================================================================
 * DEBUG
 * ============================================================================ */

void strategy_debug_print(const StrategyList* list) {
    if (!list) {
        printf("StrategyList is NULL\n");
        return;
    }
    
    printf("\n=== STRATEGY LIST ===\n");
    printf("Count: %d\n", list->count);
    for (int i = 0; i < list->count; i++) {
        StrategyInfo info = strategy_get_info(list->strategies[i]);
        printf("  [%d] %s (priority %d, max_wait %dms)\n",
               i, info.name, info.priority, info.max_wait_ms);
    }
    printf("=====================\n");
}

/* ============================================================================
 * TEST FUNCTION
 * ============================================================================ */

#ifdef STRATEGY_TEST

int main() {
    printf("=== Strategy Selector Test ===\n");
    
    /* Local profile: Full Cone NAT, no IPv6, no UPnP */
    PeerProfile local = {
        .nat_type = NAT_FULL_CONE,
        .has_ipv6 = false,
        .has_upnp = false,
        .has_relay = false,
        .is_firewalled = false
    };
    
    /* Remote profile: Symmetric NAT, no IPv6, no UPnP */
    PeerProfile remote = {
        .nat_type = NAT_SYMMETRIC,
        .has_ipv6 = false,
        .has_upnp = false,
        .has_relay = false,
        .is_firewalled = false
    };
    
    printf("\nLocal: %s, Remote: %s\n", 
           nat_type_to_string(local.nat_type), 
           nat_type_to_string(remote.nat_type));
    
    StrategyList list;
    strategy_filter(&list, &local, &remote);
    strategy_debug_print(&list);
    
    /* Test with IPv6 */
    printf("\n--- With IPv6 ---\n");
    local.has_ipv6 = true;
    remote.has_ipv6 = true;
    strategy_filter(&list, &local, &remote);
    strategy_debug_print(&list);
    
    /* Test with UPnP */
    printf("\n--- With UPnP ---\n");
    local.has_upnp = true;
    remote.has_upnp = true;
    strategy_filter(&list, &local, &remote);
    strategy_debug_print(&list);
    
    /* Test with Relay */
    printf("\n--- With Relay ---\n");
    local.has_relay = true;
    strategy_filter(&list, &local, &remote);
    strategy_debug_print(&list);
    
    return 0;
}

#endif /* STRATEGY_TEST */
