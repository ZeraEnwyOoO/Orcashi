
#ifndef UPNP_CLIENT_H
#define UPNP_CLIENT_H

#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ============================================================================
 * UPNP CONFIGURATION
 * ============================================================================ */

#define UPNP_DISCOVERY_TIMEOUT 2
#define UPNP_PORT_MAPPING_TIMEOUT 30
#define UPNP_MAX_RETRY 3

/* ============================================================================
 * UPNP PORT MAPPING
 * ============================================================================ */

typedef struct {
    int internal_port;
    int external_port;
    char protocol[8];      /* "TCP" or "UDP" */
    char description[128];
    bool enabled;
    time_t created_at;
    time_t expires_at;
} UPnPPortMapping;

/* ============================================================================
 * UPNP CLIENT FUNCTIONS
 * ============================================================================ */

/* Detect UPnP IGD (Internet Gateway Device) */
bool upnp_detect(void);

/* Add port mapping via UPnP */
int upnp_add_port_mapping(int port);

/* Add port mapping with custom external port */
int upnp_add_port_mapping_with_ext(int internal_port, int external_port, const char* protocol);

/* Remove port mapping via UPnP */
int upnp_remove_port_mapping(int external_port, const char* protocol);

/* Get external IP from UPnP gateway */
int upnp_get_external_ip(char* ip_out, size_t size);

/* Get external port from UPnP gateway */
int upnp_get_external_port(int internal_port, const char* protocol);

/* ============================================================================
 * UPNP UTILITIES
 * ============================================================================ */

/* Check if UPnP is available */
bool upnp_available(void);

/* Get UPnP gateway info */
int upnp_get_gateway_info(char* model, char* manufacturer, char* serial);

/* Refresh port mapping (renew lease) */
int upnp_refresh_port_mapping(int external_port, const char* protocol);

/* List all port mappings */
int upnp_list_mappings(UPnPPortMapping* mappings, int max);

#endif /* UPNP_CLIENT_H */
