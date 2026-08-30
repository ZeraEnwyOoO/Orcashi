 #ifndef UPNP_CLIENT_H
#define UPNP_CLIENT_H

#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define UPNP_DISCOVERY_TIMEOUT 3
#define UPNP_PORT_MAPPING_TIMEOUT 3600
#define UPNP_MAX_RETRY 3
#define UPNP_MAX_MAPPINGS 32

typedef struct {
    int internal_port;
    int external_port;
    char protocol[8];
    char description[128];
    bool enabled;
    time_t created_at;
    time_t expires_at;
    char internal_ip[INET_ADDRSTRLEN];
} UPnPPortMapping;

typedef struct {
    char control_url[256];
    char service_type[128];
    char event_url[256];
    char scpd_url[256];
    char server[128];
    char model[64];
    char manufacturer[64];
    char serial[64];
    char lan_ip[INET_ADDRSTRLEN];
    bool valid;
    time_t discovered_at;
} UPnPGatewayInfo;

bool upnp_detect(void);
bool upnp_available(void);

int upnp_add_port_mapping(int port);
int upnp_add_port_mapping_with_ext(int internal_port, int external_port, const char* protocol);
int upnp_add_port_mapping_with_desc(int internal_port, int external_port, const char* protocol, const char* description);
int upnp_remove_port_mapping(int external_port, const char* protocol);

int upnp_get_external_ip(char* ip_out, size_t size);
int upnp_get_external_port(int internal_port, const char* protocol);
int upnp_get_gateway_info(UPnPGatewayInfo* info);
int upnp_refresh_port_mapping(int external_port, const char* protocol);
int upnp_list_mappings(UPnPPortMapping* mappings, int max);

#endif
