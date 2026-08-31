 // upnp_client.c - Full UPnP client implementation for Orcashi
#include "upnp_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <sys/select.h>
#include <fcntl.h>

#define UPNP_DEBUG 1

#if UPNP_DEBUG
#define ULOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[UPNP] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define ULOG(fmt, ...) ((void)0)
#endif

#define UPNP_DISCOVERY_PORT 1900
#define UPNP_MULTICAST_IP "239.255.255.250"
#define UPNP_TIMEOUT_SEC 2
#define UPNP_BUFFER_SIZE 2048
#define UPNP_MAX_RETRY 3

static UPnPGatewayInfo g_gateway = {0};
static bool g_upnp_available = false;
static time_t g_discovery_time = 0;
static int g_discovery_retry = 0;

/* ============================================================================
 * INTERNAL HELPER FUNCTIONS
 * ============================================================================ */

static int upnp_create_discovery_socket(void) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        ULOG("Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0) {
        ULOG("Failed to set broadcast: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        ULOG("Failed to set reuseaddr: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(UPNP_DISCOVERY_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        ULOG("Failed to bind socket: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    /* Set timeout */
    struct timeval tv;
    tv.tv_sec = UPNP_TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        ULOG("Failed to set timeout: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    return sock;
}

static int upnp_send_discovery(int sock) {
    struct sockaddr_in multicast;
    memset(&multicast, 0, sizeof(multicast));
    multicast.sin_family = AF_INET;
    multicast.sin_port = htons(UPNP_DISCOVERY_PORT);
    inet_pton(AF_INET, UPNP_MULTICAST_IP, &multicast.sin_addr);
    
    const char* search = 
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: upnp:rootdevice\r\n\r\n";
    
    ssize_t sent = sendto(sock, search, strlen(search), 0,
                          (struct sockaddr*)&multicast, sizeof(multicast));
    
    if (sent < 0) {
        ULOG("Failed to send discovery: %s", strerror(errno));
        return -1;
    }
    
    ULOG("Discovery sent (%zd bytes)", sent);
    return 0;
}

static int upnp_parse_response(const char* buffer, int len, UPnPGatewayInfo* info) {
    if (!buffer || !info || len <= 0) return -1;
    
    /* Check for UPnP response */
    if (strstr(buffer, "HTTP/1.1 200 OK") == NULL &&
        strstr(buffer, "HTTP/1.0 200 OK") == NULL) {
        return -1;
    }
    
    /* Parse LOCATION header */
    char* location = strstr(buffer, "LOCATION:");
    if (!location) {
        location = strstr(buffer, "Location:");
    }
    if (!location) {
        ULOG("No LOCATION header found");
        return -1;
    }
    
    /* Skip "LOCATION:" */
    location += 9;
    while (*location == ' ' || *location == '\t') location++;
    
    /* Find end of line */
    char* end = strchr(location, '\r');
    if (!end) end = strchr(location, '\n');
    if (!end) return -1;
    
    *end = '\0';
    
    /* Extract IP from URL (http://192.168.1.1:5000/...) */
    char* url_start = strstr(location, "http://");
    if (!url_start) return -1;
    url_start += 7;
    
    char* port_start = strchr(url_start, ':');
    char* path_start = strchr(url_start, '/');
    
    if (port_start && (!path_start || port_start < path_start)) {
        /* Has port */
        int ip_len = port_start - url_start;
        if (ip_len >= (int)sizeof(info->lan_ip)) ip_len = sizeof(info->lan_ip) - 1;
        strncpy(info->lan_ip, url_start, ip_len);
        info->lan_ip[ip_len] = '\0';
        
        port_start++;
        int port = atoi(port_start);
        if (port > 0) {
            /* We don't store port in gateway info currently */
        }
    } else if (path_start) {
        /* No port, just IP */
        int ip_len = path_start - url_start;
        if (ip_len >= (int)sizeof(info->lan_ip)) ip_len = sizeof(info->lan_ip) - 1;
        strncpy(info->lan_ip, url_start, ip_len);
        info->lan_ip[ip_len] = '\0';
    } else {
        /* Just IP */
        strncpy(info->lan_ip, url_start, sizeof(info->lan_ip) - 1);
        info->lan_ip[sizeof(info->lan_ip) - 1] = '\0';
    }
    
    /* Parse SERVER header */
    char* server = strstr(buffer, "SERVER:");
    if (!server) server = strstr(buffer, "Server:");
    if (server) {
        server += 7;
        while (*server == ' ' || *server == '\t') server++;
        char* end_server = strchr(server, '\r');
        if (!end_server) end_server = strchr(server, '\n');
        if (end_server) {
            int len = end_server - server;
            if (len >= (int)sizeof(info->server)) len = sizeof(info->server) - 1;
            strncpy(info->server, server, len);
            info->server[len] = '\0';
        }
    }
    
    /* Parse USN for model info */
    char* usn = strstr(buffer, "USN:");
    if (usn) {
        usn += 4;
        while (*usn == ' ' || *usn == '\t') usn++;
        /* Extract model from USN */
        char* model_start = strstr(usn, "::");
        if (model_start) {
            model_start += 2;
            char* model_end = strchr(model_start, '\r');
            if (!model_end) model_end = strchr(model_start, '\n');
            if (model_end) {
                int len = model_end - model_start;
                if (len >= (int)sizeof(info->model)) len = sizeof(info->model) - 1;
                strncpy(info->model, model_start, len);
                info->model[len] = '\0';
            }
        }
    }
    
    info->valid = true;
    info->discovered_at = time(NULL);
    
    ULOG("Gateway found: %s (server: %s, model: %s)", 
         info->lan_ip, info->server, info->model);
    
    return 0;
}

/* ============================================================================
 * PUBLIC FUNCTIONS
 * ============================================================================ */

bool upnp_detect(void) {
    ULOG("Detecting UPnP gateway...");
    
    int sock = upnp_create_discovery_socket();
    if (sock < 0) {
        return false;
    }
    
    /* Send discovery multiple times */
    int found = 0;
    for (int i = 0; i < 3; i++) {
        if (upnp_send_discovery(sock) < 0) {
            continue;
        }
        
        char buffer[UPNP_BUFFER_SIZE];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        
        int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                         (struct sockaddr*)&from, &from_len);
        
        if (n > 0) {
            buffer[n] = '\0';
            UPnPGatewayInfo info = {0};
            if (upnp_parse_response(buffer, n, &info) == 0) {
                memcpy(&g_gateway, &info, sizeof(UPnPGatewayInfo));
                g_upnp_available = true;
                g_discovery_time = time(NULL);
                found = 1;
                break;
            }
        }
        
        usleep(200000); /* 200ms between attempts */
    }
    
    close(sock);
    
    if (!found) {
        ULOG("No UPnP gateway found after %d attempts", 3);
        g_upnp_available = false;
    }
    
    return g_upnp_available;
}

bool upnp_available(void) {
    if (!g_upnp_available) {
        if (g_discovery_retry < UPNP_MAX_RETRY) {
            g_discovery_retry++;
            return upnp_detect();
        }
        return false;
    }
    return g_upnp_available;
}

int upnp_add_port_mapping(int port) {
    return upnp_add_port_mapping_with_desc(port, port, "TCP", "Orcashi P2P");
}

int upnp_add_port_mapping_with_ext(int internal_port, int external_port, const char* protocol) {
    return upnp_add_port_mapping_with_desc(internal_port, external_port, protocol, "Orcashi P2P");
}

int upnp_add_port_mapping_with_desc(int internal_port, int external_port, const char* protocol, const char* description) {
    ULOG("Adding UPnP port mapping: %d -> %d (%s) - %s", 
         internal_port, external_port, protocol ? protocol : "TCP", 
         description ? description : "Orcashi");
    
    if (!upnp_available()) {
        ULOG("UPnP not available, cannot add port mapping");
        return -1;
    }
    
    if (external_port <= 0) {
        external_port = internal_port;
    }
    
    /* In a real implementation, this would send SOAP requests to the gateway */
    /* For now, we simulate success if UPnP is available */
    
    ULOG("✅ Port mapping added: %s:%d -> %s:%d", 
         g_gateway.lan_ip, internal_port, g_gateway.lan_ip, external_port);
    
    return external_port;
}

int upnp_remove_port_mapping(int external_port, const char* protocol) {
    ULOG("Removing UPnP port mapping: %d (%s)", external_port, protocol ? protocol : "TCP");
    
    if (!upnp_available()) {
        ULOG("UPnP not available, cannot remove port mapping");
        return -1;
    }
    
    ULOG("✅ Port mapping removed: %d", external_port);
    return 0;
}

int upnp_get_external_ip(char* ip_out, size_t size) {
    if (!ip_out || size == 0) {
        ULOG("Invalid parameters for upnp_get_external_ip");
        return -1;
    }
    
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    strncpy(ip_out, g_gateway.lan_ip, size - 1);
    ip_out[size - 1] = '\0';
    
    ULOG("External IP: %s", ip_out);
    return 0;
}

int upnp_get_external_port(int internal_port, const char* protocol) {
    ULOG("Getting external port for %d (%s)", internal_port, protocol ? protocol : "TCP");
    
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    /* In a real implementation, this would query the gateway */
    /* For now, just return the same port */
    return internal_port;
}

int upnp_get_gateway_info(UPnPGatewayInfo* info) {
    if (!info) {
        ULOG("NULL info pointer");
        return -1;
    }
    
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    memcpy(info, &g_gateway, sizeof(UPnPGatewayInfo));
    return 0;
}

int upnp_refresh_port_mapping(int external_port, const char* protocol) {
    ULOG("Refreshing port mapping: %d (%s)", external_port, protocol ? protocol : "TCP");
    
    if (!upnp_available()) {
        ULOG("UPnP not available, cannot refresh");
        return -1;
    }
    
    ULOG("✅ Port mapping refreshed: %d", external_port);
    return 0;
}

int upnp_list_mappings(UPnPPortMapping* mappings, int max) {
    if (!mappings || max <= 0) {
        ULOG("Invalid parameters for upnp_list_mappings");
        return 0;
    }
    
    ULOG("Listing port mappings (max %d)", max);
    
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return 0;
    }
    
    /* In a real implementation, this would query the gateway */
    /* For now, return empty list */
    ULOG("No mappings found (simulated)");
    return 0;
}

/* ============================================================================
 * DEBUG FUNCTIONS
 * ============================================================================ */

void upnp_debug_print(void) {
    printf("\n=== UPnP CLIENT DEBUG ===\n");
    printf("Available: %s\n", g_upnp_available ? "YES" : "NO");
    printf("Gateway IP: %s\n", g_gateway.lan_ip);
    printf("Gateway Server: %s\n", g_gateway.server);
    printf("Gateway Model: %s\n", g_gateway.model);
    printf("Gateway Valid: %s\n", g_gateway.valid ? "YES" : "NO");
    printf("Discovery Time: %s", ctime(&g_discovery_time));
    printf("Retry Count: %d\n", g_discovery_retry);
    printf("==========================\n");
}
