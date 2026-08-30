
#include "upnp_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

/* Simple UPnP client using SSDP discovery */
/* Note: For production, use miniupnpc library */

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

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================ */

static bool g_upnp_detected = false;
static char g_gateway_ip[INET_ADDRSTRLEN] = {0};
static char g_external_ip[INET_ADDRSTRLEN] = {0};
static time_t g_detection_time = 0;

/* ============================================================================
 * UPNP DETECTION (SSDP)
 * ============================================================================ */

bool upnp_detect(void) {
    if (g_upnp_detected && (time(NULL) - g_detection_time) < 60) {
        return true;
    }
    
    ULOG("Detecting UPnP gateway...");
    
    /* Create SSDP socket */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        ULOG("Failed to create SSDP socket: %s", strerror(errno));
        return false;
    }
    
    /* Set broadcast and reuse */
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    /* Bind to SSDP port */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1900);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        ULOG("Failed to bind SSDP socket: %s", strerror(errno));
        close(sock);
        return false;
    }
    
    /* Set timeout */
    struct timeval tv;
    tv.tv_sec = UPNP_DISCOVERY_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    /* Send M-SEARCH request to multicast group */
    struct sockaddr_in multicast;
    memset(&multicast, 0, sizeof(multicast));
    multicast.sin_family = AF_INET;
    multicast.sin_port = htons(1900);
    inet_pton(AF_INET, "239.255.255.250", &multicast.sin_addr);
    
    const char* search = 
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: upnp:rootdevice\r\n\r\n";
    
    ssize_t sent = sendto(sock, search, strlen(search), 0,
                          (struct sockaddr*)&multicast, sizeof(multicast));
    
    if (sent < 0) {
        ULOG("Failed to send M-SEARCH: %s", strerror(errno));
        close(sock);
        return false;
    }
    
    /* Wait for responses */
    char buffer[2048];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    bool found = false;
    
    for (int i = 0; i < 10; i++) {
        int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                         (struct sockaddr*)&from, &from_len);
        
        if (n <= 0) break;
        buffer[n] = '\0';
        
        /* Check if it's a root device response */
        if (strstr(buffer, "HTTP/1.1 200 OK") != NULL) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
            ULOG("Found UPnP gateway at %s", ip);
            strcpy(g_gateway_ip, ip);
            found = true;
            break;
        }
    }
    
    close(sock);
    
    if (found) {
        g_upnp_detected = true;
        g_detection_time = time(NULL);
        ULOG("✅ UPnP detection successful");
        return true;
    }
    
    ULOG("❌ No UPnP gateway found");
    return false;
}

/* ============================================================================
 * UPNP PORT MAPPING
 * ============================================================================ */

int upnp_add_port_mapping(int port) {
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    ULOG("Adding UPnP port mapping for port %d", port);
    return upnp_add_port_mapping_with_ext(port, port, "UDP");
}

int upnp_add_port_mapping_with_ext(int internal_port, int external_port, const char* protocol) {
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    ULOG("Adding UPnP port mapping: %s %d -> %d", protocol, internal_port, external_port);
    
    /* In production, use miniupnpc to actually do this */
    /* For now, simulate success */
    
    /* TODO: Implement actual UPnP port mapping */
    /* This would use SOAP requests to the gateway */
    
    /* Simulate success for testing */
    ULOG("✅ Port mapping added (simulated)");
    return external_port;
}

int upnp_remove_port_mapping(int external_port, const char* protocol) {
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    ULOG("Removing UPnP port mapping: %s %d", protocol, external_port);
    
    /* TODO: Implement actual UPnP port removal */
    ULOG("✅ Port mapping removed (simulated)");
    return 0;
}

/* ============================================================================
 * UPNP UTILITIES
 * ============================================================================ */

bool upnp_available(void) {
    /* Check if UPnP is available */
    if (g_upnp_detected && (time(NULL) - g_detection_time) < 60) {
        return true;
    }
    
    /* Try to detect */
    return upnp_detect();
}

int upnp_get_external_ip(char* ip_out, size_t size) {
    if (!ip_out || size == 0) return -1;
    
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    /* TODO: Get external IP from gateway */
    /* In production, this would use a SOAP request */
    strcpy(ip_out, "0.0.0.0");
    return 0;
}

int upnp_get_external_port(int internal_port, const char* protocol) {
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    /* TODO: Get external port from gateway */
    /* In production, this would use a SOAP request */
    return internal_port;
}

int upnp_get_gateway_info(char* model, char* manufacturer, char* serial) {
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    /* TODO: Get gateway info from gateway */
    if (model) strcpy(model, "Unknown");
    if (manufacturer) strcpy(manufacturer, "Unknown");
    if (serial) strcpy(serial, "Unknown");
    
    return 0;
}

int upnp_refresh_port_mapping(int external_port, const char* protocol) {
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    ULOG("Refreshing port mapping: %s %d", protocol, external_port);
    
    /* TODO: Refresh lease */
    return 0;
}

int upnp_list_mappings(UPnPPortMapping* mappings, int max) {
    if (!mappings || max <= 0) return 0;
    
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return 0;
    }
    
    /* TODO: List port mappings from gateway */
    return 0;
}

/* ============================================================================
 * TEST FUNCTION
 * ============================================================================ */

#ifdef UPNP_TEST

int main() {
    printf("=== UPnP Client Test ===\n");
    
    /* Detect UPnP */
    bool available = upnp_detect();
    printf("UPnP available: %s\n", available ? "YES" : "NO");
    
    if (available) {
        printf("Gateway IP: %s\n", g_gateway_ip);
        
        /* Add port mapping */
        int ext_port = upnp_add_port_mapping(9000);
        printf("Port mapping: %d\n", ext_port);
        
        /* Get external IP */
        char ip[INET_ADDRSTRLEN];
        upnp_get_external_ip(ip, sizeof(ip));
        printf("External IP: %s\n", ip);
        
        /* Remove port mapping */
        upnp_remove_port_mapping(9000, "UDP");
    }
    
    return 0;
}

#endif /* UPNP_TEST */
