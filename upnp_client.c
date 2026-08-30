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
#include <ctype.h>

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

#define UPNP_MULTICAST_IP "239.255.255.250"
#define UPNP_MULTICAST_PORT 1900
#define UPNP_MAX_RESPONSE 8192
#define UPNP_SOAP_TIMEOUT 5

static UPnPGatewayInfo g_gateway = {0};
static bool g_upnp_detected = false;
static time_t g_detection_time = 0;
static char g_external_ip[INET_ADDRSTRLEN] = {0};
static int g_external_port = 0;

static int upnp_send_soap_request(const char* control_url, const char* service_type,
                                   const char* action, const char* body,
                                   char* response, size_t response_size);
static int parse_soap_response(const char* response, const char* tag, char* value, size_t value_size);
static int parse_gateway_location(const char* response, char* location, size_t size);
static int get_gateway_description(const char* location, UPnPGatewayInfo* info);
static int parse_port_mapping_response(const char* response, int* port_out);
static int generate_random_uuid(char* uuid, size_t size);

bool upnp_detect(void) {
    if (g_upnp_detected && (time(NULL) - g_detection_time) < 60) {
        return true;
    }
    
    ULOG("Detecting UPnP gateway...");
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        ULOG("Failed to create SSDP socket: %s", strerror(errno));
        return false;
    }
    
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
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
    
    struct timeval tv;
    tv.tv_sec = UPNP_DISCOVERY_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in multicast;
    memset(&multicast, 0, sizeof(multicast));
    multicast.sin_family = AF_INET;
    multicast.sin_port = htons(1900);
    inet_pton(AF_INET, UPNP_MULTICAST_IP, &multicast.sin_addr);
    
    const char* search = 
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 3\r\n"
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
        "\r\n";
    
    ssize_t sent = sendto(sock, search, strlen(search), 0,
                          (struct sockaddr*)&multicast, sizeof(multicast));
    
    if (sent < 0) {
        ULOG("Failed to send M-SEARCH: %s", strerror(errno));
        close(sock);
        return false;
    }
    
    char buffer[UPNP_MAX_RESPONSE];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    bool found = false;
    char location[512] = {0};
    
    for (int i = 0; i < 10; i++) {
        int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                         (struct sockaddr*)&from, &from_len);
        
        if (n <= 0) break;
        buffer[n] = '\0';
        
        if (strstr(buffer, "HTTP/1.1 200 OK") != NULL ||
            strstr(buffer, "HTTP/1.0 200 OK") != NULL) {
            
            if (strstr(buffer, "InternetGatewayDevice") != NULL ||
                strstr(buffer, "urn:schemas-upnp-org:device:InternetGatewayDevice:1") != NULL) {
                
                if (parse_gateway_location(buffer, location, sizeof(location)) == 0) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
                    ULOG("Found UPnP gateway at %s", ip);
                    found = true;
                    break;
                }
            }
        }
    }
    
    close(sock);
    
    if (found && strlen(location) > 0) {
        UPnPGatewayInfo info = {0};
        if (get_gateway_description(location, &info) == 0) {
            g_gateway = info;
            g_gateway.valid = true;
            g_gateway.discovered_at = time(NULL);
            
            struct sockaddr_in gw_addr;
            if (inet_pton(AF_INET, info.lan_ip, &gw_addr.sin_addr) == 1) {
                strcpy(g_external_ip, info.lan_ip);
            } else {
                strcpy(g_external_ip, "0.0.0.0");
            }
            
            g_upnp_detected = true;
            g_detection_time = time(NULL);
            ULOG("UPnP detection successful");
            ULOG("Gateway: %s %s", info.manufacturer, info.model);
            ULOG("Control URL: %s", info.control_url);
            return true;
        }
    }
    
    ULOG("UPnP detection failed");
    return false;
}

bool upnp_available(void) {
    if (g_upnp_detected && (time(NULL) - g_detection_time) < 60) {
        return true;
    }
    return upnp_detect();
}

int parse_gateway_location(const char* response, char* location, size_t size) {
    if (!response || !location || size == 0) return -1;
    
    const char* loc = strstr(response, "LOCATION:");
    if (!loc) {
        loc = strstr(response, "Location:");
        if (!loc) return -1;
    }
    
    loc += 9;
    while (*loc == ' ' || *loc == '\t') loc++;
    
    const char* end = strchr(loc, '\r');
    if (!end) end = strchr(loc, '\n');
    if (!end) return -1;
    
    size_t len = end - loc;
    if (len >= size) len = size - 1;
    strncpy(location, loc, len);
    location[len] = '\0';
    
    return 0;
}

int get_gateway_description(const char* location, UPnPGatewayInfo* info) {
    if (!location || !info) return -1;
    
    ULOG("Fetching gateway description from %s", location);
    
    char host[256] = {0};
    char path[512] = {0};
    int port = 80;
    
    if (strncmp(location, "http://", 7) == 0) {
        const char* start = location + 7;
        const char* slash = strchr(start, '/');
        const char* colon = strchr(start, ':');
        
        if (slash) {
            if (colon && colon < slash) {
                port = atoi(colon + 1);
                strncpy(host, start, colon - start);
                host[colon - start] = '\0';
            } else {
                strncpy(host, start, slash - start);
                host[slash - start] = '\0';
            }
            strcpy(path, slash);
        } else {
            if (colon) {
                port = atoi(colon + 1);
                strncpy(host, start, colon - start);
                host[colon - start] = '\0';
            } else {
                strcpy(host, start);
            }
            strcpy(path, "/");
        }
    } else {
        return -1;
    }
    
    if (strlen(host) == 0) return -1;
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        ULOG("Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    struct timeval tv;
    tv.tv_sec = UPNP_SOAP_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        ULOG("Failed to resolve host: %s", host);
        close(sock);
        return -1;
    }
    
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        ULOG("Failed to connect to %s:%d: %s", host, port, strerror(errno));
        freeaddrinfo(res);
        close(sock);
        return -1;
    }
    freeaddrinfo(res);
    
    char request[1024];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Connection: close\r\n"
             "\r\n",
             path, host, port);
    
    if (send(sock, request, strlen(request), 0) < 0) {
        ULOG("Failed to send request: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    char response[UPNP_MAX_RESPONSE];
    int total = 0;
    int n;
    
    while (total < (int)sizeof(response) - 1) {
        n = recv(sock, response + total, sizeof(response) - total - 1, 0);
        if (n <= 0) break;
        total += n;
    }
    close(sock);
    
    if (total == 0) {
        ULOG("Empty response from gateway");
        return -1;
    }
    response[total] = '\0';
    
    char* body = strstr(response, "\r\n\r\n");
    if (!body) {
        ULOG("Invalid HTTP response");
        return -1;
    }
    body += 4;
    
    char control_url[256] = {0};
    char service_type[128] = {0};
    char event_url[256] = {0};
    char scpd_url[256] = {0};
    char model[64] = {0};
    char manufacturer[64] = {0};
    char serial[64] = {0};
    
    parse_soap_response(body, "controlURL", control_url, sizeof(control_url));
    parse_soap_response(body, "serviceType", service_type, sizeof(service_type));
    parse_soap_response(body, "eventSubURL", event_url, sizeof(event_url));
    parse_soap_response(body, "SCPDURL", scpd_url, sizeof(scpd_url));
    parse_soap_response(body, "modelDescription", model, sizeof(model));
    parse_soap_response(body, "manufacturer", manufacturer, sizeof(manufacturer));
    parse_soap_response(body, "serialNumber", serial, sizeof(serial));
    
    if (strlen(control_url) == 0 || strlen(service_type) == 0) {
        ULOG("Failed to parse gateway description");
        return -1;
    }
    
    if (control_url[0] == '/') {
        snprintf(info->control_url, sizeof(info->control_url), "http://%s:%d%s", host, port, control_url);
    } else {
        strcpy(info->control_url, control_url);
    }
    
    strcpy(info->service_type, service_type);
    strcpy(info->event_url, event_url);
    strcpy(info->scpd_url, scpd_url);
    strcpy(info->model, model);
    strcpy(info->manufacturer, manufacturer);
    strcpy(info->serial, serial);
    strcpy(info->server, host);
    strcpy(info->lan_ip, host);
    info->valid = true;
    
    ULOG("Gateway description parsed successfully");
    ULOG("Control URL: %s", info->control_url);
    ULOG("Service Type: %s", info->service_type);
    
    return 0;
}

int parse_soap_response(const char* response, const char* tag, char* value, size_t value_size) {
    if (!response || !tag || !value || value_size == 0) return -1;
    
    char start_tag[128];
    char end_tag[128];
    snprintf(start_tag, sizeof(start_tag), "<%s>", tag);
    snprintf(end_tag, sizeof(end_tag), "</%s>", tag);
    
    const char* start = strstr(response, start_tag);
    if (!start) {
        start = strstr(response, tag);
        if (start) {
            const char* colon = strchr(start, ':');
            if (colon) {
                start = colon + 1;
                while (*start == ' ' || *start == '\t') start++;
                const char* end = strchr(start, '\n');
                if (end) {
                    size_t len = end - start;
                    if (len >= value_size) len = value_size - 1;
                    strncpy(value, start, len);
                    value[len] = '\0';
                    while (strlen(value) > 0 && value[strlen(value) - 1] <= ' ') {
                        value[strlen(value) - 1] = '\0';
                    }
                    return 0;
                }
            }
        }
        return -1;
    }
    
    start += strlen(start_tag);
    const char* end = strstr(start, end_tag);
    if (!end) return -1;
    
    size_t len = end - start;
    if (len >= value_size) len = value_size - 1;
    strncpy(value, start, len);
    value[len] = '\0';
    
    while (strlen(value) > 0 && value[strlen(value) - 1] <= ' ') {
        value[strlen(value) - 1] = '\0';
    }
    while (*value && (*value == ' ' || *value == '\t' || *value == '\n' || *value == '\r')) {
        memmove(value, value + 1, strlen(value));
    }
    
    return 0;
}

int upnp_send_soap_request(const char* control_url, const char* service_type,
                            const char* action, const char* body,
                            char* response, size_t response_size) {
    if (!control_url || !service_type || !action || !body || !response) {
        return -1;
    }
    
    if (!g_gateway.valid) {
        if (!upnp_detect()) {
            return -1;
        }
    }
    
    char host[256] = {0};
    char path[512] = {0};
    int port = 80;
    
    if (strncmp(control_url, "http://", 7) == 0) {
        const char* start = control_url + 7;
        const char* slash = strchr(start, '/');
        const char* colon = strchr(start, ':');
        
        if (slash) {
            if (colon && colon < slash) {
                port = atoi(colon + 1);
                strncpy(host, start, colon - start);
                host[colon - start] = '\0';
            } else {
                strncpy(host, start, slash - start);
                host[slash - start] = '\0';
            }
            strcpy(path, slash);
        } else {
            if (colon) {
                port = atoi(colon + 1);
                strncpy(host, start, colon - start);
                host[colon - start] = '\0';
            } else {
                strcpy(host, start);
            }
            strcpy(path, "/");
        }
    } else {
        return -1;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        ULOG("Failed to create SOAP socket: %s", strerror(errno));
        return -1;
    }
    
    struct timeval tv;
    tv.tv_sec = UPNP_SOAP_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        ULOG("Failed to resolve host: %s", host);
        close(sock);
        return -1;
    }
    
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        ULOG("Failed to connect to %s:%d: %s", host, port, strerror(errno));
        freeaddrinfo(res);
        close(sock);
        return -1;
    }
    freeaddrinfo(res);
    
    char soap_request[UPNP_MAX_RESPONSE];
    char uuid[64];
    generate_random_uuid(uuid, sizeof(uuid));
    
    snprintf(soap_request, sizeof(soap_request),
             "POST %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Content-Type: text/xml; charset=\"utf-8\"\r\n"
             "SOAPAction: \"%s#%s\"\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             path, host, port, service_type, action, strlen(body), body);
    
    if (send(sock, soap_request, strlen(soap_request), 0) < 0) {
        ULOG("Failed to send SOAP request: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    int total = 0;
    int n;
    
    while (total < (int)response_size - 1) {
        n = recv(sock, response + total, response_size - total - 1, 0);
        if (n <= 0) break;
        total += n;
    }
    close(sock);
    
    if (total == 0) {
        ULOG("Empty SOAP response");
        return -1;
    }
    response[total] = '\0';
    
    if (strstr(response, "HTTP/1.1 200 OK") == NULL &&
        strstr(response, "HTTP/1.0 200 OK") == NULL) {
        ULOG("SOAP request failed (non-200 response)");
        return -1;
    }
    
    return 0;
}

int generate_random_uuid(char* uuid, size_t size) {
    if (!uuid || size < 37) return -1;
    
    unsigned char bytes[16];
    orca_random_bytes(bytes, 16);
    
    snprintf(uuid, size,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5], bytes[6], bytes[7],
             bytes[8], bytes[9], bytes[10], bytes[11],
             bytes[12], bytes[13], bytes[14], bytes[15]);
    
    return 0;
}

int upnp_add_port_mapping_with_desc(int internal_port, int external_port,
                                     const char* protocol, const char* description) {
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    if (!g_gateway.valid) {
        ULOG("Gateway not valid");
        return -1;
    }
    
    ULOG("Adding UPnP port mapping: %s %d -> %d", protocol, internal_port, external_port);
    
    char soap_body[2048];
    char internal_port_str[16], external_port_str[16], lease_str[16];
    char desc[128];
    
    snprintf(internal_port_str, sizeof(internal_port_str), "%d", internal_port);
    snprintf(external_port_str, sizeof(external_port_str), "%d", external_port);
    snprintf(lease_str, sizeof(lease_str), "%d", UPNP_PORT_MAPPING_TIMEOUT);
    
    if (description && strlen(description) > 0) {
        strncpy(desc, description, sizeof(desc) - 1);
        desc[sizeof(desc) - 1] = '\0';
    } else {
        snprintf(desc, sizeof(desc), "Orcashi %s %d", protocol, internal_port);
    }
    
    snprintf(soap_body, sizeof(soap_body),
             "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
             "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
             "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
             "<s:Body>"
             "<u:AddPortMapping xmlns:u=\"%s\">"
             "<NewRemoteHost></NewRemoteHost>"
             "<NewExternalPort>%s</NewExternalPort>"
             "<NewProtocol>%s</NewProtocol>"
             "<NewInternalPort>%s</NewInternalPort>"
             "<NewInternalClient>%s</NewInternalClient>"
             "<NewEnabled>1</NewEnabled>"
             "<NewPortMappingDescription>%s</NewPortMappingDescription>"
             "<NewLeaseDuration>%s</NewLeaseDuration>"
             "</u:AddPortMapping>"
             "</s:Body>"
             "</s:Envelope>",
             g_gateway.service_type,
             external_port_str,
             protocol,
             internal_port_str,
             g_gateway.lan_ip,
             desc,
             lease_str);
    
    char response[UPNP_MAX_RESPONSE];
    if (upnp_send_soap_request(g_gateway.control_url, g_gateway.service_type,
                                "AddPortMapping", soap_body,
                                response, sizeof(response)) < 0) {
        ULOG("Failed to add port mapping");
        return -1;
    }
    
    if (strstr(response, "error") != NULL) {
        ULOG("Gateway returned error for port mapping");
        return -1;
    }
    
    ULOG("Port mapping added successfully: %s %d -> %d", protocol, internal_port, external_port);
    return external_port;
}

int upnp_add_port_mapping_with_ext(int internal_port, int external_port, const char* protocol) {
    char desc[128];
    snprintf(desc, sizeof(desc), "Orcashi %s %d", protocol, internal_port);
    return upnp_add_port_mapping_with_desc(internal_port, external_port, protocol, desc);
}

int upnp_add_port_mapping(int port) {
    return upnp_add_port_mapping_with_ext(port, port, "UDP");
}

int upnp_remove_port_mapping(int external_port, const char* protocol) {
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    if (!g_gateway.valid) {
        ULOG("Gateway not valid");
        return -1;
    }
    
    ULOG("Removing UPnP port mapping: %s %d", protocol, external_port);
    
    char soap_body[1024];
    char external_port_str[16];
    
    snprintf(external_port_str, sizeof(external_port_str), "%d", external_port);
    
    snprintf(soap_body, sizeof(soap_body),
             "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
             "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
             "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
             "<s:Body>"
             "<u:DeletePortMapping xmlns:u=\"%s\">"
             "<NewRemoteHost></NewRemoteHost>"
             "<NewExternalPort>%s</NewExternalPort>"
             "<NewProtocol>%s</NewProtocol>"
             "</u:DeletePortMapping>"
             "</s:Body>"
             "</s:Envelope>",
             g_gateway.service_type,
             external_port_str,
             protocol);
    
    char response[UPNP_MAX_RESPONSE];
    if (upnp_send_soap_request(g_gateway.control_url, g_gateway.service_type,
                                "DeletePortMapping", soap_body,
                                response, sizeof(response)) < 0) {
        ULOG("Failed to remove port mapping");
        return -1;
    }
    
    ULOG("Port mapping removed successfully: %s %d", protocol, external_port);
    return 0;
}

int upnp_get_external_ip(char* ip_out, size_t size) {
    if (!ip_out || size == 0) return -1;
    
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    if (!g_gateway.valid) {
        ULOG("Gateway not valid");
        return -1;
    }
    
    ULOG("Getting external IP from gateway");
    
    char soap_body[1024];
    snprintf(soap_body, sizeof(soap_body),
             "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
             "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
             "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
             "<s:Body>"
             "<u:GetExternalIPAddress xmlns:u=\"%s\">"
             "</u:GetExternalIPAddress>"
             "</s:Body>"
             "</s:Envelope>",
             g_gateway.service_type);
    
    char response[UPNP_MAX_RESPONSE];
    if (upnp_send_soap_request(g_gateway.control_url, g_gateway.service_type,
                                "GetExternalIPAddress", soap_body,
                                response, sizeof(response)) < 0) {
        ULOG("Failed to get external IP");
        return -1;
    }
    
    char ip[64] = {0};
    if (parse_soap_response(response, "NewExternalIPAddress", ip, sizeof(ip)) < 0) {
        ULOG("Failed to parse external IP");
        return -1;
    }
    
    strncpy(ip_out, ip, size - 1);
    ip_out[size - 1] = '\0';
    strcpy(g_external_ip, ip_out);
    
    ULOG("External IP: %s", ip_out);
    return 0;
}

int upnp_get_external_port(int internal_port, const char* protocol) {
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    if (!g_gateway.valid) {
        ULOG("Gateway not valid");
        return -1;
    }
    
    ULOG("Getting external port for %s %d", protocol, internal_port);
    
    char soap_body[2048];
    char internal_port_str[16];
    
    snprintf(internal_port_str, sizeof(internal_port_str), "%d", internal_port);
    
    snprintf(soap_body, sizeof(soap_body),
             "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
             "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
             "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
             "<s:Body>"
             "<u:GetSpecificPortMappingEntry xmlns:u=\"%s\">"
             "<NewRemoteHost></NewRemoteHost>"
             "<NewExternalPort>0</NewExternalPort>"
             "<NewProtocol>%s</NewProtocol>"
             "</u:GetSpecificPortMappingEntry>"
             "</s:Body>"
             "</s:Envelope>",
             g_gateway.service_type,
             protocol);
    
    char response[UPNP_MAX_RESPONSE];
    if (upnp_send_soap_request(g_gateway.control_url, g_gateway.service_type,
                                "GetSpecificPortMappingEntry", soap_body,
                                response, sizeof(response)) < 0) {
        ULOG("Failed to get external port");
        return -1;
    }
    
    char port_str[16] = {0};
    if (parse_soap_response(response, "NewExternalPort", port_str, sizeof(port_str)) < 0) {
        ULOG("Failed to parse external port");
        return -1;
    }
    
    int port = atoi(port_str);
    if (port > 0) {
        ULOG("External port: %d", port);
        g_external_port = port;
        return port;
    }
    
    return -1;
}

int upnp_get_gateway_info(UPnPGatewayInfo* info) {
    if (!info) return -1;
    
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    if (!g_gateway.valid) {
        ULOG("Gateway not valid");
        return -1;
    }
    
    memcpy(info, &g_gateway, sizeof(UPnPGatewayInfo));
    return 0;
}

int upnp_refresh_port_mapping(int external_port, const char* protocol) {
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return -1;
    }
    
    ULOG("Refreshing port mapping: %s %d", protocol, external_port);
    
    int internal_port = external_port;
    return upnp_add_port_mapping_with_ext(internal_port, external_port, protocol);
}

int upnp_list_mappings(UPnPPortMapping* mappings, int max) {
    if (!mappings || max <= 0) {
        ULOG("Invalid parameters for list_mappings");
        return 0;
    }
    
    if (!upnp_available()) {
        ULOG("UPnP not available");
        return 0;
    }
    
    if (!g_gateway.valid) {
        ULOG("Gateway not valid");
        return 0;
    }
    
    ULOG("Listing port mappings");
    
    int count = 0;
    
    for (int i = 0; i < max && count < max; i++) {
        char soap_body[2048];
        char index_str[16];
        
        snprintf(index_str, sizeof(index_str), "%d", i);
        
        snprintf(soap_body, sizeof(soap_body),
                 "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                 "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                 "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
                 "<s:Body>"
                 "<u:GetGenericPortMappingEntry xmlns:u=\"%s\">"
                 "<NewPortMappingIndex>%s</NewPortMappingIndex>"
                 "</u:GetGenericPortMappingEntry>"
                 "</s:Body>"
                 "</s:Envelope>",
                 g_gateway.service_type,
                 index_str);
        
        char response[UPNP_MAX_RESPONSE];
        if (upnp_send_soap_request(g_gateway.control_url, g_gateway.service_type,
                                    "GetGenericPortMappingEntry", soap_body,
                                    response, sizeof(response)) < 0) {
            break;
        }
        
        if (strstr(response, "error") != NULL) {
            break;
        }
        
        UPnPPortMapping mapping = {0};
        char port_str[16] = {0};
        char protocol_str[16] = {0};
        char desc[128] = {0};
        char internal_ip[64] = {0};
        char enabled_str[16] = {0};
        char duration_str[32] = {0};
        
        if (parse_soap_response(response, "NewExternalPort", port_str, sizeof(port_str)) < 0) {
            break;
        }
        mapping.external_port = atoi(port_str);
        
        if (parse_soap_response(response, "NewProtocol", protocol_str, sizeof(protocol_str)) < 0) {
            break;
        }
        strcpy(mapping.protocol, protocol_str);
        
        if (parse_soap_response(response, "NewInternalPort", port_str, sizeof(port_str)) == 0) {
            mapping.internal_port = atoi(port_str);
        }
        
        parse_soap_response(response, "NewPortMappingDescription", desc, sizeof(desc));
        strcpy(mapping.description, desc);
        
        parse_soap_response(response, "NewInternalClient", internal_ip, sizeof(internal_ip));
        strcpy(mapping.internal_ip, internal_ip);
        
        if (parse_soap_response(response, "NewEnabled", enabled_str, sizeof(enabled_str)) == 0) {
            mapping.enabled = (strcmp(enabled_str, "1") == 0);
        }
        
        if (parse_soap_response(response, "NewLeaseDuration", duration_str, sizeof(duration_str)) == 0) {
            int duration = atoi(duration_str);
            mapping.expires_at = time(NULL) + duration;
        }
        
        mapping.created_at = time(NULL);
        
        mappings[count++] = mapping;
    }
    
    ULOG("Found %d port mappings", count);
    return count;
}

int upnp_get_external_port_from_mapping(int internal_port, const char* protocol) {
    UPnPPortMapping mappings[UPNP_MAX_MAPPINGS];
    int count = upnp_list_mappings(mappings, UPNP_MAX_MAPPINGS);
    
    for (int i = 0; i < count; i++) {
        if (mappings[i].internal_port == internal_port &&
            strcmp(mappings[i].protocol, protocol) == 0) {
            return mappings[i].external_port;
        }
    }
    
    return -1;
}
