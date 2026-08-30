#include "nat_classifier.h"
#include "dht_node.h"
#include "dht.h"
#include "p2p_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define NAT_DEBUG 1

#if NAT_DEBUG
#define NLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[NAT] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define NLOG(fmt, ...) ((void)0)
#endif

/* ============================================================================
 * NAT TYPE STRINGS
 * ============================================================================ */

const char* nat_type_to_string(NATType type) {
    switch (type) {
        case NAT_FULL_CONE: return "FULL_CONE";
        case NAT_RESTRICTED_CONE: return "RESTRICTED_CONE";
        case NAT_PORT_RESTRICTED: return "PORT_RESTRICTED";
        case NAT_SYMMETRIC: return "SYMMETRIC";
        case NAT_UNKNOWN: 
        default: return "UNKNOWN";
    }
}

/* ============================================================================
 * DHT-BASED NAT DETECTION (Tox-style)
 * ============================================================================ */

/* Structure for DHT NAT detection probe */
typedef struct {
    uint32_t magic;          /* 0x4F524341 ("ORCA") */
    uint8_t type;            /* 1 = REQUEST, 2 = RESPONSE */
    uint32_t probe_id;
    uint32_t timestamp;
    uint8_t sender_id[32];
} DHTNATProbe;

/* Callback for DHT NAT detection */
static void nat_dht_callback(void* closure, int event,
                             const unsigned char* info_hash,
                             const void* data, size_t data_len) {
    (void)closure;
    (void)info_hash;
    (void)data;
    (void)data_len;
    
    if (event == DHT_EVENT_VALUES || event == DHT_EVENT_VALUES6) {
        NLOG("Received DHT response for NAT detection");
    }
}

NATType nat_classify_via_dht(void* dht_node) {
    NLOG("Detecting NAT type via DHT (Tox-style)...");
    
    DHTNode* node = (DHTNode*)dht_node;
    if (!node) {
        NLOG("DHT node not available, using fallback");
        return nat_classify_via_stun();
    }
    
    /* 1. Generate random probe ID */
    uint32_t probe_id = (uint32_t)(time(NULL) ^ getpid());
    NLOG("Probe ID: %u", probe_id);
    
    /* 2. Find closest peers to our ID */
    unsigned char target_id[20];
    // Use our DHT ID as target
    dht_hash(target_id, 20, "nat_detection", 13, NULL, 0, NULL, 0);
    
    /* 3. Send NAT probe requests to multiple DHT peers */
    int responses_received = 0;
    int port_changes = 0;
    int ip_changes = 0;
    int ports[10] = {0};
    char ips[10][INET_ADDRSTRLEN] = {0};
    
    NLOG("Sending NAT probe to DHT peers...");
    
    /* We need to get our external IP/port from DHT peers */
    /* In Tox, this is done by sending a special DHT request */
    
    /* For now, use a simpler approach: */
    /* Try to detect NAT type based on DHT behavior */
    
    /* Check if we can see our own DHT announces */
    /* If we can see our own announces with same port → Full Cone */
    /* If same IP but different ports → Restricted Cone */
    /* If different IP/port per peer → Symmetric */
    
    /* Simulate detection based on known patterns */
    /* This will be replaced with actual DHT probe */
    
    /* For testing: simulate NAT type based on environment */
    /* In real implementation, this would use actual DHT probes */
    
    /* Check if we're in a known NAT environment */
    const char* nat_env = getenv("ORCASHI_NAT_TYPE");
    if (nat_env) {
        if (strcmp(nat_env, "full") == 0) return NAT_FULL_CONE;
        if (strcmp(nat_env, "restricted") == 0) return NAT_RESTRICTED_CONE;
        if (strcmp(nat_env, "port") == 0) return NAT_PORT_RESTRICTED;
        if (strcmp(nat_env, "symmetric") == 0) return NAT_SYMMETRIC;
    }
    
    /* Default: try to detect from socket behavior */
    int test_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (test_sock < 0) {
        NLOG("Failed to create test socket");
        return NAT_UNKNOWN;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);  /* Let OS choose port */
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(test_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        NLOG("Failed to bind test socket");
        close(test_sock);
        return NAT_UNKNOWN;
    }
    
    /* Get bound port */
    socklen_t len = sizeof(addr);
    getsockname(test_sock, (struct sockaddr*)&addr, &len);
    int local_port = ntohs(addr.sin_port);
    NLOG("Local test port: %d", local_port);
    
    /* Try to get external IP from a simple method */
    /* For now, try to connect to Google DNS and get our IP */
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &target.sin_addr);
    
    if (connect(test_sock, (struct sockaddr*)&target, sizeof(target)) == 0) {
        struct sockaddr_in name;
        socklen_t name_len = sizeof(name);
        getsockname(test_sock, (struct sockaddr*)&name, &name_len);
        char ext_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &name.sin_addr, ext_ip, sizeof(ext_ip));
        int ext_port = ntohs(name.sin_port);
        NLOG("External address: %s:%d", ext_ip, ext_port);
        
        /* Check if we got a different port */
        if (ext_port != local_port) {
            NLOG("Port changed from %d to %d - likely Symmetric NAT", local_port, ext_port);
            close(test_sock);
            return NAT_SYMMETRIC;
        }
        
        close(test_sock);
        
        /* If port same, likely Full Cone or Restricted */
        /* Need more tests to differentiate */
        /* For now, return Full Cone as best guess */
        NLOG("Port same - likely Full Cone or Restricted Cone");
        return NAT_FULL_CONE;
    }
    
    close(test_sock);
    NLOG("Could not detect NAT type, returning UNKNOWN");
    return NAT_UNKNOWN;
}

/* ============================================================================
 * STUN-BASED NAT DETECTION (Fallback)
 * ============================================================================ */

NATType nat_classify_via_stun(void) {
    NLOG("Detecting NAT type via STUN (fallback)...");
    
    /* Simple STUN-like detection */
    /* In production, this would use actual STUN protocol */
    
    /* Try multiple STUN servers */
    const char* stun_servers[] = {
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun.ekiga.net",
        NULL
    };
    
    for (int i = 0; stun_servers[i] != NULL; i++) {
        NLOG("Trying STUN server: %s", stun_servers[i]);
        /* TODO: Implement actual STUN protocol */
        /* For now, return a conservative guess */
    }
    
    NLOG("STUN detection not implemented, returning UNKNOWN");
    return NAT_UNKNOWN;
}

/* ============================================================================
 * UPnP-BASED NAT DETECTION
 * ============================================================================ */

NATType nat_classify_via_upnp(void) {
    NLOG("Detecting NAT type via UPnP...");
    
    /* Try to discover UPnP gateway */
    /* This is a simple check - actual UPnP would be more complex */
    
    /* Check if UPnP is available */
    if (nat_has_upnp()) {
        NLOG("UPnP available - NAT type likely Full Cone or Restricted");
        return NAT_FULL_CONE;  /* Best guess */
    }
    
    NLOG("UPnP not available");
    return NAT_UNKNOWN;
}

/* ============================================================================
 * NAT DETECTION HELPERS
 * ============================================================================ */

bool nat_has_ipv6(void) {
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(53);
    inet_pton(AF_INET6, "2001:4860:4860::8888", &addr.sin6_addr);
    
    bool has = (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    close(sock);
    
    NLOG("IPv6: %s", has ? "YES" : "NO");
    return has;
}

bool nat_has_upnp(void) {
    /* Simple UPnP detection */
    /* In production, this would use miniupnpc */
    
    /* Try to connect to UPnP service port */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1900);  /* UPnP SSDP port */
    addr.sin_addr.s_addr = inet_addr("239.255.255.250");
    
    /* Set timeout */
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    /* Send M-SEARCH request */
    const char* search = 
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: upnp:rootdevice\r\n\r\n";
    
    ssize_t sent = sendto(sock, search, strlen(search), 0,
                          (struct sockaddr*)&addr, sizeof(addr));
    
    bool has_upnp = false;
    if (sent > 0) {
        char buffer[1024];
        int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, NULL, NULL);
        if (n > 0) {
            buffer[n] = '\0';
            if (strstr(buffer, "HTTP/1.1 200 OK") != NULL) {
                has_upnp = true;
            }
        }
    }
    
    close(sock);
    NLOG("UPnP: %s", has_upnp ? "YES" : "NO");
    return has_upnp;
}

bool nat_is_firewalled(void) {
    /* Check if we're behind a firewall */
    /* Try to connect to common ports */
    int blocked = 0;
    int total = 0;
    
    int ports[] = {80, 443, 53, 123, 22};
    for (int i = 0; i < 5; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ports[i]);
        inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);
        
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            blocked++;
        }
        total++;
        close(sock);
    }
    
    bool firewalled = (blocked > total / 2);
    NLOG("Firewalled: %s (%d/%d blocked)", firewalled ? "YES" : "NO", blocked, total);
    return firewalled;
}

/* ============================================================================
 * DEBUG
 * ============================================================================ */

void nat_debug_print(NATClassifierResult* result) {
    if (!result) return;
    
    printf("\n=== NAT CLASSIFIER DEBUG ===\n");
    printf("Type: %s (%d)\n", nat_type_to_string(result->type), result->type);
    printf("External IP: %s\n", result->external_ip);
    printf("External Port: %d\n", result->external_port);
    printf("Detected: %s\n", result->detected ? "YES" : "NO");
    printf("Confidence: %d%%\n", result->confidence);
    printf("Detected via: %s\n", result->detected_via);
    printf("Detection time: %s", ctime(&result->detection_time));
    printf("============================\n");
}

/* ============================================================================
 * TEST FUNCTION
 * ============================================================================ */

#ifdef NAT_TEST

int main() {
    printf("=== NAT Classifier Test ===\n");
    
    /* Test DHT-based detection */
    NATType type = nat_classify_via_dht(NULL);
    printf("DHT detection result: %s\n", nat_type_to_string(type));
    
    /* Test IPv6 */
    bool has_ipv6 = nat_has_ipv6();
    printf("IPv6: %s\n", has_ipv6 ? "YES" : "NO");
    
    /* Test UPnP */
    bool has_upnp = nat_has_upnp();
    printf("UPnP: %s\n", has_upnp ? "YES" : "NO");
    
    /* Test firewall */
    bool firewalled = nat_is_firewalled();
    printf("Firewalled: %s\n", firewalled ? "YES" : "NO");
    
    /* Test result */
    NATClassifierResult result = {
        .type = type,
        .detected = (type != NAT_UNKNOWN),
        .confidence = 80,
        .detection_time = time(NULL)
    };
    strcpy(result.external_ip, "192.168.1.100");
    result.external_port = 9000;
    strcpy(result.detected_via, "dht");
    
    nat_debug_print(&result);
    
    return 0;
}

#endif /* NAT_TEST */
