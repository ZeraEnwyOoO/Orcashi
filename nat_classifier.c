 #include "nat_classifier.h"
#include "dht_node.h"
#include "dht.h"
#include "upnp_client.h"
#include "orca_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <ifaddrs.h>

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

#define PROBE_PORT_START 33445
#define PROBE_PORT_END 33455
#define PROBE_TIMEOUT_MS 2000
#define MAX_PROBE_PEERS 16
#define ICMP_TIMEOUT_MS 1000

typedef struct {
    uint32_t magic;
    uint8_t type;
    uint32_t probe_id;
    uint32_t timestamp;
    uint8_t sender_id[32];
    uint16_t src_port;
} __attribute__((packed)) DHTNATProbe;

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int port;
    int external_port;
    time_t response_time;
    bool received;
} ProbeResponse;

static NATClassifierResult g_cached_result = {0};
static bool g_result_cached = false;
static time_t g_cache_time = 0;

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

int nat_type_priority(NATType type) {
    switch (type) {
        case NAT_FULL_CONE: return 1;
        case NAT_RESTRICTED_CONE: return 2;
        case NAT_PORT_RESTRICTED: return 3;
        case NAT_SYMMETRIC: return 4;
        case NAT_UNKNOWN: 
        default: return 5;
    }
}

bool nat_is_symmetric(NATType type) {
    return type == NAT_SYMMETRIC;
}

static int create_probe_socket(int* port_out) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        NLOG("Failed to create probe socket: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;

    for (int port = PROBE_PORT_START; port <= PROBE_PORT_END; port++) {
        addr.sin_port = htons(port);
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            if (port_out) *port_out = port;
            NLOG("Probe socket bound to port %d", port);
            return sock;
        }
    }

    close(sock);
    NLOG("Failed to bind probe socket on any port");
    return -1;
}

static int send_probe_to_peer(int sock, const char* peer_ip, int peer_port, 
                               uint32_t probe_id, const char* my_id) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(peer_port);
    inet_pton(AF_INET, peer_ip, &target.sin_addr);

    DHTNATProbe probe;
    memset(&probe, 0, sizeof(probe));
    probe.magic = 0x4F524341;
    probe.type = 1;
    probe.probe_id = probe_id;
    probe.timestamp = (uint32_t)time(NULL);
    probe.src_port = htons(0);
    
    if (my_id) {
        memcpy(probe.sender_id, my_id, 32);
    }

    ssize_t sent = sendto(sock, &probe, sizeof(probe), 0,
                          (struct sockaddr*)&target, sizeof(target));
    
    if (sent < 0) {
        NLOG("Failed to send probe to %s:%d: %s", peer_ip, peer_port, strerror(errno));
        return -1;
    }

    NLOG("Sent probe %u to %s:%d", probe_id, peer_ip, peer_port);
    return 0;
}

static int receive_probe_response(int sock, ProbeResponse* resp, int timeout_ms) {
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    DHTNATProbe response;
    
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int n = recvfrom(sock, &response, sizeof(response), 0,
                     (struct sockaddr*)&from, &from_len);

    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            NLOG("recvfrom error: %s", strerror(errno));
        }
        return -1;
    }

    if (n < (int)sizeof(DHTNATProbe)) {
        NLOG("Received truncated response");
        return -1;
    }

    if (response.magic != 0x4F524341) {
        NLOG("Invalid magic in response");
        return -1;
    }

    if (response.type != 2) {
        NLOG("Unexpected response type: %d", response.type);
        return -1;
    }

    inet_ntop(AF_INET, &from.sin_addr, resp->ip, sizeof(resp->ip));
    resp->port = ntohs(from.sin_port);
    resp->response_time = time(NULL);
    resp->received = true;

    NLOG("Received probe response from %s:%d", resp->ip, resp->port);
    return 0;
}

NATType nat_classify_via_dht(void* dht_node, const char* my_id) {
    DHTNode* node = (DHTNode*)dht_node;
    NLOG("Starting DHT-based NAT classification");
    
    if (!node) {
        NLOG("DHT node is NULL, using fallback");
        return nat_classify_via_icmp();
    }

    int probe_sock = create_probe_socket(NULL);
    if (probe_sock < 0) {
        NLOG("Failed to create probe socket, using fallback");
        return nat_classify_via_icmp();
    }

    uint32_t probe_id = (uint32_t)(time(NULL) ^ getpid() ^ (rand() & 0xFFFF));
    ProbeResponse responses[MAX_PROBE_PEERS];
    memset(responses, 0, sizeof(responses));
    int resp_count = 0;

    struct sockaddr_in peers[MAX_PROBE_PEERS];
    int peer_count = 0;

    struct sockaddr_in sin[MAX_PROBE_PEERS];
    struct sockaddr_in6 sin6[MAX_PROBE_PEERS];
    int num_ipv4 = MAX_PROBE_PEERS;
    int num_ipv6 = 0;
    
    if (dht_get_nodes(sin, &num_ipv4, sin6, &num_ipv6) < 0) {
        NLOG("Failed to get DHT nodes");
        close(probe_sock);
        return nat_classify_via_icmp();
    }

    for (int i = 0; i < num_ipv4 && i < MAX_PROBE_PEERS; i++) {
        peers[peer_count++] = sin[i];
    }

    if (peer_count < 3) {
        NLOG("Not enough DHT peers (%d), using fallback", peer_count);
        close(probe_sock);
        return nat_classify_via_icmp();
    }

    NLOG("Found %d DHT peers for probing", peer_count);

    for (int i = 0; i < peer_count && i < 6; i++) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peers[i].sin_addr, ip, sizeof(ip));
        int port = ntohs(peers[i].sin_port);
        
        send_probe_to_peer(probe_sock, ip, port, probe_id + i, my_id);
        usleep(100000);
    }

    for (int i = 0; i < 12 && resp_count < 6; i++) {
        ProbeResponse resp;
        memset(&resp, 0, sizeof(resp));
        
        if (receive_probe_response(probe_sock, &resp, PROBE_TIMEOUT_MS / 6) == 0) {
            responses[resp_count++] = resp;
        }
    }

    close(probe_sock);

    if (resp_count < 2) {
        NLOG("Not enough probe responses (%d), using fallback", resp_count);
        return nat_classify_via_icmp();
    }

    int port_changes = 0;
    int ip_changes = 0;
    int first_port = responses[0].port;
    char first_ip[INET_ADDRSTRLEN];
    strcpy(first_ip, responses[0].ip);

    for (int i = 1; i < resp_count; i++) {
        if (responses[i].port != first_port) {
            port_changes++;
        }
        if (strcmp(responses[i].ip, first_ip) != 0) {
            ip_changes++;
        }
    }

    NLOG("Analysis: %d responses, %d port changes, %d IP changes",
         resp_count, port_changes, ip_changes);

    if (port_changes == 0 && ip_changes == 0) {
        NLOG("NAT type: FULL_CONE");
        return NAT_FULL_CONE;
    }
    
    if (port_changes == 0 && ip_changes > 0) {
        NLOG("NAT type: RESTRICTED_CONE");
        return NAT_RESTRICTED_CONE;
    }
    
    if (port_changes > 0 && ip_changes == 0) {
        NLOG("NAT type: PORT_RESTRICTED");
        return NAT_PORT_RESTRICTED;
    }
    
    if (port_changes > 0 && ip_changes > 0) {
        NLOG("NAT type: SYMMETRIC");
        return NAT_SYMMETRIC;
    }

    return NAT_UNKNOWN;
}

NATType nat_classify_via_icmp(void) {
    NLOG("ICMP-based NAT classification");
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        NLOG("Failed to create ICMP socket (need root): %s", strerror(errno));
        return nat_classify_via_upnp();
    }
    
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = 0;
    inet_pton(AF_INET, "8.8.8.8", &target.sin_addr);
    
    struct icmp icmp_hdr;
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.icmp_type = ICMP_ECHO;
    icmp_hdr.icmp_code = 0;
    icmp_hdr.icmp_id = getpid() & 0xFFFF;
    icmp_hdr.icmp_seq = 1;
    icmp_hdr.icmp_cksum = 0;
    
    uint16_t* words = (uint16_t*)&icmp_hdr;
    uint32_t sum = 0;
    for (int i = 0; i < sizeof(icmp_hdr) / 2; i++) {
        sum += words[i];
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    icmp_hdr.icmp_cksum = ~sum;
    
    ssize_t sent = sendto(sock, &icmp_hdr, sizeof(icmp_hdr), 0,
                          (struct sockaddr*)&target, sizeof(target));
    
    if (sent < 0) {
        NLOG("Failed to send ICMP: %s", strerror(errno));
        close(sock);
        return nat_classify_via_upnp();
    }
    
    uint8_t buffer[512];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    
    int n = recvfrom(sock, buffer, sizeof(buffer), 0,
                     (struct sockaddr*)&from, &from_len);
    
    close(sock);
    
    if (n > 0) {
        struct ip* ip_hdr = (struct ip*)buffer;
        struct icmp* icmp_resp = (struct icmp*)(buffer + (ip_hdr->ip_hl << 2));
        
        if (icmp_resp->icmp_type == ICMP_ECHOREPLY) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
            NLOG("ICMP reply from %s - external reachable", ip);
            return NAT_FULL_CONE;
        }
    }
    
    NLOG("No ICMP reply, likely behind restrictive NAT");
    return NAT_SYMMETRIC;
}

NATType nat_classify_via_upnp(void) {
    NLOG("UPnP-based NAT classification");
    
    if (!nat_has_upnp()) {
        NLOG("UPnP not available");
        return NAT_UNKNOWN;
    }

    return NAT_FULL_CONE;
}

NATType nat_classify_via_stun(void) {
    NLOG("STUN-based NAT classification (fallback)");
    
    const char* stun_hosts[] = {
        "stun.l.google.com",
        "stun1.l.google.com",
        "stun.ekiga.net",
        NULL
    };
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        NLOG("Failed to create STUN socket: %s", strerror(errno));
        return NAT_UNKNOWN;
    }

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (int i = 0; stun_hosts[i] != NULL; i++) {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;

        if (getaddrinfo(stun_hosts[i], "19302", &hints, &res) != 0) {
            continue;
        }

        unsigned char stun_req[20] = {
            0x00, 0x01, 0x00, 0x00,
            0x21, 0x12, 0xA4, 0x42,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };
        
        for (int j = 8; j < 20; j++) {
            stun_req[j] = rand() & 0xFF;
        }

        sendto(sock, stun_req, sizeof(stun_req), 0,
               res->ai_addr, res->ai_addrlen);

        unsigned char buffer[512];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        
        int n = recvfrom(sock, buffer, sizeof(buffer), 0,
                         (struct sockaddr*)&from, &from_len);
        
        freeaddrinfo(res);

        if (n > 0 && n >= 20) {
            if (buffer[1] == 0x01) {
                NLOG("STUN response received from %s", stun_hosts[i]);
                
                int external_port = 0;
                char external_ip[INET_ADDRSTRLEN] = {0};
                
                for (int pos = 20; pos < n - 4; ) {
                    uint16_t attr_type = (buffer[pos] << 8) | buffer[pos+1];
                    uint16_t attr_len = (buffer[pos+2] << 8) | buffer[pos+3];
                    pos += 4;
                    
                    if (attr_type == 0x0020 && attr_len >= 8) {
                        if (buffer[pos+1] == 0x01) {
                            external_ip[0] = buffer[pos+4] & 0xFF;
                            external_ip[1] = buffer[pos+5] & 0xFF;
                            external_ip[2] = buffer[pos+6] & 0xFF;
                            external_ip[3] = buffer[pos+7] & 0xFF;
                            external_port = (buffer[pos+2] << 8) | buffer[pos+3];
                            break;
                        }
                    }
                    pos += attr_len;
                }
                
                if (external_port > 0) {
                    NLOG("External address: %s:%d", external_ip, external_port);
                    close(sock);
                    return NAT_FULL_CONE;
                }
            }
        }
    }

    close(sock);
    NLOG("STUN detection failed, returning UNKNOWN");
    return NAT_UNKNOWN;
}

NATType nat_classify_combined(NATClassifierResult* result) {
    if (!result) {
        return NAT_UNKNOWN;
    }
    
    NLOG("Running combined NAT classification");
    
    memset(result, 0, sizeof(NATClassifierResult));
    
    char local_ip[INET_ADDRSTRLEN];
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == 0) {
        for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, local_ip, sizeof(local_ip));
            if (strcmp(local_ip, "127.0.0.1") != 0) {
                strcpy(result->local_ip, local_ip);
                break;
            }
        }
        freeifaddrs(ifaddr);
    }
    
    if (strlen(result->local_ip) == 0) {
        strcpy(result->local_ip, "127.0.0.1");
    }
    
    result->has_ipv6 = nat_has_ipv6();
    result->has_upnp = nat_has_upnp();
    result->is_firewalled = nat_is_firewalled();
    result->local_port = PROBE_PORT_START;
    
    NATType dht_type = nat_classify_via_dht(NULL, NULL);
    NATType upnp_type = nat_classify_via_upnp();
    NATType icmp_type = nat_classify_via_icmp();
    
    NLOG("DHT result: %s, UPnP result: %s, ICMP result: %s",
         nat_type_to_string(dht_type),
         nat_type_to_string(upnp_type),
         nat_type_to_string(icmp_type));
    
    if (upnp_type == NAT_FULL_CONE && result->has_upnp) {
        result->type = NAT_FULL_CONE;
        strcpy(result->detected_via, "UPnP");
        result->confidence = 90;
    } else if (dht_type != NAT_UNKNOWN) {
        result->type = dht_type;
        strcpy(result->detected_via, "DHT");
        result->confidence = 70;
    } else if (icmp_type != NAT_UNKNOWN) {
        result->type = icmp_type;
        strcpy(result->detected_via, "ICMP");
        result->confidence = 50;
    } else {
        result->type = NAT_UNKNOWN;
        strcpy(result->detected_via, "NONE");
        result->confidence = 0;
    }
    
    result->detected = (result->type != NAT_UNKNOWN);
    result->detection_time = time(NULL);
    
    NLOG("Combined result: %s (confidence: %d%%, via: %s)",
         nat_type_to_string(result->type), result->confidence, result->detected_via);
    
    return result->type;
}

bool nat_has_ipv6(void) {
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        return false;
    }
    
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
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
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
        close(sock);
        return false;
    }

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

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

    sendto(sock, search, strlen(search), 0,
           (struct sockaddr*)&multicast, sizeof(multicast));

    char buffer[2048];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    
    int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                     (struct sockaddr*)&from, &from_len);

    close(sock);

    if (n > 0) {
        buffer[n] = '\0';
        if (strstr(buffer, "HTTP/1.1 200 OK") != NULL) {
            NLOG("UPnP gateway found");
            return true;
        }
    }

    NLOG("UPnP not found");
    return false;
}

bool nat_is_firewalled(void) {
    int blocked = 0;
    int total = 0;
    
    int ports[] = {80, 443, 53, 123, 22, 993, 995, 5222};
    
    for (int i = 0; i < 8; i++) {
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
        
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            if (errno != EINPROGRESS) {
                blocked++;
            } else {
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(sock, &fds);
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                if (select(sock + 1, NULL, &fds, NULL, &tv) > 0) {
                    int error = 0;
                    socklen_t len = sizeof(error);
                    getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
                    if (error != 0) {
                        blocked++;
                    }
                } else {
                    blocked++;
                }
            }
        }
        total++;
        close(sock);
    }
    
    bool firewalled = (blocked > total / 2);
    NLOG("Firewalled: %s (%d/%d blocked)", firewalled ? "YES" : "NO", blocked, total);
    return firewalled;
}

bool nat_can_punch(void) {
    NATClassifierResult result;
    NATType type = nat_classify_combined(&result);
    
    if (type == NAT_SYMMETRIC) {
        NLOG("Symmetric NAT - punching may fail");
        return false;
    }
    
    if (result.is_firewalled) {
        NLOG("Firewalled - punching may fail");
        return false;
    }
    
    return true;
}

void nat_debug_print(NATClassifierResult* result) {
    if (!result) {
        printf("NATClassifierResult is NULL\n");
        return;
    }
    
    printf("\n=== NAT CLASSIFIER DEBUG ===\n");
    printf("Type: %s (%d)\n", nat_type_to_string(result->type), result->type);
    printf("External IP: %s\n", result->external_ip);
    printf("External Port: %d\n", result->external_port);
    printf("Local IP: %s\n", result->local_ip);
    printf("Local Port: %d\n", result->local_port);
    printf("Detected: %s\n", result->detected ? "YES" : "NO");
    printf("Confidence: %d%%\n", result->confidence);
    printf("Detected via: %s\n", result->detected_via);
    printf("Has IPv6: %s\n", result->has_ipv6 ? "YES" : "NO");
    printf("Has UPnP: %s\n", result->has_upnp ? "YES" : "NO");
    printf("Firewalled: %s\n", result->is_firewalled ? "YES" : "NO");
    printf("Detection time: %s", ctime(&result->detection_time));
    printf("============================\n");
}
