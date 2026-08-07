 #define _POSIX_C_SOURCE 200809L
#include "mdns.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <poll.h>
#include <chrono>
#include <thread>

using namespace std;

#define MDNS_ADDR "224.0.0.251"
#define MDNS_PORT 5353

MDNS::MDNS() : sock(-1), running(false) {}

MDNS::~MDNS() {
    cleanup();
}

void MDNS::cleanup() {
    running = false;
    if (listen_thread.joinable()) listen_thread.join();
    if (sock >= 0) {
        close(sock);
        sock = -1;
    }
}

string MDNS::get_local_ip() {
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        return "127.0.0.1";
    }
    
    for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(ifa->ifa_name, "lo") == 0) continue;
        
        struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        freeifaddrs(ifaddr);
        return string(ip);
    }
    
    freeifaddrs(ifaddr);
    return "127.0.0.1";
}

bool MDNS::init() {
    if (sock >= 0) {
        cleanup();
    }
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "[mDNS] Failed to create socket!" << endl;
        return false;
    }
    
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cerr << "[mDNS] Failed to set SO_REUSEADDR!" << endl;
        close(sock);
        sock = -1;
        return false;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(MDNS_PORT);
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        cerr << "[mDNS] Failed to bind to port " << MDNS_PORT << "!" << endl;
        close(sock);
        sock = -1;
        return false;
    }
    
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_ADDR);
    mreq.imr_interface.s_addr = INADDR_ANY;
    
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        cerr << "[mDNS] Failed to join multicast group!" << endl;
        close(sock);
        sock = -1;
        return false;
    }
    
    cout << "[mDNS] Pure C++ Multicast initialized!" << endl;
    return true;
}

bool MDNS::publish(const string& id, int port) {
    if (sock < 0) {
        cerr << "[mDNS] Socket not initialized!" << endl;
        return false;
    }
    
    my_id = id;
    my_endpoint = get_local_ip() + ":" + to_string(port);
    
    running = true;
    listen_thread = thread(&MDNS::listen_loop, this);
    
    string msg = "ORCA_PRESENCE:" + id + ":" + my_endpoint;
    send_announcement(msg);
    
    cout << "[mDNS] Published " << id << " at " << my_endpoint << endl;
    return true;
}

void MDNS::send_announcement(const string& msg) {
    struct sockaddr_in multicast_addr;
    memset(&multicast_addr, 0, sizeof(multicast_addr));
    multicast_addr.sin_family = AF_INET;
    multicast_addr.sin_addr.s_addr = inet_addr(MDNS_ADDR);
    multicast_addr.sin_port = htons(MDNS_PORT);
    
    sendto(sock, msg.c_str(), msg.length(), 0,
           (struct sockaddr*)&multicast_addr, sizeof(multicast_addr));
}

void MDNS::send_query(const string& query) {
    struct sockaddr_in multicast_addr;
    memset(&multicast_addr, 0, sizeof(multicast_addr));
    multicast_addr.sin_family = AF_INET;
    multicast_addr.sin_addr.s_addr = inet_addr(MDNS_ADDR);
    multicast_addr.sin_port = htons(MDNS_PORT);
    
    sendto(sock, query.c_str(), query.length(), 0,
           (struct sockaddr*)&multicast_addr, sizeof(multicast_addr));
}

void MDNS::listen_loop() {
    char buffer[4096];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    
    while (running) {
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        
        int ret = poll(&pfd, 1, 1000);
        
        if (ret <= 0) continue;
        
        if (pfd.revents & POLLIN) {
            int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                            (struct sockaddr*)&sender, &sender_len);
            if (n > 0) {
                buffer[n] = '\0';
                string msg(buffer);
                process_message(msg);
            }
        }
    }
}

void MDNS::process_message(const string& msg) {
    if (msg.find("ORCA_PRESENCE:") == 0) {
        string rest = msg.substr(15);
        size_t colon = rest.find(':');
        if (colon != string::npos) {
            string id = rest.substr(0, colon);
            string endpoint = rest.substr(colon + 1);
            
            if (id != my_id) {
                lock_guard<mutex> lock(cache_mutex);
                cache[id] = endpoint;
                cout << "[mDNS] Discovered " << id << " at " << endpoint << endl;
            }
        }
    }
    
    if (msg.find("ORCA_QUERY:") == 0) {
        string id = msg.substr(11);
        if (id == my_id && !my_endpoint.empty()) {
            string response = "ORCA_PRESENCE:" + my_id + ":" + my_endpoint;
            send_announcement(response);
        }
    }
}

string MDNS::lookup(const string& id) {
    if (sock < 0) {
        cerr << "[mDNS] Socket not initialized!" << endl;
        return "";
    }
    
    {
        lock_guard<mutex> lock(cache_mutex);
        auto it = cache.find(id);
        if (it != cache.end()) {
            cout << "[mDNS] Found " << id << " in cache: " << it->second << endl;
            return it->second;
        }
    }
    
    string query = "ORCA_QUERY:" + id;
    send_query(query);
    
    cout << "[mDNS] Waiting for " << id << " to respond..." << endl;
    
    for (int i = 0; i < 3; i++) {
        this_thread::sleep_for(chrono::seconds(1));
        
        lock_guard<mutex> lock(cache_mutex);
        auto it = cache.find(id);
        if (it != cache.end()) {
            return it->second;
        }
    }
    
    cout << "[mDNS] " << id << " not found!" << endl;
    return "";
}

void MDNS::unpublish() {
    cleanup();
    cout << "[mDNS] Unpublished" << endl;
}
