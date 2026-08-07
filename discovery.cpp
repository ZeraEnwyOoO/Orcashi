 // discovery.cpp
#include "discovery.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>   // ← បន្ថែម!
#include <ifaddrs.h>
#include <netdb.h>
#include <sstream>
#include <chrono>

using namespace std;

Discovery::Discovery() : udp_socket_(-1), port_(9001), running_(false) {}

Discovery::~Discovery() {
    stop();
}

bool Discovery::init(int port) {
    port_ = port;
    
    udp_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket_ < 0) {
        cerr << "[ERROR] Failed to create UDP socket!" << endl;
        return false;
    }
    
    int opt = 1;
    setsockopt(udp_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);
    
    if (bind(udp_socket_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        cerr << "[ERROR] Failed to bind UDP socket to port " << port_ << endl;
        close(udp_socket_);
        return false;
    }
    
    cout << "\033[32m[ORCA] Discovery initialized on port " << port_ << "\033[0m" << endl;
    return true;
}

void Discovery::start() {
    if (running_) return;
    running_ = true;
    listen_thread_ = thread(&Discovery::listen_loop, this);
    broadcast_thread_ = thread(&Discovery::broadcast_loop, this);
    cout << "\033[36m[ORCA] Discovery started!\033[0m" << endl;
}

void Discovery::stop() {
    running_ = false;
    if (listen_thread_.joinable()) listen_thread_.join();
    if (broadcast_thread_.joinable()) broadcast_thread_.join();
    if (udp_socket_ >= 0) close(udp_socket_);
    cout << "\033[33m[ORCA] Discovery stopped.\033[0m" << endl;
}

void Discovery::listen_loop() {
    char buffer[4096];
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);
    
    while (running_) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(udp_socket_, &fds);
        
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(udp_socket_ + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) break;
        if (ret == 0) {
            cleanup_stale_peers();
            continue;
        }
        
        int n = recvfrom(udp_socket_, buffer, sizeof(buffer) - 1, 0,
                        (struct sockaddr*)&sender_addr, &addr_len);
        if (n <= 0) continue;
        
        buffer[n] = '\0';
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_addr.sin_addr, ip, sizeof(ip));
        
        parse_message(string(buffer), string(ip));
    }
}

void Discovery::broadcast_loop() {
    while (running_) {
        this_thread::sleep_for(chrono::seconds(30));
        cleanup_stale_peers();
    }
}

void Discovery::broadcast_presence(const string& id, const string& endpoint) {
    string msg = "ORCA_PRESENCE:" + id + ":" + endpoint;
    
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
    broadcast_addr.sin_port = htons(port_);
    
    int broadcast = 1;
    setsockopt(udp_socket_, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
    
    sendto(udp_socket_, msg.c_str(), msg.length(), 0,
           (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
    
    cout << "\033[36m[ORCA] Broadcasted presence: " << id << " at " << endpoint << "\033[0m" << endl;
}

void Discovery::broadcast_search(const string& id) {
    string msg = "ORCA_SEARCH:" + id;
    
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
    broadcast_addr.sin_port = htons(port_);
    
    int broadcast = 1;
    setsockopt(udp_socket_, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
    
    sendto(udp_socket_, msg.c_str(), msg.length(), 0,
           (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
    
    cout << "\033[36m[ORCA] Searching for: " << id << "\033[0m" << endl;
}

void Discovery::parse_message(const string& msg, const string& sender_ip) {
    if (msg.find("ORCA_PRESENCE:") == 0) {
        string rest = msg.substr(15);
        size_t colon = rest.find(':');
        if (colon != string::npos) {
            string id = rest.substr(0, colon);
            string endpoint = rest.substr(colon + 1);
            
            PeerInfo peer;
            peer.id = id;
            peer.endpoint = endpoint;
            peer.ip = sender_ip;
            peer.last_seen = chrono::duration_cast<chrono::seconds>(
                chrono::system_clock::now().time_since_epoch()).count();
            peer.online = true;
            
            size_t port_colon = endpoint.find(':');
            if (port_colon != string::npos) {
                peer.port = stoi(endpoint.substr(port_colon + 1));
            } else {
                peer.port = 9000;
            }
            
            lock_guard<mutex> lock(mtx_);
            peer_map_[id] = peer;
            
            bool exists = false;
            for (auto& p : discovered_peers_) {
                if (p.id == id) {
                    p = peer;
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                discovered_peers_.push_back(peer);
            }
            
            if (found_callback_) {
                found_callback_(peer);
            }
            
            cout << "\033[32m[ORCA] Found peer: " << id << " at " << endpoint << "\033[0m" << endl;
        }
    }
}

bool Discovery::find_peer(const string& id, PeerInfo& out_peer) {
    lock_guard<mutex> lock(mtx_);
    auto it = peer_map_.find(id);
    if (it != peer_map_.end() && it->second.online) {
        out_peer = it->second;
        return true;
    }
    return false;
}

vector<PeerInfo> Discovery::get_discovered_peers() {
    lock_guard<mutex> lock(mtx_);
    return discovered_peers_;
}

void Discovery::cleanup_stale_peers() {
    int64_t now = chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count();
    
    lock_guard<mutex> lock(mtx_);
    for (auto& pair : peer_map_) {
        if (now - pair.second.last_seen > 60) {
            pair.second.online = false;
            if (offline_callback_) {
                offline_callback_(pair.second);
            }
        }
    }
}

string Discovery::get_local_ip() {
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == -1) return "127.0.0.1";
    
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

void Discovery::on_peer_found(PeerCallback callback) {
    found_callback_ = callback;
}

void Discovery::on_peer_offline(PeerCallback callback) {
    offline_callback_ = callback;
}
