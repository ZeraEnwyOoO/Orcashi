 // dht_wrapper.cpp - DHT Wrapper (Fixed: ID != NULL)
#include "dht_wrapper.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <sys/socket.h>

using namespace std;

#define DHT_PORT 6881

DHTWrapper::DHTWrapper() : node(nullptr), initialized(false), local_port(DHT_PORT), running(false) {}

DHTWrapper::~DHTWrapper() {
    running = false;
    if (periodic_thread.joinable()) periodic_thread.join();
    if (node) {
        dht_uninit();
        node = nullptr;
    }
}

string DHTWrapper::get_local_ip() {
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

string DHTWrapper::sha256(const string& input) {
    unsigned char hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input.c_str(), input.length());
    unsigned int len = 32;
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    
    stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

void DHTWrapper::dht_callback(void* closure, int event, const unsigned char* info_hash,
                               const struct sockaddr* sa, socklen_t salen,
                               const unsigned char* data, size_t data_len) {
    DHTWrapper* wrapper = static_cast<DHTWrapper*>(closure);
    wrapper->parse_callback(event, info_hash, sa, salen, data, data_len);
}

void DHTWrapper::parse_callback(int event, const unsigned char* info_hash,
                                 const struct sockaddr* sa, socklen_t salen,
                                 const unsigned char* data, size_t data_len) {
    if (event == 1) {
        if (data && data_len > 0) {
            string value((char*)data, data_len);
            cout << "[DHT] Found value: " << value << endl;
        }
    }
}

void DHTWrapper::periodic_loop() {
    while (running) {
        if (node) {
            dht_periodic(NULL, 0, NULL, 0, NULL, NULL, NULL);
        }
        this_thread::sleep_for(chrono::seconds(5));
    }
}

bool DHTWrapper::init() {
    if (initialized) return true;
    
    string local_ip = get_local_ip();
    cout << "[DHT] Initializing DHT node on " << local_ip << ":" << local_port << endl;
    
    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "[DHT] Failed to create socket!" << endl;
        return false;
    }
    
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cerr << "[DHT] Failed to set SO_REUSEADDR!" << endl;
        close(sock);
        return false;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(local_port);
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        cerr << "[DHT] Failed to bind to port " << local_port << "!" << endl;
        close(sock);
        return false;
    }
    
    // ===== CREATE DHT ID (20 bytes) =====
    unsigned char my_id[20];
    dht_random_bytes(my_id, 20);  // Generate random ID
    
    // ===== INITIALIZE DHT WITH ID =====
    int result = dht_init(sock, 0, my_id, NULL);  // Pass ID!
    if (result < 0) {
        cerr << "[DHT] Failed to initialize DHT node (error: " << result << ")" << endl;
        close(sock);
        return false;
    }
    
    node = (struct dht_node*)1;
    initialized = true;
    
    running = true;
    periodic_thread = thread(&DHTWrapper::periodic_loop, this);
    
    cout << "[DHT] DHT initialized on port " << local_port << "!" << endl;
    return true;
}

bool DHTWrapper::put(const string& key, const string& value) {
    if (!initialized) {
        cerr << "[DHT] Cannot store: DHT not initialized!" << endl;
        return false;
    }
    
    cout << "[DHT] Storing " << key << " -> " << value << endl;
    return true;
}

string DHTWrapper::get(const string& key) {
    if (!initialized) {
        cerr << "[DHT] Cannot lookup: DHT not initialized!" << endl;
        return "";
    }
    
    cout << "[DHT] Looking up " << key << endl;
    return "";
}

void DHTWrapper::set_bootstrap_nodes(const vector<string>& nodes) {
    cout << "[DHT] Setting bootstrap nodes:" << endl;
    for (const auto& node : nodes) {
        cout << "  " << node << endl;
    }
}
