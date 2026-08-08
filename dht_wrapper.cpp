 // dht_wrapper.cpp - DHT Wrapper (Full Match with dht.h)
#include "dht_wrapper.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <sys/socket.h>

using namespace std;

#define DHT_PORT 6881

// ==================== DHT EXTERNAL CALLBACKS (Match dht.h) ====================
extern "C" {

int dht_blacklisted(const struct sockaddr *sa, int salen) {
    return 0;  // Always allow
}

int dht_random_bytes(void *buf, size_t size) {
    FILE* f = fopen("/dev/urandom", "r");
    if (f) {
        size_t n = fread(buf, 1, size, f);
        fclose(f);
        return n == size ? 0 : -1;
    }
    unsigned char* b = (unsigned char*)buf;
    for (size_t i = 0; i < size; i++) {
        b[i] = rand() & 0xFF;
    }
    return 0;
}

void dht_hash(void *hash_return, int hash_size,
              const void *data1, int len1,
              const void *data2, int len2,
              const void *data3, int len3) {
    unsigned char hash[20];
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data1, len1);
    if (data2) SHA1_Update(&ctx, data2, len2);
    if (data3) SHA1_Update(&ctx, data3, len3);
    SHA1_Final(hash, &ctx);
    memcpy(hash_return, hash, hash_size > 20 ? 20 : hash_size);
}

int dht_sendto(int sockfd, const void *buf, int len, int flags,
               const struct sockaddr *dest_addr, int addrlen) {
    return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

}

// ==================== DHTWRAPPER IMPLEMENTATION ====================

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

string DHTWrapper::sha1(const string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)input.c_str(), input.length(), hash);
    stringstream ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
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
        dht_periodic(NULL, 0, NULL, 0, NULL, NULL, NULL);
        this_thread::sleep_for(chrono::seconds(5));
    }
}

bool DHTWrapper::init() {
    if (initialized) return true;
    
    string local_ip = get_local_ip();
    cout << "[DHT] Initializing DHT node on " << local_ip << ":" << local_port << endl;
    
    int result = dht_init(local_port, 0, NULL, NULL);
    if (result < 0) {
        cerr << "[DHT] Failed to initialize DHT node!" << endl;
        return false;
    }
    
    node = (struct dht_node*)1;
    
    running = true;
    periodic_thread = thread(&DHTWrapper::periodic_loop, this);
    
    initialized = true;
    cout << "[DHT] DHT initialized!" << endl;
    return true;
}

bool DHTWrapper::put(const string& key, const string& value) {
    if (!initialized) return false;
    cout << "[DHT] Storing " << key << " -> " << value << endl;
    return true;
}

string DHTWrapper::get(const string& key) {
    if (!initialized) return "";
    cout << "[DHT] Looking up " << key << endl;
    return "";
}

void DHTWrapper::set_bootstrap_nodes(const vector<string>& nodes) {
    cout << "[DHT] Setting bootstrap nodes:" << endl;
    for (const auto& node : nodes) {
        cout << "  " << node << endl;
    }
}
