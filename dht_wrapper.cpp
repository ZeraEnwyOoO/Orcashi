#include "dht_wrapper.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>

using namespace std;

#define DHT_PORT 6881

DHTWrapper::DHTWrapper() : node(nullptr), initialized(false), local_port(DHT_PORT) {}

DHTWrapper::~DHTWrapper() {
    if (node) {
        dht_uninit(node);
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
    if (event == DHT_EVENT_VALUES) {
        // Data found in DHT
        if (data && data_len > 0) {
            string value((char*)data, data_len);
            string hash_str;
            for (int i = 0; i < 20; i++) {
                char buf[3];
                snprintf(buf, sizeof(buf), "%02x", info_hash[i]);
                hash_str += buf;
            }
            cout << "[DHT] Found value for hash " << hash_str << ": " << value << endl;
            if (callback) {
                callback(hash_str, value);
            }
        }
    }
}

bool DHTWrapper::init() {
    if (initialized) return true;
    
    local_ip = get_local_ip();
    cout << "[DHT] Initializing DHT node on " << local_ip << ":" << local_port << endl;
    
    node = dht_init(local_port, NULL, NULL, dht_callback, this);
    if (!node) {
        cerr << "[DHT] Failed to initialize DHT node!" << endl;
        return false;
    }
    
    // Bootstrap nodes
    vector<string> bootstrap = {
        "router.bittorrent.com:6881",
        "dht.transmissionbt.com:6881",
        "router.utorrent.com:6881"
    };
    
    for (const auto& node_addr : bootstrap) {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(6881);
        
        string ip = node_addr.substr(0, node_addr.find(':'));
        if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) <= 0) {
            continue;
        }
        
        dht_ping_node(node, (struct sockaddr*)&sa, sizeof(sa));
        cout << "[DHT] Bootstrapping to " << node_addr << endl;
    }
    
    // Wait for bootstrap
    this_thread::sleep_for(chrono::seconds(2));
    
    initialized = true;
    cout << "[DHT] DHT initialized!" << endl;
    return true;
}

bool DHTWrapper::put(const string& key, const string& value) {
    if (!initialized && !init()) return false;
    
    lock_guard<mutex> lock(mtx);
    
    string key_hash = sha1(key);
    unsigned char info_hash[20];
    for (int i = 0; i < 20; i++) {
        info_hash[i] = stoi(key_hash.substr(i*2, 2), nullptr, 16);
    }
    
    const unsigned char* data = (const unsigned char*)value.c_str();
    size_t data_len = value.length();
    
    int result = dht_store(node, info_hash, data, data_len);
    if (result == 0) {
        cout << "[DHT] Stored " << key << " -> " << value << endl;
        return true;
    } else {
        cerr << "[DHT] Failed to store " << key << " (error: " << result << ")" << endl;
        return false;
    }
}

string DHTWrapper::get(const string& key) {
    if (!initialized && !init()) return "";
    
    lock_guard<mutex> lock(mtx);
    
    string key_hash = sha1(key);
    unsigned char info_hash[20];
    for (int i = 0; i < 20; i++) {
        info_hash[i] = stoi(key_hash.substr(i*2, 2), nullptr, 16);
    }
    
    cout << "[DHT] Looking up " << key << " (hash: " << key_hash << ")" << endl;
    
    // Search in DHT
    int result = dht_get(node, info_hash, NULL, NULL, NULL, NULL);
    if (result < 0) {
        cerr << "[DHT] Lookup failed: " << result << endl;
        return "";
    }
    
    // Wait for response
    this_thread::sleep_for(chrono::seconds(3));
    
    return "";
}

void DHTWrapper::set_bootstrap_nodes(const vector<string>& nodes) {
    // Implement if needed
}
