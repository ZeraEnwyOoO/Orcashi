#include "dht_wrapper.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <chrono>

using namespace std;

extern "C" {
    void dht_set_log_file(const char* filename);
    void dht_set_debug(int enabled);
}

// ===== Static Callback =====
void DHTWrapper::dht_callback_static(void* closure, int event,
                                      const unsigned char* info_hash,
                                      const void* data, size_t data_len) {
    DHTWrapper* wrapper = static_cast<DHTWrapper*>(closure);
    if (wrapper) {
        wrapper->handle_dht_event(event, info_hash, data, data_len);
    }
}

// ===== Constructor =====
DHTWrapper::DHTWrapper() 
    : dht_socket(-1)
    , dht_socket6(-1)
    , local_port(6881)
    , initialized(false)
    , running(false)
    , debug_enabled(false)
    , queries_sent(0)
    , queries_received(0)
    , responses_received(0)
    , errors_received(0) {
    
    unsigned char id[20];
    dht_random_bytes(id, 20);
    node_id = bytes_to_hex(id, 20);
    log("INFO", "DHTWrapper created, ID: " + node_id);
}

DHTWrapper::~DHTWrapper() {
    shutdown();
}

// ===== Init =====
bool DHTWrapper::init(int port, bool enable_ipv6) {
    if (initialized) return true;
    
    local_port = port;
    log("INFO", "Initializing DHT on port " + to_string(port));
    
    dht_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (dht_socket < 0) {
        log("ERROR", "Failed to create socket");
        return false;
    }
    
    int opt = 1;
    setsockopt(dht_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr4;
    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family = AF_INET;
    addr4.sin_addr.s_addr = INADDR_ANY;
    addr4.sin_port = htons(port);
    
    if (bind(dht_socket, (struct sockaddr*)&addr4, sizeof(addr4)) < 0) {
        log("ERROR", "Failed to bind to port " + to_string(port));
        close(dht_socket);
        dht_socket = -1;
        return false;
    }
    
    log("INFO", "Socket bound to port " + to_string(port));
    
    unsigned char my_id[20];
    dht_random_bytes(my_id, 20);
    node_id = bytes_to_hex(my_id, 20);
    
    int result = dht_init(dht_socket, dht_socket6, my_id, NULL);
    if (result < 0) {
        log("ERROR", "dht_init failed");
        close(dht_socket);
        dht_socket = -1;
        return false;
    }
    
    initialized = true;
    running = true;
    
    periodic_thread = thread(&DHTWrapper::periodic_loop, this);
    event_thread = thread(&DHTWrapper::process_events, this);
    
    log("INFO", "DHT initialized successfully");
    auto_bootstrap();
    
    return true;
}

void DHTWrapper::shutdown() {
    if (!initialized) return;
    
    log("INFO", "Shutting down DHT...");
    running = false;
    initialized = false;
    
    if (periodic_thread.joinable()) periodic_thread.join();
    if (event_thread.joinable()) event_thread.join();
    
    dht_uninit();
    if (dht_socket >= 0) {
        close(dht_socket);
        dht_socket = -1;
    }
    
    log("INFO", "DHT shutdown complete");
}

// ===== Periodic Loop =====
void DHTWrapper::periodic_loop() {
    char buffer[65536];
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    time_t tosleep = 0;
    fd_set readfds;
    
    log("DEBUG", "Periodic loop started");
    
    while (running && initialized) {
        FD_ZERO(&readfds);
        if (dht_socket >= 0) FD_SET(dht_socket, &readfds);
        
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int nfds = select(dht_socket + 1, &readfds, NULL, NULL, &tv);
        
        if (nfds > 0 && dht_socket >= 0 && FD_ISSET(dht_socket, &readfds)) {
            fromlen = sizeof(from);
            int n = recvfrom(dht_socket, buffer, sizeof(buffer) - 1, 0,
                            (struct sockaddr*)&from, &fromlen);
            if (n > 0) {
                queries_received++;
                dht_periodic(buffer, n, (struct sockaddr*)&from, fromlen,
                            &tosleep, dht_callback_static, this);
            }
        }
        
        dht_periodic(NULL, 0, NULL, 0, &tosleep, dht_callback_static, this);
        
        if (tosleep > 0 && running) {
            int sleep_sec = (tosleep < 5) ? tosleep : 5;
            this_thread::sleep_for(chrono::seconds(sleep_sec));
        }
    }
    
    log("DEBUG", "Periodic loop ended");
}

// ===== Process Events =====
void DHTWrapper::process_events() {
    log("DEBUG", "Event processor started");
    
    while (running) {
        vector<DHTEvent> events;
        {
            unique_lock<mutex> lock(event_mutex);
            if (event_queue.empty()) {
                event_cv.wait_for(lock, chrono::milliseconds(100));
                continue;
            }
            events.swap(event_queue);
        }
        
        for (const auto& event : events) {
            for (const auto& callback : event_callbacks) {
                try {
                    callback(event);
                } catch (...) {}
            }
            
            if (event.type == DHT_EVENT_VALUES || event.type == DHT_EVENT_VALUES6) {
                lock_guard<mutex> lock(pending_mutex);
                auto it = pending_ops.find(event.info_hash);
                if (it != pending_ops.end()) {
                    it->second->result = event.data;
                    it->second->done = true;
                    it->second->success = true;
                }
            }
        }
    }
}

// ===== Handle DHT Events =====
void DHTWrapper::handle_dht_event(int event, const unsigned char* info_hash,
                                   const void* data, size_t data_len) {
    DHTEvent dht_event;
    dht_event.timestamp = chrono::system_clock::now();
    
    if (info_hash) {
        dht_event.info_hash = bytes_to_hex(info_hash, 20);
    }
    if (data && data_len > 0) {
        dht_event.data = string((const char*)data, data_len);
    }
    
    switch (event) {
        case DHT_EVENT_VALUES:
            dht_event.type = DHT_EVENT_VALUES;
            responses_received++;
            log("INFO", "DHT_EVENT_VALUES: " + to_string(data_len) + " bytes");
            break;
        case DHT_EVENT_VALUES6:
            dht_event.type = DHT_EVENT_VALUES6;
            responses_received++;
            log("INFO", "DHT_EVENT_VALUES6: " + to_string(data_len) + " bytes");
            break;
        case DHT_EVENT_SEARCH_DONE:
            dht_event.type = DHT_EVENT_SEARCH_DONE;
            log("INFO", "DHT_EVENT_SEARCH_DONE");
            break;
        case DHT_EVENT_SEARCH_DONE6:
            dht_event.type = DHT_EVENT_SEARCH_DONE6;
            log("INFO", "DHT_EVENT_SEARCH_DONE6");
            break;
        default:
            return;
    }
    
    {
        lock_guard<mutex> lock(event_mutex);
        event_queue.push_back(dht_event);
    }
    event_cv.notify_one();
}

// ===== PUT =====
bool DHTWrapper::put(const string& key, const string& value, int timeout_sec) {
    if (!initialized) {
        log("ERROR", "PUT: DHT not initialized");
        return false;
    }
    
    log("INFO", "PUT: " + key + " -> " + value);
    
    string key_hash = sha256(key);
    unsigned char info_hash[20];
    hex_to_bytes(key_hash.substr(0, 40), info_hash, 20);
    string info_hash_str = bytes_to_hex(info_hash, 20);
    
    auto op = make_shared<PendingOperation>();
    op->key = key;
    op->done = false;
    op->success = false;
    op->timeout_sec = timeout_sec;
    
    {
        lock_guard<mutex> lock(pending_mutex);
        pending_ops[info_hash_str] = op;
    }
    
    int result = dht_search(info_hash, 9000, AF_INET, dht_callback_static, this);
    queries_sent++;
    
    if (result < 0) {
        log("ERROR", "PUT: dht_search failed");
        lock_guard<mutex> lock(pending_mutex);
        pending_ops.erase(info_hash_str);
        return false;
    }
    
    int elapsed = 0;
    while (!op->done && elapsed < timeout_sec) {
        this_thread::sleep_for(chrono::milliseconds(100));
        elapsed++;
    }
    
    bool success = op->success;
    {
        lock_guard<mutex> lock(pending_mutex);
        pending_ops.erase(info_hash_str);
    }
    
    log(success ? "INFO" : "WARNING", "PUT: " + string(success ? "success" : "failed"));
    return success;
}

// ===== GET =====
string DHTWrapper::get(const string& key, int timeout_sec) {
    if (!initialized) {
        log("ERROR", "GET: DHT not initialized");
        return "";
    }
    
    log("INFO", "GET: " + key);
    
    string key_hash = sha256(key);
    unsigned char info_hash[20];
    hex_to_bytes(key_hash.substr(0, 40), info_hash, 20);
    string info_hash_str = bytes_to_hex(info_hash, 20);
    
    auto op = make_shared<PendingOperation>();
    op->key = key;
    op->done = false;
    op->success = false;
    op->timeout_sec = timeout_sec;
    
    {
        lock_guard<mutex> lock(pending_mutex);
        pending_ops[info_hash_str] = op;
    }
    
    int result = dht_search(info_hash, 0, AF_INET, dht_callback_static, this);
    queries_sent++;
    
    if (result < 0) {
        log("ERROR", "GET: dht_search failed");
        lock_guard<mutex> lock(pending_mutex);
        pending_ops.erase(info_hash_str);
        return "";
    }
    
    int elapsed = 0;
    while (!op->done && elapsed < timeout_sec) {
        this_thread::sleep_for(chrono::milliseconds(100));
        elapsed++;
    }
    
    string result_data = op->result;
    bool success = op->success;
    
    {
        lock_guard<mutex> lock(pending_mutex);
        pending_ops.erase(info_hash_str);
    }
    
    if (success && !result_data.empty()) {
        log("INFO", "GET: found " + to_string(result_data.size()) + " bytes");
        return result_data;
    }
    
    log("WARNING", "GET: no data found");
    return "";
}

// ===== Auto Bootstrap =====
void DHTWrapper::auto_bootstrap() {
    vector<string> nodes = {
        "router.bittorrent.com",
        "dht.transmissionbt.com",
        "router.utorrent.com",
        "dht.aelitis.com"
    };
    
    for (const auto& host : nodes) {
        add_bootstrap_node(host, 6881);
        this_thread::sleep_for(chrono::milliseconds(100));
    }
}

bool DHTWrapper::add_bootstrap_node(const string& host, int port) {
    struct sockaddr_in addr;
    if (!resolve_host(host, addr)) {
        log("WARNING", "Failed to resolve: " + host);
        return false;
    }
    addr.sin_port = htons(port);
    int result = dht_ping_node((struct sockaddr*)&addr, sizeof(addr));
    log("INFO", "Bootstrap: " + host + (result >= 0 ? " success" : " failed"));
    return result >= 0;
}

// ===== Stats =====
DHTStats DHTWrapper::get_stats() {
    DHTStats stats;
    int good = 0, dubious = 0, cached = 0, incoming = 0;
    dht_nodes(AF_INET, &good, &dubious, &cached, &incoming);
    stats.total_nodes = good + dubious;
    stats.good_nodes = good;
    stats.dubious_nodes = dubious;
    stats.cached_nodes = cached;
    stats.incoming_nodes = incoming;
    stats.queries_sent = queries_sent;
    stats.queries_received = queries_received;
    stats.responses_received = responses_received;
    stats.errors_received = errors_received;
    return stats;
}

void DHTWrapper::dump_table() {
    dht_dump_tables(stderr);
}

string DHTWrapper::get_node_id() const {
    return node_id;
}

void DHTWrapper::set_event_callback(EventCallback callback) {
    event_callbacks.push_back(callback);
}

void DHTWrapper::set_log_file(const string& filename) {
    dht_set_log_file(filename.c_str());
    log("INFO", "Log file set to: " + filename);
}

// ===== Helpers =====
string DHTWrapper::bytes_to_hex(const unsigned char* bytes, int len) {
    stringstream ss;
    for (int i = 0; i < len; i++) {
        ss << hex << setw(2) << setfill('0') << (int)bytes[i];
    }
    return ss.str();
}

void DHTWrapper::hex_to_bytes(const string& hex, unsigned char* bytes, int len) {
    for (int i = 0; i < len && i * 2 < (int)hex.length(); i++) {
        string byte_str = hex.substr(i * 2, 2);
        bytes[i] = stoi(byte_str, nullptr, 16);
    }
}

string DHTWrapper::sha256(const string& input) {
    unsigned char hash[32];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input.c_str(), input.length());
    unsigned int len = 32;
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    return bytes_to_hex(hash, 32);
}

string DHTWrapper::get_local_ip() {
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == -1) return "127.0.0.1";
    for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
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

bool DHTWrapper::resolve_host(const string& host, struct sockaddr_in& addr) {
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) == 1) return true;
    struct hostent* he = gethostbyname(host.c_str());
    if (!he || he->h_addrtype != AF_INET) return false;
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    return true;
}

void DHTWrapper::log(const string& level, const string& message) {
    if (!debug_enabled && level != "ERROR") return;
    auto now = chrono::system_clock::now();
    auto time_t_now = chrono::system_clock::to_time_t(now);
    struct tm tm_info;
    localtime_r(&time_t_now, &tm_info);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    cerr << "[" << time_buf << "] [" << level << "] " << message << endl;
}
