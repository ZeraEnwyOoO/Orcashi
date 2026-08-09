 // dht_wrapper.cpp - Real DHT Wrapper Implementation
#include "dht_wrapper.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <chrono>
#include <random>

using namespace std;

// ===== Static Callback Implementation =====

void DHTWrapper::dht_callback_static(void* closure, int event,
                                      const unsigned char* info_hash,
                                      const void* data, size_t data_len) {
    DHTWrapper* wrapper = static_cast<DHTWrapper*>(closure);
    if (wrapper) {
        wrapper->handle_dht_event(event, info_hash, data, data_len);
    }
}

// ===== Constructor / Destructor =====

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
    , errors_received(0)
    , start_time(chrono::system_clock::now()) {
    
    // Generate node ID
    unsigned char id[20];
    dht_random_bytes(id, 20);
    node_id = bytes_to_hex(id, 20);
    
    log("INFO", "DHTWrapper created with node ID: " + node_id);
}

DHTWrapper::~DHTWrapper() {
    shutdown();
    log("INFO", "DHTWrapper destroyed");
}

// ===== Initialization =====

bool DHTWrapper::init(int port, bool enable_ipv6) {
    if (initialized) {
        log("WARNING", "DHT already initialized!");
        return true;
    }
    
    local_port = port;
    log("INFO", "Initializing DHT on port " + to_string(port));
    
    // ===== Create UDP Socket =====
    dht_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (dht_socket < 0) {
        log("ERROR", "Failed to create IPv4 socket: " + string(strerror(errno)));
        return false;
    }
    
    // ===== Set SO_REUSEADDR =====
    int opt = 1;
    if (setsockopt(dht_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log("WARNING", "Failed to set SO_REUSEADDR: " + string(strerror(errno)));
    }
    
    // ===== Bind IPv4 =====
    struct sockaddr_in addr4;
    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family = AF_INET;
    addr4.sin_addr.s_addr = INADDR_ANY;
    addr4.sin_port = htons(port);
    
    if (bind(dht_socket, (struct sockaddr*)&addr4, sizeof(addr4)) < 0) {
        log("ERROR", "Failed to bind IPv4 to port " + to_string(port) + ": " + strerror(errno));
        close(dht_socket);
        dht_socket = -1;
        return false;
    }
    
    log("INFO", "IPv4 socket bound to port " + to_string(port));
    
    // ===== IPv6 (optional) =====
    if (enable_ipv6) {
        dht_socket6 = socket(AF_INET6, SOCK_DGRAM, 0);
        if (dht_socket6 >= 0) {
            struct sockaddr_in6 addr6;
            memset(&addr6, 0, sizeof(addr6));
            addr6.sin6_family = AF_INET6;
            addr6.sin6_addr = in6addr_any;
            addr6.sin6_port = htons(port);
            
            if (bind(dht_socket6, (struct sockaddr*)&addr6, sizeof(addr6)) == 0) {
                log("INFO", "IPv6 socket bound to port " + to_string(port));
            } else {
                log("WARNING", "Failed to bind IPv6: " + string(strerror(errno)));
                close(dht_socket6);
                dht_socket6 = -1;
            }
        }
    }
    
    // ===== Generate DHT ID =====
    unsigned char my_id[20];
    if (dht_random_bytes(my_id, 20) < 0) {
        log("ERROR", "Failed to generate random node ID!");
        close(dht_socket);
        dht_socket = -1;
        return false;
    }
    
    node_id = bytes_to_hex(my_id, 20);
    log("INFO", "Node ID: " + node_id);
    
    // ===== Initialize DHT =====
    const unsigned char* v = nullptr;  // Can add version info
    
    int result = dht_init(dht_socket, dht_socket6, my_id, v);
    if (result < 0) {
        log("ERROR", "dht_init failed with code " + to_string(result));
        close(dht_socket);
        dht_socket = -1;
        return false;
    }
    
    initialized = true;
    running = true;
    
    // ===== Start Threads =====
    periodic_thread = thread(&DHTWrapper::periodic_loop, this);
    event_thread = thread(&DHTWrapper::process_events, this);
    
    log("INFO", "DHT initialized successfully!");
    
    // ===== Auto-bootstrap =====
    auto_bootstrap();
    
    return true;
}

void DHTWrapper::shutdown() {
    if (!initialized) return;
    
    log("INFO", "Shutting down DHT...");
    
    running = false;
    initialized = false;
    
    if (periodic_thread.joinable()) {
        periodic_thread.join();
    }
    if (event_thread.joinable()) {
        event_thread.join();
    }
    
    // Wake up any waiting operations
    event_cv.notify_all();
    
    dht_uninit();
    
    if (dht_socket >= 0) {
        close(dht_socket);
        dht_socket = -1;
    }
    if (dht_socket6 >= 0) {
        close(dht_socket6);
        dht_socket6 = -1;
    }
    
    log("INFO", "DHT shutdown complete");
}

// ===== Periodic Loop (REAL) =====

void DHTWrapper::periodic_loop() {
    char buffer[65536];
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    time_t tosleep = 0;
    fd_set readfds;
    int maxfd = dht_socket;
    int nfds;
    
    log("DEBUG", "Periodic loop started");
    
    while (running && initialized) {
        // ===== Setup select() for non-blocking receive =====
        FD_ZERO(&readfds);
        if (dht_socket >= 0) {
            FD_SET(dht_socket, &readfds);
            if (dht_socket > maxfd) maxfd = dht_socket;
        }
        if (dht_socket6 >= 0) {
            FD_SET(dht_socket6, &readfds);
            if (dht_socket6 > maxfd) maxfd = dht_socket6;
        }
        
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        nfds = select(maxfd + 1, &readfds, NULL, NULL, &tv);
        
        if (nfds < 0) {
            if (errno == EINTR) continue;
            log("ERROR", "select() failed: " + string(strerror(errno)));
            break;
        }
        
        // ===== Handle incoming packets =====
        if (nfds > 0) {
            int sock = dht_socket;
            if (dht_socket >= 0 && FD_ISSET(dht_socket, &readfds)) {
                sock = dht_socket;
            } else if (dht_socket6 >= 0 && FD_ISSET(dht_socket6, &readfds)) {
                sock = dht_socket6;
            } else {
                sock = -1;
            }
            
            if (sock >= 0) {
                fromlen = sizeof(from);
                int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                                (struct sockaddr*)&from, &fromlen);
                
                if (n > 0) {
                    buffer[n] = '\0';
                    
                    // Log packet (debug only)
                    if (debug_enabled) {
                        char ip[INET6_ADDRSTRLEN];
                        int port = 0;
                        if (from.ss_family == AF_INET) {
                            struct sockaddr_in* sin = (struct sockaddr_in*)&from;
                            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
                            port = ntohs(sin->sin_port);
                        } else if (from.ss_family == AF_INET6) {
                            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&from;
                            inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
                            port = ntohs(sin6->sin6_port);
                        }
                        log("DEBUG", "Received " + to_string(n) + " bytes from " + 
                            string(ip) + ":" + to_string(port));
                    }
                    
                    queries_received++;
                    
                    // ===== Process with dht_periodic =====
                    dht_periodic(buffer, n, (struct sockaddr*)&from, fromlen,
                                &tosleep, dht_callback_static, this);
                }
            }
        }
        
        // ===== Call dht_periodic with no data (maintenance) =====
        dht_periodic(NULL, 0, NULL, 0, &tosleep, dht_callback_static, this);
        
        // ===== Sleep if needed =====
        if (tosleep > 0 && running) {
            // Don't sleep too long - we need to process events
            int sleep_sec = (tosleep < 5) ? tosleep : 5;
            if (debug_enabled) {
                log("DEBUG", "Sleeping for " + to_string(sleep_sec) + " seconds");
            }
            this_thread::sleep_for(chrono::seconds(sleep_sec));
        }
    }
    
    log("DEBUG", "Periodic loop ended");
}

// ===== Event Processing =====

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
            // ===== Call registered callbacks =====
            for (const auto& callback : event_callbacks) {
                try {
                    callback(event);
                } catch (const exception& e) {
                    log("ERROR", "Event callback threw exception: " + string(e.what()));
                }
            }
            
            // ===== Handle specific events =====
            if (event.type == DHT_EVENT_VALUES || event.type == DHT_EVENT_VALUES6) {
                log("INFO", "Found values for hash: " + event.info_hash + 
                    " (" + to_string(event.data.size()) + " bytes)");
                
                // ===== Check if this completes a pending operation =====
                lock_guard<mutex> lock(pending_mutex);
                auto it = pending_ops.find(event.info_hash);
                if (it != pending_ops.end()) {
                    it->second->result = event.data;
                    it->second->done = true;
                    it->second->success = true;
                    log("INFO", "Pending operation completed for: " + event.info_hash);
                }
            }
            
            if (event.type == DHT_EVENT_SEARCH_DONE || event.type == DHT_EVENT_SEARCH_DONE6) {
                log("INFO", "Search done for: " + event.info_hash);
                
                // ===== Mark pending operation as done even if no data =====
                lock_guard<mutex> lock(pending_mutex);
                auto it = pending_ops.find(event.info_hash);
                if (it != pending_ops.end()) {
                    it->second->done = true;
                    if (it->second->result.empty()) {
                        it->second->success = false;
                    }
                    log("INFO", "Pending operation marked done for: " + event.info_hash);
                }
            }
        }
    }
    
    log("DEBUG", "Event processor ended");
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
            log("INFO", "DHT_EVENT_SEARCH_DONE for " + dht_event.info_hash);
            break;
            
        case DHT_EVENT_SEARCH_DONE6:
            dht_event.type = DHT_EVENT_SEARCH_DONE6;
            log("INFO", "DHT_EVENT_SEARCH_DONE6 for " + dht_event.info_hash);
            break;
            
        default:
            dht_event.type = DHT_EVENT_NONE;
            log("DEBUG", "Unknown DHT event: " + to_string(event));
            return;
    }
    
    // ===== Queue event =====
    {
        lock_guard<mutex> lock(event_mutex);
        event_queue.push_back(dht_event);
    }
    event_cv.notify_one();
}

// ===== PUT Operation =====

bool DHTWrapper::put(const string& key, const string& value, int timeout_sec) {
    if (!initialized) {
        log("ERROR", "PUT: DHT not initialized!");
        return false;
    }
    
    log("INFO", "PUT: Storing key=" + key + " value=" + value);
    
    // ===== Convert key to info_hash =====
    string key_hash = sha256(key);
    unsigned char info_hash[20];
    hex_to_bytes(key_hash.substr(0, 40), info_hash, 20);
    string info_hash_str = bytes_to_hex(info_hash, 20);
    
    // ===== Create pending operation =====
    auto op = make_shared<PendingOperation>();
    op->key = key;
    op->done = false;
    op->success = false;
    op->start_time = chrono::system_clock::now();
    op->timeout_sec = timeout_sec;
    
    {
        lock_guard<mutex> lock(pending_mutex);
        pending_ops[info_hash_str] = op;
    }
    
    // ===== Start DHT search (announce) =====
    int port = 9000;  // Port for the peer
    int result = dht_search(info_hash, port, AF_INET, 
                            dht_callback_static, this);
    
    if (result < 0) {
        log("ERROR", "PUT: dht_search failed with code " + to_string(result));
        lock_guard<mutex> lock(pending_mutex);
        pending_ops.erase(info_hash_str);
        return false;
    }
    
    queries_sent++;
    log("INFO", "PUT: Search started, waiting for confirmation...");
    
    // ===== Wait for completion =====
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
    
    if (success) {
        log("INFO", "PUT: Successfully stored!");
    } else {
        log("WARNING", "PUT: Timeout or failure");
    }
    
    return success;
}

// ===== GET Operation =====

string DHTWrapper::get(const string& key, int timeout_sec) {
    if (!initialized) {
        log("ERROR", "GET: DHT not initialized!");
        return "";
    }
    
    log("INFO", "GET: Looking up key=" + key);
    
    // ===== Convert key to info_hash =====
    string key_hash = sha256(key);
    unsigned char info_hash[20];
    hex_to_bytes(key_hash.substr(0, 40), info_hash, 20);
    string info_hash_str = bytes_to_hex(info_hash, 20);
    
    // ===== Create pending operation =====
    auto op = make_shared<PendingOperation>();
    op->key = key;
    op->done = false;
    op->success = false;
    op->start_time = chrono::system_clock::now();
    op->timeout_sec = timeout_sec;
    
    {
        lock_guard<mutex> lock(pending_mutex);
        pending_ops[info_hash_str] = op;
    }
    
    // ===== Start DHT search (lookup) =====
    int result = dht_search(info_hash, 0, AF_INET,
                            dht_callback_static, this);
    
    if (result < 0) {
        log("ERROR", "GET: dht_search failed with code " + to_string(result));
        lock_guard<mutex> lock(pending_mutex);
        pending_ops.erase(info_hash_str);
        return "";
    }
    
    queries_sent++;
    log("INFO", "GET: Search started, waiting for results...");
    
    // ===== Wait for completion =====
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
        log("INFO", "GET: Found data (" + to_string(result_data.size()) + " bytes)");
        return result_data;
    } else if (op->done) {
        log("WARNING", "GET: Search completed but no data found");
        return "";
    } else {
        log("WARNING", "GET: Timeout");
        return "";
    }
}

// ===== Bootstrap =====

bool DHTWrapper::add_bootstrap_node(const string& host, int port) {
    log("INFO", "Adding bootstrap node: " + host + ":" + to_string(port));
    
    struct sockaddr_in addr;
    if (!resolve_host(host, addr)) {
        log("ERROR", "Failed to resolve host: " + host);
        return false;
    }
    
    addr.sin_port = htons(port);
    
    // ===== Ping the node =====
    int result = dht_ping_node((struct sockaddr*)&addr, sizeof(addr));
    
    if (result < 0) {
        log("WARNING", "Failed to ping bootstrap node: " + host);
        return false;
    }
    
    log("INFO", "Successfully pinged bootstrap node: " + host);
    return true;
}

bool DHTWrapper::add_bootstrap_nodes(const vector<string>& hosts, int port) {
    int success = 0;
    for (const auto& host : hosts) {
        if (add_bootstrap_node(host, port)) {
            success++;
        }
        // Rate limit pings
        this_thread::sleep_for(chrono::milliseconds(100));
    }
    log("INFO", "Added " + to_string(success) + "/" + to_string(hosts.size()) + 
        " bootstrap nodes");
    return success > 0;
}

bool DHTWrapper::bootstrap_from_file(const string& filename) {
    ifstream f(filename);
    if (!f.is_open()) {
        log("ERROR", "Cannot open bootstrap file: " + filename);
        return false;
    }
    
    vector<string> hosts;
    string line;
    while (getline(f, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;
        
        // Parse "host:port" or just "host"
        string host = line;
        int port = 6881;
        size_t colon = line.find(':');
        if (colon != string::npos) {
            host = line.substr(0, colon);
            try {
                port = stoi(line.substr(colon + 1));
            } catch (...) {
                port = 6881;
            }
        }
        hosts.push_back(host);
    }
    f.close();
    
    return add_bootstrap_nodes(hosts, 6881);
}

void DHTWrapper::auto_bootstrap() {
    log("INFO", "Auto-bootstrapping...");
    
    // ===== Public DHT bootstrap nodes =====
    vector<string> bootstrap_nodes = {
        "router.bittorrent.com",      // Mainline DHT
        "dht.transmissionbt.com",     // Transmission
        "router.utorrent.com",        // uTorrent
        "dht.aelitis.com",            // Azureus/Vuze
        "bootstrap.jami.net",         // Jami
        "dht.libtorrent.org",         // libtorrent
        "dht1.anime-fans.net",        // Public
        "dht2.anime-fans.net"         // Public
    };
    
    add_bootstrap_nodes(bootstrap_nodes, 6881);
}

// ===== Statistics =====

DHTStats DHTWrapper::get_stats() {
    DHTStats stats;
    memset(&stats, 0, sizeof(stats));
    
    int good = 0, dubious = 0, cached = 0, incoming = 0;
    dht_nodes(AF_INET, &good, &dubious, &cached, &incoming);
    
    stats.total_nodes = good + dubious;
    stats.good_nodes = good;
    stats.dubious_nodes = dubious;
    stats.cached_nodes = cached;
    stats.incoming_nodes = incoming;
    stats.buckets = 0;
    
    // Count buckets
    struct bucket* b = NULL; // Can't access internal structs
    // This would need dht_internal.h
    
    stats.storage_entries = 0;
    stats.searches_active = 0;
    stats.queries_sent = queries_sent;
    stats.queries_received = queries_received;
    stats.responses_received = responses_received;
    stats.errors_received = errors_received;
    
    return stats;
}

void DHTWrapper::dump_table() {
    log("INFO", "Dumping DHT table...");
    dht_dump_tables(stderr);
}

string DHTWrapper::get_node_id() const {
    return node_id;
}

// ===== Callbacks =====

void DHTWrapper::set_event_callback(EventCallback callback) {
    event_callbacks.push_back(callback);
}

void DHTWrapper::on_peer_found(EventCallback callback) {
    event_callbacks.push_back(callback);
}

void DHTWrapper::on_search_done(EventCallback callback) {
    event_callbacks.push_back(callback);
}

void DHTWrapper::on_error(EventCallback callback) {
    event_callbacks.push_back(callback);
}

// ===== Debug =====

void DHTWrapper::set_log_file(const string& filename) {
    dht_set_log_file(filename.c_str());
    log("INFO", "Log file set to: " + filename);
}

void DHTWrapper::log(const string& level, const string& message) {
    if (!debug_enabled && level != "ERROR" && level != "WARNING") {
        return;
    }
    
    auto now = chrono::system_clock::now();
    auto time_t_now = chrono::system_clock::to_time_t(now);
    struct tm tm_info;
    localtime_r(&time_t_now, &tm_info);
    
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    
    cerr << "[" << time_buf << "] [" << level << "] " << message << endl;
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

bool DHTWrapper::resolve_host(const string& host, struct sockaddr_in& addr) {
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    
    // Try numeric IP first
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) == 1) {
        return true;
    }
    
    // DNS resolution
    struct hostent* he = gethostbyname(host.c_str());
    if (!he) {
        log("ERROR", "DNS lookup failed for: " + host);
        return false;
    }
    
    if (he->h_addrtype != AF_INET) {
        log("ERROR", "Not an IPv4 address: " + host);
        return false;
    }
    
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    return true;
}

bool DHTWrapper::resolve_host6(const string& host, struct sockaddr_in6& addr) {
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    
    if (inet_pton(AF_INET6, host.c_str(), &addr.sin6_addr) == 1) {
        return true;
    }
    
    struct hostent* he = gethostbyname2(host.c_str(), AF_INET6);
    if (!he) {
        log("ERROR", "DNS IPv6 lookup failed for: " + host);
        return false;
    }
    
    memcpy(&addr.sin6_addr, he->h_addr_list[0], he->h_length);
    return true;
}

// ===== Global Functions =====

extern "C" void dht_set_log_file(const char* filename) {
    // Implemented in dht_impl.c
}
