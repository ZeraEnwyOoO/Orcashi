 // dht_wrapper.hpp - Real DHT Wrapper Header
#ifndef DHT_WRAPPER_HPP
#define DHT_WRAPPER_HPP

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <thread>
#include <functional>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif
    #include "dht.h"
#ifdef __cplusplus
}
#endif

// ===== DHT Callback Events =====
enum DHTEventType {
    DHT_EVENT_NONE = 0,
    DHT_EVENT_VALUES = 1,
    DHT_EVENT_VALUES6 = 2,
    DHT_EVENT_SEARCH_DONE = 3,
    DHT_EVENT_SEARCH_DONE6 = 4,
    DHT_EVENT_PEER_STORED = 5,
    DHT_EVENT_PEER_LOOKUP = 6,
    DHT_EVENT_ERROR = 7
};

struct DHTEvent {
    DHTEventType type;
    std::string info_hash;
    std::string data;
    std::string peer_ip;
    int peer_port;
    std::chrono::system_clock::time_point timestamp;
};

// ===== DHT Node Statistics =====
struct DHTStats {
    int total_nodes;
    int good_nodes;
    int dubious_nodes;
    int cached_nodes;
    int incoming_nodes;
    int buckets;
    int storage_entries;
    int searches_active;
    int queries_sent;
    int queries_received;
    int responses_received;
    int errors_received;
};

// ===== Main DHT Wrapper Class =====
class DHTWrapper {
public:
    DHTWrapper();
    ~DHTWrapper();
    
    // ===== Initialization =====
    bool init(int port = 6881, bool enable_ipv6 = false);
    void shutdown();
    bool is_initialized() const { return initialized; }
    
    // ===== DHT Operations =====
    bool put(const std::string& key, const std::string& value, int timeout_sec = 30);
    std::string get(const std::string& key, int timeout_sec = 30);
    bool store_peer(const std::string& info_hash, int port);
    bool lookup_peer(const std::string& info_hash);
    
    // ===== Bootstrap =====
    bool add_bootstrap_node(const std::string& host, int port = 6881);
    bool add_bootstrap_nodes(const std::vector<std::string>& hosts, int port = 6881);
    bool bootstrap_from_file(const std::string& filename);
    void auto_bootstrap();
    
    // ===== Statistics =====
    DHTStats get_stats();
    void dump_table();
    std::string get_node_id() const;
    int get_socket() const { return dht_socket; }
    int get_socket6() const { return dht_socket6; }
    
    // ===== Event Callbacks =====
    using EventCallback = std::function<void(const DHTEvent&)>;
    void set_event_callback(EventCallback callback);
    void on_peer_found(EventCallback callback);
    void on_search_done(EventCallback callback);
    void on_error(EventCallback callback);
    
    // ===== Debug =====
    void set_log_file(const std::string& filename);
    void set_debug(bool enabled) { debug_enabled = enabled; }
    bool is_debug() const { return debug_enabled; }
    
private:
    // ===== DHT State =====
    int dht_socket;
    int dht_socket6;
    int local_port;
    std::atomic<bool> initialized;
    std::atomic<bool> running;
    std::atomic<bool> debug_enabled;
    std::string node_id;
    
    // ===== Threads =====
    std::thread periodic_thread;
    std::thread event_thread;
    
    // ===== Event System =====
    std::mutex event_mutex;
    std::vector<DHTEvent> event_queue;
    std::vector<EventCallback> event_callbacks;
    std::condition_variable event_cv;
    
    // ===== Pending Operations =====
    struct PendingOperation {
        std::string key;
        std::string result;
        std::atomic<bool> done;
        std::atomic<bool> success;
        std::chrono::system_clock::time_point start_time;
        int timeout_sec;
    };
    std::map<std::string, std::shared_ptr<PendingOperation>> pending_ops;
    std::mutex pending_mutex;
    
    // ===== Statistics =====
    std::atomic<int> queries_sent;
    std::atomic<int> queries_received;
    std::atomic<int> responses_received;
    std::atomic<int> errors_received;
    std::chrono::system_clock::time_point start_time;
    
    // ===== Private Methods =====
    void periodic_loop();
    void process_events();
    void handle_dht_event(int event, const unsigned char* info_hash,
                          const void* data, size_t data_len);
    
    // ===== Static Callbacks =====
    static void dht_callback_static(void* closure, int event,
                                    const unsigned char* info_hash,
                                    const void* data, size_t data_len);
    
    // ===== Helpers =====
    std::string bytes_to_hex(const unsigned char* bytes, int len);
    void hex_to_bytes(const std::string& hex, unsigned char* bytes, int len);
    std::string sha256(const std::string& input);
    std::string get_local_ip();
    bool resolve_host(const std::string& host, struct sockaddr_in& addr);
    bool resolve_host6(const std::string& host, struct sockaddr_in6& addr);
    void log(const std::string& level, const std::string& message);
};

// ===== Global Functions (for C compatibility) =====
extern "C" {
    void dht_set_log_file(const char* filename);
}

#endif // DHT_WRAPPER_HPP
