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
#include <condition_variable>
#include <memory>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

extern "C" {
    #include "dht.h"
}

enum DHTEventType {
    DHT_EVENT_NONE = 0,
    DHT_EVENT_VALUES = 1,
    DHT_EVENT_VALUES6 = 2,
    DHT_EVENT_SEARCH_DONE = 3,
    DHT_EVENT_SEARCH_DONE6 = 4
};

struct DHTEvent {
    DHTEventType type;
    std::string info_hash;
    std::string data;
    std::string peer_ip;
    int peer_port;
    std::chrono::system_clock::time_point timestamp;
};

struct DHTStats {
    int total_nodes = 0;
    int good_nodes = 0;
    int dubious_nodes = 0;
    int cached_nodes = 0;
    int incoming_nodes = 0;
    int queries_sent = 0;
    int queries_received = 0;
    int responses_received = 0;
    int errors_received = 0;
};

class DHTWrapper {
public:
    DHTWrapper();
    ~DHTWrapper();
    
    bool init(int port = 6881, bool enable_ipv6 = false);
    void shutdown();
    bool is_initialized() const { return initialized; }
    
    bool put(const std::string& key, const std::string& value, int timeout_sec = 30);
    std::string get(const std::string& key, int timeout_sec = 30);
    
    bool add_bootstrap_node(const std::string& host, int port = 6881);
    void auto_bootstrap();
    
    DHTStats get_stats();
    void dump_table();
    std::string get_node_id() const;
    int get_socket() const { return dht_socket; }
    
    using EventCallback = std::function<void(const DHTEvent&)>;
    void set_event_callback(EventCallback callback);
    
    void set_log_file(const std::string& filename);
    void set_debug(bool enabled) { debug_enabled = enabled; }
    
private:
    int dht_socket;
    int dht_socket6;
    int local_port;
    std::atomic<bool> initialized;
    std::atomic<bool> running;
    std::atomic<bool> debug_enabled;
    std::string node_id;
    
    std::thread periodic_thread;
    std::thread event_thread;
    
    std::mutex event_mutex;
    std::vector<DHTEvent> event_queue;
    std::vector<EventCallback> event_callbacks;
    std::condition_variable event_cv;
    
    struct PendingOperation {
        std::string key;
        std::string result;
        std::atomic<bool> done;
        std::atomic<bool> success;
        int timeout_sec;
    };
    std::map<std::string, std::shared_ptr<PendingOperation>> pending_ops;
    std::mutex pending_mutex;
    
    std::atomic<int> queries_sent;
    std::atomic<int> queries_received;
    std::atomic<int> responses_received;
    std::atomic<int> errors_received;
    
    void periodic_loop();
    void process_events();
    void handle_dht_event(int event, const unsigned char* info_hash,
                          const void* data, size_t data_len);
    
    static void dht_callback_static(void* closure, int event,
                                    const unsigned char* info_hash,
                                    const void* data, size_t data_len);
    
    std::string bytes_to_hex(const unsigned char* bytes, int len);
    void hex_to_bytes(const std::string& hex, unsigned char* bytes, int len);
    std::string sha256(const std::string& input);
    std::string get_local_ip();
    bool resolve_host(const std::string& host, struct sockaddr_in& addr);
    void log(const std::string& level, const std::string& message);
};

#endif
