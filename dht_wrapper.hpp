#ifndef DHT_WRAPPER_HPP
#define DHT_WRAPPER_HPP

#include <string>
#include <vector>
#include <mutex>
#include <functional>

extern "C" {
    #include "dht.h"
}

class DHTWrapper {
public:
    DHTWrapper();
    ~DHTWrapper();
    
    bool init();
    bool put(const std::string& key, const std::string& value);
    std::string get(const std::string& key);
    void set_bootstrap_nodes(const std::vector<std::string>& nodes);
    bool is_initialized() const { return initialized; }
    
    using Callback = std::function<void(const std::string& key, const std::string& value)>;
    void set_callback(Callback cb) { callback = cb; }
    
private:
    struct dht_node* node;
    std::mutex mtx;
    bool initialized;
    Callback callback;
    std::string local_ip;
    int local_port;
    
    static void dht_callback(void* closure, int event, const unsigned char* info_hash,
                             const struct sockaddr* sa, socklen_t salen,
                             const unsigned char* data, size_t data_len);
    
    std::string sha1(const std::string& input);
    std::string get_local_ip();
    void parse_callback(int event, const unsigned char* info_hash,
                        const struct sockaddr* sa, socklen_t salen,
                        const unsigned char* data, size_t data_len);
};

#endif
