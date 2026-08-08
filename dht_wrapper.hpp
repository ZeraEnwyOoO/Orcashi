 #ifndef DHT_WRAPPER_HPP
#define DHT_WRAPPER_HPP

#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif
    #include "dht.h"
#ifdef __cplusplus
}
#endif

class DHTWrapper {
public:
    DHTWrapper();
    ~DHTWrapper();
    
    bool init();
    bool put(const std::string& key, const std::string& value);
    std::string get(const std::string& key);
    void set_bootstrap_nodes(const std::vector<std::string>& nodes);
    bool is_initialized() const { return initialized; }
    
private:
    struct dht_node* node;
    std::mutex mtx;
    bool initialized;
    int local_port;
    std::atomic<bool> running;
    std::thread periodic_thread;
    
    static void dht_callback(void* closure, int event, const unsigned char* info_hash,
                             const struct sockaddr* sa, socklen_t salen,
                             const unsigned char* data, size_t data_len);
    
    std::string sha1(const std::string& input);
    std::string get_local_ip();
    void parse_callback(int event, const unsigned char* info_hash,
                        const struct sockaddr* sa, socklen_t salen,
                        const unsigned char* data, size_t data_len);
    void periodic_loop();
};

#endif
