 #ifndef MDNS_HPP
#define MDNS_HPP

#include <string>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>

class MDNS {
public:
    MDNS();
    ~MDNS();
    
    bool init();
    bool publish(const std::string& id, int port);
    std::string lookup(const std::string& id);
    void unpublish();
    bool is_running() const { return running; }
    
private:
    int sock;
    std::string my_id;
    std::string my_endpoint;
    std::atomic<bool> running;
    std::thread listen_thread;
    std::map<std::string, std::string> cache;
    std::mutex cache_mutex;
    
    void listen_loop();
    void process_message(const std::string& msg);
    void send_announcement(const std::string& msg);
    void send_query(const std::string& query);
    std::string get_local_ip();
    void cleanup();
};

#endif
