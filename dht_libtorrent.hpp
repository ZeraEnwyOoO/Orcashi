#ifndef DHT_LIBTORRENT_HPP
#define DHT_LIBTORRENT_HPP

#include <string>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>

#include <libtorrent/session.hpp>
#include <libtorrent/settings_pack.hpp>
#include <libtorrent/alert_types.hpp>

class DHTLibtorrent {
public:
    DHTLibtorrent();
    ~DHTLibtorrent();
    
    bool init(int port = 6881);
    bool put(const std::string& key, const std::string& value);
    std::string get(const std::string& key);
    bool is_initialized() const { return initialized; }
    
    using Callback = std::function<void(const std::string& key, const std::string& value)>;
    void set_callback(Callback cb) { callback = cb; }
    
private:
    std::unique_ptr<lt::session> session;
    std::map<std::string, std::string> local_cache;
    std::mutex mtx;
    bool initialized;
    std::atomic<bool> running;
    std::thread dht_thread;
    Callback callback;
    
    std::string sha256(const std::string& input);
    void dht_loop();
    void on_dht_item(const std::string& key, const std::string& value);
};

#endif
