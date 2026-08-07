 // discovery.hpp - FIXED
#ifndef DISCOVERY_HPP
#define DISCOVERY_HPP

#include <string>
#include <vector>
#include <map>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <chrono>
#include <netinet/in.h>

struct PeerInfo {
    std::string id;
    std::string endpoint;
    std::string ip;
    int port;
    std::string name;
    int64_t last_seen;
    bool online;
    std::string public_key;
};

class Discovery {
public:
    Discovery();
    ~Discovery();
    
    bool init(int port = 9001);
    void start();
    void stop();
    
    // Broadcast presence
    void broadcast_presence(const std::string& id, const std::string& endpoint);
    void broadcast_search(const std::string& id);
    
    // Discovery methods
    std::vector<PeerInfo> discover_peers(int timeout_ms = 3000);
    bool find_peer(const std::string& id, PeerInfo& out_peer);
    std::vector<PeerInfo> search_by_name(const std::string& name);
    
    // Events
    using PeerCallback = std::function<void(const PeerInfo&)>;
    void on_peer_found(PeerCallback callback);
    void on_peer_offline(PeerCallback callback);
    
    // Get discovered peers
    std::vector<PeerInfo> get_discovered_peers();
    
    // <<< PUBLIC: Get local IP >>>
    std::string get_local_ip();  // ← នៅទីនេះ!
    
private:
    int udp_socket_;
    int port_;
    std::atomic<bool> running_;
    std::thread listen_thread_;
    std::thread broadcast_thread_;
    std::vector<PeerInfo> discovered_peers_;
    std::map<std::string, PeerInfo> peer_map_;
    std::mutex mtx_;
    PeerCallback found_callback_;
    PeerCallback offline_callback_;
    
    void listen_loop();
    void broadcast_loop();
    void parse_message(const std::string& msg, const std::string& sender_ip);
    // std::string get_local_ip();  // ← លុបចេញ!
    void send_udp(const std::string& msg, const std::string& ip, int port);
    void cleanup_stale_peers();
    bool is_valid_ip(const std::string& ip);
};

#endif
