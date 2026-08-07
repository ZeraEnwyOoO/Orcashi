 // registry.hpp - HEADER ONLY
#ifndef REGISTRY_HPP
#define REGISTRY_HPP

#include <string>
#include <map>
#include <vector>
#include <ctime>

struct Peer {
    std::string id;
    std::string ip;
    std::string port;
    bool online;
    time_t last_seen;
};

class Registry {
public:
    Registry();
    
    bool register_peer(const std::string& id, const std::string& ip, const std::string& port);
    bool get_peer(const std::string& id, Peer& out_peer);
    void update_peer(const std::string& id, const std::string& ip, const std::string& port);
    void set_online(const std::string& id, bool online);
    std::vector<Peer> get_all_peers();
    std::vector<Peer> get_online_peers();
    bool remove_peer(const std::string& id);
    bool peer_exists(const std::string& id);
    
    void load();
    void save();
    
private:
    std::map<std::string, Peer> peers;
    std::string registry_file;
};

#endif
