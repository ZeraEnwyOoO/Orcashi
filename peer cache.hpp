// peer_cache.hpp
#ifndef PEER_CACHE_HPP
#define PEER_CACHE_HPP

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include "discovery.hpp"

class PeerCache {
public:
    PeerCache(const std::string& cache_file = "");
    
    void save_peer(const PeerInfo& peer);
    bool get_peer(const std::string& id, PeerInfo& out_peer);
    std::vector<PeerInfo> get_all_peers();
    void remove_peer(const std::string& id);
    void clear();
    
    void load();
    void save();
    
private:
    std::string cache_file_;
    std::map<std::string, PeerInfo> cache_;
    std::mutex mtx_;
    
    std::string expand_path(const std::string& path);
    bool file_exists(const std::string& path);
    std::string read_file(const std::string& path);
    void write_file(const std::string& path, const std::string& content);
};

#endif
