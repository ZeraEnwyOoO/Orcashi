// endpoint.hpp
#ifndef ENDPOINT_HPP
#define ENDPOINT_HPP

#include <string>
#include <map>
#include <mutex>
#include <vector>
#include <chrono>

struct EndpointInfo {
    std::string id;
    std::string ip;
    int port;
    int64_t last_update;
    bool verified;
    std::string public_key_hash;
};

class EndpointRegistry {
public:
    EndpointRegistry();
    
    void register_endpoint(const std::string& id, const std::string& ip, int port);
    bool get_endpoint(const std::string& id, EndpointInfo& out_info);
    void update_endpoint(const std::string& id, const std::string& ip, int port);
    void remove_endpoint(const std::string& id);
    std::vector<EndpointInfo> get_all();
    void cleanup_stale(int max_age_seconds = 300);
    
    void set_heartbeat_interval(int seconds) { heartbeat_interval_ = seconds; }
    
private:
    std::map<std::string, EndpointInfo> endpoints_;
    std::mutex mtx_;
    int heartbeat_interval_ = 30;
};

#endif
