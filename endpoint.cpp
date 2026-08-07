// endpoint.cpp
#include "endpoint.hpp"
#include <chrono>

using namespace std;

EndpointRegistry::EndpointRegistry() {}

void EndpointRegistry::register_endpoint(const string& id, const string& ip, int port) {
    lock_guard<mutex> lock(mtx_);
    EndpointInfo info;
    info.id = id;
    info.ip = ip;
    info.port = port;
    info.last_update = chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count();
    info.verified = false;
    endpoints_[id] = info;
}

bool EndpointRegistry::get_endpoint(const string& id, EndpointInfo& out_info) {
    lock_guard<mutex> lock(mtx_);
    auto it = endpoints_.find(id);
    if (it != endpoints_.end()) {
        out_info = it->second;
        return true;
    }
    return false;
}

void EndpointRegistry::update_endpoint(const string& id, const string& ip, int port) {
    lock_guard<mutex> lock(mtx_);
    auto it = endpoints_.find(id);
    if (it != endpoints_.end()) {
        it->second.ip = ip;
        it->second.port = port;
        it->second.last_update = chrono::duration_cast<chrono::seconds>(
            chrono::system_clock::now().time_since_epoch()).count();
    }
}

void EndpointRegistry::remove_endpoint(const string& id) {
    lock_guard<mutex> lock(mtx_);
    endpoints_.erase(id);
}

vector<EndpointInfo> EndpointRegistry::get_all() {
    lock_guard<mutex> lock(mtx_);
    vector<EndpointInfo> result;
    for (const auto& pair : endpoints_) {
        result.push_back(pair.second);
    }
    return result;
}

void EndpointRegistry::cleanup_stale(int max_age_seconds) {
    int64_t now = chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count();
    
    lock_guard<mutex> lock(mtx_);
    auto it = endpoints_.begin();
    while (it != endpoints_.end()) {
        if (now - it->second.last_update > max_age_seconds) {
            it = endpoints_.erase(it);
        } else {
            ++it;
        }
    }
}
