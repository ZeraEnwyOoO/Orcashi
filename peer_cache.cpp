// peer_cache.cpp
#include "peer_cache.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

using namespace std;

PeerCache::PeerCache(const string& cache_file) {
    if (cache_file.empty()) {
        string home = getenv("HOME");
        cache_file_ = home + "/.orcashi/peers.json";
    } else {
        cache_file_ = cache_file;
    }
    
    string dir = cache_file_.substr(0, cache_file_.find_last_of('/'));
    string cmd = "mkdir -p " + dir;
    system(cmd.c_str());
    
    load();
}

void PeerCache::save_peer(const PeerInfo& peer) {
    lock_guard<mutex> lock(mtx_);
    cache_[peer.id] = peer;
    save();
}

bool PeerCache::get_peer(const string& id, PeerInfo& out_peer) {
    lock_guard<mutex> lock(mtx_);
    auto it = cache_.find(id);
    if (it != cache_.end()) {
        out_peer = it->second;
        return true;
    }
    return false;
}

vector<PeerInfo> PeerCache::get_all_peers() {
    lock_guard<mutex> lock(mtx_);
    vector<PeerInfo> result;
    for (const auto& pair : cache_) {
        result.push_back(pair.second);
    }
    return result;
}

void PeerCache::remove_peer(const string& id) {
    lock_guard<mutex> lock(mtx_);
    cache_.erase(id);
    save();
}

void PeerCache::clear() {
    lock_guard<mutex> lock(mtx_);
    cache_.clear();
    save();
}

void PeerCache::load() {
    if (!file_exists(cache_file_)) return;
    
    string content = read_file(cache_file_);
    if (content.empty()) return;
    
    // Simple JSON parsing (for now, just parse lines)
    istringstream iss(content);
    string line;
    while (getline(iss, line)) {
        if (line.find("{\"id\":\"") != string::npos) {
            PeerInfo peer;
            // Parse ID
            size_t id_start = line.find("\"id\":\"") + 6;
            size_t id_end = line.find("\"", id_start);
            peer.id = line.substr(id_start, id_end - id_start);
            
            // Parse endpoint
            size_t ep_start = line.find("\"endpoint\":\"") + 12;
            size_t ep_end = line.find("\"", ep_start);
            peer.endpoint = line.substr(ep_start, ep_end - ep_start);
            
            // Parse IP
            size_t ip_start = line.find("\"ip\":\"") + 6;
            size_t ip_end = line.find("\"", ip_start);
            peer.ip = line.substr(ip_start, ip_end - ip_start);
            
            // Parse port
            size_t port_start = line.find("\"port\":") + 7;
            size_t port_end = line.find(",", port_start);
            peer.port = stoi(line.substr(port_start, port_end - port_start));
            
            // Parse online status
            size_t online_start = line.find("\"online\":") + 9;
            size_t online_end = line.find(",", online_start);
            peer.online = line.substr(online_start, online_end - online_start) == "true";
            
            lock_guard<mutex> lock(mtx_);
            cache_[peer.id] = peer;
        }
    }
}

void PeerCache::save() {
    stringstream ss;
    ss << "{\n  \"peers\": [\n";
    
    bool first = true;
    for (const auto& pair : cache_) {
        if (!first) ss << ",\n";
        first = false;
        
        const PeerInfo& p = pair.second;
        ss << "    {\n";
        ss << "      \"id\": \"" << p.id << "\",\n";
        ss << "      \"endpoint\": \"" << p.endpoint << "\",\n";
        ss << "      \"ip\": \"" << p.ip << "\",\n";
        ss << "      \"port\": " << p.port << ",\n";
        ss << "      \"online\": " << (p.online ? "true" : "false") << ",\n";
        ss << "      \"last_seen\": " << p.last_seen << "\n";
        ss << "    }";
    }
    
    ss << "\n  ]\n}\n";
    
    write_file(cache_file_, ss.str());
}

bool PeerCache::file_exists(const string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

string PeerCache::read_file(const string& path) {
    ifstream f(path);
    if (!f.is_open()) return "";
    string content((istreambuf_iterator<char>(f)), istreambuf_iterator<char>());
    return content;
}

void PeerCache::write_file(const string& path, const string& content) {
    ofstream f(path);
    if (f.is_open()) {
        f << content;
        f.close();
    }
}
