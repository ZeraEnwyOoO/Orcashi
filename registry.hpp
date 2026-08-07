// registry.cpp
#include "registry.hpp"
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <sstream>

using namespace std;

Registry::Registry() {
    string home = getenv("HOME");
    registry_file = home + "/.orcashi/registry.json";
    
    // Create directory if not exists
    string dir = registry_file.substr(0, registry_file.find_last_of('/'));
    string cmd = "mkdir -p " + dir;
    system(cmd.c_str());
    
    load();
}

bool Registry::register_peer(const string& id, const string& ip, const string& port) {
    // Check if ID already exists
    if (peers.find(id) != peers.end()) {
        cout << "  [ERROR] ID " << id << " already registered!\n";
        return false;
    }
    
    Peer peer;
    peer.id = id;
    peer.ip = ip;
    peer.port = port;
    peer.online = true;
    peer.last_seen = time(nullptr);
    
    peers[id] = peer;
    save();
    return true;
}

bool Registry::get_peer(const string& id, Peer& out_peer) {
    auto it = peers.find(id);
    if (it != peers.end()) {
        out_peer = it->second;
        return true;
    }
    return false;
}

void Registry::update_peer(const string& id, const string& ip, const string& port) {
    auto it = peers.find(id);
    if (it != peers.end()) {
        it->second.ip = ip;
        it->second.port = port;
        it->second.last_seen = time(nullptr);
        save();
    }
}

void Registry::set_online(const string& id, bool online) {
    auto it = peers.find(id);
    if (it != peers.end()) {
        it->second.online = online;
        it->second.last_seen = time(nullptr);
        save();
    }
}

vector<Peer> Registry::get_all_peers() {
    vector<Peer> result;
    for (auto& pair : peers) {
        result.push_back(pair.second);
    }
    return result;
}

vector<Peer> Registry::get_online_peers() {
    vector<Peer> result;
    for (auto& pair : peers) {
        if (pair.second.online) {
            result.push_back(pair.second);
        }
    }
    return result;
}

bool Registry::remove_peer(const string& id) {
    auto it = peers.find(id);
    if (it != peers.end()) {
        peers.erase(it);
        save();
        return true;
    }
    return false;
}

bool Registry::peer_exists(const string& id) {
    return peers.find(id) != peers.end();
}

void Registry::load() {
    ifstream f(registry_file);
    if (!f.is_open()) return;
    
    string line;
    Peer peer;
    bool in_peer = false;
    
    while (getline(f, line)) {
        // Find ID
        if (line.find("\"id\":\"") != string::npos) {
            size_t start = line.find("\"id\":\"") + 6;
            size_t end = line.find("\"", start);
            peer.id = line.substr(start, end - start);
            in_peer = true;
        }
        
        // Find IP
        if (line.find("\"ip\":\"") != string::npos && in_peer) {
            size_t start = line.find("\"ip\":\"") + 6;
            size_t end = line.find("\"", start);
            peer.ip = line.substr(start, end - start);
        }
        
        // Find Port
        if (line.find("\"port\":\"") != string::npos && in_peer) {
            size_t start = line.find("\"port\":\"") + 8;
            size_t end = line.find("\"", start);
            peer.port = line.substr(start, end - start);
        }
        
        // Find Online
        if (line.find("\"online\":") != string::npos && in_peer) {
            size_t start = line.find("\"online\":") + 9;
            size_t end = line.find(",", start);
            if (end == string::npos) end = line.find("}", start);
            string val = line.substr(start, end - start);
            peer.online = (val.find("true") != string::npos);
        }
        
        // End of peer
        if (line.find("}") != string::npos && in_peer) {
            if (!peer.id.empty()) {
                peers[peer.id] = peer;
                peer = Peer(); // Reset
                in_peer = false;
            }
        }
    }
    
    f.close();
}

void Registry::save() {
    ofstream f(registry_file);
    if (!f.is_open()) return;
    
    f << "{\n  \"peers\": [\n";
    
    bool first = true;
    for (auto& pair : peers) {
        if (!first) f << ",\n";
        first = false;
        
        Peer& p = pair.second;
        f << "    {\n";
        f << "      \"id\": \"" << p.id << "\",\n";
        f << "      \"ip\": \"" << p.ip << "\",\n";
        f << "      \"port\": \"" << p.port << "\",\n";
        f << "      \"online\": " << (p.online ? "true" : "false") << ",\n";
        f << "      \"last_seen\": " << p.last_seen << "\n";
        f << "    }";
    }
    
    f << "\n  ]\n}\n";
    f.close();
}
