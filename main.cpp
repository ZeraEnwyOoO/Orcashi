 // main.cpp - ORCASHI v3.1
#include "orcashi.hpp"
#include "discovery.hpp"
#include "endpoint.hpp"
#include "peer_cache.hpp"
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstdlib>

using namespace std;

int main(int argc, char* argv[]) {
    ORCASHI orcashi;
    
    // Initialize discovery
    Discovery discovery;
    discovery.init();
    discovery.start();
    
    // Initialize peer cache
    PeerCache cache;
    
    // Show peers on startup
    cout << "\n[ORCA] Loading saved peers..." << endl;
    auto saved_peers = cache.get_all_peers();
    if (!saved_peers.empty()) {
        for (const auto& peer : saved_peers) {
            cout << "  " << peer.id << " (" << (peer.online ? "online" : "offline") << ")" << endl;
        }
    } else {
        cout << "  No saved peers" << endl;
    }
    
    if (argc < 2) {
        cout << "\nORCASHI v3.1 - P2P Chat with Discovery" << endl;
        cout << "Usage:" << endl;
        cout << "  ./orcashi create              - Create room (iSH)" << endl;
        cout << "  ./orcashi join <ip>           - Join room by IP" << endl;
        cout << "  ./orcashi connect <id>        - Connect by ID (Auto-discovery)" << endl;
        cout << "  ./orcashi search <name>       - Search for peer" << endl;
        cout << "  ./orcashi peers               - Show saved peers" << endl;
        cout << "  ./orcashi --help              - Show help" << endl;
        discovery.stop();
        return 0;
    }
    
    string cmd = argv[1];
    
    if (cmd == "create") {
        orcashi.create_room();
        
        // Broadcast presence
        string my_id = orcashi.get_my_id();
        string local_ip = discovery.get_local_ip();
        discovery.broadcast_presence(my_id, local_ip + ":9000");
        
        string msg;
        while (orcashi.is_connected()) {
            if (orcashi.receive_message(msg)) {
                cout << "\r\033[K[" << orcashi.get_peer_id() << "]> " << msg << endl;
                cout << orcashi.get_my_id() << "> " << flush;
            }
        }
    } 
    else if (cmd == "join" && argc >= 3) {
        orcashi.join_room(argv[2]);
        
        string msg;
        while (orcashi.is_connected()) {
            if (orcashi.receive_message(msg)) {
                cout << "\r\033[K[" << orcashi.get_peer_id() << "]> " << msg << endl;
                cout << orcashi.get_my_id() << "> " << flush;
            }
        }
    } 
    else if (cmd == "connect" && argc >= 3) {
        string id = argv[2];
        cout << "[ORCA] Looking for " << id << "..." << endl;
        
        // Try to find peer
        PeerInfo peer;
        if (discovery.find_peer(id, peer)) {
            cout << "[ORCA] Found " << id << " at " << peer.endpoint << endl;
            orcashi.join_room(peer.ip);
            
            // Save to cache
            cache.save_peer(peer);
            
            string msg;
            while (orcashi.is_connected()) {
                if (orcashi.receive_message(msg)) {
                    cout << "\r\033[K[" << orcashi.get_peer_id() << "]> " << msg << endl;
                    cout << orcashi.get_my_id() << "> " << flush;
                }
            }
        } else {
            cout << "[ORCA] Peer not in cache. Broadcasting search..." << endl;
            discovery.broadcast_search(id);
            
            // Wait for response
            cout << "[ORCA] Waiting for response..." << endl;
            this_thread::sleep_for(chrono::seconds(3));
            
            if (discovery.find_peer(id, peer)) {
                cout << "[ORCA] Found " << id << " at " << peer.endpoint << endl;
                orcashi.join_room(peer.ip);
                cache.save_peer(peer);
                
                string msg;
                while (orcashi.is_connected()) {
                    if (orcashi.receive_message(msg)) {
                        cout << "\r\033[K[" << orcashi.get_peer_id() << "]> " << msg << endl;
                        cout << orcashi.get_my_id() << "> " << flush;
                    }
                }
            } else {
                cout << "[ORCA] Peer not found!" << endl;
            }
        }
    } 
    else if (cmd == "search" && argc >= 3) {
        string query = argv[2];
        cout << "[ORCA] Searching for: " << query << endl;
        
        // Broadcast search
        discovery.broadcast_search(query);
        
        // Wait for responses
        this_thread::sleep_for(chrono::seconds(2));
        
        auto peers = discovery.get_discovered_peers();
        bool found = false;
        for (const auto& peer : peers) {
            if (peer.id.find(query) != string::npos || peer.id == query) {
                cout << "  Found: " << peer.id << " at " << peer.endpoint << endl;
                found = true;
            }
        }
        if (!found) {
            cout << "  No peers found matching: " << query << endl;
        }
    } 
    else if (cmd == "peers") {
        auto peers = cache.get_all_peers();
        cout << "\n[ORCA] Saved Peers:" << endl;
        if (peers.empty()) {
            cout << "  No saved peers" << endl;
        } else {
            for (const auto& peer : peers) {
                cout << "  " << peer.id 
                     << " (" << (peer.online ? "\033[32monline\033[0m" : "\033[31moffline\033[0m") 
                     << ") at " << peer.endpoint << endl;
            }
        }
    } 
    else if (cmd == "--help" || cmd == "-h") {
        cout << "\nORCASHI v3.1 - P2P Chat with Discovery" << endl;
        cout << "========================================" << endl;
        cout << "Usage:" << endl;
        cout << "  ./orcashi create              - Create room (iSH)" << endl;
        cout << "  ./orcashi join <ip>           - Join room by IP" << endl;
        cout << "  ./orcashi connect <id>        - Connect by ID (Auto-discovery)" << endl;
        cout << "  ./orcashi search <name>       - Search for peer" << endl;
        cout << "  ./orcashi peers               - Show saved peers" << endl;
        cout << "  ./orcashi --help              - Show this help" << endl;
        cout << "\nCommands:" << endl;
        cout << "  Type /help during chat for more options" << endl;
        cout << "  Type /exit to disconnect" << endl;
    } 
    else {
        cout << "Unknown command: " << cmd << endl;
        cout << "Use ./orcashi --help for usage." << endl;
    }
    
    discovery.stop();
    return 0;
}
