 #include "dht_libtorrent.hpp"
#include <iostream>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>

using namespace std;

DHTLibtorrent::DHTLibtorrent() : initialized(false), running(false) {}

DHTLibtorrent::~DHTLibtorrent() {
    running = false;
    if (dht_thread.joinable()) dht_thread.join();
    session.reset();
}

string DHTLibtorrent::sha256(const string& input) {
    unsigned char hash[32];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input.c_str(), input.length());
    SHA256_Final(hash, &ctx);
    stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

bool DHTLibtorrent::init(int port) {
    if (initialized) return true;
    
    cout << "[DHT] Initializing libtorrent DHT on port " << port << endl;
    
    try {
        lt::settings_pack settings;
        settings.set_bool(lt::settings_pack::enable_dht, true);
        
        // libtorrent v2.0: use listen_interfaces instead of dht_port
        string listen_str = "0.0.0.0:" + to_string(port);
        settings.set_str(lt::settings_pack::listen_interfaces, listen_str);
        
        session = std::make_unique<lt::session>(settings);
        
        running = true;
        dht_thread = thread(&DHTLibtorrent::dht_loop, this);
        
        initialized = true;
        cout << "[DHT] libtorrent DHT initialized on port " << port << "!" << endl;
        return true;
        
    } catch (const std::exception& e) {
        cerr << "[DHT] Failed to initialize: " << e.what() << endl;
        return false;
    }
}

void DHTLibtorrent::dht_loop() {
    while (running) {
        try {
            session->wait_for_alert(chrono::seconds(5));
            vector<lt::alert*> alerts;
            session->pop_alerts(&alerts);
            
            for (auto* alert : alerts) {
                if (auto* dht_alert = lt::alert_cast<lt::dht_announce_alert>(alert)) {
                    cout << "[DHT] Announced: " << dht_alert->info_hash << endl;
                }
            }
        } catch (const std::exception& e) {
            cerr << "[DHT] Loop error: " << e.what() << endl;
        }
    }
}

bool DHTLibtorrent::put(const string& key, const string& value) {
    if (!initialized) {
        cerr << "[DHT] DHT not initialized!" << endl;
        return false;
    }
    
    cout << "[DHT] Storing " << key << " -> " << value << endl;
    {
        lock_guard<mutex> lock(mtx);
        local_cache[key] = value;
    }
    return true;
}

string DHTLibtorrent::get(const string& key) {
    if (!initialized) {
        cerr << "[DHT] DHT not initialized!" << endl;
        return "";
    }
    
    cout << "[DHT] Looking up " << key << endl;
    {
        lock_guard<mutex> lock(mtx);
        auto it = local_cache.find(key);
        if (it != local_cache.end()) {
            cout << "[DHT] Found in cache: " << it->second << endl;
            return it->second;
        }
    }
    return "";
}
