 // orcashi.hpp - ORCASHI v3.1 with DHT + mDNS
#ifndef ORCASHI_HPP
#define ORCASHI_HPP

#include "plug.hpp"
#include "dht.hpp"
#include "mdns.hpp"
#include <string>
#include <atomic>
#include <thread>

struct Identity {
    std::string id;
    std::string name;
    std::string role;
    std::string public_key;
    std::string private_key_encrypted;
    std::string signature;
};

class ORCASHI {
public:
    ORCASHI();
    ~ORCASHI();
    
    // Initialize
    bool init();
    
    // Room management
    bool create_room(int port = 9000);
    bool join_room(const std::string& ip, int port = 9000);
    
    // Messaging
    bool send_message(const std::string& msg);
    bool receive_message(std::string& msg, int timeout_ms = 100);
    
    // Connection status
    bool is_connected() const;
    void disconnect();
    
    // Identity
    std::string get_my_id() const;
    std::string get_peer_id() const;
    std::string get_peer_ip() const;
    
    // Registration
    bool register_identity();
    
    // Peer Management
    bool connect_peer(const std::string& id);
    bool add_peer(const std::string& id);
    bool check_requests();
    void show_peers();
    void show_help();
    
    // DHT
    bool init_dht();
    bool store_in_dht(const std::string& id, const std::string& endpoint);
    std::string lookup_in_dht(const std::string& id);
    
    // mDNS
    bool init_mdns();
    bool publish_mdns(const std::string& id, int port);
    std::string lookup_mdns(const std::string& id);
    
private:
    TCPPlug plug;
    DHT dht;
    MDNS mdns;
    std::string my_id;
    std::atomic<bool> running;
    std::thread ui_thread;
    bool is_ish_mode;
    
    // Registration functions
    bool register_normal_id();
    bool register_verified_id();
    std::string get_local_ip();
    std::string get_hidden_password();
    std::string detect_usb();
    bool save_to_usb(const Identity& identity, const std::string& usb_path);
    bool load_from_usb(Identity& identity, const std::string& usb_path);
    
    // Core functions
    bool detect_ish();
    std::string generate_id();
    void ui_loop();
    void show_banner();
};

#endif
