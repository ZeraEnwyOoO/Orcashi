 #ifndef ORCASHI_HPP
#define ORCASHI_HPP

#include "plug.hpp"
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
    
    bool init();
    bool create_room(int port = 9000);
    bool join_room(const std::string& ip, int port = 9000);
    bool send_message(const std::string& msg);
    bool receive_message(std::string& msg, int timeout_ms = 100);
    bool is_connected() const;
    void disconnect();
    
    std::string get_my_id() const;
    std::string get_peer_id() const;
    std::string get_peer_ip() const;
    
    bool register_identity();
    bool connect_peer(const std::string& id);
    bool add_peer(const std::string& id);
    bool check_requests();
    void show_peers();
    void show_help();
    
    // DHT (for compatibility)
    bool init_dht() { return false; }
    bool store_in_dht(const std::string& id, const std::string& endpoint) { return false; }
    std::string lookup_in_dht(const std::string& id) { return ""; }
    
private:
    TCPPlug plug;
    MDNS mdns;
    std::string my_id;
    std::atomic<bool> running;
    std::thread ui_thread;
    bool is_ish_mode;
    
    std::string get_local_ip();
    std::string get_hidden_password() { return ""; }
    std::string detect_usb() { return ""; }
    bool detect_ish();
    std::string generate_id();
    void ui_loop();
    void show_banner();
    
    // Unused functions (for compatibility)
    bool save_to_usb(const Identity&, const std::string&) { return false; }
    bool load_from_usb(Identity&, const std::string&) { return false; }
    bool register_normal_id() { return false; }
    bool register_verified_id() { return false; }
};

#endif
