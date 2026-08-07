// orcashi.hpp
#ifndef ORCASHI_HPP
#define ORCASHI_HPP

#include "plug.hpp"
#include <string>
#include <atomic>
#include <thread>

class ORCASHI {
public:
    ORCASHI();
    ~ORCASHI();
    
    // Initialize ORCASHI
    bool init();  // ← បន្ថែម!
    
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
    bool register_identity();  // ← បន្ថែម!
    
    // Peer management
    void show_peers();
    
    // Help
    void show_help();
    
private:
    TCPPlug plug;
    std::string my_id;
    std::atomic<bool> running;
    std::thread ui_thread;
    bool is_ish_mode;
    
    bool detect_ish();
    std::string generate_id();
    void ui_loop();
    void show_banner();
    std::string get_local_ip();
    std::string get_hidden_password();
};

#endif
