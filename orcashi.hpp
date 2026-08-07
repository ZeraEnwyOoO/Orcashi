 #ifndef ORCASHI_HPP
#define ORCASHI_HPP

#include "plug.hpp"
#include <string>
#include <atomic>
#include <thread>
#include <ifaddrs.h>   // ← បន្ថែម!

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
    void show_peers();
    void show_help();
    
private:
    TCPPlug plug;
    std::string my_id;
    std::atomic<bool> running;
    std::thread ui_thread;
    bool is_ish_mode;
    
    bool register_normal_id();
    bool register_verified_id();
    std::string get_local_ip();      // ← Real now!
    std::string get_hidden_password();
    std::string detect_usb();        // ← Still simulation (v3.2)
    bool save_to_usb(const struct Identity& identity, const std::string& usb_path); // ← v3.2
    
    bool detect_ish();
    std::string generate_id();
    void ui_loop();
    void show_banner();
};

#endif
