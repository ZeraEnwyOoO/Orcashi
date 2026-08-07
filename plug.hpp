// plug.hpp
#ifndef PLUG_HPP
#define PLUG_HPP

#include <string>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>

class TCPPlug {
public:
    TCPPlug();
    ~TCPPlug();
    
    bool create_plug(int port);
    bool connect_to_plug(const std::string& target_ip, int port);
    bool send_message(const std::string& msg);
    bool receive_message(std::string& msg, int timeout_ms = 100);
    bool is_connected() const;
    std::string get_peer_id() const;
    std::string get_peer_ip() const;
    void close_connection();
    
private:
    int plug_socket;
    int client_socket;
    std::atomic<bool> connected;
    std::atomic<bool> running;
    std::string peer_id;
    std::string peer_ip;
    
    std::thread receive_thread;
    std::thread send_thread;
    std::queue<std::string> message_queue;
    std::queue<std::string> send_queue;
    std::mutex queue_mtx;
    std::mutex send_mtx;
    std::condition_variable cv;
    
    void receive_loop();
    void send_loop();
};

#endif
