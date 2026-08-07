// plug.cpp
#include "plug.hpp"
#include <iostream>
#include <cstring>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/tcp.h>

using namespace std;

TCPPlug::TCPPlug() : plug_socket(-1), client_socket(-1), connected(false), running(true) {}

TCPPlug::~TCPPlug() {
    running = false;
    if (receive_thread.joinable()) receive_thread.join();
    if (send_thread.joinable()) send_thread.join();
    close_connection();
}

bool TCPPlug::create_plug(int port) {
    plug_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (plug_socket < 0) {
        cout << "\033[31m[ERROR] Failed to create socket!\033[0m" << endl;
        return false;
    }
    
    int opt = 1;
    setsockopt(plug_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(plug_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        cout << "\033[31m[ERROR] Failed to bind to port " << port << "!\033[0m" << endl;
        close(plug_socket);
        return false;
    }
    
    if (listen(plug_socket, 5) < 0) {
        cout << "\033[31m[ERROR] Failed to listen!\033[0m" << endl;
        close(plug_socket);
        return false;
    }
    
    cout << "\033[32m[ORCA] TCP Plug is ready on port " << port << "!\033[0m" << endl;
    cout << "\033[36m[ORCA] Waiting for connection...\033[0m" << endl;
    
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    client_socket = accept(plug_socket, (struct sockaddr*)&client_addr, &addr_len);
    if (client_socket < 0) {
        cout << "\033[31m[ERROR] Failed to accept connection!\033[0m" << endl;
        close(plug_socket);
        return false;
    }
    
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
    peer_ip = string(ip);
    peer_id = peer_ip;
    connected = true;
    
    cout << "\033[32m[ORCA] Client connected from " << peer_ip << "!\033[0m" << endl;
    
    int flag = 1;
    setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
    receive_thread = thread(&TCPPlug::receive_loop, this);
    send_thread = thread(&TCPPlug::send_loop, this);
    
    return true;
}

bool TCPPlug::connect_to_plug(const std::string& target_ip, int port) {
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        cout << "\033[31m[ERROR] Failed to create socket!\033[0m" << endl;
        return false;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);
    
    if (connect(client_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        cout << "\033[31m[ERROR] Failed to connect to " << target_ip << ":" << port << "!\033[0m" << endl;
        close(client_socket);
        return false;
    }
    
    peer_ip = target_ip;
    peer_id = target_ip;
    connected = true;
    
    cout << "\033[32m[ORCA] Connected to " << target_ip << ":" << port << "!\033[0m" << endl;
    
    int flag = 1;
    setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
    receive_thread = thread(&TCPPlug::receive_loop, this);
    send_thread = thread(&TCPPlug::send_loop, this);
    
    return true;
}

void TCPPlug::send_loop() {
    while (running && connected) {
        string msg;
        {
            unique_lock<mutex> lock(queue_mtx);
            if (!cv.wait_for(lock, chrono::milliseconds(100), [this] { return !send_queue.empty() || !running; })) {
                continue;
            }
            if (!running) break;
            msg = send_queue.front();
            send_queue.pop();
        }
        
        string msg_with_newline = msg + "\n";
        lock_guard<mutex> lock(send_mtx);
        int n = send(client_socket, msg_with_newline.c_str(), msg_with_newline.length(), MSG_NOSIGNAL);
        if (n <= 0) {
            cout << "\033[33m[ORCA] Send failed. Connection may be closed.\033[0m" << endl;
            connected = false;
            break;
        }
    }
}

void TCPPlug::receive_loop() {
    char buffer[4096];
    string accumulated;
    
    while (running && connected) {
        int n = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (n <= 0) {
            cout << "\033[33m[ORCA] Connection closed by peer.\033[0m" << endl;
            connected = false;
            break;
        }
        
        buffer[n] = '\0';
        accumulated += buffer;
        
        size_t pos;
        while ((pos = accumulated.find('\n')) != string::npos) {
            string msg = accumulated.substr(0, pos);
            accumulated.erase(0, pos + 1);
            if (!msg.empty()) {
                lock_guard<mutex> lock(queue_mtx);
                message_queue.push(msg);
            }
        }
    }
}

bool TCPPlug::send_message(const std::string& msg) {
    if (!connected) return false;
    lock_guard<mutex> lock(queue_mtx);
    send_queue.push(msg);
    cv.notify_one();
    return true;
}

bool TCPPlug::receive_message(std::string& msg, int timeout_ms) {
    unique_lock<mutex> lock(queue_mtx);
    if (timeout_ms > 0) {
        if (!cv.wait_for(lock, chrono::milliseconds(timeout_ms), [this] { return !message_queue.empty(); })) {
            return false;
        }
    } else {
        cv.wait(lock, [this] { return !message_queue.empty(); });
    }
    if (message_queue.empty()) return false;
    msg = message_queue.front();
    message_queue.pop();
    return true;
}

bool TCPPlug::is_connected() const { return connected; }
std::string TCPPlug::get_peer_id() const { return peer_id; }
std::string TCPPlug::get_peer_ip() const { return peer_ip; }

void TCPPlug::close_connection() {
    running = false;
    if (client_socket >= 0) close(client_socket);
    if (plug_socket >= 0) close(plug_socket);
    connected = false;
    cv.notify_all();
}
