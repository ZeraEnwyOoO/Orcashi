// orcashi.cpp
// ORCASHI v2.0 - Auto-Detect P2P Chat (iSH + Linux)
// Compile: g++ -o orcashi orcashi.cpp -lpthread -std=c++17

#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <chrono>
#include <sys/utsname.h>
#include <thread>
#include <ctime>
#include <cstdlib>
#include <random>
#include <atomic>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <iomanip>
#include <algorithm>
#include <sys/file.h>
#include <sys/wait.h>

using namespace std;

// ==================== COLORS ====================
const string CYAN = "\033[36m";
const string GREEN = "\033[32m";
const string YELLOW = "\033[33m";
const string RED = "\033[31m";
const string RESET = "\033[0m";

// ==================== CONFIG ====================
const string ORCASHI_HOME = string(getenv("HOME")) + "/.orcashi/";
const int P2P_PORT_START = 9000;
const int PLUG_PORT = 9000;
const int HEARTBEAT_INTERVAL = 30;
const int MAX_RETRANSMIT = 3;
const int ACK_TIMEOUT = 2000;
const int PEER1_TIMEOUT = 300;
const int PEER2_TIMEOUT = 120;
const int MAX_PORTS_TO_PUNCH = 1000;

// ==================== THREAD-SAFE QUEUE ====================
template<typename T>
class ThreadSafeQueue {
private:
    queue<T> q;
    mutex mtx;
    condition_variable cv;
    
public:
    void push(const T& item) {
        lock_guard<mutex> lock(mtx);
        q.push(item);
        cv.notify_one();
    }
    
    bool pop(T& item, int timeout_ms = 0) {
        unique_lock<mutex> lock(mtx);
        if (timeout_ms > 0) {
            if (!cv.wait_for(lock, chrono::milliseconds(timeout_ms), [this] { return !q.empty(); })) {
                return false;
            }
        } else {
            cv.wait(lock, [this] { return !q.empty(); });
        }
        if (q.empty()) return false;
        item = q.front();
        q.pop();
        return true;
    }
    
    size_t size() {
        lock_guard<mutex> lock(mtx);
        return q.size();
    }
};

// ==================== ID SYSTEM ====================
class IDSystem {
private:
    string id_file;
    int my_id;
    mutex mtx;
    
    bool is_valid(int id) { return id >= 1 && id <= 999; }
    
    int read_id() {
        ifstream f(id_file);
        if (!f.is_open()) return -1;
        int id;
        if (f >> id && is_valid(id)) return id;
        return -1;
    }
    
    void write_id(int id) {
        ofstream f(id_file);
        if (f.is_open()) f << id;
    }
    
public:
    IDSystem() {
        string cmd = "mkdir -p " + ORCASHI_HOME;
        system(cmd.c_str());
        id_file = ORCASHI_HOME + "id";
        
        int existing = read_id();
        if (is_valid(existing)) {
            my_id = existing;
        } else {
            random_device rd;
            mt19937 gen(rd());
            uniform_int_distribution<> dis(1, 999);
            my_id = dis(gen);
            write_id(my_id);
        }
    }
    
    int get_id() { return my_id; }
    
    string get_display() {
        stringstream ss;
        ss << "<" << setw(3) << setfill('0') << my_id << ">";
        return ss.str();
    }
};

// ==================== RELIABLE MESSAGE ====================
struct ReliableMessage {
    int id;
    string content;
    int retries;
    chrono::steady_clock::time_point sent_time;
    bool receipt_confirmed;
    
    ReliableMessage() : id(0), retries(0), receipt_confirmed(false) {}
    ReliableMessage(int i, const string& c) : id(i), content(c), retries(0), receipt_confirmed(false) {}
};

// ==================== UDP HOLE PUNCHER (Linux Normal Mode) ====================
class UDPHolePuncher {
private:
    int udp_socket;
    string peer_id;
    string peer_ip;
    int peer_port;
    bool connected;
    int local_port;
    int next_msg_id;
    map<int, ReliableMessage> pending_messages;
    mutex pending_mutex;
    mutex socket_mutex;
    thread retransmit_thread;
    atomic<bool> running;
    
    bool create_socket(int port) {
        udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_socket < 0) return false;
        
        int opt = 1;
        setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(udp_socket, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        
        if (bind(udp_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(udp_socket);
            return false;
        }
        
        int flags = fcntl(udp_socket, F_GETFL, 0);
        fcntl(udp_socket, F_SETFL, flags | O_NONBLOCK);
        
        local_port = port;
        return true;
    }
    
    bool send_to_peer(const string& msg) {
        lock_guard<mutex> lock(socket_mutex);
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(peer_port);
        inet_pton(AF_INET, peer_ip.c_str(), &addr.sin_addr);
        
        int n = sendto(udp_socket, msg.c_str(), msg.length(), 0,
                       (struct sockaddr*)&addr, sizeof(addr));
        return n > 0;
    }
    
    void retransmit_loop() {
        while (running) {
            this_thread::sleep_for(chrono::milliseconds(500));
            auto now = chrono::steady_clock::now();
            lock_guard<mutex> lock(pending_mutex);
            
            vector<int> to_remove;
            for (auto& pair : pending_messages) {
                int id = pair.first;
                ReliableMessage& msg = pair.second;
                auto elapsed = chrono::duration_cast<chrono::milliseconds>(now - msg.sent_time).count();
                if (elapsed > ACK_TIMEOUT) {
                    if (msg.retries < MAX_RETRANSMIT && !msg.receipt_confirmed) {
                        send_to_peer(msg.content);
                        msg.retries++;
                        msg.sent_time = now;
                    } else {
                        to_remove.push_back(id);
                    }
                }
            }
            for (int id : to_remove) pending_messages.erase(id);
        }
    }
    
public:
    UDPHolePuncher() : udp_socket(-1), peer_port(0), connected(false),
                       local_port(0), next_msg_id(1), running(true) {}
    
    ~UDPHolePuncher() {
        running = false;
        if (retransmit_thread.joinable()) retransmit_thread.join();
        close_connection();
    }
    
    bool init(int port) {
        return create_socket(port);
    }
    
    bool try_hole_punch(const string& target_ip, int target_port, const string& my_id) {
        cout << "[ORCA] Trying hole punch to " << target_ip << ":" << target_port << endl;
        
        string punch = "PUNCH:" + my_id;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target_port);
        inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);
        
        for (int i = 0; i < 3; i++) {
            sendto(udp_socket, punch.c_str(), punch.length(), 0,
                   (struct sockaddr*)&addr, sizeof(addr));
            usleep(100000);
        }
        
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(udp_socket, &fds);
        
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        
        int ret = select(udp_socket + 1, &fds, NULL, NULL, &tv);
        if (ret > 0) {
            char buffer[1024];
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);
            int n = recvfrom(udp_socket, buffer, sizeof(buffer) - 1, 0,
                            (struct sockaddr*)&from, &from_len);
            if (n > 0) {
                buffer[n] = '\0';
                string msg(buffer);
                if (msg.find("CONNECT:") == 0) {
                    peer_id = msg.substr(8);
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
                    peer_ip = string(ip);
                    peer_port = ntohs(from.sin_port);
                    connected = true;
                    return true;
                }
            }
        }
        return false;
    }
    
    void listen_for_connection(const string& my_id, int timeout_sec) {
        cout << "[ORCA] Listening for connection..." << endl;
        
        auto start = chrono::steady_clock::now();
        while (!connected && chrono::duration_cast<chrono::seconds>(chrono::steady_clock::now() - start).count() < timeout_sec) {
            string msg;
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(udp_socket, &fds);
            
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            
            int ret = select(udp_socket + 1, &fds, NULL, NULL, &tv);
            if (ret > 0) {
                char buffer[1024];
                struct sockaddr_in from;
                socklen_t from_len = sizeof(from);
                int n = recvfrom(udp_socket, buffer, sizeof(buffer) - 1, 0,
                                (struct sockaddr*)&from, &from_len);
                if (n > 0) {
                    buffer[n] = '\0';
                    msg = string(buffer);
                    
                    if (msg.find("PUNCH:") == 0) {
                        string sender_id = msg.substr(6);
                        char ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
                        
                        string connect_msg = "CONNECT:" + my_id;
                        struct sockaddr_in addr;
                        memset(&addr, 0, sizeof(addr));
                        addr.sin_family = AF_INET;
                        addr.sin_port = from.sin_port;
                        addr.sin_addr = from.sin_addr;
                        sendto(udp_socket, connect_msg.c_str(), connect_msg.length(), 0,
                               (struct sockaddr*)&addr, sizeof(addr));
                        
                        peer_id = sender_id;
                        peer_ip = string(ip);
                        peer_port = ntohs(from.sin_port);
                        connected = true;
                        break;
                    }
                }
            }
        }
    }
    
    bool send(const string& msg) {
        if (!connected) return false;
        
        bool need_receipt = true;
        if (msg.find("ACK:") == 0 || msg.find("HEARTBEAT") == 0 ||
            msg.find("PUNCH:") == 0 || msg.find("CONNECT:") == 0) {
            need_receipt = false;
        }
        
        if (!need_receipt) return send_to_peer(msg);
        
        int msg_id = next_msg_id++;
        string tagged_msg = "MSG:" + to_string(msg_id) + ":" + msg;
        lock_guard<mutex> lock(pending_mutex);
        pending_messages[msg_id] = ReliableMessage(msg_id, tagged_msg);
        return send_to_peer(tagged_msg);
    }
    
    bool wait_for_message(string& msg, int timeout_sec) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(udp_socket, &fds);
        
        struct timeval tv;
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;
        
        int ret = select(udp_socket + 1, &fds, NULL, NULL, &tv);
        if (ret > 0) {
            char buffer[65536];
            struct sockaddr_in from;
            socklen_t addr_len = sizeof(from);
            int n = recvfrom(udp_socket, buffer, sizeof(buffer) - 1, 0,
                            (struct sockaddr*)&from, &addr_len);
            if (n > 0) {
                buffer[n] = '\0';
                msg = string(buffer);
                return process_message(msg);
            }
        }
        return false;
    }
    
    bool process_message(string& msg) {
        if (msg.find("ACK_MSG:") == 0) {
            int msg_id = stoi(msg.substr(8));
            lock_guard<mutex> lock(pending_mutex);
            pending_messages.erase(msg_id);
            return false;
        }
        
        if (msg.find("MSG:") == 0) {
            size_t first_colon = msg.find(':', 4);
            if (first_colon != string::npos) {
                int msg_id = stoi(msg.substr(4, first_colon - 4));
                string real_msg = msg.substr(first_colon + 1);
                
                string ack = "ACK_MSG:" + to_string(msg_id);
                send_to_peer(ack);
                
                msg = real_msg;
                return true;
            }
        }
        return true;
    }
    
    bool is_connected() const { return connected; }
    string get_peer_id() const { return peer_id; }
    string get_peer_ip() const { return peer_ip; }
    int get_peer_port() const { return peer_port; }
    int get_local_port() const { return local_port; }
    
    void close_connection() {
        running = false;
        if (udp_socket >= 0) close(udp_socket);
        connected = false;
    }
};

// ==================== PLUG MODE (iSH) ====================
class PlugMode {
private:
    int plug_socket;
    int client_socket;
    bool connected;
    ThreadSafeQueue<string> message_queue;
    thread receive_thread;
    thread send_thread;
    atomic<bool> running;
    string peer_id;
    
public:
    PlugMode() : plug_socket(-1), client_socket(-1), connected(false), running(true) {}
    
    ~PlugMode() {
        running = false;
        if (receive_thread.joinable()) receive_thread.join();
        if (send_thread.joinable()) send_thread.join();
        close_connection();
    }
    
    bool create_plug(int port) {
        plug_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (plug_socket < 0) return false;
        
        int opt = 1;
        setsockopt(plug_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        
        if (bind(plug_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(plug_socket);
            return false;
        }
        
        if (listen(plug_socket, 5) < 0) {
            close(plug_socket);
            return false;
        }
        
        cout << GREEN << "[ORCA] Plug is ready on port " << port << "!" << RESET << endl;
        cout << CYAN << "[ORCA] Waiting for Linux to connect..." << RESET << endl;
        
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        client_socket = accept(plug_socket, (struct sockaddr*)&client_addr, &addr_len);
        if (client_socket < 0) {
            close(plug_socket);
            return false;
        }
        
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        peer_id = string(ip);
        connected = true;
        
        cout << GREEN << "[ORCA] Linux connected from " << peer_id << "!" << RESET << endl;
        
        // Start threads
        receive_thread = thread(&PlugMode::receive_loop, this);
        send_thread = thread(&PlugMode::send_loop, this);
        
        return true;
    }
    
    void receive_loop() {
        char buffer[4096];
        while (running && connected) {
            int n = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
            if (n <= 0) {
                connected = false;
                break;
            }
            buffer[n] = '\0';
            message_queue.push(string(buffer));
        }
    }
    
    void send_loop() {
        while (running && connected) {
            string msg;
            if (message_queue.pop(msg, 100)) {
                send(client_socket, msg.c_str(), msg.length(), 0);
            }
        }
    }
    
    bool send_message(const string& msg) {
        if (!connected) return false;
        message_queue.push(msg);
        return true;
    }
    
    bool receive_message(string& msg, int timeout_ms = 100) {
        return message_queue.pop(msg, timeout_ms);
    }
    
    bool is_connected() const { return connected; }
    string get_peer_id() const { return peer_id; }
    
    void close_connection() {
        running = false;
        if (client_socket >= 0) close(client_socket);
        if (plug_socket >= 0) close(plug_socket);
        connected = false;
    }
};

// ==================== ORCASHI MAIN ====================
class ORCASHI {
private:
    IDSystem id_system;
    UDPHolePuncher p2p;
    PlugMode plug;
    string room_code;
    string peer_id;
    string peer_ip;
    int peer_port;
    atomic<bool> running;
    ThreadSafeQueue<string> message_queue;
    thread receive_thread;
    thread ui_thread;
    thread heartbeat_thread;
    bool is_ish_mode;
    
    bool detect_ish() {
        // Check /etc/os-release for Alpine
        ifstream f("/etc/os-release");
        if (f.is_open()) {
            string line;
            while (getline(f, line)) {
                if (line.find("Alpine") != string::npos) {
                    f.close();
                    return true;
                }
            }
            f.close();
        }
        
        // Check /proc/version for iOS
        ifstream f2("/proc/version");
        if (f2.is_open()) {
            string content;
            getline(f2, content);
            if (content.find("iOS") != string::npos || content.find("iPhone") != string::npos) {
                f2.close();
                return true;
            }
            f2.close();
        }
        
        // Check uname
        struct utsname uname_data;
        if (uname(&uname_data) == 0) {
            string sysname(uname_data.sysname);
            if (sysname.find("Darwin") != string::npos) {
                return true;
            }
        }
        
        return false;
    }
    
    void heartbeat_loop() {
        while (running && p2p.is_connected()) {
            this_thread::sleep_for(chrono::seconds(HEARTBEAT_INTERVAL));
            p2p.send("HEARTBEAT");
        }
    }
    
    void receive_loop() {
        while (running && p2p.is_connected()) {
            string incoming_msg;
            if (p2p.wait_for_message(incoming_msg, 0)) {
                if (!incoming_msg.empty()) {
                    if (incoming_msg == "HEARTBEAT") continue;
                    message_queue.push(incoming_msg);
                }
            } else {
                this_thread::sleep_for(chrono::milliseconds(10));
            }
        }
    }
    
    void ui_loop() {
        string input;
        while (running) {
            if (p2p.is_connected()) {
                cout << id_system.get_display() << "> " << flush;
            } else if (plug.is_connected()) {
                cout << id_system.get_display() << "> " << flush;
            } else {
                this_thread::sleep_for(chrono::milliseconds(100));
                continue;
            }
            
            if (!cin) {
                cout << "\n[ORCA] Input stream closed." << endl;
                running = false;
                break;
            }
            
            if (!getline(cin, input)) {
                if (cin.eof()) {
                    cout << "\n[ORCA] EOF detected. Exiting..." << endl;
                    running = false;
                    break;
                }
                this_thread::sleep_for(chrono::milliseconds(10));
                continue;
            }
            
            if (!running) break;
            
            if (input == "/exit") {
                running = false;
                break;
            }
            else if (input == "/help") {
                show_help();
            }
            else if (!input.empty()) {
                if (p2p.is_connected()) {
                    p2p.send(input);
                } else if (plug.is_connected()) {
                    plug.send_message(input);
                }
            }
        }
    }
    
    void show_help() {
        cout << "\n" << string(40, '=') << endl;
        cout << "ORCASHI v2.0 - P2P Chat" << endl;
        cout << string(40, '=') << endl;
        cout << "Commands:" << endl;
        cout << "  /help    - Show this help" << endl;
        cout << "  /exit    - Disconnect" << endl;
        if (is_ish_mode) {
            cout << "\nMode: iSH (Plug)" << endl;
        } else {
            cout << "\nMode: Linux (Normal P2P)" << endl;
        }
        cout << string(40, '=') << endl << endl;
    }
    
    void start_chat() {
        cout << string(50, '=') << endl;
        cout << "ORCASHI ACTIVE" << endl;
        cout << "Your ID: " << id_system.get_display() << endl;
        if (is_ish_mode) {
            cout << "Mode: iSH (Plug)" << endl;
        } else {
            cout << "Mode: Linux (Normal P2P)" << endl;
        }
        cout << "Type /help for commands" << endl;
        cout << string(50, '=') << endl << endl;
        
        if (p2p.is_connected()) {
            peer_id = p2p.get_peer_id();
            peer_ip = p2p.get_peer_ip();
            peer_port = p2p.get_peer_port();
            
            receive_thread = thread(&ORCASHI::receive_loop, this);
            ui_thread = thread(&ORCASHI::ui_loop, this);
            heartbeat_thread = thread(&ORCASHI::heartbeat_loop, this);
            
            string incoming;
            while (running && p2p.is_connected()) {
                if (message_queue.pop(incoming, 100)) {
                    cout << "\r\033[K[" << peer_id << "]> " << incoming << endl;
                    cout << id_system.get_display() << "> " << flush;
                }
            }
        } else if (plug.is_connected()) {
            peer_id = plug.get_peer_id();
            
            ui_thread = thread(&ORCASHI::ui_loop, this);
            
            string incoming;
            while (running && plug.is_connected()) {
                if (plug.receive_message(incoming, 100)) {
                    cout << "\r\033[K[" << peer_id << "]> " << incoming << endl;
                    cout << id_system.get_display() << "> " << flush;
                }
            }
        }
        
        running = false;
        if (receive_thread.joinable()) receive_thread.join();
        if (ui_thread.joinable()) ui_thread.join();
        if (heartbeat_thread.joinable()) heartbeat_thread.join();
        p2p.close_connection();
        plug.close_connection();
        
        cout << "\n[ORCASHI] Disconnected." << endl;
    }
    
public:
    ORCASHI() : running(true) {
        string cmd = "mkdir -p " + ORCASHI_HOME;
        system(cmd.c_str());
        
        is_ish_mode = detect_ish();
    }
    
    void show_banner() {
        cout << CYAN << R"(
============================================================
     ____   ____   ____    ____    _    ____
    / __ \ / __ \ / __ \  / __ \  | |  / __ \
   / / / // / / // / / / / / / /  | | / / / /
  / /_/ // /_/ // /_/ / / /_/ /   | |/ /_/ /
 /_____/ \____/ \____/  \____/    |___\____/

            ORCASHI v2.0 - P2P Chat
        (Auto-Detect: iSH Plug + Linux P2P)
============================================================
)" << RESET << endl;
        
        cout << "\nYour ID: " << id_system.get_display() << endl;
        if (is_ish_mode) {
            cout << GREEN << "Mode: iSH (Plug)" << RESET << endl;
        } else {
            cout << GREEN << "Mode: Linux (Normal P2P)" << RESET << endl;
        }
        cout << "Type /help for commands" << endl;
    }
    
    void create_room() {
        cout << "\n" << string(50, '=') << endl;
        cout << "ORCASHI - CREATE ROOM" << endl;
        cout << string(50, '=') << endl;
        
        if (is_ish_mode) {
            // iSH Mode: Plug
            cout << CYAN << "[ORCA] iSH Mode: Creating plug..." << RESET << endl;
            
            if (plug.create_plug(PLUG_PORT)) {
                cout << GREEN << "[SUCCESS] Plug created!" << RESET << endl;
                cout << "Your ID: " << id_system.get_display() << endl;
                cout << "Waiting for Linux to connect..." << endl;
                start_chat();
            } else {
                cout << RED << "[ERROR] Failed to create plug!" << RESET << endl;
            }
        } else {
            // Linux Mode: Normal P2P
            cout << CYAN << "[ORCA] Linux Mode: Normal P2P..." << RESET << endl;
            
            stringstream ss;
            random_device rd;
            mt19937 gen(rd());
            for (int i = 0; i < 8; i++) {
                ss << hex << (gen() % 16);
            }
            room_code = ss.str();
            
            cout << "\nYour Room Code: " << room_code << endl;
            cout << "Share this code with your friend." << endl;
            
            cout << "\nWaiting for connection (" << PEER1_TIMEOUT << " seconds)..." << endl;
            
            if (p2p.init(P2P_PORT_START)) {
                cout << "UDP hole punching active on port " << P2P_PORT_START << endl;
                p2p.listen_for_connection(to_string(id_system.get_id()), PEER1_TIMEOUT);
                
                if (p2p.is_connected()) {
                    cout << GREEN << "\n[SUCCESS] Peer connected!" << RESET << endl;
                    cout << "Peer ID: " << p2p.get_peer_id() << endl;
                    cout << "Peer IP: " << p2p.get_peer_ip() << endl;
                    start_chat();
                } else {
                    cout << RED << "\nConnection timeout." << RESET << endl;
                }
            }
        }
    }
    
    void join_room(const string& code) {
        room_code = code;
        
        cout << "\n" << string(50, '=') << endl;
        cout << "ORCASHI - JOIN ROOM" << endl;
        cout << string(50, '=') << endl;
        
        if (is_ish_mode) {
            // iSH cannot join, only create plug
            cout << RED << "[ERROR] iSH mode cannot join. Please use create." << RESET << endl;
            cout << "iSH must be the creator (plug)." << endl;
            return;
        }
        
        cout << "Enter peer IP address: ";
        string peer_ip_input;
        getline(cin, peer_ip_input);
        
        if (peer_ip_input.empty()) {
            cout << "IP address required." << endl;
            return;
        }
        
        int my_port = P2P_PORT_START + (rand() % 100);
        if (p2p.init(my_port)) {
            cout << "UDP hole punching from port " << my_port << "..." << endl;
            
            if (p2p.try_hole_punch(peer_ip_input, P2P_PORT_START, to_string(id_system.get_id()))) {
                cout << GREEN << "\n[SUCCESS] Connected to peer!" << RESET << endl;
                cout << "Peer ID: " << p2p.get_peer_id() << endl;
                cout << "Peer IP: " << p2p.get_peer_ip() << endl;
                start_chat();
            } else {
                cout << RED << "Connection failed." << RESET << endl;
            }
        }
    }
};

// ==================== MAIN ====================
int main(int argc, char* argv[]) {
    srand(time(0) ^ getpid());
    
    ORCASHI orcashi;
    orcashi.show_banner();
    
    if (argc < 2) {
        cout << "\nUsage:" << endl;
        cout << "  ./orcashi create          - Create a new chat room" << endl;
        cout << "  ./orcashi join <code>     - Join an existing room" << endl;
        cout << "  ./orcashi --help          - Show this help" << endl;
        return 0;
    }
    
    string cmd = argv[1];
    
    if (cmd == "create") {
        orcashi.create_room();
    } else if (cmd == "join" && argc >= 3) {
        orcashi.join_room(argv[2]);
    } else if (cmd == "--help" || cmd == "-h") {
        cout << "\nUsage:" << endl;
        cout << "  ./orcashi create          - Create a new chat room" << endl;
        cout << "  ./orcashi join <code>     - Join an existing room" << endl;
        cout << "  ./orcashi --help          - Show this help" << endl;
    } else {
        cout << "Unknown command: " << cmd << endl;
        cout << "Use ./orcashi --help for usage." << endl;
    }
    
    return 0;
}
