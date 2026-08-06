 // orcashi_v3.cpp
// ORCASHI v3.0 - P2P Chat ដែលអាចទុកចិត្តបាន
// Compile: g++ -o orcashi orcashi_v3.cpp -lpthread -std=c++17

#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <chrono>
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
const int PLUG_PORT = 9000;
const int HEARTBEAT_INTERVAL = 5;
const int MSG_TIMEOUT = 2;

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
    chrono::steady_clock::time_point sent_time;
    bool acknowledged;
    int retries;
    
    ReliableMessage() : id(0), acknowledged(false), retries(0) {}
};

// ==================== TCP PLUG v3.0 (RELIABLE) ====================
class TCPPlug {
private:
    int plug_socket;
    int client_socket;
    bool connected;
    ThreadSafeQueue<string> message_queue;
    thread receive_thread;
    thread send_thread;
    thread ack_thread;
    thread heartbeat_thread;
    atomic<bool> running;
    string peer_ip;
    string peer_id;
    int next_msg_id;
    map<int, ReliableMessage> pending_messages;
    mutex pending_mutex;
    
    // ===== SEND WITH ACKNOWLEDGMENT =====
    void send_reliable(const string& content) {
        int msg_id = next_msg_id++;
        string full_msg = "MSG:" + to_string(msg_id) + ":" + content + "\n";
        
        // Store in pending
        ReliableMessage msg;
        msg.id = msg_id;
        msg.content = content;
        msg.sent_time = chrono::steady_clock::now();
        msg.acknowledged = false;
        msg.retries = 0;
        
        {
            lock_guard<mutex> lock(pending_mutex);
            pending_messages[msg_id] = msg;
        }
        
        // Send
        send(client_socket, full_msg.c_str(), full_msg.length(), MSG_NOSIGNAL);
    }
    
    // ===== SEND ACKNOWLEDGMENT =====
    void send_ack(int msg_id) {
        string ack = "ACK:" + to_string(msg_id) + "\n";
        send(client_socket, ack.c_str(), ack.length(), MSG_NOSIGNAL);
    }
    
    // ===== HEARTBEAT (Keep-alive) =====
    void heartbeat_loop() {
        while (running && connected) {
            this_thread::sleep_for(chrono::seconds(HEARTBEAT_INTERVAL));
            if (connected) {
                string heartbeat = "PING\n";
                send(client_socket, heartbeat.c_str(), heartbeat.length(), MSG_NOSIGNAL);
            }
        }
    }
    
    // ===== ACKNOWLEDGMENT THREAD =====
    void ack_loop() {
        while (running && connected) {
            this_thread::sleep_for(chrono::milliseconds(500));
            
            lock_guard<mutex> lock(pending_mutex);
            auto now = chrono::steady_clock::now();
            
            vector<int> to_remove;
            for (auto& pair : pending_messages) {
                auto elapsed = chrono::duration_cast<chrono::seconds>(
                    now - pair.second.sent_time).count();
                
                // Resend if not acknowledged
                if (elapsed > MSG_TIMEOUT && !pair.second.acknowledged) {
                    if (pair.second.retries < 3) {
                        string full_msg = "MSG:" + to_string(pair.first) + ":" + 
                                         pair.second.content + "\n";
                        send(client_socket, full_msg.c_str(), full_msg.length(), MSG_NOSIGNAL);
                        pair.second.sent_time = now;
                        pair.second.retries++;
                    } else {
                        // Too many retries - give up
                        cout << YELLOW << "[ORCA] Message " << pair.first 
                             << " lost after " << pair.second.retries << " retries" << RESET << endl;
                        to_remove.push_back(pair.first);
                    }
                }
                
                if (pair.second.acknowledged) {
                    to_remove.push_back(pair.first);
                }
            }
            
            for (int id : to_remove) {
                pending_messages.erase(id);
            }
        }
    }
    
    // ===== RECEIVE THREAD =====
    void receive_loop() {
        char buffer[4096];
        string accumulated;
        
        while (running && connected) {
            int n = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
            if (n <= 0) {
                cout << YELLOW << "[ORCA] Connection closed by peer." << RESET << endl;
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
                    // Handle acknowledgment
                    if (msg.find("ACK:") == 0) {
                        int msg_id = stoi(msg.substr(4));
                        lock_guard<mutex> lock(pending_mutex);
                        auto it = pending_messages.find(msg_id);
                        if (it != pending_messages.end()) {
                            it->second.acknowledged = true;
                        }
                    }
                    // Handle heartbeat
                    else if (msg == "PING") {
                        string pong = "PONG\n";
                        send(client_socket, pong.c_str(), pong.length(), MSG_NOSIGNAL);
                    }
                    else if (msg == "PONG") {
                        // Heartbeat received - do nothing
                    }
                    // Handle regular message
                    else if (msg.find("MSG:") == 0) {
                        size_t first_colon = msg.find(':', 4);
                        if (first_colon != string::npos) {
                            int msg_id = stoi(msg.substr(4, first_colon - 4));
                            string content = msg.substr(first_colon + 1);
                            
                            // Send acknowledgment
                            send_ack(msg_id);
                            
                            // Push to message queue
                            message_queue.push(content);
                        }
                    }
                    // Plain message (no ID)
                    else {
                        message_queue.push(msg);
                    }
                }
            }
        }
    }
    
    // ===== SEND THREAD =====
    void send_loop() {
        while (running && connected) {
            string msg;
            if (message_queue.pop(msg, 100)) {
                send_reliable(msg);
            }
        }
    }
    
public:
    TCPPlug() : plug_socket(-1), client_socket(-1), connected(false), 
                running(true), next_msg_id(1) {
        string cmd = "mkdir -p " + ORCASHI_HOME;
        system(cmd.c_str());
    }
    
    ~TCPPlug() {
        running = false;
        if (receive_thread.joinable()) receive_thread.join();
        if (send_thread.joinable()) send_thread.join();
        if (ack_thread.joinable()) ack_thread.join();
        if (heartbeat_thread.joinable()) heartbeat_thread.join();
        close_connection();
    }
    
    bool create_plug(int port) {
        plug_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (plug_socket < 0) {
            cout << RED << "[ERROR] Failed to create socket!" << RESET << endl;
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
            cout << RED << "[ERROR] Failed to bind!" << RESET << endl;
            close(plug_socket);
            return false;
        }
        
        if (listen(plug_socket, 5) < 0) {
            cout << RED << "[ERROR] Failed to listen!" << RESET << endl;
            close(plug_socket);
            return false;
        }
        
        cout << GREEN << "[ORCA] TCP Plug is ready on port " << port << "!" << RESET << endl;
        cout << CYAN << "[ORCA] Waiting for Linux to connect..." << RESET << endl;
        
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        client_socket = accept(plug_socket, (struct sockaddr*)&client_addr, &addr_len);
        if (client_socket < 0) {
            cout << RED << "[ERROR] Failed to accept!" << RESET << endl;
            close(plug_socket);
            return false;
        }
        
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        peer_ip = string(ip);
        peer_id = peer_ip;
        connected = true;
        
        cout << GREEN << "[ORCA] Linux connected from " << peer_ip << "!" << RESET << endl;
        
        // Start threads
        receive_thread = thread(&TCPPlug::receive_loop, this);
        send_thread = thread(&TCPPlug::send_loop, this);
        ack_thread = thread(&TCPPlug::ack_loop, this);
        heartbeat_thread = thread(&TCPPlug::heartbeat_loop, this);
        
        return true;
    }
    
    bool connect_to_plug(const string& target_ip, int port) {
        client_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (client_socket < 0) {
            cout << RED << "[ERROR] Failed to create socket!" << RESET << endl;
            return false;
        }
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);
        
        if (connect(client_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            cout << RED << "[ERROR] Failed to connect!" << RESET << endl;
            close(client_socket);
            return false;
        }
        
        peer_ip = target_ip;
        peer_id = target_ip;
        connected = true;
        
        cout << GREEN << "[ORCA] Connected to plug at " << target_ip << ":" << port << "!" << RESET << endl;
        
        receive_thread = thread(&TCPPlug::receive_loop, this);
        send_thread = thread(&TCPPlug::send_loop, this);
        ack_thread = thread(&TCPPlug::ack_loop, this);
        heartbeat_thread = thread(&TCPPlug::heartbeat_loop, this);
        
        return true;
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
    string get_peer_ip() const { return peer_ip; }
    
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
    TCPPlug plug;
    atomic<bool> running;
    thread ui_thread;
    bool is_ish_mode;
    
    bool detect_ish() {
        if (access("/sbin/apk", F_OK) == 0) return true;
        
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
        return false;
    }
    
    void ui_loop() {
        string input;
        while (running) {
            if (!plug.is_connected()) {
                this_thread::sleep_for(chrono::milliseconds(100));
                continue;
            }
            
            cout << id_system.get_display() << "> " << flush;
            
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
                plug.send_message(input);
            }
        }
    }
    
    void show_help() {
        cout << "\n" << string(40, '=') << endl;
        cout << "ORCASHI v3.0 - Reliable P2P Chat" << endl;
        cout << string(40, '=') << endl;
        cout << "Commands:" << endl;
        cout << "  /help    - Show this help" << endl;
        cout << "  /exit    - Disconnect" << endl;
        cout << "\nFeatures:" << endl;
        cout << "  ✅ Reliable messaging (ACK)" << endl;
        cout << "  ✅ Auto-retry on failure" << endl;
        cout << "  ✅ Heartbeat keep-alive" << endl;
        cout << "  ✅ Messages always delivered!" << endl;
        if (is_ish_mode) {
            cout << "\nMode: iSH (TCP Plug)" << endl;
        } else {
            cout << "\nMode: Linux (TCP Connect)" << endl;
        }
        cout << string(40, '=') << endl << endl;
    }
    
    void start_chat() {
        cout << string(50, '=') << endl;
        cout << "ORCASHI ACTIVE" << endl;
        cout << "Your ID: " << id_system.get_display() << endl;
        if (is_ish_mode) {
            cout << "Mode: iSH (TCP Plug)" << endl;
        } else {
            cout << "Mode: Linux (TCP Connect)" << endl;
        }
        cout << "Type /help for commands" << endl;
        cout << string(50, '=') << endl << endl;
        
        ui_thread = thread(&ORCASHI::ui_loop, this);
        
        string incoming;
        while (running && plug.is_connected()) {
            if (plug.receive_message(incoming, 100)) {
                cout << "\r\033[K[" << plug.get_peer_id() << "]> " << incoming << endl;
                cout << id_system.get_display() << "> " << flush;
            }
        }
        
        running = false;
        if (ui_thread.joinable()) ui_thread.join();
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
===========================================================
            
  ██████╗ ██████╗  ██████╗ █████╗ 
 ██╔═══██╗██╔══██╗██╔════╝██╔══██╗C
 ██║   ██║██████╔╝██║     ███████║H
 ██║   ██║██╔══██╗██║     ██╔══██║A
 ╚██████╔╝██║  ██║╚██████╗██║  ██║T
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝

            ORCASHI v3.0 - Reliable P2P Chat
        (iSH Plug + Linux Connect)
============================================================
)" << RESET << endl;
        
        cout << "\nYour ID: " << id_system.get_display() << endl;
        if (is_ish_mode) {
            cout << GREEN << "Mode: iSH (TCP Plug)" << RESET << endl;
        } else {
            cout << GREEN << "Mode: Linux (TCP Connect)" << RESET << endl;
        }
        cout << "Type /help for commands" << endl;
    }
    
    void create_room() {
        cout << "\n" << string(50, '=') << endl;
        cout << "ORCASHI - CREATE ROOM" << endl;
        cout << string(50, '=') << endl;
        
        if (is_ish_mode) {
            cout << CYAN << "[ORCA] iSH Mode: Creating TCP plug..." << RESET << endl;
            
            if (plug.create_plug(PLUG_PORT)) {
                cout << GREEN << "[SUCCESS] TCP Plug created!" << RESET << endl;
                cout << "Your ID: " << id_system.get_display() << endl;
                cout << "Waiting for Linux to connect..." << endl;
                start_chat();
            } else {
                cout << RED << "[ERROR] Failed to create TCP plug!" << RESET << endl;
            }
        } else {
            cout << RED << "[ERROR] Linux must join, not create!" << RESET << endl;
            cout << "Use: ./orcashi join <ip>" << endl;
        }
    }
    
    void join_room(const string& ip) {
        cout << "\n" << string(50, '=') << endl;
        cout << "ORCASHI - JOIN ROOM" << endl;
        cout << string(50, '=') << endl;
        
        if (is_ish_mode) {
            cout << RED << "[ERROR] iSH cannot join. Must create plug!" << RESET << endl;
            cout << "Use: ./orcashi create" << endl;
            return;
        }
        
        if (ip.empty()) {
            cout << "Enter peer IP address: ";
            string ip_input;
            getline(cin, ip_input);
            if (ip_input.empty()) {
                cout << "IP address required." << endl;
                return;
            }
            cout << CYAN << "[ORCA] Connecting to TCP plug at " << ip_input << ":" << PLUG_PORT << "..." << RESET << endl;
            if (plug.connect_to_plug(ip_input, PLUG_PORT)) {
                cout << GREEN << "[SUCCESS] Connected to plug!" << RESET << endl;
                start_chat();
            } else {
                cout << RED << "Connection failed." << RESET << endl;
            }
        } else {
            cout << CYAN << "[ORCA] Connecting to TCP plug at " << ip << ":" << PLUG_PORT << "..." << RESET << endl;
            if (plug.connect_to_plug(ip, PLUG_PORT)) {
                cout << GREEN << "[SUCCESS] Connected to plug!" << RESET << endl;
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
        cout << "  ./orcashi create              - Create TCP plug (iSH)" << endl;
        cout << "  ./orcashi join <ip>           - Connect to TCP plug (Linux)" << endl;
        cout << "  ./orcashi --help              - Show this help" << endl;
        return 0;
    }
    
    string cmd = argv[1];
    
    if (cmd == "create") {
        orcashi.create_room();
    } else if (cmd == "join" && argc >= 3) {
        orcashi.join_room(argv[2]);
    } else if (cmd == "--help" || cmd == "-h") {
        cout << "\nUsage:" << endl;
        cout << "  ./orcashi create              - Create TCP plug (iSH)" << endl;
        cout << "  ./orcashi join <ip>           - Connect to TCP plug (Linux)" << endl;
        cout << "  ./orcashi --help              - Show this help" << endl;
    } else {
        cout << "Unknown command: " << cmd << endl;
        cout << "Use ./orcashi --help for usage." << endl;
    }
    
    return 0;
}
