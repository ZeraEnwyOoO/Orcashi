// orcashi.cpp
// ORCASHI v2.0 - P2P Chat for iSH + Linux (TCP Plug Mode)
// Compile: g++ -o orcashi orcashi.cpp -lpthread -std=c++17

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
const int HEARTBEAT_INTERVAL = 30;

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

// ==================== TCP PLUG MODE (FIXED BUFFERING) ====================
class TCPPlug {
private:
    int plug_socket;
    int client_socket;
    bool connected;
    ThreadSafeQueue<string> message_queue;
    thread receive_thread;
    thread send_thread;
    atomic<bool> running;
    string peer_ip;
    string peer_id;
    
public:
    TCPPlug() : plug_socket(-1), client_socket(-1), connected(false), running(true) {}
    
    ~TCPPlug() {
        running = false;
        if (receive_thread.joinable()) receive_thread.join();
        if (send_thread.joinable()) send_thread.join();
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
            cout << RED << "[ERROR] Failed to bind to port " << port << "!" << RESET << endl;
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
            cout << RED << "[ERROR] Failed to accept connection!" << RESET << endl;
            close(plug_socket);
            return false;
        }
        
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        peer_ip = string(ip);
        peer_id = peer_ip;
        connected = true;
        
        cout << GREEN << "[ORCA] Linux connected from " << peer_ip << "!" << RESET << endl;
        
        receive_thread = thread(&TCPPlug::receive_loop, this);
        send_thread = thread(&TCPPlug::send_loop, this);
        
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
            cout << RED << "[ERROR] Failed to connect to " << target_ip << ":" << port << "!" << RESET << endl;
            close(client_socket);
            return false;
        }
        
        peer_ip = target_ip;
        peer_id = target_ip;
        connected = true;
        
        cout << GREEN << "[ORCA] Connected to plug at " << target_ip << ":" << port << "!" << RESET << endl;
        
        receive_thread = thread(&TCPPlug::receive_loop, this);
        send_thread = thread(&TCPPlug::send_loop, this);
        
        return true;
    }
    
    // ===== FIXED: send_loop with newline delimiter =====
    void send_loop() {
        while (running && connected) {
            string msg;
            if (message_queue.pop(msg, 100)) {
                // Add newline delimiter so receiver knows message boundary
                string msg_with_newline = msg + "\n";
                
                // Send with MSG_NOSIGNAL to prevent broken pipe crash
                int n = send(client_socket, msg_with_newline.c_str(), 
                             msg_with_newline.length(), MSG_NOSIGNAL);
                
                if (n <= 0) {
                    cout << YELLOW << "[ORCA] Send failed. Connection may be closed." << RESET << endl;
                    connected = false;
                    break;
                }
            }
        }
    }
    
    // ===== FIXED: receive_loop with newline delimiter =====
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
            
            // Split by newline delimiter
            size_t pos;
            while ((pos = accumulated.find('\n')) != string::npos) {
                string msg = accumulated.substr(0, pos);
                accumulated.erase(0, pos + 1);
                
                if (!msg.empty()) {
                    message_queue.push(msg);
                }
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
    string room_code;
    string peer_id;
    atomic<bool> running;
    ThreadSafeQueue<string> message_queue;
    thread receive_thread;
    thread ui_thread;
    thread heartbeat_thread;
    bool is_ish_mode;
    
    bool detect_ish() {
        if (access("/sbin/apk", F_OK) == 0) {
            return true;
        }
        
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
        
        ifstream f2("/proc/version");
        if (f2.is_open()) {
            string content;
            getline(f2, content);
            if (content.find("iOS") != string::npos || 
                content.find("iPhone") != string::npos) {
                f2.close();
                return true;
            }
            f2.close();
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
        cout << "ORCASHI v2.0 - P2P Chat (TCP Plug Mode)" << endl;
        cout << string(40, '=') << endl;
        cout << "Commands:" << endl;
        cout << "  /help    - Show this help" << endl;
        cout << "  /exit    - Disconnect" << endl;
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
        
        peer_id = plug.get_peer_id();
        ui_thread = thread(&ORCASHI::ui_loop, this);
        
        string incoming;
        while (running && plug.is_connected()) {
            if (plug.receive_message(incoming, 100)) {
                cout << "\r\033[K[" << peer_id << "]> " << incoming << endl;
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
============================================================
     ____   ____   ____    ____    _    ____
    / __ \ / __ \ / __ \  / __ \  | |  / __ \
   / / / // / / // / / / / / / /  | | / / / /
  / /_/ // /_/ // /_/ / / /_/ /   | |/ /_/ /
 /_____/ \____/ \____/  \____/    |___\____/

            ORCASHI v2.0 - P2P Chat (TCP Plug)
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
