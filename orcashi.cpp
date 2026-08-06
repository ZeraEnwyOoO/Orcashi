 // orcashi.cpp
// ORCASHI v4.0 - P2P Chat with Heartbeat + Online Status + Search
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
#include <netinet/tcp.h>

using namespace std;

// ==================== COLORS ====================
const string CYAN = "\033[36m";
const string GREEN = "\033[32m";
const string YELLOW = "\033[33m";
const string RED = "\033[31m";
const string PURPLE = "\033[35m";
const string RESET = "\033[0m";

// ==================== CONFIG ====================
const string ORCASHI_HOME = string(getenv("HOME")) + "/.orcashi/";
const int PLUG_PORT = 9000;
const int HEARTBEAT_PORT = 9998;
const int HEARTBEAT_INTERVAL = 30;
const int ONLINE_TIMEOUT = 60;
const int DISCOVERY_PORT = 9999;

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

// ==================== HEARTBEAT SYSTEM ====================
class HeartbeatSystem {
private:
    int my_id;
    map<int, time_t> online_peers;
    mutex online_mutex;
    int heartbeat_socket;
    thread send_thread;
    thread listen_thread;
    atomic<bool> running;
    
public:
    HeartbeatSystem(int id) : my_id(id), running(true) {
        heartbeat_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (heartbeat_socket < 0) {
            cout << RED << "[ERROR] Failed to create heartbeat socket!" << RESET << endl;
            return;
        }
        
        int broadcast = 1;
        setsockopt(heartbeat_socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(HEARTBEAT_PORT);
        addr.sin_addr.s_addr = INADDR_ANY;
        bind(heartbeat_socket, (struct sockaddr*)&addr, sizeof(addr));
        
        send_thread = thread(&HeartbeatSystem::send_loop, this);
        listen_thread = thread(&HeartbeatSystem::listen_loop, this);
    }
    
    ~HeartbeatSystem() {
        running = false;
        if (send_thread.joinable()) send_thread.join();
        if (listen_thread.joinable()) listen_thread.join();
        close(heartbeat_socket);
    }
    
    void send_loop() {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(HEARTBEAT_PORT);
        inet_pton(AF_INET, "255.255.255.255", &addr.sin_addr);
        
        while (running) {
            string msg = "HEARTBEAT:" + to_string(my_id);
            sendto(heartbeat_socket, msg.c_str(), msg.length(), 0,
                   (struct sockaddr*)&addr, sizeof(addr));
            this_thread::sleep_for(chrono::seconds(HEARTBEAT_INTERVAL));
        }
    }
    
    void listen_loop() {
        while (running) {
            char buffer[1024];
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);
            int n = recvfrom(heartbeat_socket, buffer, sizeof(buffer)-1, 0,
                            (struct sockaddr*)&from, &from_len);
            if (n > 0) {
                buffer[n] = '\0';
                string msg(buffer);
                if (msg.find("HEARTBEAT:") == 0) {
                    int peer_id = stoi(msg.substr(10));
                    lock_guard<mutex> lock(online_mutex);
                    online_peers[peer_id] = time(0);
                }
            }
        }
    }
    
    bool is_online(int peer_id) {
        lock_guard<mutex> lock(online_mutex);
        auto it = online_peers.find(peer_id);
        if (it != online_peers.end()) {
            time_t now = time(0);
            int diff = now - it->second;
            return diff < ONLINE_TIMEOUT;
        }
        return false;
    }
    
    string get_status(int peer_id) {
        return is_online(peer_id) ? "Online  " : "Offline  ";
    }
    
    vector<int> get_online_peers() {
        vector<int> result;
        lock_guard<mutex> lock(online_mutex);
        time_t now = time(0);
        for (auto& pair : online_peers) {
            if (now - pair.second < ONLINE_TIMEOUT) {
                result.push_back(pair.first);
            }
        }
        return result;
    }
};

// ==================== DISCOVERY SYSTEM ====================
class DiscoverySystem {
private:
    int discovery_socket;
    atomic<bool> running;
    map<int, string> peer_endpoints;
    mutex endpoint_mutex;
    thread listen_thread;
    
public:
    DiscoverySystem() : running(true) {
        discovery_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (discovery_socket < 0) return;
        
        int broadcast = 1;
        setsockopt(discovery_socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(DISCOVERY_PORT);
        addr.sin_addr.s_addr = INADDR_ANY;
        bind(discovery_socket, (struct sockaddr*)&addr, sizeof(addr));
        
        listen_thread = thread(&DiscoverySystem::listen_loop, this);
    }
    
    ~DiscoverySystem() {
        running = false;
        if (listen_thread.joinable()) listen_thread.join();
        close(discovery_socket);
    }
    
    void broadcast_endpoint(int my_id, const string& ip, int port) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        int broadcast = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(DISCOVERY_PORT);
        inet_pton(AF_INET, "255.255.255.255", &addr.sin_addr);
        
        string msg = "ENDPOINT:" + to_string(my_id) + ":" + ip + ":" + to_string(port);
        sendto(sock, msg.c_str(), msg.length(), 0, (struct sockaddr*)&addr, sizeof(addr));
        close(sock);
    }
    
    void listen_loop() {
        while (running) {
            char buffer[1024];
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);
            int n = recvfrom(discovery_socket, buffer, sizeof(buffer)-1, 0,
                            (struct sockaddr*)&from, &from_len);
            if (n > 0) {
                buffer[n] = '\0';
                string msg(buffer);
                if (msg.find("ENDPOINT:") == 0) {
                    string data = msg.substr(9);
                    size_t pos1 = data.find(':');
                    size_t pos2 = data.find(':', pos1 + 1);
                    if (pos1 != string::npos && pos2 != string::npos) {
                        int peer_id = stoi(data.substr(0, pos1));
                        string ip = data.substr(pos1 + 1, pos2 - pos1 - 1);
                        int port = stoi(data.substr(pos2 + 1));
                        
                        lock_guard<mutex> lock(endpoint_mutex);
                        peer_endpoints[peer_id] = ip + ":" + to_string(port);
                    }
                }
            }
        }
    }
    
    string get_endpoint(int peer_id) {
        lock_guard<mutex> lock(endpoint_mutex);
        auto it = peer_endpoints.find(peer_id);
        if (it != peer_endpoints.end()) {
            return it->second;
        }
        return "";
    }
};

// ==================== TCP PLUG ====================
class TCPPlug {
private:
    int plug_socket;
    int client_socket;
    bool connected;
    ThreadSafeQueue<string> message_queue;
    ThreadSafeQueue<string> send_queue;
    thread receive_thread;
    thread send_thread;
    atomic<bool> running;
    string peer_ip;
    string peer_id;
    mutex send_mutex;
    
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
        cout << CYAN << "[ORCA] Waiting for connections..." << RESET << endl;
        
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
        
        cout << GREEN << "[ORCA] Connected from " << peer_ip << "!" << RESET << endl;
        
        int flag = 1;
        setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        
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
        
        cout << GREEN << "[ORCA] Connected to " << target_ip << ":" << port << "!" << RESET << endl;
        
        int flag = 1;
        setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        
        receive_thread = thread(&TCPPlug::receive_loop, this);
        send_thread = thread(&TCPPlug::send_loop, this);
        
        return true;
    }
    
    void send_loop() {
        while (running && connected) {
            string msg;
            if (send_queue.pop(msg, 100)) {
                string msg_with_newline = msg + "\n";
                lock_guard<mutex> lock(send_mutex);
                int n = send(client_socket, msg_with_newline.c_str(), 
                             msg_with_newline.length(), MSG_NOSIGNAL);
                if (n <= 0) {
                    connected = false;
                    break;
                }
            }
        }
    }
    
    void receive_loop() {
        char buffer[4096];
        string accumulated;
        
        while (running && connected) {
            int n = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
            if (n <= 0) {
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
                    message_queue.push(msg);
                }
            }
        }
    }
    
    bool send_message(const string& msg) {
        if (!connected) return false;
        send_queue.push(msg);
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

// ==================== SAVED PEERS ====================
class SavedPeers {
private:
    string peers_file;
    vector<string> saved_peers;
    mutex peers_mutex;
    
public:
    SavedPeers() {
        peers_file = ORCASHI_HOME + "saved_peers.txt";
        load();
    }
    
    void load() {
        lock_guard<mutex> lock(peers_mutex);
        saved_peers.clear();
        ifstream f(peers_file);
        if (f.is_open()) {
            string line;
            while (getline(f, line)) {
                if (!line.empty()) {
                    saved_peers.push_back(line);
                }
            }
            f.close();
        }
    }
    
    void save() {
        lock_guard<mutex> lock(peers_mutex);
        ofstream f(peers_file);
        if (f.is_open()) {
            for (const string& peer : saved_peers) {
                f << peer << endl;
            }
            f.close();
        }
    }
    
    void add_peer(const string& peer_id) {
        lock_guard<mutex> lock(peers_mutex);
        if (find(saved_peers.begin(), saved_peers.end(), peer_id) == saved_peers.end()) {
            saved_peers.push_back(peer_id);
            save();
        }
    }
    
    vector<string> get_peers() {
        lock_guard<mutex> lock(peers_mutex);
        return saved_peers;
    }
};

// ==================== ORCASHI MAIN ====================
class ORCASHI {
private:
    IDSystem id_system;
    HeartbeatSystem heartbeat;
    DiscoverySystem discovery;
    TCPPlug plug;
    SavedPeers saved_peers;
    atomic<bool> running;
    thread ui_thread;
    bool is_ish_mode;
    int my_id;
    string my_ip;
    
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
    
    string get_local_ip() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(80);
        inet_pton(AF_INET, "8.8.8.8", &dest.sin_addr);
        connect(sock, (struct sockaddr*)&dest, sizeof(dest));
        
        struct sockaddr_in local;
        socklen_t addr_len = sizeof(local);
        getsockname(sock, (struct sockaddr*)&local, &addr_len);
        
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip));
        close(sock);
        return string(ip);
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
                running = false;
                break;
            }
            
            if (!getline(cin, input)) {
                if (cin.eof()) {
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
        cout << "ORCASHI v4.0 - P2P Chat" << endl;
        cout << string(40, '=') << endl;
        cout << "Commands:" << endl;
        cout << "  /help    - Show this help" << endl;
        cout << "  /exit    - Disconnect" << endl;
        cout << "\nCommands (outside chat):" << endl;
        cout << "  ./orcashi create          - Create a room" << endl;
        cout << "  ./orcashi join <ip>       - Join a room" << endl;
        cout << "  ./orcashi search          - Search for a peer" << endl;
        cout << "  ./orcashi peer-list       - Show saved peers" << endl;
        cout << string(40, '=') << endl << endl;
    }
    
    void start_chat() {
        cout << string(50, '=') << endl;
        cout << "ORCASHI ACTIVE" << endl;
        cout << "Your ID: " << id_system.get_display() << endl;
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
    ORCASHI() : running(true), heartbeat(id_system.get_id()), my_id(id_system.get_id()) {
        string cmd = "mkdir -p " + ORCASHI_HOME;
        system(cmd.c_str());
        is_ish_mode = detect_ish();
        my_ip = get_local_ip();
    }
    
    void show_banner() {
        cout << PURPLE << R"(
============================================================
  ██████╗ ██████╗  ██████╗ █████╗ 
 ██╔═══██╗██╔══██╗██╔════╝██╔══██╗ C
 ██║   ██║██████╔╝██║     ███████║ H
 ██║   ██║██╔══██╗██║     ██╔══██║ A
 ╚██████╔╝██║  ██║╚██████╗██║  ██║ T
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝

            ORCASHI v4.0 - P2P Chat
   (Heartbeat + Online Status + Search) talk what you want :3
============================================================
)" << RESET << endl;
        
        cout << "\nYour ID: " << id_system.get_display() << endl;
        if (is_ish_mode) {
            cout << GREEN << "Mode: iSH (Plug)" << RESET << endl;
        } else {
            cout << GREEN << "Mode: Linux (Connect)" << RESET << endl;
        }
        cout << "Type /help for commands" << endl;
    }
    
    void create_room() {
        cout << "\n" << string(50, '=') << endl;
        cout << "ORCASHI - CREATE ROOM" << endl;
        cout << string(50, '=') << endl;
        
        if (is_ish_mode) {
            cout << CYAN << "[ORCA] Creating TCP plug..." << RESET << endl;
            
            // Broadcast endpoint
            discovery.broadcast_endpoint(my_id, my_ip, PLUG_PORT);
            cout << CYAN << "[ORCA] Broadcasting endpoint: " << my_ip << ":" << PLUG_PORT << RESET << endl;
            
            if (plug.create_plug(PLUG_PORT)) {
                cout << GREEN << "[SUCCESS] TCP Plug created!" << RESET << endl;
                cout << "Your ID: " << id_system.get_display() << endl;
                cout << "  Waiting for connections..." << endl;
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
            cout << CYAN << "[ORCA] Connecting to " << ip_input << ":" << PLUG_PORT << "..." << RESET << endl;
            if (plug.connect_to_plug(ip_input, PLUG_PORT)) {
                cout << GREEN << "[SUCCESS] Connected!" << RESET << endl;
                start_chat();
            } else {
                cout << RED << "Connection failed." << RESET << endl;
            }
        } else {
            cout << CYAN << "[ORCA] Connecting to " << ip << ":" << PLUG_PORT << "..." << RESET << endl;
            if (plug.connect_to_plug(ip, PLUG_PORT)) {
                cout << GREEN << "[SUCCESS] Connected!" << RESET << endl;
                start_chat();
            } else {
                cout << RED << "Connection failed." << RESET << endl;
            }
        }
    }
    
    void search_peer() {
        cout << "\n" << string(50, '=') << endl;
        cout << "  Hello who you miss today?" << endl;
        cout << string(50, '=') << endl;
        
        cout << "Please type the peer ID~" << endl;
        cout << "> ";
        string peer_id_str;
        getline(cin, peer_id_str);
        
        if (peer_id_str.empty()) {
            cout << "No ID entered~" << endl;
            return;
        }
        
        int peer_id = stoi(peer_id_str);
        
        cout << "\n  Finding " << peer_id << "..." << endl;
        
        // Check online status
        bool online = heartbeat.is_online(peer_id);
        string status = online ? "Online  " : "Offline ";
        
        // Get endpoint
        string endpoint = discovery.get_endpoint(peer_id);
        
        cout << " Found! " << peer_id << endl;
        cout << " Status: " << status << endl;
        if (!endpoint.empty()) {
            cout << "🔗 Endpoint: " << endpoint << endl;
        }
        
        cout << "\nDo you wanna send connect and save this peer ID? (y/n): ";
        string answer;
        getline(cin, answer);
        
        if (answer == "y" || answer == "Y") {
            // Save peer
            saved_peers.add_peer(peer_id_str);
            cout << "  Saved! Use ./orcashi peer-list to see saved peers~" << endl;
            
            if (online && !endpoint.empty()) {
                cout << " Sending connect request..." << endl;
                // Connect to peer
                size_t pos = endpoint.find(':');
                if (pos != string::npos) {
                    string ip = endpoint.substr(0, pos);
                    int port = stoi(endpoint.substr(pos + 1));
                    if (plug.connect_to_plug(ip, port)) {
                        cout << GREEN << " Connected!" << RESET << endl;
                        start_chat();
                    }
                }
            } else {
                cout << "Request has been send~" << endl;
                cout << "If you wait too long is depend on your peer~" << endl;
                cout << "Thank you~ (uwu)" << endl;
            }
        }
    }
    
    void show_peer_list() {
        cout << "\n" << string(50, '=') << endl;
        cout << " Your saved peers~" << endl;
        cout << "Here who you miss~" << endl;
        cout << string(50, '=') << endl;
        
        vector<string> peers = saved_peers.get_peers();
        
        if (peers.empty()) {
            cout << "You haven't saved any peers yet~" << endl;
            cout << "Use ./orcashi search to find someone~" << endl;
            return;
        }
        
        for (const string& peer_id_str : peers) {
            int peer_id = stoi(peer_id_str);
            bool online = heartbeat.is_online(peer_id);
            string status = online ? "Online " : "Offline ";
            string endpoint = discovery.get_endpoint(peer_id);
            
            cout << "----------------------------------------" << endl;
            cout << "ID: " << peer_id << endl;
            cout << "Status: " << status << endl;
            if (!endpoint.empty()) {
                cout << "Endpoint: " << endpoint << endl;
            }
        }
        cout << "----------------------------------------" << endl;
    }
};

// ==================== MAIN ====================
int main(int argc, char* argv[]) {
    srand(time(0) ^ getpid());
    
    ORCASHI orcashi;
    orcashi.show_banner();
    
    if (argc < 2) {
        cout << "\nUsage:" << endl;
        cout << "  ./orcashi create          - Create a room (iSH)" << endl;
        cout << "  ./orcashi join <ip>       - Join a room (Linux)" << endl;
        cout << "  ./orcashi search          - Search for a peer" << endl;
        cout << "  ./orcashi peer-list       - Show saved peers" << endl;
        cout << "  ./orcashi --help          - Show this help" << endl;
        return 0;
    }
    
    string cmd = argv[1];
    
    if (cmd == "create") {
        orcashi.create_room();
    } else if (cmd == "join" && argc >= 3) {
        orcashi.join_room(argv[2]);
    } else if (cmd == "search") {
        orcashi.search_peer();
    } else if (cmd == "peer-list") {
        orcashi.show_peer_list();
    } else if (cmd == "--help" || cmd == "-h") {
        cout << "\nUsage:" << endl;
        cout << "  ./orcashi create          - Create a room (iSH)" << endl;
        cout << "  ./orcashi join <ip>       - Join a room (Linux)" << endl;
        cout << "  ./orcashi search          - Search for a peer" << endl;
        cout << "  ./orcashi peer-list       - Show saved peers" << endl;
        cout << "  ./orcashi --help          - Show this help" << endl;
    } else {
        cout << "Unknown command: " << cmd << endl;
        cout << "Use ./orcashi --help for usage." << endl;
    }
    
    return 0;
}
