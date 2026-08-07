 // orcashi.cpp - ORCASHI v3.1 with Request System
#include "orcashi.hpp"
#include "registry.hpp"
#include "request.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <random>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <cstring>
#include <cctype>

using namespace std;

const string CYAN = "\033[36m";
const string GREEN = "\033[32m";
const string YELLOW = "\033[33m";
const string RED = "\033[31m";
const string RESET = "\033[0m";
const string ORCASHI_HOME = string(getenv("HOME")) + "/.orcashi/";

// ==================== CONSTRUCTOR / DESTRUCTOR ====================
ORCASHI::ORCASHI() : running(true) {
    string cmd = "mkdir -p " + ORCASHI_HOME;
    system(cmd.c_str());
    is_ish_mode = detect_ish();
    my_id = generate_id();
}

ORCASHI::~ORCASHI() {
    running = false;
    if (ui_thread.joinable()) ui_thread.join();
    plug.close_connection();
}

bool ORCASHI::init() {
    return true;
}

// ==================== REAL IP DETECTION ====================
string ORCASHI::get_local_ip() {
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        return "127.0.0.1";
    }
    
    for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(ifa->ifa_name, "lo") == 0) continue;
        
        struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        freeifaddrs(ifaddr);
        return string(ip);
    }
    
    freeifaddrs(ifaddr);
    return "127.0.0.1";
}

// ==================== SYSTEM DETECTION ====================
bool ORCASHI::detect_ish() {
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
    
    return false;
}

// ==================== ID GENERATION ====================
string ORCASHI::generate_id() {
    string id_file = ORCASHI_HOME + "id";
    
    ifstream f(id_file);
    if (f.is_open()) {
        int id;
        if (f >> id && id >= 1 && id <= 999) {
            f.close();
            stringstream ss;
            ss << "<" << setw(3) << setfill('0') << id << ">";
            return ss.str();
        }
        f.close();
    }
    
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(1, 999);
    int new_id = dis(gen);
    
    ofstream f2(id_file);
    if (f2.is_open()) f2 << new_id;
    
    stringstream ss;
    ss << "<" << setw(3) << setfill('0') << new_id << ">";
    return ss.str();
}

// ==================== ROOM MANAGEMENT ====================
bool ORCASHI::create_room(int port) {
    cout << "\n" << string(50, '=') << endl;
    cout << "ORCASHI - CREATE ROOM" << endl;
    cout << string(50, '=') << endl;
    
    if (plug.create_plug(port)) {
        cout << GREEN << "[SUCCESS] TCP Plug created!" << RESET << endl;
        cout << "Your ID: " << my_id << endl;
        cout << "Waiting for connection..." << endl;
        show_banner();
        ui_thread = thread(&ORCASHI::ui_loop, this);
        return true;
    }
    return false;
}

bool ORCASHI::join_room(const string& ip, int port) {
    cout << "\n" << string(50, '=') << endl;
    cout << "ORCASHI - JOIN ROOM" << endl;
    cout << string(50, '=') << endl;
    
    if (plug.connect_to_plug(ip, port)) {
        cout << GREEN << "[SUCCESS] Connected!" << RESET << endl;
        show_banner();
        ui_thread = thread(&ORCASHI::ui_loop, this);
        return true;
    }
    return false;
}

// ==================== UI LOOP ====================
void ORCASHI::ui_loop() {
    string input;
    while (running && plug.is_connected()) {
        cout << my_id << "> " << flush;
        
        if (!getline(cin, input)) {
            if (cin.eof()) {
                cout << "\n[ORCA] EOF detected." << endl;
                running = false;
                break;
            }
            continue;
        }
        
        if (input == "/exit") {
            running = false;
            break;
        } else if (input == "/help") {
            show_help();
        } else if (!input.empty()) {
            plug.send_message(input);
        }
    }
}

// ==================== MESSAGING ====================
bool ORCASHI::send_message(const string& msg) {
    return plug.send_message(msg);
}

bool ORCASHI::receive_message(string& msg, int timeout_ms) {
    return plug.receive_message(msg, timeout_ms);
}

// ==================== CONNECTION STATUS ====================
bool ORCASHI::is_connected() const {
    return plug.is_connected();
}

void ORCASHI::disconnect() {
    running = false;
    if (ui_thread.joinable()) ui_thread.join();
    plug.close_connection();
}

// ==================== GETTERS ====================
string ORCASHI::get_my_id() const { return my_id; }
string ORCASHI::get_peer_id() const { return plug.get_peer_id(); }
string ORCASHI::get_peer_ip() const { return plug.get_peer_ip(); }

// ==================== REGISTER IDENTITY ====================
bool ORCASHI::register_identity() {
    cout << "\n";
    cout << "  +------------------------------------------+\n";
    cout << "  |           ORCA Registration              |\n";
    cout << "  +------------------------------------------+\n";
    cout << "\n";
    
    cout << "  Enter your ID (3 digits): ";
    string id;
    getline(cin, id);
    
    if (id.length() != 3 || !isdigit(id[0]) || !isdigit(id[1]) || !isdigit(id[2])) {
        cout << "  [ERROR] ID must be 3 digits!\n";
        return false;
    }
    
    string ip = get_local_ip();
    cout << "  Your IP: " << ip << "\n";
    
    Registry registry;
    if (registry.register_peer(id, ip, "9000")) {
        cout << "\n  [SUCCESS] Registered!\n";
        cout << "  Your ID: " << id << "\n";
        cout << "  Endpoint: " << ip << ":9000\n";
        cout << "\n  Your friends can connect using:\n";
        cout << "    ./orcashi add " << id << "\n";
        return true;
    }
    
    cout << "  [ERROR] Registration failed!\n";
    return false;
}

// ==================== REQUEST SYSTEM (NEW!) ====================
bool ORCASHI::add_peer(const string& id) {
    cout << "\n  [ORCA] Sending request to " << id << "...\n";
    
    RequestManager requests;
    if (requests.send_request(my_id, id)) {
        // Check if peer is in registry
        Registry registry;
        Peer peer;
        if (registry.get_peer(id, peer)) {
            cout << "  [ORCA] Peer found in registry: " << peer.ip << "\n";
        } else {
            cout << "  [ORCA] Peer not in registry. Waiting for response...\n";
        }
        return true;
    }
    return false;
}

bool ORCASHI::check_requests() {
    RequestManager requests;
    auto pending = requests.get_pending_requests(my_id);
    
    if (pending.empty()) {
        cout << "  [ORCA] No pending requests.\n";
        return false;
    }
    
    cout << "\n  [ORCA] You have " << pending.size() << " pending request(s):\n";
    
    for (const auto& req : pending) {
        cout << "    " << req.from_id << " wants to connect.\n";
        cout << "    Accept? (y/n): ";
        string answer;
        getline(cin, answer);
        
        if (answer == "y" || answer == "Y") {
            requests.accept_request(req.from_id, my_id);
            
            // Connect to peer
            Registry registry;
            Peer peer;
            if (registry.get_peer(req.from_id, peer)) {
                cout << "  [ORCA] Connecting to " << req.from_id << "...\n";
                join_room(peer.ip);
                return true;
            } else {
                cout << "  [ORCA] Peer not found in registry!\n";
                cout << "  [ORCA] Trying to discover via broadcast...\n";
                // TODO: Add discovery here
            }
        } else {
            requests.reject_request(req.from_id, my_id);
        }
    }
    return true;
}

bool ORCASHI::connect_peer(const string& id) {
    Registry registry;
    Peer peer;
    
    if (registry.get_peer(id, peer)) {
        cout << "  [ORCA] Found " << id << " at " << peer.ip << ":" << peer.port << "\n";
        return join_room(peer.ip);
    } else {
        cout << "  [ORCA] Peer not registered!\n";
        cout << "  [ORCA] Send a request: ./orcashi add " << id << "\n";
        return false;
    }
}

// ==================== SHOW PEERS ====================
void ORCASHI::show_peers() {
    Registry registry;
    auto peers = registry.get_all_peers();
    
    cout << "\n  Your Peers:\n";
    if (peers.empty()) {
        cout << "    No peers registered.\n";
        cout << "    Use ./orcashi add <id> to add peers.\n";
    } else {
        for (const auto& p : peers) {
            cout << "    " << p.id << " - " << p.ip << ":" << p.port;
            if (p.online) {
                cout << " [ONLINE]\n";
            } else {
                cout << " [OFFLINE]\n";
            }
        }
    }
    cout << "\n";
}

// ==================== SHOW BANNER ====================
void ORCASHI::show_banner() {
    cout << CYAN << R"(
============================================================
  ██████╗ ██████╗  ██████╗ █████╗ 
 ██╔═══██╗██╔══██╗██╔════╝██╔══██╗C
 ██║   ██║██████╔╝██║     ███████╗H
 ██║   ██║██╔══██╗██║     ██╔══██╗A
 ╚██████╔╝██║  ██║╚██████╗██║  ██║T
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
            ORCASHI v3.1 - P2P Chat
============================================================
)" << RESET << endl;
    
    cout << "Your ID: " << my_id << endl;
    if (is_ish_mode) {
        cout << GREEN << "Mode: iSH (TCP Plug)" << RESET << endl;
    } else {
        cout << GREEN << "Mode: Linux (TCP Connect)" << RESET << endl;
    }
    cout << "Type /help for commands" << endl;
    cout << string(50, '=') << endl << endl;
}

// ==================== SHOW HELP ====================
void ORCASHI::show_help() {
    cout << "\n" << string(40, '=') << endl;
    cout << "ORCASHI v3.1 - P2P Chat" << endl;
    cout << string(40, '=') << endl;
    cout << "Commands:" << endl;
    cout << "  /help    - Show this help" << endl;
    cout << "  /exit    - Disconnect" << endl;
    cout << "  /status  - Show connection status" << endl;
    cout << "\nYour ID: " << my_id << endl;
    cout << "Peer ID: " << get_peer_id() << endl;
    cout << string(40, '=') << endl << endl;
}

// ==================== SIMULATION (FOR v3.2) ====================
string ORCASHI::get_hidden_password() {
    string password;
    getline(cin, password);
    return password;
}

string ORCASHI::detect_usb() {
    return "";  // v3.2
}

bool ORCASHI::save_to_usb(const Identity& identity, const string& usb_path) {
    return false;  // v3.2
}

bool ORCASHI::load_from_usb(Identity& identity, const string& usb_path) {
    return false;  // v3.2
}

bool ORCASHI::register_normal_id() {
    return false;  // v3.2
}

bool ORCASHI::register_verified_id() {
    return false;  // v3.2
}
