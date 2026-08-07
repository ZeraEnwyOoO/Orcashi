 // orcashi.cpp
#include "orcashi.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <random>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

using namespace std;

const string CYAN = "\033[36m";
const string GREEN = "\033[32m";
const string YELLOW = "\033[33m";
const string RED = "\033[31m";
const string RESET = "\033[0m";
const string ORCASHI_HOME = string(getenv("HOME")) + "/.orcashi/";

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

bool ORCASHI::send_message(const string& msg) {
    return plug.send_message(msg);
}

bool ORCASHI::receive_message(string& msg, int timeout_ms) {
    return plug.receive_message(msg, timeout_ms);
}

bool ORCASHI::is_connected() const {
    return plug.is_connected();
}

void ORCASHI::disconnect() {
    running = false;
    if (ui_thread.joinable()) ui_thread.join();
    plug.close_connection();
}

string ORCASHI::get_my_id() const { return my_id; }
string ORCASHI::get_peer_id() const { return plug.get_peer_id(); }
string ORCASHI::get_peer_ip() const { return plug.get_peer_ip(); }

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

void ORCASHI::show_help() {
    cout << "\n" << string(40, '=') << endl;
    cout << "ORCASHI v3.1 - P2P Chat" << endl;
    cout << string(40, '=') << endl;
    cout << "Commands:" << endl;
    cout << "  /help    - Show this help" << endl;
    cout << "  /exit    - Disconnect" << endl;
    cout << "\nYour ID: " << my_id << endl;
    cout << "Peer ID: " << get_peer_id() << endl;
    cout << string(40, '=') << endl << endl;
}
