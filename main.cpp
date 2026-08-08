 // main.cpp - ORCASHI v3.1 with Mainline DHT
#include "orcashi.hpp"
#include "registry.hpp"
#include "request.hpp"
#include <iostream>
#include <string>
#include <cstdlib>
#include <thread>
#include <chrono>

using namespace std;

void show_help() {
    cout << "\n";
    cout << "  +------------------------------------------+\n";
    cout << "  |           ORCASHI v3.1                  |\n";
    cout << "  |           P2P Chat System               |\n";
    cout << "  +------------------------------------------+\n";
    cout << "\n";
    cout << "  Usage:\n";
    cout << "    ./orcashi                - Interactive mode\n";
    cout << "    ./orcashi register       - Register new ID\n";
    cout << "    ./orcashi connect <id>   - Connect by ID (DHT + Registry)\n";
    cout << "    ./orcashi add <id>       - Send friend request\n";
    cout << "    ./orcashi requests       - Check pending requests\n";
    cout << "    ./orcashi create         - Create room (iSH)\n";
    cout << "    ./orcashi join <ip>      - Join by IP\n";
    cout << "    ./orcashi peers          - Show peer list\n";
    cout << "    ./orcashi search <id>    - Search for peer\n";
    cout << "    ./orcashi --help         - Show this help\n";
    cout << "\n";
    cout << "  Commands during chat:\n";
    cout << "    /help   - Show commands\n";
    cout << "    /exit   - Disconnect\n";
    cout << "    /status - Show peer status\n";
    cout << "\n";
    cout << "  DHT Features:\n";
    cout << "    - Store ID -> Endpoint in Mainline DHT\n";
    cout << "    - Lookup ID from Mainline DHT\n";
    cout << "    - No need to know IP!\n";
    cout << "\n";
}

void chat_loop(ORCASHI& orcashi) {
    string input;
    while (orcashi.is_connected()) {
        cout << "  > " << flush;
        
        if (!getline(cin, input)) {
            break;
        }
        
        if (input == "/exit") {
            orcashi.disconnect();
            break;
        } else if (input == "/help") {
            cout << "  Commands: /exit, /status, /help\n";
        } else if (input == "/status") {
            cout << "  Connected to: " << orcashi.get_peer_id() << "\n";
            cout << "  IP: " << orcashi.get_peer_ip() << "\n";
        } else if (!input.empty()) {
            orcashi.send_message(input);
        }
    }
}

int main(int argc, char* argv[]) {
    ORCASHI orcashi;
    orcashi.init();
    
    if (argc < 2) {
        // Interactive mode
        cout << "\n";
        cout << "  +------------------------------------------+\n";
        cout << "  |           ORCASHI v3.1                  |\n";
        cout << "  |           Your ID: " << orcashi.get_my_id() << "                  |\n";
        cout << "  +------------------------------------------+\n";
        cout << "\n";
        cout << "  Commands: /help, /peers, /register, /exit\n";
        cout << "\n";
        
        string input;
        while (true) {
            cout << "  > ";
            getline(cin, input);
            
            if (input == "/exit") {
                break;
            } else if (input == "/help") {
                show_help();
            } else if (input == "/peers") {
                orcashi.show_peers();
            } else if (input == "/register") {
                orcashi.register_identity();
            } else if (!input.empty()) {
                cout << "  Unknown command. Type /help\n";
            }
        }
        return 0;
    }
    
    string cmd = argv[1];
    
    if (cmd == "register") {
        orcashi.register_identity();
    }
    else if (cmd == "connect" && argc >= 3) {
        string id = argv[2];
        cout << "\n  [ORCA] Looking for " << id << "...\n";
        
        if (orcashi.connect_peer(id)) {
            cout << "  [ORCA] Connected! Type /help for commands\n\n";
            
            thread receive_thread([&]() {
                string msg;
                while (orcashi.is_connected()) {
                    if (orcashi.receive_message(msg, 100)) {
                        cout << "\r\033[K  [" << id << "] " << msg << endl;
                        cout << "  > " << flush;
                    }
                }
            });
            
            chat_loop(orcashi);
            
            if (receive_thread.joinable()) {
                receive_thread.join();
            }
        } else {
            cout << "  [ORCA] Could not connect to " << id << endl;
        }
    }
    else if (cmd == "add" && argc >= 3) {
        orcashi.add_peer(argv[2]);
    }
    else if (cmd == "requests") {
        orcashi.check_requests();
    }
    else if (cmd == "create") {
        cout << "\n  [ORCA] Creating room...\n";
        if (orcashi.create_room()) {
            cout << "  [ORCA] Waiting for connection...\n";
            cout << "  [ORCA] Your ID: " << orcashi.get_my_id() << "\n\n";
            
            while (!orcashi.is_connected()) {
                this_thread::sleep_for(chrono::milliseconds(100));
            }
            
            cout << "  [ORCA] Connected! Type /help for commands\n\n";
            
            thread receive_thread([&]() {
                string msg;
                while (orcashi.is_connected()) {
                    if (orcashi.receive_message(msg, 100)) {
                        cout << "\r\033[K  [" << orcashi.get_peer_id() << "] " << msg << endl;
                        cout << "  > " << flush;
                    }
                }
            });
            
            chat_loop(orcashi);
            
            if (receive_thread.joinable()) {
                receive_thread.join();
            }
        }
    }
    else if (cmd == "join" && argc >= 3) {
        string ip = argv[2];
        cout << "\n  [ORCA] Joining " << ip << "...\n";
        
        if (orcashi.join_room(ip)) {
            cout << "  [ORCA] Connected! Type /help for commands\n\n";
            
            thread receive_thread([&]() {
                string msg;
                while (orcashi.is_connected()) {
                    if (orcashi.receive_message(msg, 100)) {
                        cout << "\r\033[K  [" << orcashi.get_peer_id() << "] " << msg << endl;
                        cout << "  > " << flush;
                    }
                }
            });
            
            chat_loop(orcashi);
            
            if (receive_thread.joinable()) {
                receive_thread.join();
            }
        } else {
            cout << "  [ERROR] Failed to join!\n";
        }
    }
    else if (cmd == "peers") {
        orcashi.show_peers();
    }
    else if (cmd == "search" && argc >= 3) {
        string id = argv[2];
        cout << "\n  [ORCA] Searching for " << id << "...\n";
        
        Registry registry;
        Peer peer;
        if (registry.get_peer(id, peer)) {
            cout << "  [ORCA] Found in registry: " << id << " at " << peer.ip << ":" << peer.port << "\n";
            cout << "  [ORCA] Connect using: ./orcashi connect " << id << "\n";
        } else {
            string endpoint = orcashi.lookup_in_dht(id);
            if (!endpoint.empty()) {
                cout << "  [ORCA] Found in DHT: " << endpoint << "\n";
                cout << "  [ORCA] Connect using: ./orcashi connect " << id << "\n";
            } else {
                cout << "  [ORCA] Peer not found!\n";
            }
        }
        cout << "\n";
    }
    else if (cmd == "--help" || cmd == "-h") {
        show_help();
    }
    else {
        cout << "\n  Unknown command: " << cmd << "\n";
        cout << "  Use ./orcashi --help for usage.\n\n";
    }
    
    return 0;
}
