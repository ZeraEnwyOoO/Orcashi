// main.cpp - Updated with Register
#include "orcashi.hpp"
#include "ui.hpp"
#include <iostream>
#include <string>

using namespace std;

int main(int argc, char* argv[]) {
    ORCASHI orcashi;
    orcashi.init();
    
    UI ui(&orcashi);
    
    if (argc < 2) {
        // Interactive mode
        while (true) {
            ui.show_main_menu();
            char choice = ui.get_choice(0, 0);
            
            if (choice == 'q' || choice == 'Q') {
                break;
            } else if (choice == 'a' || choice == 'A') {
                ui.show_requests();
            } else if (choice == 'c' || choice == 'C') {
                ui.show_peer_list();
                int peer_choice = ui.get_choice(1, 10);
                // Start chat with selected peer
            } else if (choice == 'p' || choice == 'P') {
                ui.show_peer_list();
            } else if (choice == 'r' || choice == 'R') {
                // Register new ID
                orcashi.register_identity();
            }
        }
        return 0;
    }
    
    string cmd = argv[1];
    
    if (cmd == "register") {
        orcashi.register_identity();
    }
    else if (cmd == "--peer-list" || cmd == "-p") {
        ui.show_peer_list();
    }
    else if (cmd == "--chat" && argc >= 3) {
        ui.show_chat(argv[2]);
    }
    else if (cmd == "create") {
        orcashi.create_room();
    }
    else if (cmd == "join" && argc >= 3) {
        orcashi.join_room(argv[2]);
    }
    else if (cmd == "connect" && argc >= 3) {
        orcashi.connect_peer(argv[2]);
    }
    else if (cmd == "peers") {
        ui.show_peer_list();
    }
    else if (cmd == "--help" || cmd == "-h") {
        cout << "\nORCASHI v3.1 - P2P Chat\n";
        cout << "========================================\n";
        cout << "Usage:\n";
        cout << "  ./orcashi                - Interactive mode\n";
        cout << "  ./orcashi register       - Register new ID\n";
        cout << "  ./orcashi --peer-list    - Show peers\n";
        cout << "  ./orcashi --chat <id>    - Chat with peer\n";
        cout << "  ./orcashi create         - Create room\n";
        cout << "  ./orcashi join <ip>      - Join by IP\n";
        cout << "  ./orcashi connect <id>   - Connect by ID\n";
        cout << "  ./orcashi peers          - Show peers\n";
        cout << "  ./orcashi --help         - Show help\n";
    }
    else {
        cout << "Unknown command: " << cmd << "\n";
        cout << "Use ./orcashi --help for usage.\n";
    }
    
    return 0;
}
