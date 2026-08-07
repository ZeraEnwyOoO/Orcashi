// main.cpp
#include "orcashi.hpp"
#include <iostream>
#include <string>

using namespace std;

int main(int argc, char* argv[]) {
    ORCASHI orcashi;
    
    if (argc < 2) {
        cout << "\nORCASHI v3.1 - P2P Chat" << endl;
        cout << "Usage:" << endl;
        cout << "  ./orcashi create              - Create room (iSH)" << endl;
        cout << "  ./orcashi join <ip>           - Join room (Linux)" << endl;
        cout << "  ./orcashi --help              - Show help" << endl;
        return 0;
    }
    
    string cmd = argv[1];
    
    if (cmd == "create") {
        orcashi.create_room();
        
        string msg;
        while (orcashi.is_connected()) {
            if (orcashi.receive_message(msg)) {
                cout << "\r\033[K[" << orcashi.get_peer_id() << "]> " << msg << endl;
                cout << orcashi.get_my_id() << "> " << flush;
            }
        }
    } else if (cmd == "join" && argc >= 3) {
        orcashi.join_room(argv[2]);
        
        string msg;
        while (orcashi.is_connected()) {
            if (orcashi.receive_message(msg)) {
                cout << "\r\033[K[" << orcashi.get_peer_id() << "]> " << msg << endl;
                cout << orcashi.get_my_id() << "> " << flush;
            }
        }
    } else if (cmd == "--help" || cmd == "-h") {
        cout << "\nORCASHI v3.1 - P2P Chat" << endl;
        cout << "Usage:" << endl;
        cout << "  ./orcashi create              - Create room (iSH)" << endl;
        cout << "  ./orcashi join <ip>           - Join room (Linux)" << endl;
    } else {
        cout << "Unknown command: " << cmd << endl;
        cout << "Use ./orcashi --help for usage." << endl;
    }
    
    return 0;
}
