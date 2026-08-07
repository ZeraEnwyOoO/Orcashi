// ui.cpp - Interactive Terminal UI Implementation
#include "ui.hpp"
#include <iostream>
#include <algorithm>

using namespace std;

UI::UI(ORCASHI* orcashi) : orcashi(orcashi) {}

void UI::clear_screen() {
    cout << "\033[2J\033[H";
}

void UI::print_separator() {
    cout << "  ---------------------------------\n";
}

void UI::print_header(const string& title) {
    clear_screen();
    cout << "\n";
    cout << "  +------------------------------------------+\n";
    cout << "  |           " << title << "\n";
    cout << "  +------------------------------------------+\n";
    cout << "\n";
}

void UI::print_status(const string& msg, bool success) {
    if (success) {
        cout << "  [OK] " << msg << "\n";
    } else {
        cout << "  [FAIL] " << msg << "\n";
    }
}

void UI::show_main_menu() {
    print_header("ORCASHI v3.1");
    
    cout << "  Your ID: " << orcashi->get_my_id() << "\n\n";
    
    // Show pending requests
    if (!pending_requests.empty()) {
        cout << "  [NOTICE] You have " << pending_requests.size() 
             << " connection requests\n";
        for (size_t i = 0; i < pending_requests.size(); i++) {
            cout << "    [" << (i+1) << "] " << pending_requests[i] << "\n";
        }
        cout << "\n";
    }
    
    // Show online peers
    update_peer_lists();
    if (!online_peers.empty()) {
        cout << "  Online Peers (" << online_peers.size() << "):\n";
        for (const auto& peer : online_peers) {
            cout << "    * " << peer << "\n";
        }
        cout << "\n";
    }
    
    // Show offline peers
    if (!offline_peers.empty()) {
        cout << "  Offline Peers (" << offline_peers.size() << "):\n";
        for (const auto& peer : offline_peers) {
            cout << "    " << peer << "\n";
        }
        cout << "\n";
    }
    
    cout << "  [a] Accept Request  [c] Chat\n";
    cout << "  [p] Peer List       [q] Quit\n";
    cout << "\n";
    cout << "  > ";
}

void UI::show_peer_list() {
    print_header("Peer List");
    
    update_peer_lists();
    
    cout << "  Your Peers:\n";
    print_separator();
    
    int i = 1;
    for (const auto& peer : online_peers) {
        cout << "  " << i++ << ". " << peer << "  [ONLINE]  *\n";
    }
    for (const auto& peer : offline_peers) {
        cout << "  " << i++ << ". " << peer << "  [OFFLINE]\n";
    }
    
    print_separator();
    cout << "  Total: " << (online_peers.size() + offline_peers.size()) 
         << " peers (" << online_peers.size() << " online)\n\n";
    
    cout << "  [c] Chat  [r] Remove  [b] Back\n\n";
    cout << "  > ";
}

void UI::show_chat(const string& peer_id) {
    print_header("Chat with " + peer_id);
    
    cout << "  Connected to " << peer_id << "\n";
    print_separator();
    cout << "  /help - Show commands\n";
    cout << "  /exit - Disconnect\n";
    print_separator();
    cout << "\n";
    
    // Chat loop
    string input;
    while (true) {
        cout << "  > ";
        getline(cin, input);
        
        if (input == "/exit") {
            break;
        } else if (input == "/help") {
            cout << "  Commands: /exit, /status, /clear\n";
        } else if (!input.empty()) {
            orcashi->send_message(peer_id, input);
        }
    }
}

void UI::show_requests() {
    print_header("Connection Requests");
    
    if (pending_requests.empty()) {
        cout << "  No pending requests\n\n";
        return;
    }
    
    cout << "  Pending requests:\n";
    print_separator();
    for (size_t i = 0; i < pending_requests.size(); i++) {
        cout << "  [" << (i+1) << "] " << pending_requests[i] << "\n";
    }
    print_separator();
    cout << "\n";
    
    cout << "  Accept request? (y/n): ";
    string response;
    getline(cin, response);
    
    if (response == "y" || response == "Y") {
        cout << "  Choose request number: ";
        int choice;
        cin >> choice;
        cin.ignore();
        
        if (choice >= 1 && choice <= (int)pending_requests.size()) {
            string id = pending_requests[choice-1];
            orcashi->accept_request(id);
            print_status("Accepted " + id, true);
        }
    }
}

void UI::update_peer_lists() {
    online_peers.clear();
    offline_peers.clear();
    pending_requests.clear();
    
    // Get peers from ORCASHI
    auto peers = orcashi->get_peers();
    for (const auto& peer : peers) {
        if (peer.online) {
            online_peers.push_back(peer.id);
        } else {
            offline_peers.push_back(peer.id);
        }
    }
    
    // Get pending requests
    auto requests = orcashi->get_requests();
    pending_requests = requests;
}

string UI::get_input(const string& prompt) {
    cout << prompt;
    string input;
    getline(cin, input);
    return input;
}

int UI::get_choice(int min, int max) {
    string input;
    int choice;
    while (true) {
        cout << "  Choose (";
        if (min == 0) {
            cout << "a-z";
        } else {
            cout << min << "-" << max;
        }
        cout << "): ";
        getline(cin, input);
        
        if (min == 0) {
            if (input.length() == 1) {
                return input[0];
            }
        } else {
            try {
                choice = stoi(input);
                if (choice >= min && choice <= max) {
                    return choice;
                }
            } catch (...) {}
        }
        cout << "  Invalid choice. Try again.\n";
    }
}

bool UI::get_yes_no(const string& prompt) {
    string input;
    while (true) {
        cout << prompt << " (y/n): ";
        getline(cin, input);
        if (input == "y" || input == "Y") return true;
        if (input == "n" || input == "N") return false;
        cout << "  Please enter y or n.\n";
    }
}

void UI::draw_box(const string& content) {
    cout << "  +------------------------------------------+\n";
    cout << "  | " << content << "\n";
    cout << "  +------------------------------------------+\n";
}
